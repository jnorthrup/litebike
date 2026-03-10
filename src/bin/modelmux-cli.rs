//! ModelMux CLI - Console Launcher
//!
//! Provides CLI commands for launching and managing ModelMux instances.
//! Recognizes argv[0] for automatic mode selection (agent8888, ollama, lmstudio, etc.)

use clap::{Parser, Subcommand};
use serde_json::json;
use std::process::Command;
use std::fs;
use std::path::Path;
use std::path::PathBuf;

/// Get the program name from argv[0]
fn get_argv0_name() -> String {
    std::env::args_os()
        .next()
        .and_then(|s| s.into_string().ok())
        .and_then(|s| PathBuf::from(s).file_name().map(|s| s.to_string_lossy().to_string()))
        .unwrap_or_else(|| "modelmux".to_string())
}

#[derive(Parser)]
#[command(name = "modelmux")]
#[command(bin_name = "modelmux")]
#[command(about = "ModelMux - Model Multiplexer and Proxy Gateway")]
#[command(long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start ModelMux server
    Start {
        /// Port to bind
        #[arg(short, long, default_value = "11434")]
        port: u16,

        /// Host to bind
        // changed short flag to 'H' because '-h' conflicts with the help flag
        #[arg(short = 'H', long, default_value = "0.0.0.0")]
        host: String,

        /// Environment file
        #[arg(short, long)]
        env: Option<String>,

        /// Log level
        #[arg(short, long, default_value = "info")]
        log: String,

        /// Run in background
        #[arg(short, long)]
        daemon: bool,

        /// Run as agent8888 on port 8888
        #[arg(long)]
        agent8888: bool,
    },

    /// Stop running ModelMux instance
    Stop,

    /// Restart ModelMux server
    Restart {
        #[arg(short, long, default_value = "11434")]
        port: u16,

        #[arg(long)]
        agent8888: bool,
    },

    /// Check if ModelMux is running
    Status,

    /// View ModelMux logs
    Logs {
        /// Number of lines
        #[arg(short, long, default_value = "50")]
        lines: usize,
    },

    /// Test ModelMux endpoints
    Test,

    /// List available models
    Models,

    /// Interactive chat with a model
    Chat {
        /// Model to use
        #[arg(short, long, default_value = "kilo_code/minimax-minimax-m2.5:free")]
        model: String,

        /// System prompt
        #[arg(short, long, default_value = "You are a helpful assistant.")]
        system: String,
    },

    /// Show current configuration
    Config,

    /// Manage environment files
    Env {
        #[command(subcommand)]
        action: EnvActions,
    },

    /// Manage model cache
    Cache {
        #[command(subcommand)]
        action: CacheActions,
    },

    /// Inspect or update runtime gateway control state
    Control {
        #[command(subcommand)]
        action: ControlActions,
    },
}

#[derive(Subcommand)]
enum EnvActions {
    /// List environment files and variables
    List,
    /// Create .env file from example
    Create,
    /// Check configured API keys
    Check,
}

#[derive(Subcommand)]
enum CacheActions {
    /// Show cache status
    Status,
    /// Clear cache
    Clear,
    /// Show cache files
    Show,
}

#[derive(Subcommand)]
enum ControlActions {
    /// Show current runtime control state
    State,
    /// Prefer a provider for plain model names
    SetPreferredProvider { provider: String },
    /// Clear preferred provider override
    ClearPreferredProvider,
    /// Set default model
    SetDefaultModel { model: String },
    /// Clear default model
    ClearDefaultModel,
    /// Set fallback model
    SetFallbackModel { model: String },
    /// Clear fallback model
    ClearFallbackModel,
    /// Enable or disable runtime streaming
    SetStreaming { enabled: bool },
    /// Replace Claude-requested models with configured stand-ins
    SetClaudeRewrite {
        #[arg(long, default_value_t = true)]
        enabled: bool,
        #[arg(long)]
        default_model: Option<String>,
        #[arg(long)]
        haiku_model: Option<String>,
        #[arg(long)]
        sonnet_model: Option<String>,
        #[arg(long)]
        opus_model: Option<String>,
        #[arg(long)]
        reasoning_model: Option<String>,
    },
    /// Clear Claude model rewriting
    ClearClaudeRewrite,
    /// Set provider key policy (keymux override behavior)
    SetProviderKeyPolicy {
        provider: String,
        #[arg(long)]
        env_key: Option<String>,
        #[arg(long)]
        override_env_key: Option<String>,
        #[arg(long, default_value = "environment_first")]
        precedence: String,
    },
    /// Clear provider key policy for one provider
    ClearProviderKeyPolicy { provider: String },
    /// Import provider-key aliases from cc-switch env file (additive)
    ImportCcSwitchKeysAdditive {
        #[arg(long)]
        path: Option<String>,
    },
    /// Reset runtime overrides to defaults
    Reset,
}

fn main() {
    let argv0_name = get_argv0_name();
    
    // Auto-detect mode from argv[0]
    let is_agent8888 = argv0_name == "agent8888";
    let is_ollama = argv0_name == "ollama";
    let is_lmstudio = argv0_name == "lmstudio";
    
    // Auto-start server if invoked as agent8888/ollama/lmstudio without arguments
    if std::env::args().len() == 1 && (is_agent8888 || is_ollama || is_lmstudio) {
        if is_agent8888 {
            cmd_start(8888, "0.0.0.0", None, "info", false, true);
        } else if is_ollama {
            cmd_start(11434, "0.0.0.0", None, "info", false, false);
        } else if is_lmstudio {
            cmd_start(1234, "0.0.0.0", None, "info", false, false);
        }
        return;
    }
    
    let cli = Cli::parse();

    match &cli.command {
        Some(Commands::Start { port, host, env, log, daemon, agent8888 }) => {
            // Auto-enable agent8888 mode if invoked as agent8888
            let effective_agent8888 = *agent8888 || is_agent8888;
            let effective_port = if *port == 11434 && is_agent8888 { 8888 } else { *port };
            cmd_start(effective_port, host, env.as_deref(), log, *daemon, effective_agent8888);
        }
        Some(Commands::Stop) => {
            cmd_stop();
        }
        Some(Commands::Restart { port, agent8888 }) => {
            cmd_stop();
            std::thread::sleep(std::time::Duration::from_secs(1));
            let effective_agent8888 = *agent8888 || is_agent8888;
            let effective_port = if *port == 11434 && is_agent8888 { 8888 } else { *port };
            cmd_start(effective_port, "0.0.0.0", None, "info", false, effective_agent8888);
        }
        Some(Commands::Status) => {
            cmd_status();
        }
        Some(Commands::Logs { lines }) => {
            cmd_logs(*lines);
        }
        Some(Commands::Test) => {
            cmd_test();
        }
        Some(Commands::Models) => {
            cmd_models();
        }
        Some(Commands::Chat { model, system }) => {
            cmd_chat(model, system);
        }
        Some(Commands::Config) => {
            cmd_config();
        }
        Some(Commands::Env { action }) => {
            cmd_env(action);
        }
        Some(Commands::Cache { action }) => {
            cmd_cache(action);
        }
        Some(Commands::Control { action }) => {
            cmd_control(action);
        }
        None => {
            // Default: start server with argv[0] detection
            if is_agent8888 {
                cmd_start(8888, "0.0.0.0", None, "info", false, true);
            } else if is_ollama {
                // Ollama compatibility mode - just start serving
                cmd_start(11434, "0.0.0.0", None, "info", false, false);
            } else if is_lmstudio {
                // LMStudio compatibility mode
                cmd_start(1234, "0.0.0.0", None, "info", false, false);
            } else {
                cmd_start(11434, "0.0.0.0", None, "info", false, false);
            }
        }
    }
}

fn cmd_start(port: u16, host: &str, env_file: Option<&str>, log_level: &str, daemon: bool, agent8888: bool) {
    println!("🚀 Starting ModelMux...");
    println!("   Host: {}", host);
    println!("   Port: {}", port);
    println!("   Log:  {}", log_level);

    // Load environment file if specified
    let env_path = env_file
        .map(|s| s.to_string())
        .or_else(|| {
            if Path::new(".env").exists() {
                Some(".env".to_string())
            } else {
                dirs::home_dir()
                    .map(|h| h.join(".modelmux/.env").to_string_lossy().to_string())
                    .filter(|p| Path::new(p).exists())
            }
        });

    if let Some(path) = &env_path {
        if let Ok(content) = fs::read_to_string(path) {
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                if let Some(eq) = line.find('=') {
                    let key = line[..eq].trim();
                    let value = line[eq + 1..].trim().trim_matches('"').trim_matches('\'');
                    std::env::set_var(key, value);
                }
            }
            println!("✓ Loaded environment from {}", path);
        }
    }

    // Find sibling modelmux binary next to this executable
    let modelmux_bin = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("modelmux")))
        .unwrap_or_else(|| PathBuf::from("modelmux"));

    let mut cmd = Command::new(&modelmux_bin);

    if agent8888 {
        cmd.arg("--agent8888");
    } else {
        cmd.arg("--port").arg(port.to_string()).arg("--serve");
    }

    cmd.env("RUST_LOG", log_level);

    if daemon {
        println!("✓ Running in background");
        // In a real implementation, you'd use proper daemonization
        match cmd.spawn() {
            Ok(child) => {
                let pid = child.id();
                if let Err(e) = fs::write("modelmux.pid", pid.to_string()) {
                    eprintln!("Warning: Could not write PID file: {}", e);
                }
                println!("✓ ModelMux started successfully (PID: {})", pid);
            }
            Err(e) => {
                eprintln!("✗ Failed to start ModelMux: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        println!("✓ Starting interactive mode (Ctrl+C to stop)");
        let status = cmd.status().expect("Failed to start ModelMux");
        if !status.success() {
            std::process::exit(status.code().unwrap_or(1));
        }
    }
}

fn cmd_stop() {
    // Try PID file first
    if let Ok(pid_str) = fs::read_to_string("modelmux.pid") {
        if let Ok(pid) = pid_str.trim().parse::<u32>() {
            #[cfg(unix)]
            {
                Command::new("kill")
                    .arg("-TERM")
                    .arg(pid.to_string())
                    .status()
                    .ok();
                let _ = fs::remove_file("modelmux.pid");
                println!("✓ ModelMux stopped (PID: {})", pid);
                return;
            }
            #[cfg(not(unix))]
            {
                Command::new("taskkill")
                    .args(["/PID", &pid.to_string(), "/F"])
                    .status()
                    .ok();
                let _ = fs::remove_file("modelmux.pid");
                println!("✓ ModelMux stopped (PID: {})", pid);
                return;
            }
        }
    }

    // Try to find by port
    #[cfg(unix)]
    {
        let output = Command::new("lsof")
            .args(["-ti", ":11434"])
            .output();
        if let Ok(out) = output {
            let pid = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !pid.is_empty() {
                Command::new("kill")
                    .arg(&pid)
                    .status()
                    .ok();
                println!("✓ ModelMux stopped (PID: {})", pid);
                return;
            }
        }
    }

    println!("⚠ No running ModelMux instance found");
}

fn cmd_status() {
    #[cfg(unix)]
    {
        if let Ok(pid_str) = fs::read_to_string("modelmux.pid") {
            if let Ok(pid) = pid_str.trim().parse::<u32>() {
                let alive = Command::new("sh")
                    .arg("-c")
                    .arg(format!("kill -0 {} 2>/dev/null", pid))
                    .status()
                    .map(|s| s.success())
                    .unwrap_or(false);
                if alive {
                    print_running_status(&pid.to_string());
                    return;
                }
            }
        }
    }

    #[cfg(unix)]
    {
        let output = Command::new("lsof").args(["-ti", ":11434"]).output();
        if let Ok(out) = output {
            let pid = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !pid.is_empty() {
                print_running_status(&pid);
                return;
            }
        }
    }

    println!("⚠ ModelMux is not running");
    println!("   Icon: not available (no menu-bar/tray surface in this build)");
    print_control_path_hints(false);
}

fn print_running_status(pid: &str) {
    println!("✓ ModelMux is running");
    println!("   Port: 11434");
    println!("   PID:  {}", pid);
    println!("   Icon: not available (no menu-bar/tray surface in this build)");
    let client = reqwest::blocking::Client::new();
    if let Ok(resp) = client.get("http://localhost:11434/health").send() {
        if resp.status().is_success() {
            println!("   Health: OK");
        } else {
            println!("   Health: Unknown");
        }
    }
    print_control_state_summary(&client);
    print_control_path_hints(true);
}

fn print_control_state_summary(client: &reqwest::blocking::Client) {
    let response = match client.get("http://localhost:11434/control/state").send() {
        Ok(resp) => resp,
        Err(_) => {
            println!("   Control: unavailable");
            return;
        }
    };

    let state = match response.json::<serde_json::Value>() {
        Ok(value) => value,
        Err(_) => {
            println!("   Control: invalid state payload");
            return;
        }
    };

    let preferred_provider = state
        .pointer("/routing/preferred_provider")
        .and_then(|v| v.as_str())
        .unwrap_or("auto");
    let default_model = state
        .pointer("/routing/default_model")
        .and_then(|v| v.as_str())
        .unwrap_or("-");
    let fallback_model = state
        .pointer("/routing/fallback_model")
        .and_then(|v| v.as_str())
        .unwrap_or("-");
    let streaming_enabled = state
        .pointer("/streaming/enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let provider_count = state
        .get("providers")
        .and_then(|v| v.as_array())
        .map(|providers| providers.len())
        .unwrap_or(0);

    let key_states = state
        .pointer("/keymux/provider_keys")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let key_present_count = key_states
        .iter()
        .filter(|entry| {
            entry
                .get("key_present")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
        })
        .count();
    let trading_key_ready = key_states.iter().any(|entry| {
        let key_present = entry
            .get("key_present")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let selected = entry
            .get("selected_env_key")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        key_present && looks_like_trading_env_key(selected)
    });

    println!(
        "   Control: provider={} default={} fallback={} streaming={}",
        preferred_provider, default_model, fallback_model, streaming_enabled
    );
    println!(
        "   Keymux: {} configured key(s) across {} provider slot(s)",
        key_present_count,
        key_states.len()
    );
    println!(
        "   Trading path key signal: {}",
        if trading_key_ready { "present" } else { "not detected" }
    );
    println!("   Providers discovered: {}", provider_count);
}

fn looks_like_trading_env_key(env_key: &str) -> bool {
    let upper = env_key.to_ascii_uppercase();
    upper.contains("TRADE") || upper.contains("TRADING") || upper.contains("EXCHANGE") || upper.contains("BINANCE")
}

fn print_control_path_hints(running: bool) {
    if running {
        println!("   Control path: modelmux control state");
        println!("   Proxy test: modelmux test");
    } else {
        println!("   Control path: start first, then run `modelmux control state`");
        println!("   Proxy test: start first, then run `modelmux test`");
    }
}

fn cmd_logs(lines: usize) {
    if Path::new("modelmux.log").exists() {
        #[cfg(unix)]
        {
            let output = Command::new("tail")
                .args(["-n", &lines.to_string(), "modelmux.log"])
                .output();
            if let Ok(out) = output {
                println!("{}", String::from_utf8_lossy(&out.stdout));
            }
        }
        #[cfg(not(unix))]
        {
            if let Ok(content) = fs::read_to_string("modelmux.log") {
                let lines: Vec<&str> = content.lines().rev().take(lines).collect();
                for line in lines.iter().rev() {
                    println!("{}", line);
                }
            }
        }
    } else {
        println!("⚠ No log file found");
        println!("Start ModelMux with --daemon to create logs");
    }
}

fn cmd_test() {
    println!("🧪 Testing ModelMux endpoints...\n");

    let port = 11434;
    let client = reqwest::blocking::Client::new();

    // Health check
    print!("Health check... ");
    match client.get(format!("http://localhost:{}/health", port)).send() {
        Ok(resp) => {
            if resp.status().is_success() {
                println!("✓ OK");
            } else {
                println!("✗ FAILED");
            }
        }
        Err(_) => println!("✗ FAILED"),
    }

    // Models endpoint
    print!("Models endpoint... ");
    match client.get(format!("http://localhost:{}/v1/models", port)).send() {
        Ok(resp) => {
            if let Ok(json) = resp.json::<serde_json::Value>() {
                if let Some(data) = json.get("data").and_then(|d| d.as_array()) {
                    println!("✓ OK ({} models)", data.len());
                } else {
                    println!("✗ FAILED");
                }
            } else {
                println!("✗ FAILED");
            }
        }
        Err(_) => println!("✗ FAILED"),
    }

    // Stats endpoint
    print!("Stats endpoint... ");
    match client.get(format!("http://localhost:{}/stats", port)).send() {
        Ok(resp) => {
            if resp.status().is_success() {
                println!("✓ OK");
            } else {
                println!("✗ FAILED");
            }
        }
        Err(_) => println!("✗ FAILED"),
    }

    println!("\nSample model list:");
    if let Ok(resp) = client.get(format!("http://localhost:{}/v1/models", port)).send() {
        if let Ok(json) = resp.json::<serde_json::Value>() {
            if let Some(data) = json.get("data").and_then(|d| d.as_array()) {
                for model in data.iter().take(5) {
                    if let (Some(id), Some(owned)) = (
                        model.get("id").and_then(|v| v.as_str()),
                        model.get("owned_by").and_then(|v| v.as_str()),
                    ) {
                        println!("  • {} ({})", id, owned);
                    }
                }
            }
        }
    }
}

fn cmd_models() {
    let client = reqwest::blocking::Client::new();
    
    match client.get("http://localhost:11434/v1/models").send() {
        Ok(resp) => {
            if let Ok(json) = resp.json::<serde_json::Value>() {
                if let Some(data) = json.get("data").and_then(|d| d.as_array()) {
                    println!("Available models:");
                    for model in data.iter() {
                        if let (Some(id), Some(owned)) = (
                            model.get("id").and_then(|v| v.as_str()),
                            model.get("owned_by").and_then(|v| v.as_str()),
                        ) {
                            println!("  {} ({})", id, owned);
                        }
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("✗ Failed to fetch models: {}", e);
            eprintln!("Is ModelMux running? (modelmux status)");
        }
    }
}

fn cmd_chat(model: &str, system: &str) {
    println!("💬 Interactive Chat");
    println!("   Model: {}", model);
    println!("   Type 'quit' or 'exit' to stop\n");

    let client = reqwest::blocking::Client::new();
    let mut messages: Vec<serde_json::Value> = vec![
        serde_json::json!({"role": "system", "content": system}),
    ];

    loop {
        print!("{} ", colored::Colorize::green("You:"));
        use std::io::Write;
        std::io::stdout().flush().unwrap();

        let mut input = String::new();
        if std::io::stdin().read_line(&mut input).is_err() {
            break;
        }

        let input = input.trim();
        if input == "quit" || input == "exit" {
            println!("{} Goodbye!", colored::Colorize::yellow(""));
            break;
        }

        if input.is_empty() {
            continue;
        }

        messages.push(serde_json::json!({"role": "user", "content": input}));

        let response = client
            .post("http://localhost:11434/v1/chat/completions")
            .header("Content-Type", "application/json")
            .json(&serde_json::json!({
                "model": model,
                "messages": messages,
            }))
            .send();

        match response {
            Ok(resp) => {
                if let Ok(json) = resp.json::<serde_json::Value>() {
                    if let Some(content) = json
                        .get("choices")
                        .and_then(|c| c.as_array())
                        .and_then(|arr| arr.first())
                        .and_then(|c| c.get("message"))
                        .and_then(|m| m.get("content"))
                        .and_then(|c| c.as_str())
                    {
                        println!("{} {}", colored::Colorize::blue("Assistant:"), content);
                        println!();
                        messages.push(serde_json::json!({"role": "assistant", "content": content}));
                    } else {
                        println!("Error: No response");
                    }
                }
            }
            Err(e) => {
                eprintln!("Error: {}", e);
            }
        }
    }
}

fn cmd_config() {
    println!("ModelMux Configuration:");
    println!();
    println!("  MODELMUX_PORT:     11434");
    println!("  MODELMUX_HOST:     0.0.0.0");
    println!("  MODELMUX_LOG_LEVEL: info");
    println!();
    println!("Environment Variables:");
    
    let env_file = if Path::new(".env").exists() {
        Some(".env".to_string())
    } else {
        dirs::home_dir()
            .map(|h| h.join(".modelmux/.env").to_string_lossy().to_string())
            .filter(|p| Path::new(p).exists())
    };

    if let Some(path) = &env_file {
        if let Ok(content) = fs::read_to_string(path) {
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                if let Some(eq) = line.find('=') {
                    let key = line[..eq].trim();
                    if key.contains("_API_KEY") {
                        println!("  {} = ***hidden***", key);
                    } else {
                        let value = line[eq + 1..].trim();
                        println!("  {} = {}", key, value);
                    }
                }
            }
        }
    } else {
        println!("  No environment file found");
    }
}

fn cmd_env(action: &EnvActions) {
    match action {
        EnvActions::List => {
            println!("Available environment files:");
            if let Ok(entries) = fs::read_dir(".") {
                for entry in entries.flatten() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    if name.starts_with(".env") {
                        println!("  {}", name);
                    }
                }
            }
            println!();
            println!("System environment:");
            for (key, value) in std::env::vars() {
                if key.contains("API_KEY") || key.contains("BASE_URL") || key.starts_with("MODELMUX") {
                    if key.contains("_API_KEY") {
                        println!("  {} = ***hidden***", key);
                    } else {
                        println!("  {} = {}", key, value);
                    }
                }
            }
        }
        EnvActions::Create => {
            if Path::new(".env").exists() {
                println!("⚠ .env already exists");
                print!("Overwrite? (y/N) ");
                let mut confirm = String::new();
                std::io::stdin().read_line(&mut confirm).ok();
                if confirm.trim().to_lowercase() != "y" {
                    return;
                }
            }
            
            if Path::new(".env.example").exists() {
                if let Err(e) = fs::copy(".env.example", ".env") {
                    eprintln!("Failed to create .env: {}", e);
                } else {
                    println!("✓ Created .env file");
                    println!("Edit .env and add your API keys");
                }
            } else {
                let content = "# Add your API keys here\n";
                if let Err(e) = fs::write(".env", content) {
                    eprintln!("Failed to create .env: {}", e);
                } else {
                    println!("✓ Created .env file");
                }
            }
        }
        EnvActions::Check => {
            println!("Checking environment configuration...");
            let mut found = 0;
            for key in &["KILO_API_KEY", "MOONSHOT_API_KEY", "DEEPSEEK_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY"] {
                if std::env::var(key).is_ok() {
                    println!("  ✓ {}", key);
                    found += 1;
                } else {
                    println!("  ○ {} (not set)", key);
                }
            }
            println!();
            if found == 0 {
                println!("⚠ No API keys configured");
                println!("Run 'modelmux env create' to create a .env file");
            } else {
                println!("✓ Found {} API key(s)", found);
            }
        }
    }
}

fn cmd_cache(action: &CacheActions) {
    match action {
        CacheActions::Status => {
            let client = reqwest::blocking::Client::new();
            if let Ok(resp) = client.get("http://localhost:11434/stats").send() {
                if let Ok(json) = resp.json::<serde_json::Value>() {
                    if let Some(cached) = json.get("models_cached") {
                        println!("Cache Status: {} models cached", cached);
                    }
                }
            } else {
                println!("⚠ ModelMux not running");
            }
        }
        CacheActions::Clear => {
            let cache_dir = dirs::home_dir()
                .map(|h| h.join(".modelmux/cache"));
            
            if let Some(path) = &cache_dir {
                if path.exists() {
                    let _ = fs::remove_dir_all(path);
                }
            }
            println!("✓ Cache cleared");
        }
        CacheActions::Show => {
            let cache_dir = dirs::home_dir()
                .map(|h| h.join(".modelmux/cache"));
            
            if let Some(path) = &cache_dir {
                if path.exists() {
                    println!("Cache directory: {}", path.display());
                    if let Ok(entries) = fs::read_dir(path) {
                        for entry in entries.flatten() {
                            println!("  {}", entry.file_name().to_string_lossy());
                        }
                    }
                } else {
                    println!("  No cache directory");
                }
            }
        }
    }
}

fn cmd_control(action: &ControlActions) {
    let client = reqwest::blocking::Client::new();

    match action {
        ControlActions::State => match client.get("http://localhost:11434/control/state").send() {
            Ok(resp) => match resp.text() {
                Ok(body) => println!("{}", body),
                Err(e) => eprintln!("✗ Failed to read response: {}", e),
            },
            Err(e) => {
                eprintln!("✗ Failed to fetch control state: {}", e);
                eprintln!("Is ModelMux running? (modelmux status)");
            }
        },
        ControlActions::SetPreferredProvider { provider } => {
            post_control_action(&client, json!({
                "action": "set_preferred_provider",
                "provider": provider,
            }));
        }
        ControlActions::ClearPreferredProvider => {
            post_control_action(&client, json!({"action": "clear_preferred_provider"}));
        }
        ControlActions::SetDefaultModel { model } => {
            post_control_action(&client, json!({
                "action": "set_default_model",
                "model": model,
            }));
        }
        ControlActions::ClearDefaultModel => {
            post_control_action(&client, json!({"action": "clear_default_model"}));
        }
        ControlActions::SetFallbackModel { model } => {
            post_control_action(&client, json!({
                "action": "set_fallback_model",
                "model": model,
            }));
        }
        ControlActions::ClearFallbackModel => {
            post_control_action(&client, json!({"action": "clear_fallback_model"}));
        }
        ControlActions::SetStreaming { enabled } => {
            post_control_action(&client, json!({
                "action": "set_streaming_enabled",
                "enabled": enabled,
            }));
        }
        ControlActions::SetClaudeRewrite {
            enabled,
            default_model,
            haiku_model,
            sonnet_model,
            opus_model,
            reasoning_model,
        } => {
            post_control_action(&client, json!({
                "action": "set_claude_rewrite_policy",
                "enabled": enabled,
                "default_model": default_model,
                "haiku_model": haiku_model,
                "sonnet_model": sonnet_model,
                "opus_model": opus_model,
                "reasoning_model": reasoning_model,
            }));
        }
        ControlActions::ClearClaudeRewrite => {
            post_control_action(&client, json!({"action": "clear_claude_rewrite_policy"}));
        }
        ControlActions::SetProviderKeyPolicy {
            provider,
            env_key,
            override_env_key,
            precedence,
        } => {
            post_control_action(&client, json!({
                "action": "set_provider_key_policy",
                "provider": provider,
                "env_key": env_key,
                "override_env_key": override_env_key,
                "precedence": precedence,
            }));
        }
        ControlActions::ClearProviderKeyPolicy { provider } => {
            post_control_action(&client, json!({
                "action": "clear_provider_key_policy",
                "provider": provider,
            }));
        }
        ControlActions::ImportCcSwitchKeysAdditive { path } => {
            post_control_action(&client, json!({
                "action": "import_cc_switch_keys_additive",
                "path": path,
            }));
        }
        ControlActions::Reset => {
            post_control_action(&client, json!({"action": "reset"}));
        }
    }
}

fn post_control_action(client: &reqwest::blocking::Client, payload: serde_json::Value) {
    match client
        .post("http://localhost:11434/control/actions")
        .json(&payload)
        .send()
    {
        Ok(resp) => match resp.text() {
            Ok(body) => println!("{}", body),
            Err(e) => eprintln!("✗ Failed to read response: {}", e),
        },
        Err(e) => {
            eprintln!("✗ Failed to update control state: {}", e);
            eprintln!("Is ModelMux running? (modelmux status)");
        }
    }
}
