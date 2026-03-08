//! ModelMux - Model Multiplexer and Proxy Gateway
//!
//! OpenAI-compatible model gateway similar to Kilo.ai Gateway.
//! Boots from env and .env config, caches model selections, proxies to multiple providers.
//!
//! Usage:
//!   modelmux --serve              # Start HTTP server on port 11434
//!   modelmux --port 8888 --serve  # Start on port 8888 (agent8888 mode)
//!   modelmux --env-file .env      # Load .env file
//!   modelmux --list               # List available models
//!   modelmux --health             # Check health status

use std::env;
use log::{info, warn, error};

use litebike::models::{ModelProxy, ProxyConfig, ModelCache};

#[tokio::main]
async fn main() {
    // Initialize logging
    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "info");
    }
    env_logger::init();

    let args: Vec<String> = env::args().skip(1).collect();
    
    // Parse arguments
    let mut serve = args.iter().any(|a| a == "--serve" || a == "-s");
    let mut port: u16 = args.iter()
        .position(|a| a == "--port" || a == "-p")
        .and_then(|i| args.get(i + 1))
        .and_then(|p| p.parse().ok())
        .unwrap_or(11434);
    
    let env_file: Option<String> = args.iter()
        .position(|a| a == "--env-file" || a == "-e")
        .and_then(|i| args.get(i + 1))
        .cloned();
    
    let list_models = args.iter().any(|a| a == "--list" || a == "-l");
    let show_health = args.iter().any(|a| a == "--health" || a == "-h");
    let show_stats = args.iter().any(|a| a == "--stats");
    let clear_cache = args.iter().any(|a| a == "--clear-cache");
    
    // Check for agent8888 mode
    let exe_name = env::args().next().unwrap_or_else(|| "modelmux".to_string());
    let exe = std::path::Path::new(&exe_name)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("modelmux");
    
    let is_agent8888 = exe == "agent8888" || args.iter().any(|a| a == "--agent8888");
    if is_agent8888 && !args.iter().any(|a| a == "--port") {
        port = 8888;
        serve = true; // Auto-serve in agent8888 mode
    }
    
    // Auto-serve if no command specified
    if !serve && !list_models && !show_health && !show_stats && !clear_cache && args.is_empty() {
        serve = true;
    }

    info!("🚀 ModelMux v0.1.0 - Model Proxy Gateway");
    info!("   Binary: {}", exe);
    info!("   Mode: {}", if serve { "server" } else { "cli" });

    // Create proxy instance
    let mut proxy = ModelProxy::new(ProxyConfig {
        port,
        default_model: std::env::var("MODELMUX_DEFAULT_MODEL").ok().filter(|s| !s.is_empty()),
        fallback_model: std::env::var("MODELMUX_FALLBACK_MODEL").ok().filter(|s| !s.is_empty()),
        ..Default::default()
    });

    // Initialize from env
    let env_path = env_file.or_else(|| {
        // Check for .env in current directory
        if std::path::Path::new(".env").exists() {
            Some(".env".to_string())
        } else {
            // Check for ~/.modelmux/.env
            dirs::home_dir()
                .map(|h| h.join(".modelmux/.env"))
                .filter(|p| p.exists())
                .map(|p| p.to_string_lossy().to_string())
        }
    });

    if let Err(e) = proxy.init_from_env(env_path.as_deref()).await {
        warn!("Failed to initialize from env: {}", e);
    }

    // Handle commands
    if clear_cache {
        let mut cache = ModelCache::with_defaults();
        cache.clear();
        println!("✓ Cache cleared");
        return;
    }

    if list_models {
        let models = proxy.get_models().await;
        if let Some(data) = models.get("data").and_then(|d| d.as_array()) {
            println!("Available models ({}):", data.len());
            for model in data {
                let id = model.get("id").and_then(|i| i.as_str()).unwrap_or("unknown");
                let owned_by = model.get("owned_by").and_then(|o| o.as_str()).unwrap_or("unknown");
                println!("  {} ({})", id, owned_by);
            }
        }
        return;
    }

    if show_health {
        let health = proxy.health().await;
        println!("{}", serde_json::to_string_pretty(&health).unwrap());
        return;
    }

    if show_stats {
        let stats = proxy.stats().await;
        println!("{}", serde_json::to_string_pretty(&stats).unwrap());
        return;
    }

    if serve {
        if let Err(e) = proxy.start_server().await {
            error!("Server error: {}", e);
            std::process::exit(1);
        }
    }
}
