//! DSEL CLI
//!
//! Usage:
//!   dsel route kilo_code/some-model    # Get provider routing
//!   dsel available                     # List providers with API keys
//!   dsel status                        # All providers + status
//!   dsel tokens nvidia/kimi            # Show [used/remaining] for provider

use clap::{Parser, Subcommand};
use litebike::dsel;

#[derive(Parser)]
#[command(name = "dsel")]
#[command(about = "DSEL - Domain Specific Expression Language")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Route model to provider
    Route {
        /// Model ID (e.g., "kilo_code/model" or just "model")
        model: String,
    },
    /// List available providers (with API keys)
    Available,
    /// Show all providers status
    Status,
    /// Show DSEL token quota [used/remaining] for provider
    Tokens {
        /// Model ID (e.g., "nvidia/kimi" shows nvidia provider quota)
        model: String,
    },
    /// Show all provider quotas
    Quotas,
    /// Track token usage
    Track {
        /// Provider name (e.g., "nvidia")
        provider: String,
        /// Number of tokens used
        tokens: u64,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Route { model } => {
            if let Some((name, url, key_env)) = dsel::route(&model) {
                println!("provider={}", name);
                println!("url={}", url);
                println!("key_env={}", key_env);
                if let Some(key) = dsel::key(&key_env) {
                    let masked = format!("{}***{}", &key[..2.min(key.len())], &key[key.len().saturating_sub(2)..]);
                    println!("key={}", masked);
                }
            } else {
                println!("No provider found for model: {}", model);
            }
        }

        Commands::Available => {
            for name in dsel::available() {
                println!("{}", name);
            }
        }

        Commands::Status => {
            println!("PROVIDER       PRIO  HAS_KEY  BASE_URL");
            for (name, url, prio, has_key) in dsel::status() {
                println!("{:<14} {:<5} {:<7} {}", name, prio, if has_key { "✓" } else { "" }, url);
            }
        }

        Commands::Tokens { model } => {
            // Parse provider from model path (e.g., "nvidia/kimi" -> "nvidia")
            let provider = model.split('/').next().unwrap_or("");
            
            // Get actual DSEL quota status
            if let Some((used, remaining, _confidence)) = dsel::provider_quota_status(provider) {
                println!("{}/{}", 
                    format_tokens(used), 
                    format_tokens(remaining)
                );
            } else {
                // Provider not in DSEL tracking, show default initialization message
                println!("0/0");
            }
        }

        Commands::Quotas => {
            println!("PROVIDER       USED     REMAINING  CONFIDENCE");
            for (name, used, remaining, confidence) in dsel::all_provider_quotas() {
                println!("{:<14} {:<8} {:<10} {:.2}", 
                    name, 
                    format_tokens(used), 
                    format_tokens(remaining),
                    confidence
                );
            }
        }

        Commands::Track { provider, tokens } => {
            match dsel::track_tokens(&provider, tokens) {
                Ok(_) => println!("Tracked {} tokens for {}", tokens, provider),
                Err(e) => eprintln!("Error tracking tokens: {}", e),
            }
        }
    }
}

/// Format token count with K/M suffix for readability
fn format_tokens(tokens: u64) -> String {
    if tokens >= 1_000_000 {
        format!("{}M", tokens / 1_000_000)
    } else if tokens >= 1_000 {
        format!("{}K", tokens / 1_000)
    } else {
        tokens.to_string()
    }
}
