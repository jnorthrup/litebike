//! KeyMux - Private Keystore Manager
//! Manages API keys securely with env/.env support

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::PathBuf;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKey {
    pub id: String,
    pub provider: String,
    pub key: String,
    pub quota_limit: Option<f64>,
    pub quota_used: f64,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KeyStore {
    pub keys: BTreeMap<String, ApiKey>,
}

impl KeyStore {
    pub fn load_from_env() -> Self {
        let mut store = Self::new();
        for (key, value) in env::vars() {
            if key.ends_with("_API_KEY") && !key.contains("_SEARCH_") {
                let provider = key.trim_end_matches("_API_KEY").to_lowercase();
                let id = format!("env-{}-1", provider);
                store.keys.insert(id.clone(), ApiKey {
                    id, provider, key: value,
                    quota_limit: None, quota_used: 0.0,
                    created_at: chrono::Utc::now().timestamp() as u64,
                });
            }
        }
        store
    }
    
    pub fn load_from_file(path: &PathBuf) -> Result<Self, String> {
        let content = fs::read_to_string(path).map_err(|e| format!("Failed: {}", e))?;
        serde_json::from_str(&content).map_err(|e| format!("Parse: {}", e))
    }
    
    pub fn save_to_file(&self, path: &PathBuf) -> Result<(), String> {
        let content = serde_json::to_string_pretty(self).map_err(|e| format!("Serialize: {}", e))?;
        fs::write(path, content).map_err(|e| format!("Write: {}", e))?;
        #[cfg(unix)] { use std::os::unix::fs::PermissionsExt; fs::set_permissions(path, fs::Permissions::from_mode(0o600)).ok(); }
        Ok(())
    }
    
    pub fn list_providers(&self) -> Vec<String> {
        let mut p: Vec<String> = self.keys.values().map(|k| k.provider.clone()).collect();
        p.sort(); p.dedup(); p
    }
    
    pub fn get_key(&self, provider: &str) -> Option<&ApiKey> {
        self.keys.values().find(|k| k.provider == provider)
    }
    
    pub fn total_keys(&self) -> usize { self.keys.len() }
}

fn main() {
    env_logger::init();
    let args: Vec<String> = env::args().skip(1).collect();
    let exe = std::path::Path::new(&env::args().next().unwrap_or_else(|| "keymux".into()))
        .file_name().and_then(|s| s.to_str()).unwrap_or("keymux");
    
    if args.is_empty() || args.iter().any(|a| a == "-h" || a == "--help") {
        println!("KeyMux - Private Keystore Manager\n\nUsage: keymux [COMMAND] [OPTIONS]\n\n\
Commands:\n  list              List all providers\n  show <provider>   Show key details\n  \
export            Export keys (JSON)\n  init              Initialize keystore\n\n\
Options:\n  --env             Load from environment\n  --env-file <path> Load from .env\n  \
--keystore <path> Keystore file path\n\nBinary names:\n  keymux          Main manager\n  \
agent8888       8888 agent alias");
        return;
    }
    
    let load_env = args.iter().any(|a| a == "--env");
    let env_file = args.iter().position(|a| a == "--env-file").and_then(|i| args.get(i+1));
    let keystore_path = args.iter().position(|a| a == "--keystore").and_then(|i| args.get(i+1)).map(PathBuf::from);
    
    // Load .env if specified
    if let Some(path) = env_file {
        if let Ok(content) = fs::read_to_string(path) {
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') { continue; }
                if let Some(eq) = line.find('=') {
                    env::set_var(line[..eq].trim(), line[eq+1..].trim().trim_matches('"').trim_matches('\''));
                }
            }
        }
    }
    
    // Load keystore
    let store = if load_env {
        KeyStore::load_from_env()
    } else if let Some(path) = keystore_path {
        KeyStore::load_from_file(&path).unwrap_or_else(|_| KeyStore::new())
    } else {
        let default = dirs::home_dir().map(|mut p| { p.push(".keymux/keys.json"); p })
            .unwrap_or_else(|| PathBuf::from(".keymux/keys.json"));
        KeyStore::load_from_file(&default).unwrap_or_else(|_| KeyStore::load_from_env())
    };
    
    let cmd = args.iter().find(|a| !a.starts_with('-')).map(|s| s.as_str()).unwrap_or("list");
    
    match cmd {
        "list" => {
            let providers = store.list_providers();
            println!("Configured providers ({} keys):", store.total_keys());
            for p in providers {
                if let Some(k) = store.get_key(&p) {
                    let quota = match k.quota_limit { Some(l) => format!("{:.0}/{:.0}", k.quota_used, l), None => format!("{:.0}/∞", k.quota_used) };
                    println!("  {} - {} (quota: {})", k.id, k.provider, quota);
                }
            }
        }
        "show" => {
            if let Some(provider) = args.iter().find(|a| !a.starts_with('-') && *a != "show") {
                if let Some(k) = store.get_key(provider) {
                    println!("Provider: {}\nKey ID: {}\nKey: {}...\nQuota: {:.0} / {:?}",
                        k.provider, k.id, &k.key[..std::cmp::min(8, k.key.len())], k.quota_used, k.quota_limit);
                } else { eprintln!("Provider '{}' not found", provider); }
            } else { eprintln!("Usage: keymux show <provider>"); }
        }
        "export" => { println!("{}", serde_json::to_string_pretty(&store).unwrap()); }
        "init" => {
            let path = keystore_path.unwrap_or_else(|| {
                let mut p = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
                p.push(".keymux"); fs::create_dir_all(&p).ok(); p.push("keys.json"); p
            });
            store.save_to_file(&path).expect("Failed to init keystore");
            println!("Initialized: {}", path.display());
        }
        _ => { eprintln!("Unknown: {}", cmd); }
    }
}
