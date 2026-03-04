//! KeyMux - Private Keystore Manager

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::PathBuf;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKey { pub id: String, pub provider: String, pub key: String, pub quota_limit: Option<f64>, pub quota_used: f64, pub created_at: u64 }

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KeyStore { pub keys: BTreeMap<String, ApiKey> }

impl KeyStore {
    pub fn new() -> Self { Self { keys: BTreeMap::new() } }
    pub fn load_from_env() -> Self {
        let mut store = Self::new();
        for (key, value) in env::vars() {
            if key.ends_with("_API_KEY") && !key.contains("_SEARCH_") {
                let provider = key.trim_end_matches("_API_KEY").to_lowercase();
                let id = format!("env-{}-1", provider);
                store.keys.insert(id.clone(), ApiKey { id, provider, key: value, quota_limit: None, quota_used: 0.0, created_at: chrono::Utc::now().timestamp() as u64 });
            }
        }
        store
    }
    pub fn list_providers(&self) -> Vec<String> { let mut p: Vec<String> = self.keys.values().map(|k| k.provider.clone()).collect(); p.sort(); p.dedup(); p }
    pub fn get_key(&self, provider: &str) -> Option<&ApiKey> { self.keys.values().find(|k| k.provider == provider) }
    pub fn total_keys(&self) -> usize { self.keys.len() }
}

fn main() {
    env_logger::init();
    let args: Vec<String> = env::args().skip(1).collect();
    let exe = std::path::Path::new(&env::args().next().unwrap_or_else(|| "keymux".into())).file_name().and_then(|s| s.to_str()).unwrap_or("keymux");
    
    if args.is_empty() || args.iter().any(|a| a == "-h" || a == "--help") {
        println!("KeyMux\n\nUsage: keymux [COMMAND] [OPTIONS]\n\nCommands:\n  list, show, export, init\nOptions:\n  --env, --env-file, --keystore\n\nBinary: keymux, agent8888");
        return;
    }
    
    let load_env = args.iter().any(|a| a == "--env");
    let env_file: Option<String> = args.iter().position(|a| a == "--env-file").and_then(|i| args.get(i+1)).cloned();
    let keystore_path: Option<PathBuf> = args.iter().position(|a| a == "--keystore").and_then(|i| args.get(i+1)).map(PathBuf::from);
    
    if let Some(ref path) = env_file {
        if let Ok(content) = fs::read_to_string(path) {
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') { continue; }
                if let Some(eq) = line.find('=') { env::set_var(line[..eq].trim(), line[eq+1..].trim().trim_matches('"').trim_matches('\'')); }
            }
        }
    }
    
    let store = if load_env { KeyStore::load_from_env() }
        else if let Some(ref path) = keystore_path { KeyStore::load_from_file(path).unwrap_or_else(|_| KeyStore::new()) }
        else { let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
            let default = home.join(".keymux/keys.json");
            KeyStore::load_from_file(&default).unwrap_or_else(|_| KeyStore::load_from_env()) };
    
    let cmd = args.iter().find(|a| !a.starts_with('-')).map(|s| s.as_str()).unwrap_or("list");
    
    match cmd {
        "list" => { println!("Providers ({} keys):", store.total_keys());
            for p in store.list_providers() { if let Some(k) = store.get_key(&p) { println!("  {} - {}", k.id, k.provider); }} }
        "show" => { if let Some(provider) = args.iter().find(|a| !a.starts_with('-') && *a != "show") {
            if let Some(k) = store.get_key(provider) { println!("Provider: {}\nKey: {}...\nQuota: {:.0}", k.provider, &k.key[..8.min(k.key.len())], k.quota_used); }
            else { eprintln!("Not found: {}", provider); }} }
        "export" => { println!("{}", serde_json::to_string_pretty(&store).unwrap()); }
        "init" => { let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
            let path = keystore_path.unwrap_or_else(|| home.join(".keymux/keys.json"));
            fs::create_dir_all(path.parent().unwrap()).ok();
            if let Ok(content) = serde_json::to_string_pretty(&store) { fs::write(&path, content).ok(); println!("Initialized: {}", path.display()); } }
        _ => { eprintln!("Unknown: {}", cmd); }
    }
}

impl KeyStore {
    pub fn load_from_file(path: &PathBuf) -> Result<Self, String> {
        let content = fs::read_to_string(path).map_err(|e| format!("Failed: {}", e))?;
        serde_json::from_str(&content).map_err(|e| format!("Parse: {}", e))
    }
}
