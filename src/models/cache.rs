//! Model Cache for ModelMux
//!
//! Caches model selections and provider configurations.
//! Models loaded from env/API only - no predefined models.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use log::{info, warn, debug};

/// Cached model information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedModel {
    pub id: String,
    pub provider: String,
    pub name: String,
    pub context_window: u64,
    pub max_tokens: u64,
    pub input_cost_per_million: f64,
    pub output_cost_per_million: f64,
    pub is_free: bool,
    pub supports_streaming: bool,
    pub supports_tools: bool,
    pub cached_at: u64,
    pub expires_at: Option<u64>,
}

impl CachedModel {
    pub fn is_expired(&self) -> bool {
        if let Some(expires) = self.expires_at {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            now > expires
        } else {
            false
        }
    }
}

/// Model cache configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    pub cache_dir: PathBuf,
    pub max_age_secs: u64,
    pub enable_disk_cache: bool,
    pub enable_memory_cache: bool,
}

impl Default for CacheConfig {
    fn default() -> Self {
        let cache_dir = dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".modelmux/cache");
        Self {
            cache_dir,
            max_age_secs: 3600,
            enable_disk_cache: true,
            enable_memory_cache: true,
        }
    }
}

/// Model cache with memory and disk backing
pub struct ModelCache {
    config: CacheConfig,
    memory_cache: HashMap<String, CachedModel>,
    models_by_provider: HashMap<String, Vec<String>>,
}

impl ModelCache {
    pub fn new(config: CacheConfig) -> Self {
        let mut cache = Self {
            config,
            memory_cache: HashMap::new(),
            models_by_provider: HashMap::new(),
        };
        cache.init();
        cache
    }

    pub fn with_defaults() -> Self {
        Self::new(CacheConfig::default())
    }

    pub fn empty() -> Self {
        Self {
            config: CacheConfig::default(),
            memory_cache: HashMap::new(),
            models_by_provider: HashMap::new(),
        }
    }

    fn init(&mut self) {
        if self.config.enable_disk_cache {
            if let Err(e) = fs::create_dir_all(&self.config.cache_dir) {
                warn!("Failed to create cache dir: {}", e);
            }
            self.load_from_disk();
        }
    }

    pub fn get(&self, model_id: &str) -> Option<CachedModel> {
        if self.config.enable_memory_cache {
            self.memory_cache.get(model_id).cloned()
        } else {
            self.load_from_disk_single(model_id)
        }
    }

    pub fn get_provider_models(&self, provider: &str) -> Vec<CachedModel> {
        let mut models = Vec::new();
        if let Some(model_ids) = self.models_by_provider.get(provider) {
            for id in model_ids {
                if let Some(model) = self.get(id) {
                    models.push(model);
                }
            }
        }
        models
    }

    pub fn get_all_models(&self) -> Vec<CachedModel> {
        self.memory_cache.values().cloned().collect()
    }

    pub fn cache(&mut self, model: CachedModel) {
        let provider = model.provider.clone();
        let id = model.id.clone();

        if self.config.enable_memory_cache {
            self.memory_cache.insert(id.clone(), model);
            self.models_by_provider
                .entry(provider.clone())
                .or_insert_with(Vec::new)
                .push(id.clone());
        }

        if self.config.enable_disk_cache {
            self.save_to_disk(&id);
        }

        debug!("Cached model: {}", id);
    }

    pub fn cache_many(&mut self, models: Vec<CachedModel>) {
        for model in models {
            self.cache(model);
        }
        info!("Cached {} models", self.memory_cache.len());
    }

    pub fn clear(&mut self) {
        self.memory_cache.clear();
        self.models_by_provider.clear();
        if self.config.enable_disk_cache {
            let _ = fs::remove_dir_all(&self.config.cache_dir);
            let _ = fs::create_dir_all(&self.config.cache_dir);
        }
        info!("Cleared model cache");
    }

    fn cache_file_path(&self, model_id: &str) -> PathBuf {
        let safe_id = model_id.replace('/', "_").replace(':', "_");
        self.config.cache_dir.join(format!("{}.json", safe_id))
    }

    fn save_to_disk(&self, model_id: &str) {
        if let Some(model) = self.memory_cache.get(model_id) {
            let path = self.cache_file_path(model_id);
            let _ = fs::write(&path, serde_json::to_string_pretty(model).unwrap());
        }
    }

    fn load_from_disk(&mut self) {
        if !self.config.cache_dir.exists() {
            return;
        }

        if let Ok(entries) = fs::read_dir(&self.config.cache_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("json") {
                    if let Ok(content) = fs::read_to_string(&path) {
                        if let Ok(model) = serde_json::from_str::<CachedModel>(&content) {
                            if !model.is_expired() {
                                let provider = model.provider.clone();
                                let id = model.id.clone();
                                self.memory_cache.insert(id.clone(), model);
                                self.models_by_provider
                                    .entry(provider)
                                    .or_insert_with(Vec::new)
                                    .push(id);
                            }
                        }
                    }
                }
            }
        }

        info!("Loaded {} models from disk cache", self.memory_cache.len());
    }

    fn load_from_disk_single(&self, model_id: &str) -> Option<CachedModel> {
        let path = self.cache_file_path(model_id);
        if path.exists() {
            if let Ok(content) = fs::read_to_string(&path) {
                if let Ok(model) = serde_json::from_str::<CachedModel>(&content) {
                    if !model.is_expired() {
                        return Some(model);
                    }
                }
            }
        }
        None
    }
}

/// Predefined model definitions for common providers
pub mod predefined {
    use super::CachedModel;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// Kilo.ai Gateway free models
    pub fn kilo_free_models() -> Vec<CachedModel> {
        vec![
            CachedModel {
                id: "kilo_code/minimax-minimax-m2.5:free".to_string(),
                provider: "kilo_code".to_string(),
                name: "MiniMax M2.5 (Free)".to_string(),
                context_window: 256000,
                max_tokens: 64000,
                input_cost_per_million: 0.0,
                output_cost_per_million: 0.0,
                is_free: true,
                supports_streaming: true,
                supports_tools: true,
                cached_at: now(),
                expires_at: Some(now() + 86400),
            }
        ]
    }

    /// Moonshot static models
    pub fn moonshot_models() -> Vec<CachedModel> {
        vec![
            CachedModel {
                id: "moonshotai/kimi-k2".to_string(),
                provider: "moonshot".to_string(),
                name: "Kimi K2 (Moonshot)".to_string(),
                context_window: 256000,
                max_tokens: 64000,
                input_cost_per_million: 0.0,
                output_cost_per_million: 0.0,
                is_free: true,
                supports_streaming: true,
                supports_tools: true,
                cached_at: now(),
                expires_at: Some(now() + 86400),
            }
        ]
    }

    /// Deepseek static models
    pub fn deepseek_models() -> Vec<CachedModel> {
        vec![
            CachedModel {
                id: "deepseek/dk-lm".to_string(),
                provider: "deepseek".to_string(),
                name: "DK-LM (Deepseek)".to_string(),
                context_window: 256000,
                max_tokens: 64000,
                input_cost_per_million: 0.0,
                output_cost_per_million: 0.0,
                is_free: true,
                supports_streaming: true,
                supports_tools: true,
                cached_at: now(),
                expires_at: Some(now() + 86400),
            }
        ]
    }

    /// NVIDIA free demo models
    pub fn nvidia_free_models() -> Vec<CachedModel> {
        vec![
            CachedModel {
                id: "nvidia/moonshotai/kimi-2-instruct".to_string(),
                provider: "nvidia".to_string(),
                name: "Kimi 2 Instruct (NVIDIA)".to_string(),
                context_window: 256000,
                max_tokens: 64000,
                input_cost_per_million: 0.0,
                output_cost_per_million: 0.0,
                is_free: true,
                supports_streaming: true,
                supports_tools: true,
                cached_at: now(),
                expires_at: Some(now() + 86400),
            }
        ]
    }

    /// OpenCode free demo models
    pub fn opencode_free_models() -> Vec<CachedModel> {
        vec![
            CachedModel {
                id: "opencode/kimi-2-instruct".to_string(),
                provider: "opencode".to_string(),
                name: "Kimi 2 Instruct (OpenCode)".to_string(),
                context_window: 256000,
                max_tokens: 64000,
                input_cost_per_million: 0.0,
                output_cost_per_million: 0.0,
                is_free: true,
                supports_streaming: true,
                supports_tools: true,
                cached_at: now(),
                expires_at: Some(now() + 86400),
            }
        ]
    }
}
