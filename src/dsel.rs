//! DSEL - Domain Specific Expression Language
//!
//! Pure routing. No hardcoded providers. No models endpoint.
//! Providers discovered from environment variables only.

use std::env;
use std::sync::{Arc, RwLock};
use once_cell::sync::Lazy;

// Import keymux DSEL for quota tracking
use crate::keymux::dsel::{RuleEngine, ProviderQuotaTracking};

/// Global DSEL rule engine for quota tracking
static DSEL_ENGINE: Lazy<Arc<RwLock<RuleEngine>>> = Lazy::new(|| {
    let mut engine = RuleEngine::new();
    engine.enable_token_ledger();
    Arc::new(RwLock::new(engine))
});

/// Provider configuration
#[derive(Clone)]
pub struct Provider {
    pub name: String,
    pub base_url: String,
    pub key_env: String,
    pub priority: u8,
}

/// Check if an API key value is a real key (not a placeholder)
fn is_real_key(val: &str) -> bool {
    let v = val.trim();
    if v.len() < 10 { return false; }
    if v.starts_with("your_") || v.starts_with("sk-placeholder") { return false; }
    if v.contains("xxx") || v.contains("here") || v.contains("TODO") { return false; }
    true
}

/// Public wrapper for proxy.rs draw-through filter
pub fn is_real_key_pub(val: &str) -> bool { is_real_key(val) }

/// Discover providers from environment
/// Looks for *_API_KEY and *_BASE_URL patterns.
/// Skips placeholder/empty keys automatically.
pub fn discover_providers() -> Vec<Provider> {
    let mut providers = Vec::new();
    
    // (canonical_name, [env_var_names_to_try]) — first real key wins
    let provider_specs: &[(&str, &[&str])] = &[
        ("kilo_code",  &["KILOCODE_API_KEY", "KILOAI_API_KEY", "KILO_CODE_API_KEY", "KILO_API_KEY"]),
        ("moonshot",   &["MOONSHOTAI_API_KEY", "KIMI_API_KEY", "MOONSHOT_API_KEY"]),
        ("moonshotai", &["MOONSHOTAI_API_KEY", "KIMI_API_KEY", "MOONSHOT_API_KEY"]),
        ("deepseek",   &["DEEPSEEK_API_KEY"]),
        ("openai",     &["OPENAI_API_KEY"]),
        ("anthropic",  &["ANTHROPIC_API_KEY"]),
        ("openrouter", &["OPENROUTER_API_KEY"]),
        ("groq",       &["GROQ_API_KEY"]),
        ("xai",        &["XAI_API_KEY", "GROK_API_KEY"]),
        ("cerebras",   &["CEREBRAS_API_KEY"]),
        ("nvidia",     &["NVIDIA_API_KEY"]),
        ("opencode",   &["OPENCODE_API_KEY"]),
        ("perplexity", &["PERPLEXITY_API_KEY"]),
        ("gemini",     &["GEMINI_API_KEY"]),
    ];
    
    for (priority, (name, key_envs)) in provider_specs.iter().enumerate() {
        // Try each env var alias; skip placeholders
        let found = key_envs.iter().find_map(|k| {
            env::var(k).ok().filter(|v| is_real_key(v)).map(|_| k.to_string())
        });
        
        if let Some(key_env) = found {
            let base_url_env = format!("{}_BASE_URL", name.to_uppercase());
            let base_url = env::var(&base_url_env)
                .unwrap_or_else(|_| get_default_base_url(name));
            
            providers.push(Provider {
                name: name.to_string(),
                base_url,
                key_env,
                priority: (priority + 1) as u8,
            });
        }
    }
    
    providers
}

fn get_default_base_url(name: &str) -> String {
    match name {
        "kilo_code"  => "https://api.kilo.ai/api/gateway".to_string(),
        "moonshot"   => "https://api.moonshot.cn/v1".to_string(),
        "deepseek"   => "https://api.deepseek.com/v1".to_string(),
        "openai"     => "https://api.openai.com/v1".to_string(),
        "anthropic"  => "https://api.anthropic.com/v1".to_string(),
        "openrouter" => "https://openrouter.ai/api/v1".to_string(),
        "groq"       => "https://api.groq.com/openai/v1".to_string(),
        "xai"        => "https://api.x.ai/v1".to_string(),
        "cerebras"   => "https://api.cerebras.ai/v1".to_string(),
        "nvidia"     => "https://integrate.api.nvidia.com/v1".to_string(),
        "opencode"   => "https://api.opencode.ai".to_string(),
        "moonshotai" => "https://api.moonshot.cn/v1".to_string(),
        "perplexity" => "https://api.perplexity.ai".to_string(),
        "gemini"     => "https://generativelanguage.googleapis.com/v1beta".to_string(),
        _ => String::new(),
    }
}

/// Route a model ID to its provider
/// Returns (provider_name, base_url, api_key_env)
pub fn route(model: &str) -> Option<(String, String, String)> {
    let providers = discover_providers();
    
    let prefix = model.split('/').next().unwrap_or("");
    
    if !prefix.is_empty() {
        // Exact provider name match
        if let Some(p) = providers.iter().find(|p| p.name == prefix) {
            return Some((p.name.clone(), p.base_url.clone(), p.key_env.clone()));
        }
        // Slashed model ID (PROVIDER/MODEL) but prefix unknown → refuse rather than
        // silently routing to the wrong provider and getting a confusing 502.
        if model.contains('/') {
            return None;
        }
    }
    
    // No slash — plain model name, use lowest-priority available provider
    providers.into_iter()
        .min_by_key(|p| p.priority)
        .map(|p| (p.name, p.base_url, p.key_env))
}

pub fn key(env_var: &str) -> Option<String> {
    env::var(env_var).ok()
}

pub fn has_key(env_var: &str) -> bool {
    env::var(env_var).is_ok()
}

pub fn available() -> Vec<String> {
    discover_providers().iter().map(|p| p.name.clone()).collect()
}

pub fn status() -> Vec<(String, String, u8, bool)> {
    // Reuse discover_providers — it already handles aliases + placeholder filtering
    let all_names: &[(&str, &[&str])] = &[
        ("kilo_code",  &["KILOCODE_API_KEY", "KILOAI_API_KEY", "KILO_CODE_API_KEY", "KILO_API_KEY"]),
        ("moonshot",   &["MOONSHOTAI_API_KEY", "KIMI_API_KEY", "MOONSHOT_API_KEY"]),
        ("deepseek",   &["DEEPSEEK_API_KEY"]),
        ("openai",     &["OPENAI_API_KEY"]),
        ("anthropic",  &["ANTHROPIC_API_KEY"]),
        ("openrouter", &["OPENROUTER_API_KEY"]),
        ("groq",       &["GROQ_API_KEY"]),
        ("xai",        &["XAI_API_KEY", "GROK_API_KEY"]),
        ("cerebras",   &["CEREBRAS_API_KEY"]),
        ("nvidia",     &["NVIDIA_API_KEY"]),
        ("perplexity", &["PERPLEXITY_API_KEY"]),
        ("gemini",     &["GEMINI_API_KEY"]),
    ];
    
    all_names.iter().enumerate().map(|(priority, (name, key_envs))| {
        let has_key = key_envs.iter().any(|k| {
            env::var(k).ok().map_or(false, |v| is_real_key(&v))
        });
        let base_url_env = format!("{}_BASE_URL", name.to_uppercase());
        let base_url = env::var(&base_url_env)
            .unwrap_or_else(|_| get_default_base_url(name));
        
        (name.to_string(), base_url, (priority + 1) as u8, has_key)
    }).collect()
}

pub fn get_provider(name: &str) -> Option<Provider> {
    discover_providers().into_iter().find(|p| p.name == name)
}

/// Get quota status for a provider
/// Returns (tokens_used_today, estimated_remaining, confidence)
pub fn provider_quota_status(provider: &str) -> Option<(u64, u64, f64)> {
    let engine = DSEL_ENGINE.read().ok()?;
    engine.get_quota_status(provider)
}

/// Get all provider quota statuses
pub fn all_provider_quotas() -> Vec<(String, u64, u64, f64)> {
    let engine = match DSEL_ENGINE.read() {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };
    
    let quotas = engine.get_all_quota_tracking();
    quotas.iter().map(|(name, tracking)| {
        (name.clone(), tracking.tokens_used_today, tracking.estimated_remaining_quota, tracking.quota_confidence)
    }).collect()
}

/// Track token usage for a provider
pub fn track_tokens(provider: &str, tokens: u64) -> Result<(), String> {
    let mut engine = DSEL_ENGINE.write().map_err(|e| e.to_string())?;
    engine.track_token_usage(provider, tokens)
}
