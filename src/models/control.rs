use crate::dsel;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

use super::proxy::ProxyConfig;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GatewayFacadeFamily {
    OpenAiCompatible,
    AnthropicCompatible,
    GeminiNative,
    OllamaCompatible,
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GatewayRoutingMode {
    ModelPrefixThenPriority,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GatewayProviderStatus {
    pub name: String,
    pub family: GatewayFacadeFamily,
    pub base_url: String,
    pub key_env: String,
    pub priority: u8,
    pub active: bool,
    pub tokens_used_today: u64,
    pub estimated_remaining_quota: u64,
    pub quota_confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GatewayTransportState {
    pub bind_address: String,
    pub port: u16,
    pub unified_agent_port: bool,
    pub listener: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GatewayRoutingState {
    pub mode: GatewayRoutingMode,
    pub preferred_provider: Option<String>,
    pub default_model: Option<String>,
    pub fallback_model: Option<String>,
    pub failover_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GatewayStreamingState {
    pub enabled: bool,
    pub openai_chat_completions: String,
    pub ollama_chat: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClaudeModelRewritePolicy {
    pub enabled: bool,
    pub default_model: Option<String>,
    pub haiku_model: Option<String>,
    pub sonnet_model: Option<String>,
    pub opus_model: Option<String>,
    pub reasoning_model: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GatewayControlState {
    pub transport: GatewayTransportState,
    pub routing: GatewayRoutingState,
    pub streaming: GatewayStreamingState,
    pub claude_model_rewrite: ClaudeModelRewritePolicy,
    pub providers: Vec<GatewayProviderStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GatewayRuntimeControl {
    pub preferred_provider: Option<String>,
    pub default_model: Option<String>,
    pub fallback_model: Option<String>,
    pub streaming_enabled: bool,
    pub claude_model_rewrite: ClaudeModelRewritePolicy,
}

impl GatewayRuntimeControl {
    pub fn from_config(config: &ProxyConfig) -> Self {
        let default_model = config.default_model.clone();
        let fallback_model = config.fallback_model.clone();
        let rewrite_configured = [
            "MODELMUX_CLAUDE_DEFAULT_MODEL",
            "MODELMUX_CLAUDE_SONNET_MODEL",
            "MODELMUX_CLAUDE_OPUS_MODEL",
            "MODELMUX_CLAUDE_HAIKU_MODEL",
            "MODELMUX_CLAUDE_REASONING_MODEL",
            "ANTHROPIC_MODEL",
            "ANTHROPIC_DEFAULT_SONNET_MODEL",
            "ANTHROPIC_DEFAULT_OPUS_MODEL",
            "ANTHROPIC_DEFAULT_HAIKU_MODEL",
            "ANTHROPIC_REASONING_MODEL",
        ]
        .into_iter()
        .any(|key| env_string(key).is_some());
        let rewrite = ClaudeModelRewritePolicy {
            enabled: bool_env("MODELMUX_CLAUDE_REWRITE").unwrap_or(rewrite_configured),
            default_model: env_string_any(&["MODELMUX_CLAUDE_DEFAULT_MODEL", "ANTHROPIC_MODEL"]),
            haiku_model: env_string_any(&[
                "MODELMUX_CLAUDE_HAIKU_MODEL",
                "ANTHROPIC_DEFAULT_HAIKU_MODEL",
            ]),
            sonnet_model: env_string_any(&[
                "MODELMUX_CLAUDE_SONNET_MODEL",
                "ANTHROPIC_DEFAULT_SONNET_MODEL",
            ]),
            opus_model: env_string_any(&[
                "MODELMUX_CLAUDE_OPUS_MODEL",
                "ANTHROPIC_DEFAULT_OPUS_MODEL",
            ]),
            reasoning_model: env_string_any(&[
                "MODELMUX_CLAUDE_REASONING_MODEL",
                "ANTHROPIC_REASONING_MODEL",
            ]),
        };

        Self {
            preferred_provider: None,
            default_model,
            fallback_model,
            streaming_enabled: config.enable_streaming,
            claude_model_rewrite: rewrite,
        }
    }

    pub fn snapshot(&self, config: &ProxyConfig) -> GatewayControlState {
        let mut quota_map = BTreeMap::new();
        for (provider, used, remaining, confidence) in dsel::all_provider_quotas() {
            quota_map.insert(provider, (used, remaining, confidence));
        }

        let providers = dsel::discover_providers()
            .into_iter()
            .map(|provider| {
                let (used, remaining, confidence) = quota_map
                    .get(&provider.name)
                    .copied()
                    .unwrap_or((0, 0, 0.0));

                GatewayProviderStatus {
                    family: infer_provider_family(&provider.name, &provider.base_url),
                    name: provider.name,
                    base_url: provider.base_url,
                    key_env: provider.key_env,
                    priority: provider.priority,
                    active: true,
                    tokens_used_today: used,
                    estimated_remaining_quota: remaining,
                    quota_confidence: confidence,
                }
            })
            .collect();

        GatewayControlState {
            transport: GatewayTransportState {
                bind_address: config.bind_address.clone(),
                port: config.port,
                unified_agent_port: config.port == 8888,
                listener: "http1".to_string(),
            },
            routing: GatewayRoutingState {
                mode: GatewayRoutingMode::ModelPrefixThenPriority,
                preferred_provider: self.preferred_provider.clone(),
                default_model: self.default_model.clone(),
                fallback_model: self.fallback_model.clone(),
                failover_enabled: self.fallback_model.is_some()
                    || std::env::var("OPENROUTER_API_KEY").is_ok(),
            },
            streaming: GatewayStreamingState {
                enabled: self.streaming_enabled,
                openai_chat_completions: "disabled".to_string(),
                ollama_chat: if self.streaming_enabled {
                    "ndjson".to_string()
                } else {
                    "disabled".to_string()
                },
            },
            claude_model_rewrite: self.claude_model_rewrite.clone(),
            providers,
        }
    }

    pub fn apply_action(&mut self, action: GatewayControlAction) -> Result<(), String> {
        match action {
            GatewayControlAction::SetPreferredProvider { provider } => {
                if dsel::get_provider(&provider).is_none() {
                    return Err(format!("Unknown provider: {}", provider));
                }
                self.preferred_provider = Some(provider);
            }
            GatewayControlAction::ClearPreferredProvider => {
                self.preferred_provider = None;
            }
            GatewayControlAction::SetDefaultModel { model } => {
                self.default_model = normalize_string(model);
            }
            GatewayControlAction::ClearDefaultModel => {
                self.default_model = None;
            }
            GatewayControlAction::SetFallbackModel { model } => {
                self.fallback_model = normalize_string(model);
            }
            GatewayControlAction::ClearFallbackModel => {
                self.fallback_model = None;
            }
            GatewayControlAction::SetStreamingEnabled { enabled } => {
                self.streaming_enabled = enabled;
            }
            GatewayControlAction::SetClaudeRewritePolicy {
                enabled,
                default_model,
                haiku_model,
                sonnet_model,
                opus_model,
                reasoning_model,
            } => {
                self.claude_model_rewrite.enabled = enabled;
                self.claude_model_rewrite.default_model = normalize_optional(default_model);
                self.claude_model_rewrite.haiku_model = normalize_optional(haiku_model);
                self.claude_model_rewrite.sonnet_model = normalize_optional(sonnet_model);
                self.claude_model_rewrite.opus_model = normalize_optional(opus_model);
                self.claude_model_rewrite.reasoning_model =
                    normalize_optional(reasoning_model);
            }
            GatewayControlAction::ClearClaudeRewritePolicy => {
                self.claude_model_rewrite = ClaudeModelRewritePolicy {
                    enabled: false,
                    default_model: None,
                    haiku_model: None,
                    sonnet_model: None,
                    opus_model: None,
                    reasoning_model: None,
                };
            }
            GatewayControlAction::Reset => {
                *self = Self::from_config(config_defaults());
            }
        }

        Ok(())
    }

    pub fn effective_default_model(&self) -> Option<&str> {
        self.default_model.as_deref()
    }

    pub fn effective_fallback_model(&self) -> Option<&str> {
        self.fallback_model.as_deref()
    }

    pub fn preferred_provider_for_model(&self, model: &str) -> Option<String> {
        if model.contains('/') {
            None
        } else {
            self.preferred_provider.clone()
        }
    }

    pub fn rewrite_model(&self, model: &str, request: &Value) -> Option<String> {
        let policy = &self.claude_model_rewrite;
        if !policy.enabled || !is_claude_like_model(model) {
            return None;
        }

        if has_thinking_enabled(request) {
            if let Some(reasoning) = policy.reasoning_model.as_ref() {
                return Some(reasoning.clone());
            }
        }

        let lower = model.to_ascii_lowercase();
        if lower.contains("haiku") {
            if let Some(model) = policy.haiku_model.as_ref() {
                return Some(model.clone());
            }
        }
        if lower.contains("opus") {
            if let Some(model) = policy.opus_model.as_ref() {
                return Some(model.clone());
            }
        }
        if lower.contains("sonnet") {
            if let Some(model) = policy.sonnet_model.as_ref() {
                return Some(model.clone());
            }
        }

        let mut mapped = policy.default_model.clone()?;
        if has_tools(request) && should_fallback_to_default_for_tool_use(&mapped) {
            if let Some(default_model) = policy.default_model.as_ref() {
                mapped = default_model.clone();
            }
        }
        Some(mapped)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum GatewayControlAction {
    SetPreferredProvider { provider: String },
    ClearPreferredProvider,
    SetDefaultModel { model: String },
    ClearDefaultModel,
    SetFallbackModel { model: String },
    ClearFallbackModel,
    SetStreamingEnabled { enabled: bool },
    SetClaudeRewritePolicy {
        enabled: bool,
        default_model: Option<String>,
        haiku_model: Option<String>,
        sonnet_model: Option<String>,
        opus_model: Option<String>,
        reasoning_model: Option<String>,
    },
    ClearClaudeRewritePolicy,
    Reset,
}

fn config_defaults() -> &'static ProxyConfig {
    static DEFAULTS: std::sync::OnceLock<ProxyConfig> = std::sync::OnceLock::new();
    DEFAULTS.get_or_init(ProxyConfig::default)
}

fn normalize_string(input: String) -> Option<String> {
    normalize_optional(Some(input))
}

fn normalize_optional(input: Option<String>) -> Option<String> {
    input.and_then(|s| {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

fn env_string(key: &str) -> Option<String> {
    std::env::var(key).ok().and_then(|v| normalize_optional(Some(v)))
}

fn env_string_any(keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| env_string(key))
}

fn bool_env(key: &str) -> Option<bool> {
    std::env::var(key).ok().and_then(|v| {
        let lower = v.trim().to_ascii_lowercase();
        match lower.as_str() {
            "1" | "true" | "yes" | "on" => Some(true),
            "0" | "false" | "no" | "off" => Some(false),
            _ => None,
        }
    })
}

fn infer_provider_family(provider: &str, base_url: &str) -> GatewayFacadeFamily {
    let provider_lower = provider.to_ascii_lowercase();
    let base_lower = base_url.to_ascii_lowercase();

    if provider_lower.contains("anthropic") || provider_lower.contains("claude") {
        return GatewayFacadeFamily::AnthropicCompatible;
    }
    if provider_lower.contains("gemini")
        || provider_lower.contains("google")
        || base_lower.contains("generativelanguage.googleapis.com")
    {
        return GatewayFacadeFamily::GeminiNative;
    }
    if provider_lower.contains("ollama")
        || provider_lower.contains("lmstudio")
        || base_lower.contains("localhost:11434")
    {
        return GatewayFacadeFamily::OllamaCompatible;
    }
    if !base_lower.is_empty() {
        return GatewayFacadeFamily::OpenAiCompatible;
    }

    GatewayFacadeFamily::Unknown
}

fn is_claude_like_model(model: &str) -> bool {
    let normalized = model.trim().to_ascii_lowercase();
    normalized.starts_with("claude-") || normalized.starts_with("anthropic/claude-")
}

fn has_tools(request: &Value) -> bool {
    request
        .get("tools")
        .and_then(|v| v.as_array())
        .map(|arr| !arr.is_empty())
        .unwrap_or(false)
}

fn should_fallback_to_default_for_tool_use(mapped_model: &str) -> bool {
    let normalized = mapped_model.trim().to_ascii_lowercase();
    !normalized.is_empty()
        && !is_claude_like_model(&normalized)
        && normalized.ends_with(":free")
}

fn has_thinking_enabled(request: &Value) -> bool {
    matches!(
        request
            .get("thinking")
            .and_then(|v| v.as_object())
            .and_then(|o| o.get("type"))
            .and_then(|t| t.as_str()),
        Some("enabled") | Some("adaptive")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn config() -> ProxyConfig {
        ProxyConfig {
            bind_address: "127.0.0.1".to_string(),
            port: 8888,
            enable_streaming: true,
            enable_caching: true,
            default_model: Some("openai/gpt-4o-mini".to_string()),
            fallback_model: None,
            request_timeout_secs: 30,
            max_retries: 2,
        }
    }

    #[test]
    fn claude_rewrite_policy_maps_sonnet() {
        let mut control = GatewayRuntimeControl::from_config(&config());
        control
            .apply_action(GatewayControlAction::SetClaudeRewritePolicy {
                enabled: true,
                default_model: Some("anthropic/claude-sonnet-4.5".to_string()),
                haiku_model: None,
                sonnet_model: Some("ordinal/sonnet".to_string()),
                opus_model: None,
                reasoning_model: Some("ordinal/reasoning".to_string()),
            })
            .unwrap();

        let mapped = control.rewrite_model("claude-sonnet-4-5", &json!({}));
        assert_eq!(mapped.as_deref(), Some("ordinal/sonnet"));
    }

    #[test]
    fn claude_rewrite_policy_prefers_reasoning_model() {
        let mut control = GatewayRuntimeControl::from_config(&config());
        control
            .apply_action(GatewayControlAction::SetClaudeRewritePolicy {
                enabled: true,
                default_model: Some("ordinal/default".to_string()),
                haiku_model: None,
                sonnet_model: None,
                opus_model: None,
                reasoning_model: Some("ordinal/reasoning".to_string()),
            })
            .unwrap();

        let mapped = control.rewrite_model(
            "claude-sonnet-4-5",
            &json!({"thinking":{"type":"enabled"}}),
        );
        assert_eq!(mapped.as_deref(), Some("ordinal/reasoning"));
    }

    #[test]
    fn control_action_accepts_canonical_rewrite_action() {
        let action: GatewayControlAction = serde_json::from_value(json!({
            "action": "set_claude_rewrite_policy",
            "enabled": true,
            "default_model": "ordinal/default",
            "sonnet_model": "ordinal/sonnet"
        }))
        .unwrap();

        assert_eq!(
            action,
            GatewayControlAction::SetClaudeRewritePolicy {
                enabled: true,
                default_model: Some("ordinal/default".to_string()),
                haiku_model: None,
                sonnet_model: Some("ordinal/sonnet".to_string()),
                opus_model: None,
                reasoning_model: None,
            }
        );
    }

    #[test]
    fn control_action_accepts_canonical_clear_rewrite_action() {
        let action: GatewayControlAction =
            serde_json::from_value(json!({ "action": "clear_claude_rewrite_policy" })).unwrap();

        assert_eq!(action, GatewayControlAction::ClearClaudeRewritePolicy);
    }
}
