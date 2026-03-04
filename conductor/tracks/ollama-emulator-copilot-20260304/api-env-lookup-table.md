# API Environment Variable Lookup Table

**Sources:**
- `literbike/src/env_facade_parity.rs`
- `literbike/src/provider_facade_models.rs`
- `../CC-switch/src/config/claudeProviderPresets.ts`
- `../CC-switch/src/config/geminiProviderPresets.ts`
- `../CC-switch/src/config/modelPicker.ts`

---

## Provider API Key Patterns

### OpenAI / OpenAI-Compatible

| Env Key | Role | Required | Secret | Notes |
|---------|------|----------|--------|-------|
| `OPENAI_API_KEY` | ApiKey | No | Yes | Standard OpenAI key |
| `OPENAI_BASE_URL` | BaseUrl | No | No | Custom endpoint |
| `OPENAI_MODEL` | Model | No | No | Default model |

**CC-Switch Presets:**
- Anthropic-compatible endpoints via `ANTHROPIC_BASE_URL`
- OpenAI-compatible via `OPENAI_BASE_URL`

### Anthropic / Claude-Compatible

| Env Key | Role | Required | Secret | Notes |
|---------|------|----------|--------|-------|
| `ANTHROPIC_AUTH_TOKEN` | ApiKey | No | Yes | Primary key |
| `ANTHROPIC_API_KEY` | ApiKey (alias) | No | Yes | Alias for AUTH_TOKEN |
| `ANTHROPIC_BASE_URL` | BaseUrl | No | No | Custom endpoint |
| `ANTHROPIC_MODEL` | Model | No | No | Main model |
| `ANTHROPIC_REASONING_MODEL` | ReasoningModel | No | No | Thinking model |
| `ANTHROPIC_DEFAULT_HAIKU_MODEL` | Model | No | No | Haiku default |
| `ANTHROPIC_DEFAULT_SONNET_MODEL` | Model | No | No | Sonnet default |
| `ANTHROPIC_DEFAULT_OPUS_MODEL` | Model | No | No | Opus default |

**CC-Switch Presets:**
```typescript
// Moonshot (Kimi)
ANTHROPIC_BASE_URL: "https://api.moonshot.cn/anthropic"
ANTHROPIC_MODEL: "kimi-k2.5"

// DeepSeek
ANTHROPIC_BASE_URL: "https://api.deepseek.com/anthropic"
ANTHROPIC_MODEL: "DeepSeek-V3.2"

// ZhipuAI
ANTHROPIC_BASE_URL: "https://open.bigmodel.cn/api/anthropic"
ANTHROPIC_MODEL: "glm-4.7"

// Z.ai
ANTHROPIC_BASE_URL: "https://api.z.ai/api/anthropic"

// Alibaba DashScope
ANTHROPIC_BASE_URL: "https://dashscope.aliyuncs.com/apps/anthropic"

// ModelScope
ANTHROPIC_BASE_URL: "https://api-inference.modelscope.cn"
ANTHROPIC_MODEL: "ZhipuAI/GLM-4.7"

// Kimi Coding
ANTHROPIC_BASE_URL: "https://api.kimi.com/coding/"

// OpenRouter
ANTHROPIC_BASE_URL: "https://openrouter.ai/api"
```

### Gemini / Google

| Env Key | Role | Required | Secret | Notes |
|---------|------|----------|--------|-------|
| `GEMINI_API_KEY` | ApiKey | No | Yes | Primary key |
| `GOOGLE_API_KEY` | ApiKey (alias) | No | Yes | Alias for GEMINI_API_KEY |
| `GOOGLE_GEMINI_BASE_URL` | BaseUrl | No | No | Custom endpoint |
| `GEMINI_MODEL` | Model | No | No | Default model |

**CC-Switch Presets:**
```typescript
// OpenCode Zen
GOOGLE_GEMINI_BASE_URL: "https://opencode.ai/zen/v1"
GEMINI_MODEL: "gemini-3-pro"

// PackyAPI
GOOGLE_GEMINI_BASE_URL: "https://www.packyapi.com"
GEMINI_MODEL: "gemini-3-pro"

// Cubence
GOOGLE_GEMINI_BASE_URL: "https://api.cubence.com"
GEMINI_MODEL: "gemini-3-pro"

// AIGoCode
GOOGLE_GEMINI_BASE_URL: "https://api.aigocode.com"
GEMINI_MODEL: "gemini-3-pro"

// AICodeMirror
GOOGLE_GEMINI_BASE_URL: "https://api.aicodemirror.com/api/gemini"
GEMINI_MODEL: "gemini-3-pro"

// OpenRouter
GOOGLE_GEMINI_BASE_URL: "https://openrouter.ai/api"
GEMINI_MODEL: "gemini-3-pro-preview"
```

### Codex (OpenAI)

| Env Key | Role | Required | Secret | Notes |
|---------|------|----------|--------|-------|
| `OPENAI_API_KEY` | ApiKey | No | Yes | In auth.json |
| `OPENAI_BASE_URL` | BaseUrl | No | No | API endpoint |

**Config Files:**
- `auth.json` - API key storage
- `config.toml` - Configuration

### OpenCode

| Env Key | Role | Required | Secret | Notes |
|---------|------|----------|--------|-------|
| Provider-specific keys | ApiKey | Varies | Yes | Defined in openclaw.json |

**Config Files:**
- `openclaw.json` - Environment variables, tool permissions, agents config

---

## Search API Keys

### Brave Search

| Env Key | Role | Required | Secret | Notes |
|---------|------|----------|--------|-------|
| `BRAVE_SEARCH_API_KEY` | ApiKey | No | Yes | Search key |
| `BRAVE_SEARCH_API_KEY_1` | ApiKey (indexed) | No | Yes | Multi-key support |
| `BRAVE_SEARCH_API_KEY_2` | ApiKey (indexed) | No | Yes | Multi-key support |

### Tavily Search

| Env Key | Role | Required | Secret | Notes |
|---------|------|----------|--------|-------|
| `TAVILY_SEARCH_API_KEY` | ApiKey | No | Yes | Search key |
| `TAVILY_SEARCH_API_KEY_1` | ApiKey (indexed) | No | Yes | Multi-key support |

**Pattern:** `{PROVIDER}_SEARCH_API_KEY[_{index}]`

---

## Exchange / Trading API Keys

### Binance

| Env Key | Role | Required | Secret | Notes |
|---------|------|----------|--------|-------|
| `BINANCE_API_KEY` | ApiKey | No | Yes | Exchange key |

**Pattern:** `{EXCHANGE}_API_KEY`

---

## Aggregator / Router Keys

### OpenRouter

| Env Key | Role | Required | Secret | Notes |
|---------|------|----------|--------|-------|
| `OPENROUTER_API_KEY` | ApiKey | No | Yes | Router key |

### Moonshot

| Env Key | Role | Required | Secret | Notes |
|---------|------|----------|--------|-------|
| `MOONSHOT_API_KEY` | ApiKey | No | Yes | Moonshot key |

---

## Generic API Key Pattern

**Detection Logic (literbike/env_facade_parity.rs):**

```rust
// Suffix-based detection
if key.ends_with("_API_KEY") {
    // Generic API key
    // Classify by hostname/base_url probe
}

if key.ends_with("_SEARCH_API_KEY") {
    // Search provider key
    // Group by provider prefix
}
```

**Classification Flow:**
1. Check for known exact matches (e.g., `OPENAI_API_KEY`)
2. Check for known aliases (e.g., `ANTHROPIC_API_KEY` → `ANTHROPIC_AUTH_TOKEN`)
3. Check for `_SEARCH_API_KEY` suffix → Search provider group
4. Check for `_API_KEY` suffix → Generic API key
   - Probe `/models` endpoint if base_url available
   - Classify by hostname patterns
   - Cache classification result

---

## Base URL Patterns

| Provider | Env Key | Default |
|----------|---------|---------|
| OpenAI | `OPENAI_BASE_URL` | `https://api.openai.com/v1` |
| Anthropic | `ANTHROPIC_BASE_URL` | `https://api.anthropic.com` |
| Gemini | `GOOGLE_GEMINI_BASE_URL` | `https://generativelanguage.googleapis.com` |
| Moonshot | - | `https://api.moonshot.cn` |
| DeepSeek | - | `https://api.deepseek.com` |
| ZhipuAI | - | `https://open.bigmodel.cn` |

---

## Model Selection Patterns

### Anthropic Models (CC-Switch)

```typescript
ANTHROPIC_MODEL: "claude-sonnet-4-5-20250929"  // Main
ANTHROPIC_DEFAULT_HAIKU_MODEL: "claude-sonnet-4-5-20250929"
ANTHROPIC_DEFAULT_SONNET_MODEL: "claude-sonnet-4-5-20250929"
ANTHROPIC_DEFAULT_OPUS_MODEL: "claude-sonnet-4-5-20250929"
```

### Gemini Models (CC-Switch)

```typescript
GEMINI_MODEL: "gemini-3-pro"
```

### OpenAI Models (CC-Switch)

```typescript
OPENAI_MODEL: "gpt-4.1"
```

---

## Env Recognition Rules (literbike)

### Rule Matching

```rust
EnvRecognitionRule {
    id: "openai-compatible",
    family_hint: ProviderFamily::OpenAiCompatible,
    host_contains_any: ["api.openai.com", "openai.com"],
    env_keys_all: ["OPENAI_API_KEY", "OPENAI_BASE_URL"],
    inferred_templates: [ServingTemplateId::OpenAiV1],
    confidence: 95,
}
```

### Provider Family Detection

| Pattern | Family | Confidence |
|---------|--------|------------|
| `OPENAI_*` | OpenAiCompatible | 95 |
| `ANTHROPIC_*` | AnthropicCompatible | 95 |
| `GEMINI_*` or `GOOGLE_*` | GeminiNative | 95 |
| `*_SEARCH_API_KEY` | ModelProvider | 85 |
| `*_API_KEY` (generic) | Unknown → Probe | 50 |

---

## CC-Switch Provider Presets Summary

### Claude-Compatible Providers

| Provider | Base URL | API Key Field | Model |
|----------|----------|---------------|-------|
| Anthropic Official | `https://api.anthropic.com` | Browser login | claude-sonnet-4-5 |
| Moonshot | `https://api.moonshot.cn/anthropic` | `ANTHROPIC_AUTH_TOKEN` | kimi-k2.5 |
| DeepSeek | `https://api.deepseek.com/anthropic` | `ANTHROPIC_AUTH_TOKEN` | DeepSeek-V3.2 |
| ZhipuAI | `https://open.bigmodel.cn/api/anthropic` | `ANTHROPIC_AUTH_TOKEN` | glm-4.7 |
| Z.ai | `https://api.z.ai/api/anthropic` | `ANTHROPIC_AUTH_TOKEN` | glm-4.7 |
| Alibaba | `https://dashscope.aliyuncs.com/apps/anthropic` | `ANTHROPIC_AUTH_TOKEN` | - |
| ModelScope | `https://api-inference.modelscope.cn` | `ANTHROPIC_AUTH_TOKEN` | ZhipuAI/GLM-4.7 |
| Kimi Coding | `https://api.kimi.com/coding/` | `ANTHROPIC_AUTH_TOKEN` | - |
| OpenRouter | `https://openrouter.ai/api` | `ANTHROPIC_AUTH_TOKEN` | - |

### Gemini Providers

| Provider | Base URL | API Key Field | Model |
|----------|----------|---------------|-------|
| Google Official | `https://generativelanguage.googleapis.com` | `GEMINI_API_KEY` | gemini-pro |
| OpenCode Zen | `https://opencode.ai/zen/v1` | `GEMINI_API_KEY` | gemini-3-pro |
| PackyAPI | `https://www.packyapi.com` | `GEMINI_API_KEY` | gemini-3-pro |
| Cubence | `https://api.cubence.com` | `GEMINI_API_KEY` | gemini-3-pro |
| AIGoCode | `https://api.aigocode.com` | `GEMINI_API_KEY` | gemini-3-pro |
| AICodeMirror | `https://api.aicodemirror.com/api/gemini` | `GEMINI_API_KEY` | gemini-3-pro |
| OpenRouter | `https://openrouter.ai/api` | `GEMINI_API_KEY` | gemini-3-pro-preview |

---

## literbike Env Binding Structure

```rust
EnvVarBinding {
    key: "OPENAI_API_KEY",
    aliases: vec![],
    role: EnvVarRole::ApiKey,
    required: false,
    secret: true,
    pattern_hint: Some("sk-.*"),
}
```

### EnvVarRole Enum

```rust
pub enum EnvVarRole {
    ProviderId,
    BaseUrl,
    Model,
    ReasoningModel,
    ApiKey,
    AccessToken,
    RefreshToken,
    OAuthClientId,
    OAuthClientSecret,
    OAuthTokenUrl,
    OAuthAuthUrl,
    OAuthAudience,
    OAuthScopes,
    PubkeyFingerprint,
    PubkeyMaterial,
    PubkeyAllowedProviders,
    KeymuxUrl,
    KeyVaultUrl,
    MuxPolicy,
    QuotaProfile,
    TemplateOverride,
    WrapperPath,
    ControlToken,
}
```

---

## Multi-Key Support Patterns

### Search Key Grouping

```rust
// Groups keys by provider prefix
"BRAVE_SEARCH_API_KEY"    → group: "BRAVE", index: None
"BRAVE_SEARCH_API_KEY_1"  → group: "BRAVE", index: Some(1)
"BRAVE_SEARCH_API_KEY_2"  → group: "BRAVE", index: Some(2)
"TAVILY_SEARCH_API_KEY"   → group: "TAVILY", index: None
```

### Multi-Key Pumping Behavior

- **Rotation**: Cycle through keys on rate limit
- **Fanout**: Distribute requests across keys
- **Load-sharing**: Weight by remaining quota

---

## Integration Notes

### Ollama Emulator Integration

The Ollama emulator should recognize these env patterns:

1. **Direct mapping:**
   - `OLLAMA_API_KEY` → Ollama provider
   - `OLLAMA_BASE_URL` → `http://localhost:11434`

2. **Proxy mapping:**
   - `OPENAI_API_KEY` + `OPENAI_BASE_URL` → Ollama-compatible endpoint
   - `ANTHROPIC_AUTH_TOKEN` + `ANTHROPIC_BASE_URL` → Ollama with Anthropic shim

3. **Quota integration:**
   - All `*_API_KEY` patterns can have associated quota slots
   - QuotaDrainer arbitrates across all providers

### literbike Modelmux Projection

```rust
// Projects from env_profile.entries
ProviderState {
    family: "OpenAiCompatible",
    base_url: Some("https://api.openai.com/v1"),
    model: Some("gpt-4.1"),
    api_key_env: Some("OPENAI_API_KEY"),
    confidence: 95,
}

// Projects from quota_selection.candidates
QuotaState {
    slot_id: "free-kimi",
    model_ref: "/free/moonshotai/kimi-k2",
    free: true,
    remaining_requests: Some(100),
    remaining_tokens: Some(50000),
    selectors: vec!["quota-dsel-free"],
}
```

---

## References

- `literbike/src/env_facade_parity.rs:569-612` - Generic API key detection
- `literbike/src/provider_facade_models.rs:275-774` - Provider facade models
- `../CC-switch/src/config/claudeProviderPresets.ts` - Claude provider presets
- `../CC-switch/src/config/geminiProviderPresets.ts` - Gemini provider presets
- `../CC-switch/src/config/modelPicker.ts` - Model definitions
