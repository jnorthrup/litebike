# Model Mux Provider Rules

**Corrected:** 2026-03-04

---

## Rule 1: Models Are Lazy Cache

- Models are NOT hardcoded
- Models are discovered/fetched lazily from provider endpoints
- No pre-defined model lists
- Model enumeration happens at runtime via `/v1/models` endpoint

---

## Rule 2: Provider Detection

**Providers are detected by `XXXXX_API_KEY` env vars:**

```bash
# Provider API keys
MOONSHOT_API_KEY      → moonshot provider
DEEPSEEK_API_KEY      → deepseek provider
OPENAI_API_KEY        → openai provider
ANTHROPIC_AUTH_TOKEN  → anthropic provider
ZHIPU_API_KEY         → zhipu provider
MINIMAX_API_KEY       → minimax provider
...

# NOT providers (search tools)
BRAVE_SEARCH_API_KEY  → search tool
TAVILY_SEARCH_API_KEY → search tool
```

---

## Rule 3: Default Provider Tuple

**Format:** `PROVIDER/MODEL`

```
moonshotai/kimi-k2.5
deepseek/deepseek-chat
openai/gpt-4.1
anthropic/claude-sonnet-4-5
```

**We don't decide:**
- Any `PROVIDER` is valid if corresponding `PROVIDER_API_KEY` exists
- Any `MODEL` is valid - no validation
- Pattern: `XXXXX/.*` accepts anything

---

## Implementation

### Provider Detection (from env)

```rust
// Detect providers from env vars
fn detect_providers_from_env() -> Vec<String> {
    std::env::vars()
        .filter(|(k, v)| k.ends_with("_API_KEY") && !v.is_empty())
        .filter(|(k, _)| !k.contains("_SEARCH_"))  // Exclude search keys
        .map(|(k, _)| {
            k.trim_end_matches("_API_KEY")
             .trim_end_matches("_AUTH_TOKEN")
             .to_lowercase()
        })
        .collect()
}
```

### Model Reference Parsing

```rust
// Parse PROVIDER/MODEL tuple
fn parse_model_ref(model_ref: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = model_ref.splitn(2, '/').collect();
    if parts.len() == 2 {
        Some((parts[0].to_string(), parts[1].to_string()))
    } else {
        None  // Use default provider
    }
}
```

### Lazy Model Discovery

```rust
// Fetch models from provider endpoint
async fn discover_models(provider: &str, base_url: &str, api_key: &str) -> Vec<String> {
    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/models", base_url))
        .header("Authorization", format!("Bearer {}", api_key))
        .send()
        .await
        .ok()?;
    
    // Parse and return model IDs
    // Cache results for subsequent requests
}
```

---

## Env Var Patterns

### Provider API Keys
```
XXXXX_API_KEY         → Standard pattern
XXXXX_AUTH_TOKEN      → Alternative pattern
```

### Search Tool Keys (NOT providers)
```
XXXXX_SEARCH_API_KEY  → Search functionality
```

### Base URLs (optional)
```
XXXXX_BASE_URL        → Custom endpoint
```

---

## Examples

### Valid Provider Detection

```bash
# These are providers (have _API_KEY)
export MOONSHOT_API_KEY=sk-...      # → moonshot provider
export DEEPSEEK_API_KEY=sk-...      # → deepseek provider
export OPENAI_API_KEY=sk-...        # → openai provider

# These are NOT providers (search tools)
export BRAVE_SEARCH_API_KEY=...     # → search tool
export TAVILY_SEARCH_API_KEY=...    # → search tool
```

### Valid Model References

```
# All valid - we don't validate model names
moonshotai/kimi-k2.5
moonshotai/any-model-name
deepseek/deepseek-chat
deepseek/random-model
openai/gpt-4.1
openai/made-up-model
```

---

## Files to Update

| File | Change |
|------|--------|
| `literbike/src/env_facade_parity.rs` | Remove hardcoded provider lists |
| `literbike/src/bin/ollama_emulator.rs` | Lazy model discovery |
| `tests/modelmux/test_8888_cloaking.rs` | Update tests |

---

## Summary

1. **Models = Lazy Cache** - Discover at runtime, don't hardcode
2. **Providers = `XXXXX_API_KEY`** - Detect from env, exclude `_SEARCH_`
3. **Tuple = `PROVIDER/MODEL`** - Accept any `XXXXX/.*` pattern, no validation

---

## Implementation Complete

**File:** `literbike/src/env_facade_parity.rs`

**Changes:**
```rust
// BEFORE: Hardcoded provider list
match provider_fragment.to_ascii_lowercase().as_str() {
    "anthropic" | "claude" => Some(ProviderFamily::AnthropicCompatible),
    "google" | "gemini" => Some(ProviderFamily::GeminiNative),
    "openrouter" => Some(ProviderFamily::OpenRouter),
    "azure" | "azure-openai" => Some(ProviderFamily::AzureOpenAi),
    "openai" | "moonshotai" | "kimi" | "groq" | "mistral" | "together" | "fireworks"
    | "xai" | "deepseek" | "perplexity" => Some(ProviderFamily::OpenAiCompatible),
    "ollama" => Some(ProviderFamily::Ollama),
    _ => None,
}

// AFTER: Generic pattern - any XXXXX_API_KEY provider defaults to OpenAiCompatible
match provider_fragment.to_ascii_lowercase().as_str() {
    "anthropic" | "claude" => Some(ProviderFamily::AnthropicCompatible),
    "google" | "gemini" => Some(ProviderFamily::GeminiNative),
    "ollama" => Some(ProviderFamily::Ollama),
    _ => Some(ProviderFamily::OpenAiCompatible),  // Default for any XXXXX_API_KEY provider
}
```

**Result:**
- Any provider with `XXXXX_API_KEY` env var is automatically recognized
- No hardcoded provider names
- Default to `OpenAiCompatible` for unknown providers (most are OpenAI-compatible)
- Special handling only for Anthropic, Google/Gemini, Ollama


---

## Model Mappings Erased

**Protocol mappings ONLY** - No hardcoded model names.

**What's kept:**
- API key detection (`XXXXX_API_KEY` → provider)
- Protocol format detection (OpenAI-compatible, Anthropic-compatible, etc.)
- Model reference parsing (`PROVIDER/MODEL` tuple)

**What's erased:**
- Hardcoded model lists
- Model validation
- Model availability checks

**Models are lazy cache:**
- Discovered at runtime via `/v1/models` endpoint
- Any model name is valid: `PROVIDER/.*`
- No pre-defined model catalog

**Example:**
```bash
# All valid - no validation
ollama_emulator --model moonshotai/kimi-k2
ollama_emulator --model moonshotai/any-model-name
ollama_emulator --model deepseek/deepseek-chat
ollama_emulator --model deepseek/random-model
```

**Protocol detection (kept):**
```rust
// API format detection - kept
match provider.as_str() {
    "anthropic" | "claude" => AnthropicCompatible,
    "google" | "gemini" => GeminiNative,
    "ollama" => Ollama,
    _ => OpenAiCompatible,  // Default for any XXXXX_API_KEY
}
```

**Model validation (erased):**
```rust
// REMOVED: No model validation
// if model != "kimi-k2" && model != "deepseek-chat" { error!() }
```


---

## No /models/ API, No Provider Enumeration

**Confirmed:** No model discovery API, no provider lists.

**Pure pattern matching:**
1. **Env var pattern:** `XXXXX_API_KEY` → provider exists
2. **Model tuple:** `PROVIDER/MODEL` → parse and route
3. **Protocol pattern:** Provider name → API format

**No:**
- ❌ `/v1/models` endpoint calls
- ❌ Provider enumeration
- ❌ Model availability checks
- ❌ Provider capability discovery

**Just:**
- ✅ Env var detection
- ✅ String parsing
- ✅ Protocol routing

**Example flow:**
```bash
# User sets env
export FOOBAR_API_KEY=sk-...

# User requests model
ollama_emulator --model foobar/some-model

# System:
# 1. Detects FOOBAR_API_KEY → foobar provider exists
# 2. Parses foobar/some-model → provider=foobar, model=some-model
# 3. Matches "foobar" → OpenAiCompatible (default)
# 4. Routes to FOOBAR_BASE_URL or default endpoint
# 5. No validation, no discovery, no enumeration
```

**Code:**
```rust
// Provider detection - pure env var pattern
fn detect_providers_from_env() -> Vec<String> {
    std::env::vars()
        .filter(|(k, v)| k.ends_with("_API_KEY") && !v.is_empty())
        .filter(|(k, _)| !k.contains("_SEARCH_"))
        .map(|(k, _)| k.trim_end_matches("_API_KEY").to_lowercase())
        .collect()
}

// Model parsing - pure string split
fn parse_model_ref(model_ref: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = model_ref.splitn(2, '/').collect();
    if parts.len() == 2 {
        Some((parts[0].to_string(), parts[1].to_string()))
    } else {
        None
    }
}

// Protocol detection - pure pattern match
fn infer_provider_family(provider: &str) -> Option<ProviderFamily> {
    match provider {
        "anthropic" | "claude" => AnthropicCompatible,
        "google" | "gemini" => GeminiNative,
        "ollama" => Ollama,
        _ => OpenAiCompatible,  // Any XXXXX_API_KEY provider
    }
}
```

**Result:**
- Zero external API calls
- Zero hardcoded lists
- Pure pattern matching
- Works with any provider that follows `XXXXX_API_KEY` convention

