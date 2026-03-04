# API Host to API_KEY Recognition Mapping

**Purpose:** Map API hostnames to their corresponding `*_API_KEY` environment variables with automatic detection and clear error instructions for Claude-assisted codebase updates.

---

## Recognition Flow

```
┌─────────────────────────────────────────────────────────────┐
│  1. Check known exact matches (OPENAI_API_KEY, etc.)        │
│  2. Check known aliases (ANTHROPIC_API_KEY → AUTH_TOKEN)    │
│  3. Check _SEARCH_API_KEY suffix → Search provider group    │
│  4. Check _API_KEY suffix → Generic API key                 │
│     └─→ Probe /models endpoint                              │
│     └─→ Classify by hostname pattern                        │
│     └─→ Cache classification result                         │
└─────────────────────────────────────────────────────────────┘
```

---

## Host Pattern → API_KEY Mapping Table

### OpenAI-Compatible Hosts

| Hostname Pattern | API_KEY Env | Base URL Env | Provider Family |
|-----------------|-------------|--------------|-----------------|
| `api.openai.com` | `OPENAI_API_KEY` | `OPENAI_BASE_URL` | OpenAiCompatible |
| `*.openai.com` | `OPENAI_API_KEY` | `OPENAI_BASE_URL` | OpenAiCompatible |
| `api.deepseek.com` | `OPENAI_API_KEY` | `OPENAI_BASE_URL` | OpenAiCompatible |
| `api.moonshot.cn` | `OPENAI_API_KEY` | `OPENAI_BASE_URL` | OpenAiCompatible |
| `api.z.ai` | `OPENAI_API_KEY` | `OPENAI_BASE_URL` | OpenAiCompatible |
| `open.bigmodel.cn` | `OPENAI_API_KEY` | `OPENAI_BASE_URL` | OpenAiCompatible |
| `dashscope.aliyuncs.com` | `OPENAI_API_KEY` | `OPENAI_BASE_URL` | OpenAiCompatible |
| `api-inference.modelscope.cn` | `OPENAI_API_KEY` | `OPENAI_BASE_URL` | OpenAiCompatible |
| `openrouter.ai` | `OPENROUTER_API_KEY` | `OPENAI_BASE_URL` | OpenAiCompatible |
| `*.together.ai` | `TOGETHER_API_KEY` | `OPENAI_BASE_URL` | OpenAiCompatible |
| `*.anyscale.com` | `ANYSCALE_API_KEY` | `OPENAI_BASE_URL` | OpenAiCompatible |

### Anthropic-Compatible Hosts

| Hostname Pattern | API_KEY Env | Base URL Env | Provider Family |
|-----------------|-------------|--------------|-----------------|
| `api.anthropic.com` | `ANTHROPIC_AUTH_TOKEN` | `ANTHROPIC_BASE_URL` | AnthropicCompatible |
| `*.anthropic.com` | `ANTHROPIC_AUTH_TOKEN` | `ANTHROPIC_BASE_URL` | AnthropicCompatible |
| `api.moonshot.cn/anthropic` | `ANTHROPIC_AUTH_TOKEN` | `ANTHROPIC_BASE_URL` | AnthropicCompatible |
| `api.deepseek.com/anthropic` | `ANTHROPIC_AUTH_TOKEN` | `ANTHROPIC_BASE_URL` | AnthropicCompatible |
| `open.bigmodel.cn/api/anthropic` | `ANTHROPIC_AUTH_TOKEN` | `ANTHROPIC_BASE_URL` | AnthropicCompatible |
| `api.z.ai/api/anthropic` | `ANTHROPIC_AUTH_TOKEN` | `ANTHROPIC_BASE_URL` | AnthropicCompatible |
| `dashscope.aliyuncs.com/apps/anthropic` | `ANTHROPIC_AUTH_TOKEN` | `ANTHROPIC_BASE_URL` | AnthropicCompatible |
| `api.kimi.com/coding` | `ANTHROPIC_AUTH_TOKEN` | `ANTHROPIC_BASE_URL` | AnthropicCompatible |

### Gemini/Google Hosts

| Hostname Pattern | API_KEY Env | Base URL Env | Provider Family |
|-----------------|-------------|--------------|-----------------|
| `generativelanguage.googleapis.com` | `GEMINI_API_KEY` | `GOOGLE_GEMINI_BASE_URL` | GeminiNative |
| `*.googleapis.com` | `GEMINI_API_KEY` | `GOOGLE_GEMINI_BASE_URL` | GeminiNative |
| `opencode.ai/zen` | `GEMINI_API_KEY` | `GOOGLE_GEMINI_BASE_URL` | GeminiNative |
| `packyapi.com` | `GEMINI_API_KEY` | `GOOGLE_GEMINI_BASE_URL` | GeminiNative |
| `api.cubence.com` | `GEMINI_API_KEY` | `GOOGLE_GEMINI_BASE_URL` | GeminiNative |
| `api.aigocode.com` | `GEMINI_API_KEY` | `GOOGLE_GEMINI_BASE_URL` | GeminiNative |
| `api.aicodemirror.com` | `GEMINI_API_KEY` | `GOOGLE_GEMINI_BASE_URL` | GeminiNative |

### Search Provider Hosts

| Hostname Pattern | API_KEY Env | Type | Notes |
|-----------------|-------------|------|-------|
| `api.search.brave.com` | `BRAVE_SEARCH_API_KEY` | Search | Multi-key support |
| `api.tavily.com` | `TAVILY_SEARCH_API_KEY` | Search | POST JSON API |
| `api.serper.dev` | `SERPER_API_KEY` | Search | Google SERP |
| `api.searchapi.io` | `SEARCHAPI_KEY` | Search | Multi-engine |

### Exchange Hosts

| Hostname Pattern | API_KEY Env | Type | Notes |
|-----------------|-------------|------|-------|
| `api.binance.com` | `BINANCE_API_KEY` | Exchange | Trading API |
| `api.coinbase.com` | `COINBASE_API_KEY` | Exchange | Trading API |
| `api.kraken.com` | `KRAKEN_API_KEY` | Exchange | Trading API |

---

## Error Messages with Claude Instructions

### Generic API Key Detection Error

```
❌ Unrecognized API Key: CUSTOM_PROVIDER_API_KEY

The hostname 'api.custom-provider.com' was not recognized.

🔍 Classification attempted:
   • Pattern: *_API_KEY (generic)
   • Hostname: api.custom-provider.com
   • Probe result: No /models endpoint found
   • Confidence: 50/100

💡 To add support for this provider:

   Option 1: Quick fix (add to .env)
   ─────────────────────────────────────
   Add to your .env file:
   
   OPENAI_API_KEY="your-key"
   OPENAI_BASE_URL="https://api.custom-provider.com/v1"
   
   Then restart: ollama_emulator --env-file .env

   Option 2: Add provider to codebase (Claude)
   ────────────────────────────────────────────
   Run this Claude prompt:
   
   'Add custom-provider.com support to ollama_emulator:
   
   1. In literbike/src/provider_facade_models.rs:
      - Add env_binding("CUSTOM_PROVIDER_API_KEY", ...)
      - Add to openai-compat provider model
   
   2. In literbike/src/env_facade_parity.rs:
      - Add hostname rule: "api.custom-provider.com" → OpenAiCompatible
      - Add to env_recognition_rules()
   
   3. Rebuild: cargo build --bin ollama_emulator
   
   See: api-host-recognition.md for examples'

   Option 3: Use generic OpenAI compatibility
   ───────────────────────────────────────────
   Set these env vars:
   
   export OPENAI_API_KEY="your-custom-key"
   export OPENAI_BASE_URL="https://api.custom-provider.com/v1"
   
   The emulator will auto-detect the provider family.
```

### Search API Key Error

```
❌ Unrecognized Search Provider: EXAMPLE_SEARCH_API_KEY

The search provider 'EXAMPLE' is not configured.

🔍 Classification:
   • Pattern: *_SEARCH_API_KEY
   • Provider prefix: EXAMPLE
   • Known providers: BRAVE, TAVILY, SERPER

💡 To add search provider support:

   Quick test with curl:
   ─────────────────────────────────────
   cd conductor/tracks/ollama-emulator-copilot-20260304/search-scripts/
   ./search_generic.sh "your query" EXAMPLE
   
   Add provider to codebase (Claude):
   ────────────────────────────────────────────
   Run this Claude prompt:
   
   'Add EXAMPLE search support to ollama_emulator:
   
   1. In literbike/src/env_facade_parity.rs:
      - Add EXAMPLE to search provider prefix detection
      - Add hostname rule for api.example.com
   
   2. In literbike/src/bin/ollama_emulator.rs:
      - Add handle_search() endpoint
      - Add EXAMPLE API curl adapter
   
   3. Create search-scripts/search_example.sh
      - Copy from search_brave.sh template
   
   See: search-scripts/README.md for API patterns'
```

### Missing API Key Error

```
❌ Missing API Key for Provider: Anthropic

The provider 'Anthropic' requires authentication but no API key was found.

🔍 Expected environment variables:
   • ANTHROPIC_AUTH_TOKEN (primary)
   • ANTHROPIC_API_KEY (alias)

💡 To configure Anthropic:

   Get API Key:
   ─────────────────────────────────────
   1. Visit: https://console.anthropic.com/settings/keys
   2. Create new API key
   3. Copy the key (starts with 'sk-ant-')

   Set Environment:
   ─────────────────────────────────────
   export ANTHROPIC_AUTH_TOKEN="sk-ant-..."
   
   Or add to .env file:
   ANTHROPIC_AUTH_TOKEN=sk-ant-...

   Use with emulator:
   ─────────────────────────────────────
   ollama_emulator --env ANTHROPIC_AUTH_TOKEN=sk-ant-...
   
   Or: ollama_emulator --env-file .env

   Claude assistance:
   ─────────────────────────────────────
   'Add Anthropic support to ollama_emulator:
    - Verify ANTHROPIC_AUTH_TOKEN in provider_facade_models.rs
    - Add /api/anthropic/* route handling
    - See api-host-recognition.md#anthropic-compatible-hosts'
```

### Hostname Probe Failure

```
⚠️ API Key Classification: Hostname Probe Failed

Key: CUSTOM_API_KEY
Base URL: https://api.custom.com

🔍 Probe attempts:
   • GET /v1/models → 404 Not Found
   • GET /models → 404 Not Found
   • GET /api/models → 404 Not Found

💡 Classification fallback:

   The API endpoint does not expose a /models endpoint.
   Classification will use hostname pattern matching.

   Detected family: OpenAiCompatible (based on hostname)
   Confidence: 65/100

   To improve detection:
   ─────────────────────────────────────
   1. Add explicit provider configuration:
      
      export OPENAI_BASE_URL="https://api.custom.com/v1"
      export OPENAI_API_KEY="your-key"
   
   2. Or add provider to codebase (Claude):
      
      'Add api.custom.com to recognized hosts:
       
       In literbike/src/env_facade_parity.rs:
       
       EnvRecognitionRule {
           id: "custom-provider",
           family_hint: ProviderFamily::OpenAiCompatible,
           host_contains_any: vec!["api.custom.com"],
           env_keys_any: vec!["CUSTOM_API_KEY"],
           confidence: 95,
       }'
```

---

## Implementation in literbike

### env_facade_parity.rs - Hostname Recognition

```rust
pub fn env_recognition_rules() -> Vec<EnvRecognitionRule> {
    vec![
        // OpenAI Compatible
        EnvRecognitionRule {
            id: "openai-official".to_string(),
            family_hint: ProviderFamily::OpenAiCompatible,
            host_contains_any: vec!["api.openai.com", "openai.com"],
            env_keys_all: vec!["OPENAI_API_KEY", "OPENAI_BASE_URL"],
            inferred_templates: vec![ServingTemplateId::OpenAiV1],
            confidence: 98,
            notes: "Official OpenAI API".to_string(),
        },
        // Anthropic Compatible
        EnvRecognitionRule {
            id: "anthropic-official".to_string(),
            family_hint: ProviderFamily::AnthropicCompatible,
            host_contains_any: vec!["api.anthropic.com", "anthropic.com"],
            env_keys_all: vec!["ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL"],
            inferred_templates: vec![ServingTemplateId::ClaudeMessages],
            confidence: 98,
            notes: "Official Anthropic API".to_string(),
        },
        // ... more rules
    ]
}
```

### Generic API Key Classification

```rust
pub fn classify_generic_api_key(
    key: &str,
    base_url: Option<&str>,
) -> GenericApiKeyClassification {
    // 1. Check hostname patterns
    if let Some(url) = base_url {
        if let Some(host) = extract_hostname(url) {
            // Check known host patterns
            if host.contains("openai.com") {
                return GenericApiKeyClassification {
                    prefix: "OPENAI",
                    api_kind: ApiKind::ModelProvider,
                    family_hint: Some(ProviderFamily::OpenAiCompatible),
                    confidence: 95,
                    reason: format!("hostname match: {}", host),
                };
            }
            // ... more patterns
        }
    }
    
    // 2. Fallback to unknown with probe suggestion
    GenericApiKeyClassification {
        prefix: extract_prefix(key),
        api_kind: ApiKind::Unknown,
        family_hint: None,
        confidence: 50,
        reason: "generic *_API_KEY pattern, probe /models endpoint for classification".to_string(),
    }
}
```

---

## Quick Reference

### Add New Provider (Claude Prompt Template)

```
'Add <provider-name> support to ollama_emulator:

1. In literbike/src/provider_facade_models.rs:
   - Add env_binding("<PROVIDER>_API_KEY", [...], EnvVarRole::ApiKey, ...)
   - Add to <family> provider model

2. In literbike/src/env_facade_parity.rs:
   - Add hostname rule: "<hostname>" → <ProviderFamily>
   - Add to env_recognition_rules()

3. In literbike/src/bin/ollama_emulator.rs:
   - Add <PROVIDER>_API_KEY to provider state projection
   - Add handle_<provider>() if custom endpoint needed

4. Create search-scripts/search_<provider>.sh (if search provider)
   - Copy from search_brave.sh template

See: api-host-recognition.md for examples'
```

### Test Provider Detection

```bash
# Test with specific provider
ollama_emulator \
  --env OPENAI_API_KEY=sk-test \
  --env OPENAI_BASE_URL=https://api.custom.com/v1 \
  --port 8888

# Check logs for classification
tail -f /tmp/ollama-server.log | grep "Provider:"
```

---

## Files Reference

| File | Purpose |
|------|---------|
| `literbike/src/env_facade_parity.rs` | Env normalization, hostname recognition |
| `literbike/src/provider_facade_models.rs` | Provider facade definitions |
| `literbike/src/model_serving_taxonomy.rs` | ProviderFamily enum |
| `literbike/src/bin/ollama_emulator.rs` | Provider state projection |
| `search-scripts/search_*.sh` | Search provider curl scripts |
| `api-env-lookup-table.md` | Complete env var reference |
