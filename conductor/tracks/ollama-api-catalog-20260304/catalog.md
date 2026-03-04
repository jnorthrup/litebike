# Ollama API Behavior Catalog

**Created:** 2026-03-04  
**Goal:** Document all Ollama API endpoints and behaviors for modelmux/ollama_emulator compatibility

---

## Endpoint Status Matrix

| Endpoint | Method | Status | Response | Notes |
|----------|--------|--------|----------|-------|
| `/v1/models` | GET | ✅ Implemented | 200 OK | OpenAI-compatible model listing |
| `/models` | GET | ✅ Implemented | 200 OK | Alias for /v1/models |
| `/health` | GET | ✅ Implemented | 200 OK | Health + quota status |
| `/quota` | GET | ✅ Implemented | 200 OK | Per-provider usage tracking |
| `/api/version` | GET | ❌ Not Implemented | 404 | Ollama version info |
| `/api/tags` | GET | ❌ Not Implemented | 404 | Ollama model tags |
| `/api/chat` | POST | ❌ Not Implemented | 404 | Chat completion |
| `/api/generate` | POST | ❌ Not Implemented | 404 | Text generation |
| `/api/show` | POST | ❌ Not Implemented | 404 | Model info |
| `/api/pull` | POST | ❌ Not Implemented | 404 | Model download |
| `/api/push` | POST | ❌ Not Implemented | 404 | Model upload |
| `/api/delete` | DELETE | ❌ Not Implemented | 404 | Model deletion |
| `/api/copy` | POST | ❌ Not Implemented | 404 | Model copy |
| `/api/blobs/:digest` | GET/POST | ❌ Not Implemented | 404 | Blob storage |

---

## Implemented Endpoints

### GET /v1/models

**Purpose:** List all available models (OpenAI-compatible)

**Response:**
```json
{
  "object": "list",
  "data": [
    {
      "id": "openai/openai-model",
      "owned_by": "openai"
    },
    {
      "id": "groq/groq-model",
      "owned_by": "groq"
    },
    {
      "id": "deepseek/deepseek-model",
      "owned_by": "deepseek"
    }
  ]
}
```

**Implementation:** `literbike/src/bin/ollama_emulator.rs`

---

### GET /models

**Purpose:** Alias for /v1/models

**Response:** Same as /v1/models

---

### GET /health

**Purpose:** Health check with quota summary

**Response:**
```json
{
  "status": "ready",
  "providers": 12,
  "total_tokens": 0,
  "total_cost_usd": 0.0
}
```

---

### GET /quota

**Purpose:** Detailed quota/usage tracking per provider

**Response:**
```json
{
  "object": "quota",
  "total_tokens": 0,
  "total_cost_usd": 0.0,
  "providers": [
    {
      "id": "openai",
      "tokens": 0,
      "cost_usd": 0.0,
      "requests": 0
    },
    {
      "id": "groq",
      "tokens": 0,
      "cost_usd": 0.0,
      "requests": 0
    }
  ]
}
```

---

## Pending Endpoints (To Implement)

### GET /api/version

**Purpose:** Return Ollama version info

**Expected Response:**
```json
{
  "version": "0.1.0-ollama-emulator"
}
```

**Implementation Needed:**
```rust
("GET", "/api/version") => {
    let response = OllamaVersionResponse { version: "0.1.0".to_string() };
    (200, serde_json::to_string(&response).unwrap())
}
```

---

### GET /api/tags

**Purpose:** List models in Ollama format

**Expected Response:**
```json
{
  "models": [
    {
      "name": "openai/gpt-4:latest",
      "model": "openai/gpt-4",
      "modified_at": "2026-03-04T00:00:00Z",
      "size": 0,
      "digest": "sha256:...",
      "details": {
        "family": "openai",
        "families": ["openai"],
        "parameter_size": "unknown",
        "quantization_level": "unknown"
      }
    }
  ]
}
```

**Implementation Needed:**
```rust
("GET", "/api/tags") => {
    let state = state.read().await;
    let tags: Vec<OllamaModelTag> = state.models.iter().map(|m| {
        OllamaModelTag {
            name: format!("{}:latest", m.id),
            model: m.id.clone(),
            modified_at: chrono::Utc::now().to_rfc3339(),
            size: 0,
            digest: format!("sha256:{}", m.provider),
            details: OllamaModelDetails {
                family: m.provider.clone(),
                families: vec![m.provider.clone()],
                parameter_size: "unknown".to_string(),
                quantization_level: "unknown".to_string(),
            },
        }
    }).collect();
    let response = OllamaTagsResponse { models: tags };
    (200, serde_json::to_string(&response).unwrap())
}
```

---

### POST /api/chat

**Purpose:** Chat completion (Ollama format)

**Request:**
```json
{
  "model": "openai/gpt-4",
  "messages": [
    {"role": "user", "content": "Hello"}
  ],
  "stream": false
}
```

**Expected Response:**
```json
{
  "model": "openai/gpt-4",
  "message": {
    "role": "assistant",
    "content": "Hello! How can I help you?"
  },
  "done": true
}
```

**Implementation Needed:**
- Parse Ollama chat request
- Convert to unified format
- Route through N-Way API conversion layer
- Convert response back to Ollama format

---

### POST /api/generate

**Purpose:** Text generation (completion)

**Request:**
```json
{
  "model": "openai/gpt-4",
  "prompt": "Write a poem about",
  "stream": false
}
```

**Expected Response:**
```json
{
  "model": "openai/gpt-4",
  "response": "Roses are red...",
  "done": true
}
```

---

### POST /api/show

**Purpose:** Get model information

**Request:**
```json
{
  "model": "openai/gpt-4"
}
```

**Expected Response:**
```json
{
  "license": "MIT",
  "modelfile": "# Modelfile for gpt-4",
  "parameters": "",
  "template": "{{ .Prompt }}",
  "details": {
    "family": "openai",
    "families": ["openai"],
    "parameter_size": "unknown",
    "quantization_level": "unknown"
  }
}
```

---

## Provider Detection

**Method:** Environment variable pattern matching

```rust
Provider::from_env_key("OPENAI_API_KEY")  // → Provider::OpenAI
Provider::from_env_key("ANTHROPIC_AUTH_TOKEN")  // → Provider::Anthropic
Provider::from_env_key("GEMINI_API_KEY")  // → Provider::Gemini
```

**Detected Providers (12):**
1. openai
2. groq
3. deepseek
4. moonshot
5. nvidia
6. perplexity
7. openrouter
8. cerebras
9. huggingface
10. kilo
11. kilocode
12. xai

---

## Model Reference Format

**Pattern:** `PROVIDER/MODEL`

**Examples:**
- `openai/gpt-4`
- `groq/llama-3.1-8b-instant`
- `deepseek/deepseek-chat`
- `moonshot/kimi-k2`

**Auto-generated models per provider:**
- `{provider}/{provider}-model`
- `{provider}/default`

---

## Quota Tracking

**Tracked Metrics:**
- `total_tokens` - Sum across all providers
- `total_cost_usd` - Sum of costs (from OpenRouter-style responses)
- Per-provider: `tokens`, `cost_usd`, `requests`

**Policy:** Free-first selection (configured in modelmux)

---

## Integration Points

### N-Way API Conversion

The ollama_emulator uses the `literbike::api_translation` module for:
- Format conversion (OpenAI ↔ Anthropic ↔ Gemini)
- Unified request/response types
- Provider auto-detection

### ModelMux Integration

The ollama_emulator is a thin wrapper around modelmux lifecycle:
- Provider projection from env vars
- Quota arbitration (free-first policy)
- Model routing

---

## Test Commands

```bash
# Start server
./target/debug/ollama_emulator --port 8888

# Test endpoints
curl http://localhost:8888/v1/models | jq .
curl http://localhost:8888/health | jq .
curl http://localhost:8888/quota | jq .

# N-Way demo
cargo run --bin nway_demo
```

---

## Files Reference

| File | Purpose |
|------|---------|
| `literbike/src/bin/ollama_emulator.rs` | Main emulator binary |
| `literbike/src/api_translation/types.rs` | Unified API types |
| `literbike/src/api_translation/converter.rs` | Format conversion |
| `literbike/src/api_translation/client.rs` | Unified API client |
| `litebike/src/bin/modelmux.rs` | Model multiplexer |
| `litebike/src/bin/keymux.rs` | Keystore manager |

---

## Next Steps

1. **Implement /api/version** - Return version info
2. **Implement /api/tags** - Ollama-format model listing
3. **Implement /api/chat** - Chat completion with N-Way routing
4. **Implement /api/generate** - Text generation
5. **Implement /api/show** - Model details
6. **Add streaming support** - SSE for chat/generate
7. **Add model pulling** - Integration with provider APIs
