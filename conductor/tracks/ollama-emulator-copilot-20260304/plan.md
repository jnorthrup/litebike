# Plan: Ollama Emulator for Copilot Models

## Priority: P0 - First Priority

This track is the **only nexus to copilot models** and **first priority** for enabling gateway quota bearing.

## Phase 1: Ollama API Surface

- [ ] Create `literbike/src/bin/ollama_emulator.rs` with basic HTTP server
- [ ] Implement `GET /api/tags` endpoint (empty model list initially)
- [ ] Implement `GET /api/version` endpoint
- [ ] Implement `POST /api/chat` endpoint (stub that returns mock response)
- [ ] Implement `POST /api/generate` endpoint (stub that returns mock response)
- [ ] Implement `POST /api/show` endpoint (stub)
- [ ] Add CLI parser for `--port`, `--agent-name`, `--env-file`, `--env`, `--mock-quota`

**Validation:**
- [ ] `cargo check --bin ollama_emulator` passes
- [ ] `curl http://localhost:8888/api/version` returns version JSON
- [ ] `curl http://localhost:8888/api/tags` returns empty models list

## Phase 2: Model Mux Integration

- [ ] Wire Ollama emulator to use `run_modelmux_mvp_lifecycle_with_options` from env_facade_parity
- [ ] Add Ollama provider facade object model to `provider_facade_models.rs`
- [ ] Add Ollama-specific env recognition rules
- [ ] Support Ollama model ref parsing (`ollama/llama3`, `ollama/mistral`, etc.)
- [ ] Add Ollama to `ProviderFamily` taxonomy (already exists, verify integration)

**Validation:**
- [ ] `cargo test provider_facade_models --quiet` passes (Ollama provider present)
- [ ] Ollama emulator can parse `--model ollama/llama3` style refs
- [ ] Lifecycle output shows Ollama route resolution

## Phase 3: Backend Translation Layer

- [ ] Create `literbike/src/ollama_adapter.rs` module
- [ ] Implement Ollama → OpenAI chat completion translation
- [ ] Implement Ollama → Anthropic messages translation
- [ ] Implement Ollama → Gemini generateContent translation
- [ ] Implement OpenAI → Ollama response translation
- [ ] Implement Anthropic → Ollama response translation
- [ ] Implement Gemini → Ollama response translation

**Validation:**
- [ ] `cargo test ollama_adapter --quiet` passes
- [ ] Ollama chat request successfully routes to OpenAI backend (mock)
- [ ] Response translation preserves message structure

## Phase 4: Quota Arbitration

- [ ] Wire Ollama emulator to use `run_modelmux_quota_drainer_dry_run` from env_facade_parity
- [ ] Add Ollama-specific quota inventory adapter interface
- [ ] Support quota discovery from multiple backends
- [ ] Implement free-first selection policy
- [ ] Implement paid fallback with minima thresholds
- [ ] Add quota tracking per request/token

**Validation:**
- [ ] `cargo test env_facade_parity --quiet` passes (quota tests)
- [ ] Ollama emulator with `--mock-quota` flags shows quota selection output
- [ ] Free-tier quota is selected before paid when both available
- [ ] Paid fallback triggers when free below minima

## Phase 5: 888agent Integration

- [ ] Default port 8888 for Ollama emulator
- [ ] Default agent name `agent8888`
- [ ] Support unified-port config via `OLLAMA_UNIFIED_PORT` env
- [ ] Support agent name via `OLLAMA_AGENT_NAME` env
- [ ] Add readiness probe endpoint (`GET /health`)
- [ ] Add metrics endpoint (`GET /metrics`)

**Validation:**
- [ ] Ollama emulator starts on port 8888 by default
- [ ] `curl http://localhost:8888/health` returns ready status
- [ ] `curl http://localhost:8888/metrics` returns quota/request metrics

## Phase 6: End-to-End Testing

- [ ] Create integration test: Ollama emulator → mock OpenAI backend
- [ ] Create integration test: Ollama emulator → mock Anthropic backend
- [ ] Create integration test: Ollama emulator → mock Gemini backend
- [ ] Create integration test: Quota arbitration with multiple mock providers
- [ ] Create smoke test script for manual validation
- [ ] Document deployment in DEPLOY.md

**Validation:**
- [ ] All integration tests pass
- [ ] Smoke test script succeeds
- [ ] End-to-end latency < 500ms for mock backends

## Phase 7: litebike Gate Integration (Optional)

- [ ] Create `litebike/src/ollama_gate.rs` (if needed)
- [ ] Wire Ollama emulator through litebike integrated proxy
- [ ] Add Ollama route classification to shared taxonomy
- [ ] Add logging/metrics for Ollama routes

**Validation:**
- [ ] `cargo check --quiet` passes in litebike
- [ ] Ollama routes logged through integrated proxy

## Notes

- Ollama is already a `ProviderFamily` variant in `model_serving_taxonomy.rs`
- Model mux lifecycle already exists in `modelmux_mvp_lifecycle.rs`
- QuotaDrainer dry-run already implemented in `env_facade_parity.rs`
- This track wires existing primitives together with Ollama-specific translation

## Dependencies

- literbike `model_serving_taxonomy` (exists)
- literbike `provider_facade_models` (exists, needs Ollama provider)
- literbike `env_facade_parity` (exists, needs Ollama quota adapter)
- literbike `modelmux_mvp_lifecycle` (exists)

## Binary Names (argv[0])

The Ollama emulator supports multiple executable names for compatibility:

- `ollama` - Standard Ollama CLI compatibility (e.g., `ollama serve`)
- `ollama_emulator` - Full emulator name
- `modelmux` - Model muxer alias
- `agent8888` - 888agent alias

### Usage Examples by Binary Name

```bash
# As 'ollama' (Ollama CLI compatibility)
ollama serve --port 8888
ollama --version

# As 'ollama_emulator' (full name)
ollama_emulator --port 8888 --agent-name agent8888
ollama_emulator --mock-quota "free::/free/moonshotai/kimi-k2;req=100;tok=50000;free"

# As 'modelmux' (muxer alias)
modelmux --port 8888 --model /free/moonshotai/kimi-k2

# As 'agent8888' (888agent alias)
agent8888 --port 8888 --env OPENAI_API_KEY=sk-...
```

### Implementation Details

- Executable name is extracted from `argv[0]` at runtime
- `ollama serve` subcommand is recognized and handled for CLI compatibility
- `--version` / `-v` flags return version with exe name
- Help output includes the actual executable name used
- All binary names share the same underlying implementation

## Build & Test Results (2026-03-04)

### Build Status
```bash
cd /Users/jim/work/literbike
cargo build --bin ollama_emulator
# Success - binary at target/debug/ollama_emulator (10.5MB)
```

### API Endpoint Tests

**GET /api/version**
```json
{"version": "0.1.0-ollama-emulator"}
```

**GET /api/tags** - Models projected from lifecycle with quota metadata
```json
{
  "models": [{
    "name": "moonshotai/kimi-k2",
    "digest": "sha256:agent8888:default:free:moonshotai/kimi-k2",
    "details": {
      "family": "free",
      "families": ["agent/agent8888", "modality/free", "quota-dsel-free", ...],
      "parameter_size": "50000",
      "quantization_level": "free-tier"
    }
  }]
}
```

**GET /health**
```json
{
  "status": "ready",
  "has_lifecycle": true,
  "providers": 26,
  "quotas": 1
}
```

**GET /metrics** - Prometheus-style
```
ollama_providers_total 26
ollama_quotas_total 1
ollama_quotas_free 1
ollama_quotas_paid 0
ollama_tokens_remaining 50000
```

**POST /api/chat** - Quota-aware routing
```json
{
  "model": "moonshotai/kimi-k2",
  "message": {
    "content": "[Ollama Emulator] Chat routed via modelmux.\nProvider: OpenAiCompatible\nQuota: free\nTags: [free]"
  },
  "done": true
}
```

### Lifecycle Output
```
ready=true;reason=provider api key selected
route_key=agent8888:default:free:moonshotai/kimi-k2
selected_key=MOONSHOT_API_KEY
quota_candidates=1;quota_selected_slot=free;quota_selected_score=532
quota_drainer_ready=true;policy=free-first;fallback_used=false
```

## Next Steps

1. Add backend translation layer (Ollama → OpenAI/Anthropic/Gemini)
2. Wire actual provider API calls through modelmux routing
3. Add streaming response support
4. Integrate with litebike gates for unified proxy routing

## Phase 3b: OpenAI → OpenAI Targets (FIRST PRIORITY)

**Goal:** OpenAI-compatible `/v1/chat/completions` endpoint

### Implementation Steps

1. **Add OpenAI Chat Structs** (ollama_emulator.rs):
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenAiChatMessage {
    pub role: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenAiChatRequest {
    pub model: String,
    pub messages: Vec<OpenAiChatMessage>,
    pub stream: Option<bool>,
    pub temperature: Option<f32>,
    pub max_tokens: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenAiChatChoice {
    pub index: u32,
    pub message: OpenAiChatMessage,
    pub finish_reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenAiUsage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_tokens: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenAiChatResponse {
    pub id: String,
    pub object: String,  // "chat.completion"
    pub created: u64,
    pub model: String,
    pub choices: Vec<OpenAiChatChoice>,
    pub usage: OpenAiUsage,
}
```

2. **Add Route** (in route_request function):
```rust
// OpenAI-compatible /v1/chat/completions endpoint
("POST", "/v1/chat/completions") => {
    handle_openai_chat(body, state).await
}
```

3. **Implement Handler**:
```rust
async fn handle_openai_chat(
    body: &str,
    state: &Arc<RwLock<OllamaEmulatorState>>,
) -> (u16, String) {
    // Parse OpenAI request
    let request: OpenAiChatRequest = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(e) => {
            return (400, serde_json::json!({
                "error": {"message": format!("Invalid: {}", e)}
            }).to_string());
        }
    };
    
    // Get model from lifecycle
    let state = state.read().await;
    let model_name = state.lifecycle.as_ref()
        .map(|lc| lc.route.upstream_model_id.clone())
        .unwrap_or_else(|| request.model.clone());
    
    // Build OpenAI response
    let response = OpenAiChatResponse {
        id: format!("chatcmpl-{}", uuid::Uuid::new_v4()),
        object: "chat.completion".to_string(),
        created: chrono::Utc::now().timestamp() as u64,
        model: model_name.clone(),
        choices: vec![OpenAiChatChoice {
            index: 0,
            message: OpenAiChatMessage {
                role: "assistant".to_string(),
                content: "Response via modelmux".to_string(),
            },
            finish_reason: "stop".to_string(),
        }],
        usage: OpenAiUsage {
            prompt_tokens: 10,
            completion_tokens: 20,
            total_tokens: 30,
        },
    };
    
    (200, serde_json::to_string(&response).unwrap())
}
```

### Test Command
```bash
curl -X POST http://localhost:8888/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"kimi-k2","messages":[{"role":"user","content":"Hello"}]}' | jq .
```

### Expected Response
```json
{
  "id": "chatcmpl-xxx",
  "object": "chat.completion",
  "created": 1709568000,
  "model": "kimi-k2",
  "choices": [{
    "index": 0,
    "message": {"role": "assistant", "content": "..."},
    "finish_reason": "stop"
  }],
  "usage": {
    "prompt_tokens": 10,
    "completion_tokens": 20,
    "total_tokens": 30
  }
}
```

- [ ] Add OpenAI chat structs to ollama_emulator.rs
- [ ] Add `/v1/chat/completions` route
- [ ] Implement `handle_openai_chat` function
- [ ] Test with curl command above
- [ ] Add test to live_demo.sh

**Validation:**
- [ ] `curl POST /v1/chat/completions` returns OpenAI format
- [ ] Response includes: id, object, created, model, choices, usage
- [ ] choices[].message has role + content
- [ ] usage has prompt_tokens, completion_tokens, total_tokens

