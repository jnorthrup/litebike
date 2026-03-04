# Implementation Record: OpenAI → OpenAI Targets

**Date:** 2026-03-04  
**Location:** `conductor/tracks/ollama-emulator-copilot-20260304/plan.md`

---

## How To Implement `/v1/chat/completions`

### Step 1: Add Structs (ollama_emulator.rs, line ~115)

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

---

### Step 2: Add Route (route_request function, ~line 920)

```rust
// OpenAI-compatible /v1/chat/completions endpoint
("POST", "/v1/chat/completions") => {
    handle_openai_chat(body, state).await
}
```

---

### Step 3: Implement Handler (after handle_chat, ~line 1200)

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
                "error": {
                    "message": format!("Invalid request: {}", e),
                    "type": "invalid_request_error"
                }
            }).to_string());
        }
    };
    
    log::info!("OpenAI chat request for model: {}", request.model);
    
    // Get model from lifecycle
    let state = state.read().await;
    let model_name = if let Some(ref lc) = state.lifecycle {
        lc.route.upstream_model_id.clone()
    } else {
        request.model.clone()
    };
    
    // Get quota info
    let quota_info = state.quota_state.iter()
        .find(|q| q.model_ref == model_name);
    
    // Build OpenAI-compatible response
    let response = OpenAiChatResponse {
        id: format!("chatcmpl-{}", uuid::Uuid::new_v4()),
        object: "chat.completion".to_string(),
        created: chrono::Utc::now().timestamp() as u64,
        model: model_name.clone(),
        choices: vec![OpenAiChatChoice {
            index: 0,
            message: OpenAiChatMessage {
                role: "assistant".to_string(),
                content: format!(
                    "[OpenAI-Compatible] Chat via modelmux.\n\
                     Model: {}\n\
                     Quota: {}",
                    model_name,
                    quota_info.map(|q| if q.free { "free" } else { "paid" })
                        .unwrap_or("none"),
                ),
            },
            finish_reason: "stop".to_string(),
        }],
        usage: OpenAiUsage {
            prompt_tokens: request.messages.iter()
                .map(|m| m.content.len() / 4)
                .sum::<usize>() as u32,
            completion_tokens: 50,
            total_tokens: 0,
        },
    };
    
    // Calculate total
    let mut response = response;
    response.usage.total_tokens = 
        response.usage.prompt_tokens + response.usage.completion_tokens;
    
    (200, serde_json::to_string(&response).unwrap())
}
```

---

### Step 4: Add Dependencies (Cargo.toml if needed)

```toml
[dependencies]
uuid = { version = "1.0", features = ["v4"] }
```

---

### Step 5: Test

```bash
curl -X POST http://localhost:8888/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "kimi-k2",
    "messages": [
      {"role": "user", "content": "Hello"}
    ]
  }' | jq .
```

**Expected Response:**
```json
{
  "id": "chatcmpl-xxx",
  "object": "chat.completion",
  "created": 1709568000,
  "model": "kimi-k2",
  "choices": [
    {
      "index": 0,
      "message": {
        "role": "assistant",
        "content": "[OpenAI-Compatible] Chat via modelmux..."
      },
      "finish_reason": "stop"
    }
  ],
  "usage": {
    "prompt_tokens": 1,
    "completion_tokens": 50,
    "total_tokens": 51
  }
}
```

---

## Files Modified

| File | Lines | Change |
|------|-------|--------|
| `literbike/src/bin/ollama_emulator.rs` | ~115 | Add OpenAI chat structs |
| `literbike/src/bin/ollama_emulator.rs` | ~920 | Add route |
| `literbike/src/bin/ollama_emulator.rs` | ~1200 | Add handler |
| `live_demo.sh` | - | Add test |

---

## Recorded In

- `conductor/tracks/ollama-emulator-copilot-20260304/plan.md` (Phase 3b)
- `conductor/tracks/ollama-emulator-copilot-20260304/IMPLEMENTATION_RECORD.md` (this file)

---

## Status

**Implementation:** Documented and ready to code  
**Priority:** P0 - First Goal  
**Next:** Execute implementation steps above
