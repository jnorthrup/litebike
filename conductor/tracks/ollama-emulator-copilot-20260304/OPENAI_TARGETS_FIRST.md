# OpenAI → OpenAI Targets (First Priority)

**Date:** 2026-03-04  
**Priority:** P0 - First Goal

---

## Goal

**OpenAI → OpenAI targets are first goal**

The Ollama emulator should act as an **OpenAI-compatible proxy** that:
1. Accepts OpenAI API format at `/v1/chat/completions`
2. Routes through modelmux lifecycle
3. Returns OpenAI-compatible response

---

## Required Endpoints

### OpenAI Chat Completions (PRIMARY)

```
POST /v1/chat/completions
Content-Type: application/json

{
  "model": "kimi-k2",
  "messages": [
    {"role": "system", "content": "You are helpful"},
    {"role": "user", "content": "Hello"}
  ],
  "stream": false
}
```

**Response:**
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
        "content": "Hello! How can I help?"
      },
      "finish_reason": "stop"
    }
  ],
  "usage": {
    "prompt_tokens": 10,
    "completion_tokens": 20,
    "total_tokens": 30
  }
}
```

---

## Implementation Plan

### 1. Add OpenAI Chat Request/Response Structs

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
    pub object: String,
    pub created: u64,
    pub model: String,
    pub choices: Vec<OpenAiChatChoice>,
    pub usage: OpenAiUsage,
}
```

### 2. Add Route Handler

```rust
// In route_request function:

// OpenAI-compatible /v1/chat/completions endpoint
("POST", "/v1/chat/completions") => {
    handle_openai_chat(body, state).await
}
```

### 3. Implement Handler

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
    
    // Get lifecycle state
    let state = state.read().await;
    
    // Select model from lifecycle
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
                .sum(),
            completion_tokens: 50,  // Mock
            total_tokens: 0,  // Will calculate
        },
    };
    
    // Calculate total
    let response_clone = response.clone();
    let mut response = response;
    response.usage.total_tokens = 
        response_clone.usage.prompt_tokens + response_clone.usage.completion_tokens;
    
    (200, serde_json::to_string(&response).unwrap())
}
```

---

## API Compatibility Matrix

| Endpoint | OpenAI Format | Status |
|----------|---------------|--------|
| `/v1/models` | ✅ List models | Implemented |
| `/v1/models/{model}` | ✅ Get model | Implemented |
| `/v1/chat/completions` | ✅ Chat | **TODO** |
| `/v1/completions` | ⚠️ Legacy completions | Later |
| `/v1/embeddings` | ⚠️ Embeddings | Later |
| `/v1/images/generations` | ⚠️ Images | Later |

---

## Priority Order

1. **`/v1/chat/completions`** ← FIRST (this is the goal)
2. `/v1/models` ← Done
3. `/v1/models/{model}` ← Done
4. `/v1/completions` ← Later
5. Others ← Much later

---

## Testing

### OpenAI-Compatible Chat Test

```bash
curl -X POST http://localhost:8888/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer sk-test" \
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
  "choices": [{
    "index": 0,
    "message": {
      "role": "assistant",
      "content": "..."
    },
    "finish_reason": "stop"
  }],
  "usage": {
    "prompt_tokens": 1,
    "completion_tokens": 50,
    "total_tokens": 51
  }
}
```

---

## Files to Modify

| File | Change |
|------|--------|
| `literbike/src/bin/ollama_emulator.rs` | Add OpenAI chat structs + handler |
| `live_demo.sh` | Add `/v1/chat/completions` test |

---

## Summary

**First Goal:** OpenAI → OpenAI targets

1. ✅ `/v1/models` - List models (OpenAI format)
2. ✅ `/v1/models/{model}` - Get model detail
3. **`/v1/chat/completions`** - Chat completion (TODO - PRIMARY)
4. ⚠️ Other endpoints - Later

**Focus:** Make `/v1/chat/completions` work with OpenAI-compatible request/response format.
