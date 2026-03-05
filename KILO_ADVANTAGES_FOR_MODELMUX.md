# Kilo Gateway Advantages for ModelMux DSEL

## Executive Summary

Analysis of Kilo.ai Gateway reveals **8 key architectural advantages** we can port to ModelMux DSEL for improved robustness, error handling, and provider management.

---

## 1. Enhanced Error Handling & Translation

### Current ModelMux
- Basic error types (BadRequest, Unauthorized, NotFound, UpstreamError)
- No error code mapping
- No context-length specific handling

### Kilo Gateway Advantages

#### A. Standardized Error Response Format
```json
{
  "error": {
    "message": "Human-readable description",
    "code": 400
  }
}
```

**Action**: Update `ProxyError` to include error codes and structured responses.

#### B. Special Error Translation
- **402 → 503**: Upstream payment errors mapped to service unavailable (hides billing)
- **Context length errors**: Return 400 with token counts in message
- **Provider-specific errors**: Normalize to gateway-standard codes

**Action**: Add error translation layer in `proxy.rs`:
```rust
pub enum ErrorCode {
    BadRequest = 400,
    Unauthorized = 401,
    InsufficientBalance = 402,
    Forbidden = 403,
    RateLimited = 429,
    InternalError = 500,
    ProviderError = 502,
    ServiceUnavailable = 503,
}

impl ProxyError {
    fn translate_upstream_error(&self, upstream_status: u16) -> Self {
        match upstream_status {
            402 => ProxyError::ServiceUnavailable, // Hide billing
            502 | 503 => ProxyError::ProviderError,
            _ => self.clone(),
        }
    }
}
```

#### C. Context-Length Aware Errors
```rust
pub struct ContextLengthError {
    pub model: String,
    pub model_context_limit: u64,
    pub request_token_count: u64,
}

impl std::fmt::Display for ContextLengthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "This request exceeds the model's context window of {} tokens. \
             Your request contains approximately {} tokens.",
            self.model_context_limit, self.request_token_count
        )
    }
}
```

**Priority**: HIGH - Improves user experience and debugging

---

## 2. Advanced Tool Calling Normalization

### Current ModelMux
- Basic tool support in data models
- No normalization or repair logic

### Kilo Gateway Advantages

#### A. Automatic Tool Call Repair
Kilo handles:
1. **Deduplication**: Removes duplicate tool calls with same ID
2. **Orphan cleanup**: Removes tool results without matching calls
3. **Missing results**: Inserts placeholders for calls without responses
4. **ID normalization**: Adapts IDs per provider requirements

**Action**: Add tool call normalizer:
```rust
pub struct ToolCallNormalizer {
    provider: String,
}

impl ToolCallNormalizer {
    pub fn normalize(&self, tool_calls: Vec<ToolCall>) -> Vec<ToolCall> {
        let mut normalized = self.deduplicate(tool_calls);
        normalized = self.remove_orphans(normalized);
        normalized = self.normalize_ids(normalized);
        normalized
    }

    fn deduplicate(&self, calls: Vec<ToolCall>) -> Vec<ToolCall> {
        let mut seen_ids = std::collections::HashSet::new();
        calls.into_iter()
            .filter(|call| seen_ids.insert(call.id.clone()))
            .collect()
    }

    fn remove_orphans(&self, calls: Vec<ToolCall>) -> Vec<ToolCall> {
        // Remove tool result messages without matching calls
        // Implementation depends on message context
        calls
    }

    fn normalize_ids(&self, calls: Vec<ToolCall>) -> Vec<ToolCall> {
        match self.provider.as_str() {
            "anthropic" | "mistral" => {
                // These providers have specific ID format requirements
                calls.into_iter()
                    .map(|mut call| {
                        call.id = call.id.replace("-", "_"); // Example
                        call
                    })
                    .collect()
            }
            _ => calls,
        }
    }
}
```

#### B. Tool Call Schema Validation
```rust
pub struct ToolCallValidator {
    max_tools: usize,
    max_arguments_size: usize,
}

impl ToolCallValidator {
    pub fn validate(&self, tools: &[Tool]) -> Result<(), ValidationError> {
        if tools.len() > self.max_tools {
            return Err(ValidationError::TooManyTools {
                limit: self.max_tools,
                actual: tools.len(),
            });
        }
        
        for tool in tools {
            let args_size = serde_json::to_string(&tool.function.parameters)?
                .len();
            if args_size > self.max_arguments_size {
                return Err(ValidationError::ToolArgumentsTooLarge {
                    tool: tool.function.name.clone(),
                    limit: self.max_arguments_size,
                    actual: args_size,
                });
            }
        }
        
        Ok(())
    }
}
```

**Priority**: MEDIUM - Important for production tool calling reliability

---

## 3. Provider-Specific Adaptation Layer

### Current ModelMux
- Basic `is_openai_compatible` flag
- Simple Anthropic transformation

### Kilo Gateway Advantages

#### A. Provider Adapter Pattern
```rust
pub trait ProviderAdapter: Send + Sync {
    fn name(&self) -> &str;
    
    // Request transformation
    fn transform_request(&self, request: OpenAIRequest) -> ProviderRequest;
    
    // Response transformation
    fn transform_response(&self, response: ProviderResponse) -> OpenAIResponse;
    
    // Error translation
    fn translate_error(&self, error: ProviderError) -> ProxyError;
    
    // Provider-specific capabilities
    fn capabilities(&self) -> ProviderCapabilities;
}

pub struct ProviderCapabilities {
    pub supports_streaming: bool,
    pub supports_tools: bool,
    pub supports_vision: bool,
    pub supports_function_calling: bool,
    pub max_context_length: u64,
    pub max_output_tokens: u64,
    pub tool_call_id_format: ToolCallIdFormat,
}

#[derive(Debug, Clone, Copy)]
pub enum ToolCallIdFormat {
    Alphanumeric,      // OpenAI, DeepSeek
    UnderscoreOnly,    // Anthropic, Mistral
    Base64,           // Some providers
}
```

#### B. Provider-Specific Implementations
```rust
pub struct AnthropicAdapter {
    api_version: String,
}

impl ProviderAdapter for AnthropicAdapter {
    fn name(&self) -> &str { "anthropic" }
    
    fn transform_request(&self, request: OpenAIRequest) -> ProviderRequest {
        // Convert OpenAI messages to Anthropic format
        // Handle system prompt extraction
        // Transform tool calls to Anthropic tools
        ProviderRequest::Anthropic(AnthropicRequest {
            model: request.model.replace("anthropic/", ""),
            messages: self.convert_messages(request.messages),
            max_tokens: request.max_tokens.unwrap_or(4096),
            system: self.extract_system_prompt(&request.messages),
            tools: request.tools.map(|t| self.convert_tools(t)),
            ..Default::default()
        })
    }
    
    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities {
            supports_streaming: true,
            supports_tools: true,
            supports_vision: true,
            supports_function_calling: true,
            max_context_length: 200_000,
            max_output_tokens: 64_000,
            tool_call_id_format: ToolCallIdFormat::UnderscoreOnly,
        }
    }
}
```

**Priority**: HIGH - Critical for multi-provider support

---

## 4. Streaming SSE Implementation

### Current ModelMux
- No streaming support implemented

### Kilo Gateway Advantages

#### A. SSE Streaming Format
```rust
use tokio_stream::Stream;
use futures::stream::StreamExt;

pub struct SseStreamer {
    model: String,
    created: u64,
}

impl SseStreamer {
    pub fn new(model: &str) -> Self {
        Self {
            model: model.to_string(),
            created: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }
    
    pub async fn stream_chunk(
        &self,
        content: &str,
        index: usize,
        finish_reason: Option<&str>,
    ) -> String {
        let chunk = serde_json::json!({
            "id": format!("chatcmpl-{}", uuid::Uuid::new_v4()),
            "object": "chat.completion.chunk",
            "created": self.created,
            "model": self.model,
            "choices": [{
                "index": index,
                "delta": {
                    "role": "assistant",
                    "content": content,
                },
                "finish_reason": finish_reason,
            }]
        });
        
        format!("data: {}\n\n", serde_json::to_string(&chunk).unwrap())
    }
    
    pub fn final_chunk(&self, usage: &Usage) -> String {
        let chunk = serde_json::json!({
            "id": format!("chatcmpl-{}", uuid::Uuid::new_v4()),
            "object": "chat.completion.chunk",
            "created": self.created,
            "model": self.model,
            "choices": [{
                "index": 0,
                "delta": {},
                "finish_reason": "stop",
            }],
            "usage": usage,
        });
        
        format!("data: {}\n\ndata: [DONE]\n\n", serde_json::to_string(&chunk).unwrap())
    }
}
```

#### B. Streaming Response Handler
```rust
pub async fn handle_streaming_response(
    provider_stream: impl Stream<Item = Result<Bytes, ProxyError>>,
    streamer: SseStreamer,
) -> Result<SseResponse, ProxyError> {
    let mut stream = provider_stream;
    let mut response_body = String::new();
    
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        let sse_data = streamer.stream_chunk(&chunk, 0, None).await;
        response_body.push_str(&sse_data);
    }
    
    // Send final chunk with usage
    response_body.push_str(&streamer.final_chunk(&Usage::default()));
    
    Ok(SseResponse::new(response_body))
}
```

**Priority**: HIGH - Essential for LLM UX

---

## 5. Rate Limiting & Quota Headers

### Current ModelMux
- Basic quota tracking in DSEL
- No HTTP rate limit headers

### Kilo Gateway Advantages

#### A. Standard Rate Limit Headers
```rust
pub struct RateLimitInfo {
    pub limit: u64,           // X-RateLimit-Limit
    pub remaining: u64,       // X-RateLimit-Remaining
    pub reset: u64,           // X-RateLimit-Reset (Unix timestamp)
    pub retry_after: Option<u64>, // Retry-After (seconds)
}

impl RateLimitInfo {
    pub fn from_quota(quota: &ProviderQuota) -> Self {
        Self {
            limit: quota.daily_tokens as u64,
            remaining: quota.remaining_tokens(),
            reset: quota.reset_timestamp(),
            retry_after: None,
        }
    }
    
    pub fn to_headers(&self) -> Vec<(&str, String)> {
        vec![
            ("X-RateLimit-Limit", self.limit.to_string()),
            ("X-RateLimit-Remaining", self.remaining.to_string()),
            ("X-RateLimit-Reset", self.reset.to_string()),
        ]
    }
}
```

#### B. 429 Response with Retry-After
```rust
impl HttpResponse {
    fn rate_limited(retry_after_secs: u64) -> Self {
        let body = serde_json::json!({
            "error": {
                "message": "Rate limited -- too many requests",
                "code": 429
            }
        });
        
        Self {
            status: 429,
            status_text: "Too Many Requests",
            body: serde_json::to_string(&body).unwrap().into_bytes(),
            headers: vec![
                ("Content-Type", "application/json"),
                ("Retry-After", retry_after_secs.to_string()),
            ],
        }
    }
}
```

**Priority**: MEDIUM - Important for production API behavior

---

## 6. Model Discovery & Metadata

### Current ModelMux
- Basic model listing
- Limited metadata

### Kilo Gateway Advantages

#### A. Rich Model Metadata
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelMetadata {
    pub id: String,
    pub object: String,
    pub created: u64,
    pub owned_by: String,
    
    // Extended metadata
    pub name: String,                    // Human-readable name
    pub description: Option<String>,     // Model description
    pub context_length: u64,            // Max context window
    pub max_output_tokens: u64,         // Max generation tokens
    pub pricing: PricingInfo,           // Token pricing
    pub capabilities: ModelCapabilities,
    pub tags: Vec<String>,              // e.g., ["free", "fast", "code"]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PricingInfo {
    pub prompt: String,      // Per-token price (microdollars)
    pub completion: String,  // Per-token price (microdollars)
    pub currency: String,    // "USD"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelCapabilities {
    pub supports_streaming: bool,
    pub supports_tools: bool,
    pub supports_vision: bool,
    pub supports_json_mode: bool,
    pub supports_fim: bool,  // Fill-in-the-middle for code
}
```

#### B. Model Filtering & Search
```rust
impl ModelRegistry {
    pub fn filter_models(
        &self,
        filters: ModelFilters,
    ) -> Vec<&ModelMetadata> {
        self.models
            .values()
            .filter(|m| {
                if let Some(min_context) = filters.min_context_length {
                    if m.context_length < min_context {
                        return false;
                    }
                }
                if let Some(max_price) = filters.max_price_per_million {
                    if m.pricing.prompt.parse::<f64>().unwrap_or(f64::MAX) > max_price {
                        return false;
                    }
                }
                if let Some(required_cap) = filters.required_capability {
                    if !m.capabilities.has_capability(required_cap) {
                        return false;
                    }
                }
                true
            })
            .collect()
    }
}

pub struct ModelFilters {
    pub min_context_length: Option<u64>,
    pub max_price_per_million: Option<f64>,
    pub required_capability: Option<Capability>,
    pub tags: Vec<String>,
    pub providers: Vec<String>,
}
```

**Priority**: MEDIUM - Improves model selection UX

---

## 7. Organization & Access Control

### Current ModelMux
- No access control layer
- No organization support

### Kilo Gateway Advantages

#### A. Organization Policy Engine
```rust
pub struct OrganizationPolicy {
    pub org_id: String,
    pub name: String,
    
    // Access control
    pub allowed_models: Vec<String>,      // Model allowlist
    pub blocked_models: Vec<String>,      // Model blocklist
    pub allowed_providers: Vec<String>,   // Provider allowlist
    
    // Spending limits
    pub daily_spending_limit: Option<f64>,  // USD
    pub monthly_spending_limit: Option<f64>,
    
    // Rate limits
    pub requests_per_minute: Option<u64>,
    pub requests_per_day: Option<u64>,
}

impl OrganizationPolicy {
    pub fn can_access_model(&self, model_id: &str) -> bool {
        // Blocklist takes precedence
        if self.blocked_models.iter().any(|m| model_id.starts_with(m)) {
            return false;
        }
        
        // If allowlist exists, must be in it
        if !self.allowed_models.is_empty() {
            return self.allowed_models.iter().any(|m| model_id.starts_with(m));
        }
        
        // Check provider allowlist
        if let Some(provider) = model_id.split('/').next() {
            if !self.allowed_providers.is_empty() {
                return self.allowed_providers.contains(&provider.to_string());
            }
        }
        
        true
    }
}
```

#### B. Policy Enforcement Middleware
```rust
pub struct PolicyEnforcer {
    policies: Arc<RwLock<HashMap<String, OrganizationPolicy>>>,
}

impl PolicyEnforcer {
    pub async fn enforce(
        &self,
        org_id: &str,
        request: &OpenAIRequest,
    ) -> Result<(), PolicyViolation> {
        let policies = self.policies.read().await;
        
        if let Some(policy) = policies.get(org_id) {
            // Check model access
            if !policy.can_access_model(&request.model) {
                return Err(PolicyViolation::ModelNotAllowed {
                    model: request.model.clone(),
                });
            }
            
            // Check spending limits
            // Check rate limits
            // Log access for audit
        }
        
        Ok(())
    }
}

pub enum PolicyViolation {
    ModelNotAllowed { model: String },
    ProviderNotAllowed { provider: String },
    SpendingLimitExceeded { limit: f64, spent: f64 },
    RateLimitExceeded { limit: u64, current: u64 },
}
```

**Priority**: LOW (for now) - Important for multi-tenant deployments

---

## 8. FIM (Fill-in-the-Middle) Support

### Current ModelMux
- No FIM endpoint

### Kilo Gateway Advantages

#### A. FIM Endpoint for Code Completion
```rust
// POST /api/fim/completions
pub struct FIMRequest {
    pub model: String,
    pub prompt: String,      // Code before cursor
    pub suffix: Option<String>, // Code after cursor
    pub max_tokens: Option<u64>,
    pub temperature: Option<f32>,
    pub stop: Option<Vec<String>>,
}

pub struct FIMResponse {
    pub id: String,
    pub object: String,
    pub created: u64,
    pub model: String,
    pub choices: Vec<FIMChoice>,
}

pub struct FIMChoice {
    pub text: String,
    pub index: u64,
    pub finish_reason: String,
}

// Handler
pub async fn handle_fim_completion(
    request: FIMRequest,
) -> Result<FIMResponse, ProxyError> {
    // Only allow for code models (mistralai/codestral, etc.)
    if !request.model.starts_with("mistralai/") 
        && !request.model.contains("code") 
    {
        return Err(ProxyError::BadRequest(
            "FIM endpoint only available for code models".to_string()
        ));
    }
    
    // Transform to provider-specific FIM format
    // Forward to provider
    // Return response
}
```

**Priority**: LOW - Nice to have for code completion use cases

---

## Implementation Priority Matrix

| Feature | Priority | Effort | Impact |
|---------|----------|--------|--------|
| **1. Enhanced Error Handling** | HIGH | Low | High |
| **2. Tool Call Normalization** | MEDIUM | Medium | High |
| **3. Provider Adapter Layer** | HIGH | High | Critical |
| **4. Streaming SSE** | HIGH | Medium | Critical |
| **5. Rate Limit Headers** | MEDIUM | Low | Medium |
| **6. Rich Model Metadata** | MEDIUM | Medium | Medium |
| **7. Organization Policies** | LOW | High | Low (now) |
| **8. FIM Endpoints** | LOW | Medium | Low |

---

## Recommended Implementation Order

### Phase 1: Core Robustness (Week 1)
1. Enhanced error handling with codes
2. Provider adapter trait
3. Basic Anthropic adapter implementation

### Phase 2: Critical Features (Week 2)
4. Streaming SSE support
5. Tool call normalization
6. Rate limit headers

### Phase 3: Enhanced UX (Week 3)
7. Rich model metadata
8. Model filtering/search
9. Context-length aware errors

### Phase 4: Advanced Features (Week 4)
10. Organization policies
11. FIM endpoints
12. Advanced tool call repair

---

## Code Structure Recommendations

```
src/models/
├── mod.rs
├── cache.rs              # Model caching
├── registry.rs           # Model/provider registry
├── proxy.rs              # Main proxy server
├── adapters/             # NEW: Provider adapters
│   ├── mod.rs
│   ├── openai.rs
│   ├── anthropic.rs
│   ├── ollama.rs
│   └── lmstudio.rs
├── streaming.rs          # NEW: SSE streaming
├── tools.rs              # NEW: Tool call normalization
├── errors.rs             # NEW: Enhanced error handling
├── policies.rs           # NEW: Access control (later)
└── fim.rs                # NEW: FIM endpoint (later)
```

---

## Key Takeaways

1. **Error translation is critical** - Hides provider-specific details, provides consistent UX
2. **Provider adapters enable extensibility** - Clean separation of concerns
3. **Tool call repair prevents failures** - Automatic normalization across providers
4. **Streaming is non-negotiable** - Essential for LLM user experience
5. **Rich metadata improves discovery** - Users can make informed model choices
6. **Rate limiting headers are standard** - Expected by API clients

---

## References

- Kilo Gateway Docs: https://kilo.ai/docs/gateway
- API Reference: https://kilo.ai/docs/gateway/api-reference
- OpenAI API: https://platform.openai.com/docs/api-reference
- Anthropic API: https://docs.anthropic.com/claude/reference
