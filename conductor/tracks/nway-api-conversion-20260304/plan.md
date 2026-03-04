# N-Way API Conversion Layer

**Created:** 2026-03-04  
**Goal:** Unified API translation between all major AI providers

---

## Target Providers

| Provider | API Format | Auth | Base URL |
|----------|-----------|------|----------|
| **Gemini** | Google Native | `GEMINI_API_KEY` | `generativelanguage.googleapis.com` |
| **Codex** | OpenAI Chat | `OPENAI_API_KEY` | `api.openai.com/v1` |
| **Anthropic** | Messages API | `ANTHROPIC_AUTH_TOKEN` | `api.anthropic.com` |
| **OpenAI** | Chat Completions | `OPENAI_API_KEY` | `api.openai.com/v1` |
| **DeepSeek R1** | OpenAI Compatible | `DEEPSEEK_API_KEY` | `api.deepseek.com` |
| **WebSearch** | Multiple | Varies | Various |

---

## Additional Providers to Consider

| Provider | API Format | Notes |
|----------|-----------|-------|
| **Moonshot (Kimi)** | OpenAI Compatible | `api.moonshot.cn/v1` |
| **Groq** | OpenAI Compatible | Fast inference |
| **xAI (Grok)** | OpenAI Compatible | `api.x.ai/v1` |
| **Cohere** | Native | Chat/completions |
| **Mistral** | OpenAI Compatible | `api.mistral.ai` |
| **Perplexity** | OpenAI Compatible | Search + chat |
| **OpenRouter** | OpenAI Compatible | Multi-provider gateway |
| **NVIDIA** | OpenAI Compatible | `integrate.api.nvidia.com` |
| **Cerebras** | OpenAI Compatible | Fast inference |
| **HuggingFace** | Native/Compatible | Inference API |

---

## API Format Mapping

### Input Formats (Unified)

```rust
pub enum UnifiedRequest {
    Chat(ChatRequest),      // OpenAI-style chat
    Messages(MessagesRequest), // Anthropic-style messages
    Generate(GenerateRequest), // Text completion
    Search(SearchRequest),  // Web search
}
```

### Output Formats

```rust
pub enum UnifiedResponse {
    Chat(ChatResponse),
    Messages(MessagesResponse),
    Generate(GenerateResponse),
    Search(SearchResponse),
}
```

---

## Conversion Matrix

| From \ To | OpenAI | Anthropic | Gemini | DeepSeek |
|-----------|--------|-----------|--------|----------|
| **OpenAI** | - | OpenAI→Anthropic | OpenAI→Gemini | Direct |
| **Anthropic** | Anthropic→OpenAI | - | Anthropic→Gemini | Anthropic→OpenAI→DeepSeek |
| **Gemini** | Gemini→OpenAI | Gemini→Anthropic | - | Gemini→OpenAI→DeepSeek |
| **DeepSeek** | Direct | DeepSeek→OpenAI→Anthropic | DeepSeek→OpenAI→Gemini | - |

---

## Implementation Plan

### Phase 1: Core Translation Layer

1. **Define unified request/response types**
2. **Implement OpenAI ↔ Anthropic conversion**
3. **Implement OpenAI ↔ Gemini conversion**
4. **Add DeepSeek R1 (OpenAI compatible)**

### Phase 2: WebSearch Integration

1. **Brave Search API**
2. **Tavily API**
3. **Serper API**
4. **Unified search interface**

### Phase 3: Additional Providers

1. **Moonshot/Kimi**
2. **Groq**
3. **xAI/Grok**
4. **Cohere**
5. **Mistral**
6. **Perplexity**
7. **OpenRouter**
8. **NVIDIA**
9. **Cerebras**

### Phase 4: ModelMux Integration

1. **Wire through litebike gates**
2. **Add to ollama_emulator**
3. **Quota-aware routing**
4. **Fallback chains**

---

## API Endpoint Mapping

### Chat Completions

| Provider | Endpoint | Method |
|----------|----------|--------|
| OpenAI | `/v1/chat/completions` | POST |
| Anthropic | `/v1/messages` | POST |
| Gemini | `/v1beta/models/{model}:generateContent` | POST |
| DeepSeek | `/chat/completions` | POST |
| Moonshot | `/v1/chat/completions` | POST |
| Groq | `/openai/v1/chat/completions` | POST |
| xAI | `/v1/chat/completions` | POST |

### Models

| Provider | Endpoint | Method |
|----------|----------|--------|
| OpenAI | `/v1/models` | GET |
| Anthropic | N/A | - |
| Gemini | `/v1beta/models` | GET |
| DeepSeek | `/models` | GET |

---

## Message Format Conversion

### OpenAI Format
```json
{
  "model": "gpt-4",
  "messages": [
    {"role": "system", "content": "You are helpful"},
    {"role": "user", "content": "Hello"},
    {"role": "assistant", "content": "Hi there!"}
  ]
}
```

### Anthropic Format
```json
{
  "model": "claude-3",
  "system": "You are helpful",
  "messages": [
    {"role": "user", "content": "Hello"},
    {"role": "assistant", "content": "Hi there!"}
  ]
}
```

### Gemini Format
```json
{
  "contents": [
    {"role": "user", "parts": [{"text": "Hello"}]},
    {"role": "model", "parts": [{"text": "Hi there!"}]}
  ],
  "systemInstruction": {"parts": [{"text": "You are helpful"}]}
}
```

---

## Key Conversion Challenges

1. **System messages**: Anthropic has separate `system` field, OpenAI/Gemini use messages
2. **Role names**: `assistant` vs `model`, `user` vs `user`
3. **Content structure**: Simple string vs `{parts: [{text: ...}]}`
4. **Streaming**: Different chunk formats
5. **Tool calling**: Different function calling formats
6. **Vision**: Different image input formats
7. **Rate limits**: Different header formats

---

## Success Criteria

- [ ] OpenAI ↔ Anthropic conversion working
- [ ] OpenAI ↔ Gemini conversion working
- [ ] DeepSeek R1 direct passthrough
- [ ] WebSearch unified interface
- [ ] All 10+ providers mapped
- [ ] Integrated with modelmux routing
- [ ] Quota-aware fallback
- [ ] Streaming support for all

---

## Files to Create

| File | Purpose |
|------|---------|
| `literbike/src/api_translation/mod.rs` | Main translation module |
| `literbike/src/api_translation/openai.rs` | OpenAI format |
| `literbike/src/api_translation/anthropic.rs` | Anthropic format |
| `literbike/src/api_translation/gemini.rs` | Gemini format |
| `literbike/src/api_translation/deepseek.rs` | DeepSeek R1 |
| `literbike/src/api_translation/websearch.rs` | Search providers |
| `literbike/src/api_translation/converter.rs` | Conversion logic |
| `litebike/src/gates/nway_gate.rs` | litebike gate integration |

---

## Testing Strategy

1. **Unit tests** for each conversion function
2. **Integration tests** with mock providers
3. **Live tests** with actual API keys
4. **Round-trip tests** (A→B→A should preserve meaning)
