# N-Way API Conversion Layer

**Created:** 2026-03-04  
**Updated:** 2026-03-11  
**Status:** Phase 3 provider scaffolding extended (88%)  
**Goal:** Unified API translation between all major AI providers, with quota-aware provider surfaces in `litebike`

---

## Implementation Status

### Phase 1: Core Translation Layer ✅ COMPLETE

- [x] Define unified request/response types
- [x] Implement OpenAI ↔ Anthropic conversion
- [x] Implement OpenAI ↔ Gemini conversion
- [x] Add DeepSeek R1 (OpenAI compatible)
- [x] Create all module files (9/9 complete)
- [x] Build successful
- [x] 228 tests passing

### Phase 2: WebSearch Integration ✅ COMPLETE

- [x] Brave Search API
- [x] Tavily API
- [x] Serper API
- [x] Unified search interface

### Phase 3: Additional Providers 🔄 IN PROGRESS

- [x] Moonshot/Kimi (`litebike` keymux token-ledger + DSEL parity)
- [x] Groq (`litebike` keymux token-ledger + DSEL parity)
- [x] xAI/Grok + Cerebras (`litebike` keymux DSEL quota scaffolding)
- [ ] xAI/Grok (full token-ledger/API-check parity)
- [ ] Cohere
- [ ] Mistral
- [ ] Perplexity
- [ ] OpenRouter
- [ ] NVIDIA
- [ ] Cerebras (full token-ledger/API-check parity)
- [ ] HuggingFace

Phase 3 is now started in `litebike`: Moonshot/Kimi and Groq have provider-config structs, token-ledger initialization, API-status checks, and quota-estimation defaults in `src/keymux/dsel.rs` and `src/keymux/token_ledger.rs`. This slice extends `src/keymux/dsel.rs` with xAI/Grok and Cerebras provider-config structs plus DSEL quota initialization/reset defaults, but the matching token-ledger/API-check work for those two providers is still pending in `src/keymux/token_ledger.rs`. Full request/response translation remains pending for the rest of the provider matrix.

### Phase 4: ModelMux Integration 🔄 PENDING

- [ ] Wire through litebike gates
- [ ] Add to ollama_emulator (partially complete)
- [ ] Quota-aware routing
- [ ] Fallback chains

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

1. **Moonshot/Kimi** - quota/DSEL parity landed in `litebike`; full translation work remains
2. **Groq** - quota/DSEL parity landed in `litebike`; full translation work remains
3. **xAI/Grok** - DSEL quota scaffolding landed in `litebike`; full token-ledger/API-check parity remains
4. **Cohere**
5. **Mistral**
6. **Perplexity**
7. **OpenRouter**
8. **NVIDIA**
9. **Cerebras** - DSEL quota scaffolding landed in `litebike`; full token-ledger/API-check parity remains

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
