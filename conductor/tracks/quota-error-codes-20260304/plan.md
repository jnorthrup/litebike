# Quota Countdown Error Codes Investigation

**Created:** 2026-03-04  
**Goal:** Find error codes that contain quota countdown information

---

## Hypothesis

API error responses may contain useful quota information:
- Remaining tokens
- Remaining requests  
- Reset timestamps
- Rate limit headers
- Billing tier info

---

## Target Providers

| Provider | Error Format | Quota Info Expected |
|----------|--------------|---------------------|
| OpenAI | JSON error object | remaining_tokens, reset_time |
| DeepSeek | JSON error | quota_remaining |
| Groq | JSON error | rate_limit_remaining |
| xAI | JSON error | quota info |
| OpenRouter | JSON error | credits_remaining |
| NVIDIA | JSON error | tokens_remaining |

---

## Investigation Plan

1. **Capture error responses** from exhausted providers
2. **Parse error objects** for quota fields
3. **Check HTTP headers** for rate limit info
4. **Document quota countdown patterns**
5. **Implement quota tracking** in ollama_emulator

---

## Test Cases

### OpenAI (Known Exhausted)
```bash
curl -v https://api.openai.com/v1/chat/completions \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}],"max_tokens":1}'
```

Expected: Error with quota info

### Groq (Access Denied)
```bash
curl -v https://api.groq.com/openai/v1/chat/completions \
  -H "Authorization: Bearer $GROQ_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"llama-3.1-8b-instant","messages":[{"role":"user","content":"hi"}],"max_tokens":1}'
```

Expected: Error with network/rate info

---

## Quota Header Patterns

Common HTTP headers for rate limits:

```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 500
X-RateLimit-Reset: 1709568000
Retry-After: 3600
```

---

## Error Object Patterns

### OpenAI Style
```json
{
  "error": {
    "message": "You exceeded your current quota...",
    "type": "insufficient_quota",
    "param": null,
    "code": "insufficient_quota"
  }
}
```

### OpenRouter Style
```json
{
  "error": {
    "message": "Insufficient credits",
    "code": "insufficient_credits",
    "credits_remaining": 0.001
  }
}
```

---

## Deliverables

1. **Error code catalog** - All quota-related error codes
2. **Header patterns** - Rate limit HTTP headers
3. **Quota extraction** - Parse remaining quota from errors
4. **Integration** - Add to ollama_emulator /health endpoint

---

## Success Criteria

- [ ] Documented error codes for 6+ providers
- [ ] Extracted quota countdown info from errors
- [ ] Implemented in ollama_emulator
- [ ] /health shows per-provider quota status
