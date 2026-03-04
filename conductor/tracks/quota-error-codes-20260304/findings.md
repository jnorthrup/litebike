# Quota Error Code Findings

**Date:** 2026-03-04  
**Status:** Initial findings

---

## Key Discovery: OpenRouter Usage Details

OpenRouter returns **detailed usage/cost info** in successful responses:

```json
{
  "usage": {
    "prompt_tokens": 8,
    "completion_tokens": 1,
    "total_tokens": 9,
    "cost": 0.0000018,
    "is_byok": false,
    "prompt_tokens_details": {
      "cached_tokens": 0,
      "cache_write_tokens": 0,
      "audio_tokens": 0,
      "video_tokens": 0
    },
    "cost_details": {
      "upstream_inference_cost": 0.0000018,
      "upstream_inference_prompt_cost": 0.0000012,
      "upstream_inference_completions_cost": 6e-7
    }
  }
}
```

**This is a quota countdown!** Shows:
- Tokens used per request
- Cost in USD
- Breakdown by prompt/completion
- Cache usage

---

## OpenAI Error (429 - Insufficient Quota)

**HTTP Status:** `429 Too Many Requests`

**Error Object:**
```json
{
  "error": {
    "message": "You exceeded your current quota...",
    "type": "insufficient_quota",
    "code": "insufficient_quota"
  }
}
```

**Headers:**
```
HTTP/2 429
content-type: application/json
x-request-id: req_c18b9de0de9041529a4e8f3778bbf877
```

**Missing:** No quota countdown info in error (just says "exceeded")

---

## Groq Error (403 - Access Denied)

**HTTP Status:** `403 Forbidden`

**Error Object:**
```json
{
  "error": {
    "message": "Access denied. Please check your network settings."
  }
}
```

**Headers:**
```
HTTP/2 403
cache-control: private, max-age=0, no-store, no-cache
```

**Note:** Not a quota error - network/access issue

---

## Rate Limit Header Patterns (NOT FOUND)

Expected headers that were **NOT** present:

```
X-RateLimit-Limit: ???
X-RateLimit-Remaining: ???
X-RateLimit-Reset: ???
Retry-After: ???
```

None of the tested providers return standard rate limit headers.

---

## Actionable Findings

### 1. OpenRouter - Full Usage Tracking

OpenRouter provides complete quota tracking in response body:
- Parse `usage.cost` for dollar amount spent
- Parse `usage.total_tokens` for token count
- Track cumulative usage per API key

### 2. OpenAI - Error Code Only

OpenAI only indicates quota exceeded, no countdown:
- Error code `insufficient_quota` = no quota remaining
- No reset time provided
- Must check dashboard for quota details

### 3. Missing: Quota Headers

No providers return standard quota headers. Must:
- Parse response body for usage info
- Track locally between requests
- Use provider dashboards for quota limits

---

## Next Steps

1. **Test more providers** for quota info in errors
2. **Check OpenRouter credits endpoint** for remaining balance
3. **Implement usage tracking** in ollama_emulator
4. **Add /quota endpoint** showing per-provider usage

---

## Provider Quota Info Summary

| Provider | Success Response | Error Response | Headers |
|----------|-----------------|----------------|---------|
| OpenAI | Usage tokens | `insufficient_quota` | None |
| OpenRouter | Usage + cost | Unknown | None |
| Groq | Unknown | `Access denied` | None |
| DeepSeek | Unknown | Unknown | None |
| NVIDIA | Unknown | Unknown | None |
| xAI | Unknown | Unknown | None |

---

## Implementation: Quota Tracking (2026-03-04)

**Implemented in ollama_emulator:**

### Endpoints

```bash
GET /health
{
  "status": "ready",
  "providers": 12,
  "total_tokens": 0,
  "total_cost_usd": 0.0
}

GET /quota
{
  "object": "quota",
  "total_tokens": 0,
  "total_cost_usd": 0.0,
  "providers": [
    {"id": "openai", "tokens": 0, "cost_usd": 0.0, "requests": 0},
    {"id": "openrouter", "tokens": 0, "cost_usd": 0.0, "requests": 0},
    ...
  ]
}
```

### How It Works

1. **Startup:** Scan env for `XXXXX_API_KEY` patterns
2. **Per-provider tracking:** tokens, cost, request_count
3. **On response:** Parse `usage` object from provider response
4. **Aggregate:** Sum across all providers for totals

### Providers Tracked

| Provider | Env Var | Base URL |
|----------|---------|----------|
| openai | OPENAI_API_KEY | api.openai.com |
| groq | GROQ_API_KEY | api.groq.com |
| deepseek | DEEPSEEK_API_KEY | api.deepseek.com |
| moonshot | MOONSHOT_API_KEY | api.moonshot.cn |
| xai | XAI_API_KEY | api.x.ai |
| perplexity | PERPLEXITY_API_KEY | api.perplexity.ai |
| openrouter | OPENROUTER_API_KEY | openrouter.ai |
| nvidia | NVIDIA_API_KEY | integrate.api.nvidia.com |
| cerebras | CEREBRAS_API_KEY | api.cerebras.ai |
| huggingface | HUGGINGFACE_API_KEY | api-inference.huggingface.co |
| kilo | KILO_API_KEY | api.kilo.ai |
| kilocode | KILOCODE_API_KEY | api.kilocode.ai |


---

## RBCursive Precompile Tests (2026-03-04)

**All 53 rbcursive tests passing:**
- 7 combinator tests
- 3 continuation tests  
- 10 pattern tests
- 22 protocol tests (HTTP, JSON, SOCKS5)
- 11 SIMD/scanner tests

**Precompile module added:**
- `literbike/src/rbcursive/precompile.rs`
- 7 new tests for port 8888 protocol detection
- All protocols baked at compile time:
  - Ollama: /api/generate, /api/chat, /api/tags, /api/show
  - OpenAI: /v1/chat/completions, /v1/models
  - Anthropic: /v1/messages
  - Health: /health, /metrics
  - HTTP: GET, POST, PUT, DELETE

**Test command:**
```bash
cd /Users/jim/work/literbike
cargo test --lib precompile  # 7 tests pass
cargo test --lib rbcursive   # 53 tests pass
```

---

## KeyMux and ModelMux Binaries

**Created:**
- `litebike/src/bin/keymux.rs` - Private keystore manager
- `litebike/src/bin/modelmux.rs` - Model multiplexer

**KeyMux features:**
- Load API keys from env, .env file, or JSON keystore
- Commands: list, show, export, init
- Secure file permissions (0o600)
- Binary names: keymux, agent8888

**ModelMux features:**
- Free-first quota policy
- HTTP server on port 8888 (agent8888 mode) or 8889
- Endpoints: /v1/models, /health, /quota
- Binary names: modelmux, agent8888, ollama

**Note:** macOS linking blocked by SDK sysroot issue (not code issue)

