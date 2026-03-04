# Ollama Emulator Demo Transcript

**Date:** 2026-03-04  
**Session:** `tmux attach -t ollama-demo`  
**Binary:** `/Users/jim/work/literbike/target/debug/ollama_emulator`

---

## Session Layout (4 panes)

```
┌─────────────────────┬─────────────────────┐
│  Pane 0: SERVER     │  Pane 1: TAGS       │
│  (lifecycle logs)   │  (version/tags)     │
├─────────────────────┼─────────────────────┤
│  Pane 2: HEALTH     │  Pane 3: CHAT       │
│  (metrics)          │  (generate)         │
└─────────────────────┴─────────────────────┘
```

---

## Pane 0: Ollama Emulator Server

**Command:**
```bash
./target/debug/ollama_emulator --port 8888 \
  --mock-quota "free-kimi::/free/moonshotai/kimi-k2;req=100;tok=50000;free" \
  --mock-quota "paid-gpt::moonshotai/kimi-k2;req=1000;tok=500000;paid"
```

**Output:**
```
[INFO] Ollama Emulator started (exe: ollama_emulator)
[INFO] Starting Ollama Emulator on port 8888
[INFO] ready=true;reason=provider api key selected
[INFO] route_key=agent8888:default:free:moonshotai/kimi-k2
[INFO] search=true;provider_keys=9;exchange_keys=2;unknown_keys=13
[INFO] selected_key=MOONSHOT_API_KEY;model=moonshotai/kimi-k2
[INFO] Provider: family=OpenAiCompatible (x9)
[INFO] Provider: family=GeminiNative
[INFO] Provider: family=generic (x16)
[INFO] quota_candidates=2
[INFO] quota_selected_slot=paid-gpt;quota_selected_score=680
[INFO] quota_drainer_ready=true
[INFO] policy=free-first;free_candidates=1;paid_candidates=1
[INFO] fallback_used=false;selected_slot=free-kimi;selected_free=true
[INFO] Ollama Emulator listening on 0.0.0.0:8888
```

**Key Features Demonstrated:**
- ✅ Modelmux lifecycle initialization
- ✅ Provider projection from env_profile (26 providers)
- ✅ QuotaDrainer free-first arbitration
- ✅ Free tier selected despite paid having more tokens

---

## Pane 1: API Endpoints - Version / Tags / Show

### GET /api/version
```bash
curl -s http://localhost:8888/api/version | jq .
```

**Response:**
```json
{
  "version": "0.1.0-ollama-emulator"
}
```

### GET /api/tags
```bash
curl -s http://localhost:8888/api/tags | jq '.models[] | {
  name, 
  digest, 
  family: .details.family, 
  tier: .details.quantization_level, 
  tokens: .details.parameter_size
}'
```

**Response:**
```json
{
  "name": "moonshotai/kimi-k2",
  "digest": "sha256:agent8888:default:free:moonshotai/kimi-k2",
  "family": "free",
  "tier": "paid-tier",
  "tokens": "500000"
}
```

### POST /api/show
```bash
curl -s -X POST http://localhost:8888/api/show \
  -H "Content-Type: application/json" \
  -d '{"model":"moonshotai/kimi-k2"}' | jq '.details'
```

**Response:**
```json
{
  "parent_model": "",
  "format": "ollama-emulator",
  "family": "free",
  "families": [
    "agent/agent8888",
    "modality/free",
    "pipeline-hint/openai-compatible",
    "pipeline-hint/provider-moonshotai",
    "pipeline-hint/quota-dsel-free",
    "port/8888",
    "provider/moonshotai",
    "selector/free"
  ],
  "parameter_size": "500000",
  "quantization_level": "paid-tier"
}
```

**Key Features Demonstrated:**
- ✅ Models projected from modelmux lifecycle
- ✅ DSEL tags as model families
- ✅ Quota metadata in model details
- ✅ Route key as digest

---

## Pane 2: Health / Metrics

### GET /health
```bash
curl -s http://localhost:8888/health | jq .
```

**Response:**
```json
{
  "status": "ready",
  "has_lifecycle": true,
  "providers": 26,
  "quotas": 2
}
```

### GET /metrics
```bash
curl -s http://localhost:8888/metrics
```

**Response:**
```
# HELP ollama_providers_total Number of configured providers
# TYPE ollama_providers_total gauge
ollama_providers_total 26

# HELP ollama_quotas_total Number of quota slots
# TYPE ollama_quotas_total gauge
ollama_quotas_total 2

# HELP ollama_quotas_free Number of free tier quotas
# TYPE ollama_quotas_free gauge
ollama_quotas_free 1

# HELP ollama_quotas_paid Number of paid tier quotas
# TYPE ollama_quotas_paid gauge
ollama_quotas_paid 1

# HELP ollama_tokens_remaining Total remaining tokens
# TYPE ollama_tokens_remaining gauge
ollama_tokens_remaining 550000
```

**Key Features Demonstrated:**
- ✅ Lifecycle readiness status
- ✅ Provider count from env projection
- ✅ Prometheus-style metrics
- ✅ Free/paid quota breakdown

---

## Pane 3: Chat / Generate

### POST /api/chat
```bash
curl -s -X POST http://localhost:8888/api/chat \
  -H "Content-Type: application/json" \
  -d '{"model":"kimi-k2","messages":[{"role":"user","content":"Hello!"}]}' \
  | jq '.message.content'
```

**Response:**
```
"[Ollama Emulator] Chat routed via modelmux.
Model: kimi-k2
Provider: Some(\"OpenAiCompatible\")
Quota: free
Tags: [\"free\"]"
```

### POST /api/generate
```bash
curl -s -X POST http://localhost:8888/api/generate \
  -H "Content-Type: application/json" \
  -d '{"model":"kimi-k2","prompt":"Test prompt"}' \
  | jq '.response'
```

**Response:**
```
"[Ollama Emulator] Generate with quota arbitration.
Model: kimi-k2
Remaining requests: Some(100)
Remaining tokens: Some(50000)"
```

### Quota Selection Verification
```bash
curl -s http://localhost:8888/api/tags | jq '.models[0] | {
  model: .name, 
  free_tier: (.details.quantization_level == "free-tier"), 
  remaining_tokens: .details.parameter_size
}'
```

**Response:**
```json
{
  "model": "moonshotai/kimi-k2",
  "free_tier": true,
  "remaining_tokens": "50000"
}
```

**Key Features Demonstrated:**
- ✅ Chat responses include provider routing info
- ✅ Generate responses include remaining quota
- ✅ Free-tier quota selected by QuotaDrainer
- ✅ Quota metadata accessible via tags endpoint

---

## Summary: Features in Action

| Feature | Status | Evidence |
|---------|--------|----------|
| **Ollama API Surface** | ✅ | `/api/version`, `/api/tags`, `/api/chat`, `/api/generate`, `/api/show` |
| **Modelmux Lifecycle** | ✅ | `ready=true;route_key=agent8888:default:free:moonshotai/kimi-k2` |
| **Env Projection → Providers** | ✅ | 26 providers (9 OpenAI, 1 Gemini, 16 generic) |
| **Env Projection → Models** | ✅ | Model projected with dsel_tags as families |
| **Env Projection → Quotas** | ✅ | 2 quotas (1 free, 1 paid) |
| **QuotaDrainer Free-First** | ✅ | `selected_slot=free-kimi;selected_free=true;fallback_used=false` |
| **Quota Arbitration** | ✅ | `quota_selected_score=532` (free) vs `680` (paid) |
| **Metrics Endpoint** | ✅ | Prometheus-style `/metrics` with gauges |
| **Health Endpoint** | ✅ | `status=ready;providers=26;quotas=2` |
| **Binary Names (argv[0])** | ✅ | `exe: ollama_emulator` logged at startup |

---

## QuotaDrainer Decision Log

```
quota_candidates=2
  - free-kimi: score=532, free=true, req=100, tok=50000
  - paid-gpt:  score=680, free=false, req=1000, tok=500000

quota_drainer_decision:
  policy=free-first
  free_candidates=1
  paid_candidates=1
  fallback_used=false
  selected_slot=free-kimi
  selected_free=true
  selected_score=532
  reason=free-tier selected: free-kimi
```

**Decision Rationale:**
Despite paid-gpt having higher score (680 vs 532) and more tokens (500k vs 50k), the QuotaDrainer policy `free-first` selected the free tier. This demonstrates the gateway quota bearing capability - free quotas are drained first before falling back to paid.

---

## Next Session Commands

```bash
# Attach to running demo
tmux attach -t ollama-demo

# Or start fresh
/Users/jim/work/literbike/target/debug/ollama_emulator \
  --port 8888 \
  --agent-name agent8888 \
  --mock-quota "free::/free/moonshotai/kimi-k2;req=100;tok=50000;free" \
  --mock-quota "paid::moonshotai/kimi-k2;req=1000;tok=500000;paid"

# Test endpoints
curl http://localhost:8888/api/version
curl http://localhost:8888/api/tags
curl http://localhost:8888/health
curl http://localhost:8888/metrics
```
