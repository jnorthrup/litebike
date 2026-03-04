# Model Muxer Demo - tmux Session

**Session:** `modelmux`  
**URL:** http://localhost:8888  
**Attach:** `tmux attach -t modelmux`

---

## Session Layout (4 Panes)

```
┌─────────────────────┬─────────────────────┐
│  Pane 0: SERVER     │  Pane 1: DISCOVERY  │
│  (ollama_emulator)  │  (version/tags)     │
│  Port: 8888         │  /api/version       │
│                     │  /api/tags          │
│                     │  /api/show          │
├─────────────────────┼─────────────────────┤
│  Pane 2: HEALTH     │  Pane 3: CHAT       │
│  (metrics)          │  (generate)         │
│  /health            │  /api/chat          │
│  /metrics           │  /api/generate      │
└─────────────────────┴─────────────────────┘
```

---

## Pane Contents

### Pane 0: Ollama Emulator Server

**Command:**
```bash
./target/debug/ollama_emulator \
  --port 8888 \
  --mock-quota "free-kimi::/free/moonshotai/kimi-k2;req=100;tok=50000;free" \
  --mock-quota "paid-gpt::moonshotai/kimi-k2;req=1000;tok=500000;paid"
```

**Output:**
```
[INFO] Ollama Emulator started (exe: ollama_emulator)
[INFO] Starting Ollama Emulator on port 8888
[INFO] ready=true;reason=provider api key selected
[INFO] route_key=agent8888:default:free:moonshotai/kimi-k2
[INFO] quota_candidates=2
[INFO] quota_selected_slot=paid-gpt;quota_selected_score=680
[INFO] quota_drainer_ready=true
[INFO] policy=free-first;free_candidates=1;paid_candidates=1
[INFO] fallback_used=false;selected_slot=free-kimi;selected_free=true
[INFO] Ollama Emulator listening on 0.0.0.0:8888
```

---

### Pane 1: API Discovery

**Commands:**
```bash
curl -s http://localhost:8888/api/version | jq .
curl -s http://localhost:8888/api/tags | jq '.models[] | {name, family, tier}'
curl -s -X POST http://localhost:8888/api/show \
  -H "Content-Type: application/json" \
  -d '{"model":"moonshotai/kimi-k2"}' | jq '.details'
```

**Response - /api/version:**
```json
{
  "version": "0.1.0-ollama-emulator"
}
```

**Response - /api/tags:**
```json
{
  "name": "moonshotai/kimi-k2",
  "family": "free",
  "tier": "paid-tier",
  "tokens": "500000"
}
```

**Response - /api/show:**
```json
{
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

---

### Pane 2: Health & Metrics

**Commands:**
```bash
curl -s http://localhost:8888/health | jq .
curl -s http://localhost:8888/metrics
```

**Response - /health:**
```json
{
  "status": "ready",
  "has_lifecycle": true,
  "providers": 26,
  "quotas": 2
}
```

**Response - /metrics:**
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

---

### Pane 3: Chat & Generate

**Commands:**
```bash
# Chat
curl -s -X POST http://localhost:8888/api/chat \
  -H "Content-Type: application/json" \
  -d '{"model":"kimi-k2","messages":[{"role":"user","content":"hello"}]}' | jq .

# Generate
curl -s -X POST http://localhost:8888/api/generate \
  -H "Content-Type: application/json" \
  -d '{"model":"kimi-k2","prompt":"Test"}' | jq .
```

**Response - /api/chat:**
```json
{
  "model": "moonshotai/kimi-k2",
  "message": {
    "content": "[Ollama Emulator] Chat routed via modelmux.\nModel: kimi-k2\nProvider: Some(\"OpenAiCompatible\")\nQuota: free\nTags: [\"free\"]"
  },
  "done": true
}
```

**Response - /api/generate:**
```json
{
  "model": "moonshotai/kimi-k2",
  "response": "[Ollama Emulator] Generate with quota arbitration.\nModel: kimi-k2\nRemaining requests: Some(1000)\nRemaining tokens: Some(500000)"
}
```

---

## Key Features Demonstrated

| Feature | Evidence |
|---------|----------|
| **Ollama API Surface** | `/api/version`, `/api/tags`, `/api/chat`, `/api/generate`, `/api/show` |
| **Modelmux Lifecycle** | `ready=true;route_key=agent8888:default:free:moonshotai/kimi-k2` |
| **Provider Projection** | 26 providers from env_profile |
| **Quota Projection** | 2 quotas (1 free, 1 paid) |
| **QuotaDrainer Free-First** | `selected_slot=free-kimi;selected_free=true;fallback_used=false` |
| **Metrics Endpoint** | Prometheus-style `/metrics` with gauges |
| **Health Endpoint** | `status=ready;providers=26;quotas=2` |

---

## QuotaDrainer Decision

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
  reason=free-tier selected: free-kimi
```

**Decision Rationale:**
Despite paid-gpt having higher score (680 vs 532) and more tokens (500k vs 50k), the QuotaDrainer policy `free-first` selected the free tier. This demonstrates **gateway quota bearing** - free quotas are drained first before falling back to paid.

---

## Quick Commands

```bash
# Attach to demo
tmux attach -t modelmux

# Test endpoints manually
curl http://localhost:8888/api/version
curl http://localhost:8888/api/tags
curl http://localhost:8888/health
curl http://localhost:8888/metrics

# Stop server
tmux send-keys -t modelmux:0.0 'C-c'

# Kill session
tmux kill-session -t modelmux
```

---

## Related Files

- `conductor/tracks/ollama-emulator-copilot-20260304/demo-transcript.md` - Previous demo transcript
- `conductor/tracks/ollama-emulator-copilot-20260304/BASE_ENV_EXECUTION.md` - Base env documentation
- `conductor/tracks/ollama-emulator-copilot-20260304/api-host-recognition.md` - API host mapping
- `conductor/tracks/ollama-emulator-copilot-20260304/search-scripts/` - Search provider scripts
