# Ollama Emulator for Copilot Models

## Overview

Build and ship an Ollama API-compatible emulator/wrapper that runs through literbike's modelmux infrastructure, exposed via litebike's 888agent on port 8888. This is the **only nexus to copilot models** and **first priority** for enabling gateway quota arbitration across all providers.

## Problem

- No unified Ollama-compatible surface for copilot model access
- Gateway quotas across providers are not being leveraged
- Need a central mux point that can route to multiple backends while exposing Ollama API surface

## Goals

1. Expose Ollama-compatible API surface (`/api/generate`, `/api/chat`, `/api/tags`, `/api/show`)
2. Route requests through literbike modelmux with quota arbitration
3. Support multiple backend providers (OpenAI-compatible, Anthropic, Gemini, Ollama local/remote)
4. Enable QuotaDrainer-style free-tier-first arbitration across all provider quotas
5. Run on port 8888 as litebike 888agent

## Functional Requirements

1. **Ollama API Surface**
   - `POST /api/generate` - completion endpoint
   - `POST /api/chat` - chat completion endpoint
   - `GET /api/tags` - list available models
   - `POST /api/show` - show model info
   - `GET /api/version` - version endpoint

2. **Backend Routing**
   - Translate Ollama requests to OpenAI-compatible backends
   - Translate Ollama requests to Anthropic-compatible backends
   - Translate Ollama requests to Gemini-native backends
   - Direct passthrough to Ollama backends (local or remote)

3. **Quota Integration**
   - Consume quota inventory from multiple adapters (LiteLLM, cc-switch SQLite, static mocks, provider APIs)
   - Apply QuotaDrainer policy: free-tier-first, paid fallback
   - Track requests, tokens, cost per provider
   - Enforce minima thresholds before selection

4. **Model Mux Integration**
   - Use literbike `model_serving_taxonomy` for provider classification
   - Use `provider_facade_models` for env recognition and routing
   - Apply `FacadeV1Matrix` route selection
   - Support OAuth and pubkey grant resolution

5. **888agent Integration**
   - Listen on port 8888 by default
   - Agent name: `agent8888`
   - Support unified-port config via CLI or env

## Architecture

```
┌─────────────────┐
│   Ollama CLI    │
│   HTTP Client   │
└────────┬────────┘
         │ Ollama API
         ▼
┌─────────────────────────────────────────┐
│   Ollama Emulator (literbike)           │
│   ┌─────────────────────────────────┐   │
│   │  Ollama API Surface             │   │
│   │  /api/generate, /api/chat, ...  │   │
│   └────────────┬────────────────────┘   │
│                │                         │
│   ┌────────────▼────────────────────┐   │
│   │  Model Mux Lifecycle            │   │
│   │  - Env normalization            │   │
│   │  - Route resolution             │   │
│   │  - Provider key selection       │   │
│   │  - Readiness probes             │   │
│   └────────────┬────────────────────┘   │
│                │                         │
│   ┌────────────▼────────────────────┐   │
│   │  Quota Arbitration              │   │
│   │  - Discover quota inventory     │   │
│   │  - Score candidates             │   │
│   │  - Select (free-first)          │   │
│   │  - Fallback policy              │   │
│   └────────────┬────────────────────┘   │
└─────────────────┼───────────────────────┘
                  │
    ┌─────────────┼─────────────┐
    │             │             │
    ▼             ▼             ▼
┌─────────┐ ┌─────────┐ ┌─────────┐
│ OpenAI  │ │Anthropic│ │ Gemini  │
│ Compat  │ │ Native  │ │ Native  │
└─────────┘ └─────────┘ └─────────┘
```

## Acceptance Criteria

- [ ] `cargo build --bin ollama_emulator` succeeds in literbike
- [ ] Ollama emulator listens on port 8888
- [ ] `GET /api/tags` returns models from configured backends
- [ ] `POST /api/chat` routes to backend with quota arbitration
- [ ] QuotaDrainer free-first policy is enforced
- [ ] Multiple provider backends can be configured via env
- [ ] `cargo test ollama_emulator --quiet` passes in literbike
- [ ] End-to-end smoke test with mock quota adapters passes

## Out of Scope

- Full Ollama embedding API (can be added later)
- Ollama pull/push model management
- Streaming responses (can be added later)
- Vision/multimodal endpoints (can be added later)

## Files

- `literbike/src/bin/ollama_emulator.rs` - Main binary
- `literbike/src/ollama_adapter.rs` - Ollama API surface + translation layer
- `literbike/src/env_facade_parity.rs` - Extend with Ollama-specific quota adapters
- `literbike/src/provider_facade_models.rs` - Add Ollama provider facade object model
- `litebike/src/ollama_gate.rs` - Optional: litebike gate integration

## Validation Commands

```bash
# Build
cd /Users/jim/work/literbike
cargo build --bin ollama_emulator

# Test
cargo test ollama_emulator --quiet

# Run with mock quota
./target/debug/ollama_emulator \
  --port 8888 \
  --agent-name agent8888 \
  --env-file .env \
  --mock-quota "free::/free/moonshotai/kimi-k2;req=100;tok=50000;free" \
  --mock-quota "paid::moonshotai/kimi-k2;req=1000;tok=500000;paid"

# Smoke test
curl http://localhost:8888/api/tags
curl -X POST http://localhost:8888/api/chat \
  -H "Content-Type: application/json" \
  -d '{"model":"kimi-k2","messages":[{"role":"user","content":"hello"}]}'
```
