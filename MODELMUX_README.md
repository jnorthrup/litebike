# ModelMux - Model Multiplexer and Proxy Gateway

**OpenAI-compatible model gateway** similar to [Kilo.ai Gateway](https://kilo.ai/docs/gateway).

ModelMux provides a unified API endpoint for accessing multiple LLM providers with:
- **OpenAI-compatible API** - Drop-in replacement for OpenAI SDK
- **Multi-provider routing** - Access 500+ models from 60+ providers
- **DSEL quota management** - Intelligent provider selection based on quotas
- **Model caching** - Fast model discovery and selection
- **BYOK support** - Bring Your Own Key for cost optimization
- **Free tier prioritization** - Auto-route to free models when available

## Quick Start

### 1. Configure API Keys

Copy the example env file and add your API keys:

```bash
cp .env.example .env
```

Edit `.env` and add at least one API key:

```bash
# Free tier providers (recommended)
KILO_API_KEY=your_kilo_api_key_here
MOONSHOT_API_KEY=your_moonshot_api_key_here
DEEPSEEK_API_KEY=your_deepseek_api_key_here

# Paid providers
OPENAI_API_KEY=your_openai_api_key_here
ANTHROPIC_API_KEY=your_anthropic_api_key_here
```

### 2. Start ModelMux Server

```bash
# Start with default port 8889
cargo run --bin modelmux -- --serve

# Or use agent8888 mode on port 8888
cargo run --bin modelmux -- --agent8888

# Load from custom .env file
cargo run --bin modelmux -- --env-file /path/to/.env --serve

# Custom port
cargo run --bin modelmux -- --port 9000 --serve
```

### 3. Use with OpenAI SDK

```typescript
import OpenAI from "openai";

const client = new OpenAI({
  apiKey: "not-needed", // API key validation optional
  baseURL: "http://localhost:8889/v1",
});

const response = await client.chat.completions.create({
  model: "kilo_code/minimax-minimax-m2.5:free",
  messages: [{ role: "user", content: "Hello!" }],
});

console.log(response.choices[0].message.content);
```

### 4. Use with curl

```bash
# List available models
curl http://localhost:8889/v1/models

# Chat completion
curl http://localhost:8889/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "kilo_code/minimax-minimax-m2.5:free",
    "messages": [{"role": "user", "content": "Hello!"}]
  }'

# Health check
curl http://localhost:8889/health
```

## CLI Commands

```bash
# List available models
modelmux --list

# Check health status
modelmux --health

# Show statistics
modelmux --stats

# Clear model cache
modelmux --clear-cache

# Show help
modelmux --help
```

## API Endpoints

### GET /v1/models

List all available models.

**Response:**
```json
{
  "object": "list",
  "data": [
    {
      "id": "kilo_code/minimax-minimax-m2.5:free",
      "object": "model",
      "created": 1234567890,
      "owned_by": "kilo_code"
    }
  ]
}
```

### POST /v1/chat/completions

Create a chat completion (OpenAI-compatible).

**Request:**
```json
{
  "model": "kilo_code/minimax-minimax-m2.5:free",
  "messages": [
    {"role": "system", "content": "You are a helpful assistant."},
    {"role": "user", "content": "Hello!"}
  ],
  "temperature": 0.7,
  "max_tokens": 1000,
  "stream": false
}
```

**Response:**
```json
{
  "id": "chatcmpl-123",
  "object": "chat.completion",
  "created": 1234567890,
  "model": "kilo_code/minimax-minimax-m2.5:free",
  "choices": [{
    "index": 0,
    "message": {
      "role": "assistant",
      "content": "Hello! How can I help you today?"
    },
    "finish_reason": "stop"
  }],
  "usage": {
    "prompt_tokens": 10,
    "completion_tokens": 20,
    "total_tokens": 30
  }
}
```

### GET /health

Health check endpoint.

**Response:**
```json
{
  "status": "healthy",
  "models_cached": 50,
  "providers_available": 5,
  "quota_status": "ok"
}
```

### GET /stats

Server statistics.

**Response:**
```json
{
  "uptime_secs": 3600,
  "models_cached": 50,
  "requests_total": 1000,
  "requests_success": 980,
  "requests_error": 20
}
```

## Model Naming Convention

Models are specified as: `<provider>/<model-name>` or `<provider>/<model-name>:free`

**Examples:**
- `kilo_code/minimax-minimax-m2.5:free` - Free tier via Kilo Gateway
- `moonshot/moonshot-v1-8k` - Moonshot (Kimi) 8K context
- `deepseek/deepseek-coder` - DeepSeek Coder
- `openai/gpt-4o` - OpenAI GPT-4o
- `anthropic/claude-sonnet-4-20250514` - Claude Sonnet 4
- `ollama/llama3.2` - Local Ollama model
- `lmstudio/llama3.2` - Local LMStudio model

## Supported Providers

### Free Tier Providers

| Provider | Models | Context | Notes |
|----------|--------|---------|-------|
| Kilo Gateway | 500+ | Varies | Aggregates free models |
| Moonshot | Kimi K2, V1 | 128K | Chinese LLM |
| DeepSeek | Coder, Chat | 128K | Code-specialized |

### Paid Providers

| Provider | Models | Context | Pricing |
|----------|--------|---------|---------|
| OpenAI | GPT-4o, GPT-4o-mini | 128K | $5-15/1M tokens |
| Anthropic | Claude Sonnet/Opus | 200K | $3-75/1M tokens |
| Google | Gemini Pro/Flash | 128K | $0.25-7/1M tokens |

### Local Providers

| Provider | Models | Notes |
|----------|--------|-------|
| Ollama | Any local model | Requires ollama running |
| LMStudio | Any local model | OpenAI-compatible API |

## DSEL Quota Management

ModelMux uses a **Domain-Specific Expression Language (DSEL)** for intelligent provider selection:

```rust
use litebike::models::{ModelProxy, ProxyConfig};
use litebike::keymux::dsel::DSELBuilder;

// Configure quota-aware provider selection
let dsel = DSELBuilder::new()
    .with_quota("production", 10_000_000)
    .with_free_provider("kilo_code", 1_000_000, 1, 100_000, 3_000_000, 0)
    .with_free_provider("moonshot", 500_000, 2, 50_000, 1_500_000, 0)
    .with_provider("openai", 2_000_000, 3, 5.0, false);

let proxy = ModelProxy::new(ProxyConfig::default());
```

**Features:**
- Priority-based routing (lower priority number = higher preference)
- Free tier prioritization
- Quota tracking per provider
- Automatic fallback on quota exhaustion
- Rate limiting support

## Architecture

```
┌─────────────┐
│   Client    │
│  (OpenAI    │
│    SDK)     │
└──────┬──────┘
       │
       ▼
┌─────────────────────────────────┐
│        ModelMux Gateway         │
│  ┌───────────────────────────┐  │
│  │  OpenAI-Compatible API    │  │
│  │  /v1/chat/completions     │  │
│  │  /v1/models               │  │
│  │  /health                  │  │
│  └───────────┬───────────────┘  │
│              │                   │
│  ┌───────────▼───────────────┐  │
│  │    DSEL Router            │  │
│  │  - Quota Management       │  │
│  │  - Provider Selection     │  │
│  │  - Load Balancing         │  │
│  └───────────┬───────────────┘  │
│              │                   │
│  ┌───────────▼───────────────┐  │
│  │    Model Cache            │  │
│  │  - Model Discovery        │  │
│  │  - Provider Registry      │  │
│  └───────────┬───────────────┘  │
└──────────────┼──────────────────┘
               │
       ┌───────┼───────┬──────────┐
       ▼       ▼       ▼          ▼
   ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐
   │Kilo  │ │Moon- │ │Deep- │ │OpenAI│
   │Gateway│ │shot  │ │ seek │ │      │
   └──────┘ └──────┘ └──────┘ └──────┘
```

## Comparison with Similar Tools

| Feature | ModelMux | Kilo Gateway | Ollama | LMStudio |
|---------|----------|--------------|--------|----------|
| OpenAI-compatible | ✅ | ✅ | ✅ | ✅ |
| Multi-provider | ✅ | ✅ | ❌ | ❌ |
| Free tier routing | ✅ | ✅ | N/A | N/A |
| DSEL quota mgmt | ✅ | ❌ | ❌ | ❌ |
| Model caching | ✅ | ✅ | ❌ | ❌ |
| Local models | ❌ | ❌ | ✅ | ✅ |
| Self-hosted | ✅ | ❌ | ✅ | ✅ |
| Managed service | ❌ | ✅ | ❌ | ❌ |

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `RUST_LOG` | Log level | `info` |
| `MODELmux_DEFAULT_MODEL` | Default model | Auto-select |
| `MODELmux_FALLBACK_MODEL` | Fallback model | None |
| `MODELmux_TIMEOUT` | Request timeout (secs) | 120 |
| `MODELmux_STREAMING` | Enable streaming | true |
| `MODELmux_CACHE` | Enable caching | true |

## Configuration Files

### ~/.modelmux/.env

Alternative location for API keys:

```bash
mkdir -p ~/.modelmux
cp .env ~/.modelmux/.env
```

### ~/.modelmux/cache/

Model cache directory (auto-created).

Clear cache:
```bash
modelmux --clear-cache
# or manually
rm -rf ~/.modelmux/cache
```

## Development

### Build

```bash
cargo build --bin modelmux
```

### Run tests

```bash
cargo test --package litebike -- modelmux
```

### Run with debug logging

```bash
RUST_LOG=debug cargo run --bin modelmux -- --serve
```

## License

AGPL-3.0 (same as LiteBike)

## Related Projects

- [Kilo Gateway](https://kilo.ai/docs/gateway) - Managed model gateway
- [Ollama](https://ollama.ai) - Local LLM runner
- [LMStudio](https://lmstudio.ai) - Local LLM server
- [LiteBike](https://github.com/jnorthrup/litebike) - Parent project

## Contributing

Contributions welcome! Please read the contributing guidelines first.

## Support

- Issues: https://github.com/jnorthrup/litebike/issues
- Documentation: https://kilo.ai/docs/gateway (for API reference)
