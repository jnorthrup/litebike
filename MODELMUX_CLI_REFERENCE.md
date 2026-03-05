# ModelMux CLI Reference

## Overview

ModelMux provides a **Rust CLI** (`modelmux-cli`) for launching and managing the model proxy gateway.

---

## Quick Start

```bash
# Build CLI
cargo build --bin modelmux-cli

# Start server
cargo run --bin modelmux-cli -- start

# Or use the compiled binary
./target/debug/modelmux-cli start
```

---

## Commands

### Server Management

#### `start` - Start ModelMux server

```bash
cargo run --bin modelmux-cli -- start [OPTIONS]
```

**Options:**
- `-p, --port <PORT>` - Port to bind (default: 8889)
- `-h, --host <HOST>` - Host to bind (default: 0.0.0.0)
- `-e, --env <FILE>` - Environment file (default: .env)
- `-l, --log <LEVEL>` - Log level (default: info)
- `-d, --daemon` - Run in background
- `--agent8888` - Run as agent8888 on port 8888

**Examples:**
```bash
# Start with defaults
cargo run --bin modelmux-cli -- start

# Start on port 9000
cargo run --bin modelmux-cli -- start -p 9000

# Start in background with custom env
cargo run --bin modelmux-cli -- start -e prod.env -d

# Run as agent8888
cargo run --bin modelmux-cli -- start --agent8888
```

#### `stop` - Stop running ModelMux instance

```bash
cargo run --bin modelmux-cli -- stop
```

#### `restart` - Restart ModelMux server

```bash
cargo run --bin modelmux-cli -- restart [OPTIONS]
```

#### `status` - Check if ModelMux is running

```bash
cargo run --bin modelmux-cli -- status
```

**Output:**
```
✓ ModelMux is running
   Port: 8889
   PID:  12345
   Health: OK
```

---

### Testing & Debugging

#### `test` - Test ModelMux endpoints

```bash
cargo run --bin modelmux-cli -- test
```

**Output:**
```
🧪 Testing ModelMux endpoints...

Health check... ✓ OK
Models endpoint... ✓ OK (50 models)
Stats endpoint... ✓ OK

Sample model list:
  • kilo_code/minimax-minimax-m2.5:free (kilo_code)
  • moonshot/moonshot-v1-8k (moonshot)
  • deepseek/deepseek-coder (deepseek)
```

#### `logs` - View ModelMux logs

```bash
cargo run --bin modelmux-cli -- logs -n 50
```

**Options:**
- `-n, --lines <LINES>` - Number of lines (default: 50)

---

### Model Operations

#### `models` - List available models

```bash
cargo run --bin modelmux-cli -- models
```

**Output:**
```
Available models:
  kilo_code/minimax-minimax-m2.5:free (kilo_code)
  moonshot/moonshot-v1-8k (moonshot)
  deepseek/deepseek-coder (deepseek)
  openai/gpt-4o (openai)
  anthropic/claude-sonnet-4-20250514 (anthropic)
```

#### `chat` - Interactive chat with a model

```bash
cargo run --bin modelmux-cli -- chat [OPTIONS]
```

**Options:**
- `-m, --model <MODEL>` - Model to use (default: kilo_code/minimax-minimax-m2.5:free)
- `-s, --system <PROMPT>` - System prompt (default: "You are a helpful assistant.")

**Example:**
```bash
cargo run --bin modelmux-cli -- chat -m "moonshot/moonshot-v1-32k" -s "You are a coding assistant."
```

**Session:**
```
💬 Interactive Chat
   Model: moonshot/moonshot-v1-32k
   Type 'quit' or 'exit' to stop

You: Write a Python function to reverse a string
Assistant: def reverse_string(s):
    return s[::-1]

You: Thanks!
Assistant: You're welcome!

You: quit
Goodbye!
```

---

### Configuration

#### `config` - Show current configuration

```bash
cargo run --bin modelmux-cli -- config
```

**Output:**
```
ModelMux Configuration:

  MODELMUX_PORT:     8889
  MODELMUX_HOST:     0.0.0.0
  MODELMUX_LOG_LEVEL: info

Environment Variables:
  KILO_API_KEY = ***hidden***
  MOONSHOT_API_KEY = ***hidden***
  OPENAI_BASE_URL = https://api.openai.com/v1
```

#### `env` - Manage environment files

```bash
cargo run --bin modelmux-cli -- env <ACTION>
```

**Actions:**

`list` - List environment files and variables
```bash
cargo run --bin modelmux-cli -- env list
```

`create` - Create .env file from example
```bash
cargo run --bin modelmux-cli -- env create
```

`check` - Check configured API keys
```bash
cargo run --bin modelmux-cli -- env check
```

**Output:**
```
Checking environment configuration...
  ✓ KILO_API_KEY
  ✓ MOONSHOT_API_KEY
  ○ DEEPSEEK_API_KEY (not set)
  ○ OPENAI_API_KEY (not set)
  ○ ANTHROPIC_API_KEY (not set)

✓ Found 2 API key(s)
```

#### `cache` - Manage model cache

```bash
cargo run --bin modelmux-cli -- cache <ACTION>
```

**Actions:**

`status` - Show cache status
```bash
cargo run --bin modelmux-cli -- cache status
```

`clear` - Clear cache
```bash
cargo run --bin modelmux-cli -- cache clear
```

`show` - Show cache files
```bash
cargo run --bin modelmux-cli -- cache show
```

---

## Command Summary

| Command | Description |
|---------|-------------|
| `start` | Start server |
| `stop` | Stop server |
| `restart` | Restart server |
| `status` | Check status |
| `logs` | View logs |
| `test` | Test endpoints |
| `models` | List models |
| `chat` | Interactive chat |
| `config` | Show config |
| `env` | Manage env files |
| `cache` | Manage cache |

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MODELMUX_PORT` | 8889 | Default port |
| `MODELMUX_HOST` | 0.0.0.0 | Default host |
| `MODELMUX_LOG_LEVEL` | info | Default log level |

---

## Typical Workflows

### Development Workflow
```bash
# 1. Set up environment
cargo run --bin modelmux-cli -- env create
# Edit .env and add API keys

# 2. Verify configuration
cargo run --bin modelmux-cli -- env check

# 3. Start server
cargo run --bin modelmux-cli -- start

# 4. Test endpoints
cargo run --bin modelmux-cli -- test

# 5. Chat with models
cargo run --bin modelmux-cli -- chat -m "kilo_code/minimax-minimax-m2.5:free"
```

### Production Workflow
```bash
# 1. Start in background
cargo run --bin modelmux-cli -- start -e prod.env -d

# 2. Check status
cargo run --bin modelmux-cli -- status

# 3. Monitor logs
cargo run --bin modelmux-cli -- logs -n 100

# 4. Restart when needed
cargo run --bin modelmux-cli -- restart -e prod.env
```

---

## Installation

### Build Release Version
```bash
cargo build --release --bin modelmux-cli
```

### Install to Cargo Bin
```bash
cp target/release/modelmux-cli ~/.cargo/bin/modelmux
```

---

## Troubleshooting

### Port Already in Use
```bash
# Check what's using the port
lsof -i :8889

# Kill the process
kill -9 <PID>

# Or use a different port
cargo run --bin modelmux-cli -- start -p 9000
```

### No API Keys Configured
```bash
# Check configuration
cargo run --bin modelmux-cli -- env check

# Create .env file
cargo run --bin modelmux-cli -- env create
```

### Server Won't Start
```bash
# Check logs
cargo run --bin modelmux-cli -- logs

# Try with debug logging
cargo run --bin modelmux-cli -- start -l debug
```

---

## Help

```bash
cargo run --bin modelmux-cli -- --help
```

---

## See Also

- [MODELMUX_README.md](./MODELMUX_README.md) - Full ModelMux documentation
- [.env.example](./.env.example) - Example environment configuration
- [KILO_ADVANTAGES_FOR_MODELMUX.md](./KILO_ADVANTAGES_FOR_MODELMUX.md) - Architecture analysis
