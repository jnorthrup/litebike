# Base Environment Execution

**All scripts and the Ollama emulator use BASE ENVIRONMENT variables for actual execution.**

---

## Environment Loading Order

```
1. Process environment (already exported)
   ↓
2. .env file in current directory (if exists)
   ↓
3. ~/.cc-switch/.env (if exists)
   ↓
4. CLI --env flags (override)
```

---

## Ollama Emulator - Base Env Execution

### Default Behavior (reads from base env)

```bash
# Start with base environment
export OPENAI_API_KEY="sk-..."
export ANTHROPIC_AUTH_TOKEN="sk-ant-..."
export BRAVE_SEARCH_API_KEY="..."

# Emulator reads from base env automatically
ollama_emulator --port 8888
```

### With .env File

```bash
# Create .env in project root
cat > .env << 'EOF'
OPENAI_API_KEY=sk-...
ANTHROPIC_AUTH_TOKEN=sk-ant-...
BRAVE_SEARCH_API_KEY=...
EOF

# Emulator auto-loads .env
ollama_emulator --env-file .env --port 8888
```

### Override Specific Vars

```bash
# Base env provides defaults, CLI overrides specific vars
ollama_emulator \
  --env OPENAI_API_KEY=sk-override \
  --port 8888
```

### Ignore Base Env (Testing)

```bash
# Start with clean slate (no base env)
ollama_emulator \
  --ignore-process-env \
  --env OPENAI_API_KEY=sk-test \
  --port 8888
```

---

## Search Scripts - Base Env Execution

### Brave Search

```bash
# Set in base env
export BRAVE_SEARCH_API_KEY="your-key"

# Script reads from base env
./search-scripts/search_brave.sh "query"
```

### With .env File

```bash
# Add to .env
echo "BRAVE_SEARCH_API_KEY=your-key" >> .env

# Script auto-loads .env
./search-scripts/search_brave.sh "query"
```

### Multi-Key (Base Env)

```bash
# All keys in base env
export BRAVE_SEARCH_API_KEY="primary"
export BRAVE_SEARCH_API_KEY_1="backup1"
export BRAVE_SEARCH_API_KEY_2="backup2"

# Script tries keys in order on failure
./search-scripts/search_brave.sh "query"
```

---

## Code Implementation

### Ollama Emulator (ollama_emulator.rs)

```rust
fn initialize_state(args: &CliArgs) -> (...) {
    // 1. Start with base environment (default)
    let mut merged_env = if args.ignore_process_env {
        BTreeMap::new()
    } else {
        std::env::vars().collect()  // ← BASE ENV
    };

    // 2. Merge .env file (if provided)
    if let Some(path) = args.env_file.as_deref() {
        if let Ok(data) = std::fs::read_to_string(path) {
            for line in data.lines() {
                // Parse and merge
                merged_env.insert(k, v);
            }
        }
    }

    // 3. Apply CLI overrides
    for (k, v) in &args.env_overrides {
        merged_env.insert(k.clone(), v.clone());
    }

    // Use merged_env for lifecycle
    ...
}
```

### Search Scripts (search_brave.sh)

```bash
#!/bin/bash
# Load .env file if available
load_env_file() {
    if [ -f ".env" ]; then
        info "Loading .env file..."
        set -a  # ← Export to base env
        source .env
        set +a
    elif [ -f "$HOME/.cc-switch/.env" ]; then
        info "Loading ~/.cc-switch/.env..."
        set -a
        source "$HOME/.cc-switch/.env"
        set +a
    fi
}

# Read from BASE ENV
API_KEY="${BRAVE_SEARCH_API_KEY:-${BRAVE_SEARCH_API_KEY_1:-}}"

if [ -z "$API_KEY" ]; then
    error "BRAVE_SEARCH_API_KEY not set in base environment."
fi
```

---

## Best Practices

### 1. Use .env for Development

```bash
# Project root .env (gitignored)
OPENAI_API_KEY=sk-dev-...
ANTHROPIC_AUTH_TOKEN=sk-ant-dev-...
BRAVE_SEARCH_API_KEY=brave-dev-...

# Load automatically
ollama_emulator --env-file .env
```

### 2. Use Base Env for Production

```bash
# Systemd service or docker
Environment=OPENAI_API_KEY=sk-prod-...
Environment=ANTHROPIC_AUTH_TOKEN=sk-ant-prod-...

# Or export in shell profile
echo 'export OPENAI_API_KEY=sk-prod-...' >> ~/.bashrc
source ~/.bashrc
```

### 3. Use CLI for Testing

```bash
# Test with mock data
ollama_emulator \
  --ignore-process-env \
  --mock-quota "free::/free/moonshotai/kimi-k2;req=100;tok=50000;free"
```

---

## Environment Variable Reference

### Provider API Keys (Base Env)

```bash
# OpenAI
export OPENAI_API_KEY="sk-..."
export OPENAI_BASE_URL="https://api.openai.com/v1"

# Anthropic
export ANTHROPIC_AUTH_TOKEN="sk-ant-..."
export ANTHROPIC_BASE_URL="https://api.anthropic.com"

# Gemini
export GEMINI_API_KEY="..."
export GOOGLE_GEMINI_BASE_URL="https://generativelanguage.googleapis.com"

# Search
export BRAVE_SEARCH_API_KEY="..."
export TAVILY_SEARCH_API_KEY="..."
```

### Ollama Emulator Specific

```bash
# Optional overrides
export OLLAMA_UNIFIED_PORT=8888
export OLLAMA_AGENT_NAME=agent8888
```

---

## Troubleshooting

### "API Key not set in base environment"

```bash
# Check if var is set
echo $OPENAI_API_KEY

# If empty, set in base env
export OPENAI_API_KEY="sk-..."

# Or check .env file
cat .env | grep OPENAI_API_KEY

# Reload .env
source .env
```

### ".env file not loading"

```bash
# Verify file exists
ls -la .env

# Check format (no spaces around =)
cat .env
# Correct: OPENAI_API_KEY=sk-...
# Wrong: OPENAI_API_KEY = sk-...

# Source manually
set -a && source .env && set +a
```

### "CLI override not working"

```bash
# CLI --env flags override base env
ollama_emulator --env OPENAI_API_KEY=sk-override

# Check order: base env → .env → CLI
echo "Base: $OPENAI_API_KEY"
ollama_emulator --env-file .env --env OPENAI_API_KEY=cli-override
```

---

## Files Using Base Env

| File | Reads Base Env | Loads .env |
|------|---------------|------------|
| `ollama_emulator.rs` | ✅ (default) | ✅ (--env-file) |
| `search_brave.sh` | ✅ | ✅ (auto) |
| `search_tavily.sh` | ✅ | ✅ (auto) |
| `search_generic.sh` | ✅ | ✅ (auto) |

---

## Related Files

- `api-env-lookup-table.md` - Complete env var reference
- `api-host-recognition.md` - Hostname → API_KEY mapping
- `search-scripts/README.md` - Search script usage
