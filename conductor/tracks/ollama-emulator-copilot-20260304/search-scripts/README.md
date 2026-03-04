# Search Provider Scripts

Curl-based search scripts for testing and development. Maps `*_SEARCH_API_KEY` patterns to working curl commands.

## Quick Start

```bash
cd conductor/tracks/ollama-emulator-copilot-20260304/search-scripts/

# Brave Search
export BRAVE_SEARCH_API_KEY="your-key"
./search_brave.sh "your query"

# Tavily Search
export TAVILY_SEARCH_API_KEY="your-key"
./search_tavily.sh "your query"

# Auto-detect (tries all configured *_SEARCH_API_KEY vars)
./search_generic.sh "your query" auto
```

## Scripts

| Script | Provider | Env Key | API Format |
|--------|----------|---------|------------|
| `search_brave.sh` | Brave Search | `BRAVE_SEARCH_API_KEY` | GET + Header |
| `search_tavily.sh` | Tavily | `TAVILY_SEARCH_API_KEY` | POST JSON |
| `search_generic.sh` | Auto-detect | `*_SEARCH_API_KEY` | Multi-provider |

## Multi-Key Support

Brave Search supports multiple keys for rotation:

```bash
export BRAVE_SEARCH_API_KEY="primary-key"
export BRAVE_SEARCH_API_KEY_1="backup-key-1"
export BRAVE_SEARCH_API_KEY_2="backup-key-2"

./search_brave.sh "query"
# Automatically tries keys in order on rate limit/failure
```

## Error Messages

Scripts include Claude-assisted error messages:

```
❌ BRAVE_SEARCH_API_KEY not set.

💡 To fix this:
   1. Set the required environment variable
   2. Or run: claude 'Add support for brave search in ollama_emulator'
   3. See: api-env-lookup-table.md
```

## Integration with Ollama Emulator

These scripts serve as:
1. **Testing tools** - Verify API keys work before integrating
2. **Reference implementations** - Copy curl patterns to Rust
3. **Fallback search** - Call from shell when native integration unavailable

### Add Provider to Ollama Emulator (Claude Prompt)

```
'Add <provider> search support to ollama_emulator:

1. In literbike/src/env_facade_parity.rs:
   - Add <PROVIDER>_SEARCH_API_KEY to search key detection
   - Add hostname rule for api.<provider>.com

2. In literbike/src/bin/ollama_emulator.rs:
   - Add handle_search() endpoint
   - Add curl adapter based on search-scripts/search_<provider>.sh

3. Test with:
   curl -X POST http://localhost:8888/api/search \
     -H "Content-Type: application/json" \
     -d "{\"query\": \"test\"}"

See: search-scripts/search_<provider>.sh for API format'
```

## API Patterns

### Brave Search (GET + Header)

```bash
curl -s -X GET "https://api.search.brave.com/res/v1/web/search" \
  -H "Accept: application/json" \
  -H "X-Subscription-Token: $API_KEY" \
  -G --data-urlencode "q=$QUERY"
```

### Tavily Search (POST JSON)

```bash
curl -s -X POST "https://api.tavily.com/search" \
  -H "Content-Type: application/json" \
  -d '{
    "api_key": "$API_KEY",
    "query": "$QUERY",
    "search_depth": "basic",
    "max_results": 10
  }'
```

## Environment Variable Patterns

| Pattern | Purpose | Example |
|---------|---------|---------|
| `{PROVIDER}_SEARCH_API_KEY` | Primary key | `BRAVE_SEARCH_API_KEY` |
| `{PROVIDER}_SEARCH_API_KEY_1` | Backup key 1 | `BRAVE_SEARCH_API_KEY_1` |
| `{PROVIDER}_SEARCH_API_KEY_2` | Backup key 2 | `BRAVE_SEARCH_API_KEY_2` |

## Related Files

- `api-env-lookup-table.md` - Complete env var reference
- `api-host-recognition.md` - Hostname → API_KEY mapping
- `../ollama_emulator.rs` - Rust integration point
