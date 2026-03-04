#!/bin/bash
# Tavily Search Provider Script
# Env: TAVILY_SEARCH_API_KEY or TAVILY_SEARCH_API_KEY_1
# Docs: https://tavily.com/
#
# Uses BASE ENVIRONMENT variables for actual execution.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/search_providers.sh"

# Load .env file if available
load_env_file

# Read from base env
API_KEY="${TAVILY_SEARCH_API_KEY:-${TAVILY_SEARCH_API_KEY_1:-}}"

if [ -z "$API_KEY" ]; then
    error "TAVILY_SEARCH_API_KEY" "TAVILY_SEARCH_API_KEY not set in base environment.

To configure Tavily Search:
1. Get API key: https://app.tavily.com/
2. Export in base env: export TAVILY_SEARCH_API_KEY='your-key-here'
3. Or add to .env file in project root or ~/.cc-switch/.env

💡 Claude instruction:
   'Add Tavily Search support to ollama_emulator:
    - Add TAVILY_SEARCH_API_KEY to provider_facade_models.rs
    - Add POST /search endpoint adapter
    - See search-scripts/search_tavily.sh for API format'
"
fi

QUERY="${1:-}"
if [ -z "$QUERY" ]; then
    error "Usage: $0 <search-query>"
fi

info "Tavily Search"
info "Query: $QUERY"

# Tavily uses POST with JSON body
RESPONSE=$(curl -s -X POST "https://api.tavily.com/search" \
    -H "Content-Type: application/json" \
    -d "{
        \"api_key\": \"$API_KEY\",
        \"query\": \"$QUERY\",
        \"search_depth\": \"basic\",
        \"include_answer\": true,
        \"include_raw_content\": false,
        \"max_results\": 10
    }")

if echo "$RESPONSE" | grep -q '"detail"'; then
    error "Tavily API error: $(echo "$RESPONSE" | jq -r '.detail')"
fi

echo "$RESPONSE" | jq '.'
info "Search successful"
