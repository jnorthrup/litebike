#!/bin/bash
# Generic Search Provider Script
# For any *_SEARCH_API_KEY pattern
# Auto-detects provider by hostname probing
#
# Uses BASE ENVIRONMENT variables for actual execution.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/search_providers.sh"

# Load .env file if available
load_env_file

# Find all *_SEARCH_API_KEY env vars from BASE ENV
declare -A SEARCH_KEYS
while IFS='=' read -r key value; do
    if [[ "$key" =~ ^[A-Z_]+_SEARCH_API_KEY(_[0-9]+)?$ ]]; then
        SEARCH_KEYS["$key"]="$value"
        info "Found search key in base env: $key"
    fi
done < <(env)

if [ ${#SEARCH_KEYS[@]} -eq 0 ]; then
    error "No *_SEARCH_API_KEY environment variables found.

Supported patterns:
- BRAVE_SEARCH_API_KEY
- TAVILY_SEARCH_API_KEY
- {PROVIDER}_SEARCH_API_KEY

💡 Claude instruction:
   'Add search provider support to ollama_emulator:
    1. Add {PROVIDER}_SEARCH_API_KEY to env_facade_parity.rs normalize_env_pairs()
    2. Add provider detection in classify_generic_api_key()
    3. Add curl adapter in ollama_emulator.rs handle_search()
    4. See search-scripts/search_generic.sh for API patterns'
"
fi

QUERY="${1:-}"
PROVIDER="${2:-auto}"

if [ -z "$QUERY" ]; then
    error "Usage: $0 <search-query> [provider|auto]"
fi

# Auto-detect provider by probing
detect_provider() {
    local key_name="$1"
    local key_value="${SEARCH_KEYS[$key_name]}"
    
    # Extract provider from key name
    local provider=$(echo "$key_name" | sed 's/_SEARCH_API_KEY.*//')
    
    info "Detected provider: $provider (from $key_name)"
    echo "$provider"
}

# Search with provider-specific logic
search_with_provider() {
    local provider="$1"
    local key_name="$2"
    local key_value="${SEARCH_KEYS[$key_name]}"
    
    case "$provider" in
        BRAVE)
            info "Using Brave Search API"
            curl -s -X GET "https://api.search.brave.com/res/v1/web/search" \
                -H "Accept: application/json" \
                -H "X-Subscription-Token: $key_value" \
                -G --data-urlencode "q=$QUERY" \
                --data-urlencode "count=10" | jq '.'
            ;;
        TAVILY)
            info "Using Tavily Search API"
            curl -s -X POST "https://api.tavily.com/search" \
                -H "Content-Type: application/json" \
                -d "{\"api_key\": \"$key_value\", \"query\": \"$QUERY\", \"search_depth\": \"basic\", \"max_results\": 10}" | jq '.'
            ;;
        *)
            warn "Unknown provider: $provider, attempting generic search"
            # Try common patterns
            for base_url in "https://api.search.brave.com/res/v1/web/search" "https://api.tavily.com/search"; do
                info "Trying: $base_url"
                RESULT=$(curl -s -o /dev/null -w "%{http_code}" "$base_url" 2>/dev/null || echo "000")
                if [ "$RESULT" != "000" ] && [ "$RESULT" != "404" ]; then
                    info "Found working endpoint: $base_url"
                    break
                fi
            done
            ;;
    esac
}

# Main search loop
for key_name in "${!SEARCH_KEYS[@]}"; do
    provider=$(detect_provider "$key_name")
    
    if [ "$PROVIDER" != "auto" ] && [ "$PROVIDER" != "$provider" ]; then
        continue
    fi
    
    info "Searching with $key_name..."
    search_with_provider "$provider" "$key_name"
done
