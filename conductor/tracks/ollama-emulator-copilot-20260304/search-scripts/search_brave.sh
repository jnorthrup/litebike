#!/bin/bash
# Brave Search Provider Script
# Env: BRAVE_SEARCH_API_KEY or BRAVE_SEARCH_API_KEY_1, BRAVE_SEARCH_API_KEY_2
# Docs: https://developer.brave.com/docs/search/web-search-api
#
# Uses BASE ENVIRONMENT variables for actual execution.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/search_providers.sh"

# Load .env file if available
load_env_file

# Multi-key support (reads from base env)
API_KEY="${BRAVE_SEARCH_API_KEY:-${BRAVE_SEARCH_API_KEY_1:-}}"
API_KEY_2="${BRAVE_SEARCH_API_KEY_2:-}"

if [ -z "$API_KEY" ]; then
    error "BRAVE_SEARCH_API_KEY" "BRAVE_SEARCH_API_KEY not set in base environment.
    
To configure Brave Search:
1. Get API key: https://brave.com/search/api/
2. Export in base env: export BRAVE_SEARCH_API_KEY='your-key-here'
3. Or add to .env file in project root or ~/.cc-switch/.env

💡 Claude instruction:
   'Add Brave Search support to ollama_emulator:
    - Add BRAVE_SEARCH_API_KEY to env_facade_parity.rs
    - Add curl search adapter in ollama_emulator.rs
    - See search-scripts/search_brave.sh for API format'
"
fi

QUERY="${1:-}"
if [ -z "$QUERY" ]; then
    error "Usage: $0 <search-query>"
fi

# Count configuration
KEY_COUNT=1
[ -n "$API_KEY_2" ] && KEY_COUNT=2

info "Brave Search: $KEY_COUNT key(s) configured"
info "Query: $QUERY"

# Multi-key rotation function
rotate_key() {
    local attempt=$1
    if [ $attempt -eq 1 ] && [ -n "$API_KEY" ]; then
        echo "$API_KEY"
    elif [ $attempt -eq 2 ] && [ -n "$API_KEY_2" ]; then
        echo "$API_KEY_2"
    else
        echo "$API_KEY"
    fi
}

# Search with retry/failover
search() {
    local attempt=1
    local max_attempts=$KEY_COUNT
    
    while [ $attempt -le $max_attempts ]; do
        local key=$(rotate_key $attempt)
        
        info "Attempting with key $attempt..."
        
        RESPONSE=$(curl -s -X GET "https://api.search.brave.com/res/v1/web/search" \
            -H "Accept: application/json" \
            -H "Accept-Encoding: gzip" \
            -H "X-Subscription-Token: $key" \
            -G --data-urlencode "q=$QUERY" \
            --data-urlencode "count=10" \
            --data-urlencode "safesearch=off")
        
        HTTP_CODE=$?
        
        if [ $HTTP_CODE -eq 0 ]; then
            # Check if response contains error
            if echo "$RESPONSE" | grep -q '"status":"error"'; then
                warn "Key $attempt returned error, trying next key..."
                attempt=$((attempt + 1))
                continue
            fi
            
            # Success
            echo "$RESPONSE" | jq '.'
            info "Search successful with key $attempt"
            return 0
        else
            warn "Key $attempt failed (curl error: $HTTP_CODE)"
            attempt=$((attempt + 1))
        fi
    done
    
    error "All keys exhausted. Search failed."
}

search
