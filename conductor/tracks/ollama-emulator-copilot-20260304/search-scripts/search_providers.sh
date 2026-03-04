#!/bin/bash
# Search Provider curl Scripts
# Generated from CC-Switch + literbike env patterns
# Usage: ./search_<provider>.sh "query"
#
# NOTE: These scripts use BASE ENVIRONMENT variables for actual execution.
#       Set env vars in your shell or .env file before running.

set -e

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

error() {
    echo -e "${RED}ERROR:${NC} $1" >&2
    echo ""
    echo -e "${YELLOW}💡 To fix this:${NC}"
    echo "   1. Set the required environment variable in your base env:"
    echo "      export ${2:-PROVIDER}_API_KEY='your-key-here'"
    echo "   2. Or add to .env file and source it:"
    echo "      echo '${2:-PROVIDER}_API_KEY=key' >> .env && source .env"
    echo "   3. Or run: claude 'Add support for <provider> search in ollama_emulator'"
    echo "   4. See: conductor/tracks/ollama-emulator-copilot-20260304/api-env-lookup-table.md"
    exit 1
}

info() {
    echo -e "${GREEN}INFO:${NC} $1"
}

warn() {
    echo -e "${YELLOW}WARN:${NC} $1"
}

# Load .env file if it exists in current directory
load_env_file() {
    if [ -f ".env" ]; then
        info "Loading .env file..."
        set -a
        source .env
        set +a
    elif [ -f "$HOME/.cc-switch/.env" ]; then
        info "Loading ~/.cc-switch/.env..."
        set -a
        source "$HOME/.cc-switch/.env"
        set +a
    fi
}
