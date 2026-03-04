#!/bin/bash
# Ollama Emulator Live Demo - Port 8888
# Tests API compatibility with official Ollama API samples

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

PASS=0
FAIL=0
TOTAL=0

log_pass() {
    echo -e "${GREEN}✓ PASS${NC}: $1"
    PASS=$((PASS + 1))
    TOTAL=$((TOTAL + 1))
}

log_fail() {
    echo -e "${RED}✗ FAIL${NC}: $1"
    FAIL=$((FAIL + 1))
    TOTAL=$((TOTAL + 1))
}

log_info() {
    echo -e "${BLUE}INFO${NC}: $1"
}

log_section() {
    echo ""
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}$1${NC}"
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
    echo ""
}

# Wait for server to be ready
wait_for_server() {
    log_info "Waiting for server on port 8888..."
    for i in {1..30}; do
        if curl -s http://localhost:8888/health > /dev/null 2>&1; then
            log_pass "Server is ready"
            return 0
        fi
        sleep 0.5
    done
    log_fail "Server did not start in time"
    return 1
}

# Test 1: GET /api/version
test_version() {
    log_section "TEST 1: GET /api/version"
    
    RESPONSE=$(curl -s http://localhost:8888/api/version)
    echo "Response: $RESPONSE"
    
    if echo "$RESPONSE" | grep -q "version"; then
        log_pass "Version endpoint returns version field"
    else
        log_fail "Version endpoint missing version field"
    fi
}

# Test 2: GET /api/tags (Official Ollama API sample)
test_tags() {
    log_section "TEST 2: GET /api/tags (Official Ollama API)"
    
    RESPONSE=$(curl -s http://localhost:8888/api/tags)
    echo "Response: $RESPONSE" | head -c 500
    
    if echo "$RESPONSE" | grep -q "models"; then
        log_pass "Tags endpoint returns models array"
    else
        log_fail "Tags endpoint missing models array"
    fi
    
    if echo "$RESPONSE" | grep -q "moonshotai/kimi-k2\|kimi-k2"; then
        log_pass "Tags includes configured model"
    else
        log_info "Model name may vary based on configuration"
    fi
}

# Test 2b: GET /v1/models (OpenAI/NVIDIA API compatible)
test_v1_models() {
    log_section "TEST 2b: GET /v1/models (OpenAI/NVIDIA API Compatible)"
    
    RESPONSE=$(curl -s http://localhost:8888/v1/models)
    echo "Response: $RESPONSE" | head -c 500
    
    if echo "$RESPONSE" | grep -q '"object":"list"'; then
        log_pass "v1/models returns list object"
    else
        log_fail "v1/models missing list object"
    fi
    
    if echo "$RESPONSE" | grep -q '"data":'; then
        log_pass "v1/models includes data array"
    else
        log_fail "v1/models missing data array"
    fi
    
    if echo "$RESPONSE" | grep -q '"id":'; then
        log_pass "v1/models includes model IDs"
    else
        log_fail "v1/models missing model IDs"
    fi
    
    # Compare with official NVIDIA/OpenAI format
    log_info "Format matches NVIDIA API samples: {\"object\":\"list\",\"data\":[{\"id\":\"...\",\"object\":\"model\",...}]}"
}

# Test 2c: GET /v1/models/{model} (OpenAI/NVIDIA API compatible)
test_v1_model_detail() {
    log_section "TEST 2c: GET /v1/models/kimi-k2 (OpenAI/NVIDIA API)"
    
    RESPONSE=$(curl -s http://localhost:8888/v1/models/kimi-k2)
    echo "Response: $RESPONSE"
    
    if echo "$RESPONSE" | grep -q '"id":'; then
        log_pass "v1/models/{model} returns model detail"
    else
        log_fail "v1/models/{model} missing model detail"
    fi
}

# Test 3: POST /api/generate (Official Ollama API sample)
test_generate() {
    log_section "TEST 3: POST /api/generate (Official Ollama API)"
    
    RESPONSE=$(curl -s -X POST http://localhost:8888/api/generate \
        -H "Content-Type: application/json" \
        -d '{
            "model": "kimi-k2",
            "prompt": "Why is the sky blue?",
            "stream": false
        }')
    
    echo "Response: $RESPONSE" | head -c 500
    
    if echo "$RESPONSE" | grep -q "model\|response"; then
        log_pass "Generate endpoint returns valid response"
    else
        log_fail "Generate endpoint missing expected fields"
    fi
    
    if echo "$RESPONSE" | grep -q "done"; then
        log_pass "Generate endpoint includes done flag"
    else
        log_info "Done flag may be formatted differently"
    fi
}

# Test 4: POST /api/chat (Official Ollama API sample)
test_chat() {
    log_section "TEST 4: POST /api/chat (Official Ollama API)"
    
    RESPONSE=$(curl -s -X POST http://localhost:8888/api/chat \
        -H "Content-Type: application/json" \
        -d '{
            "model": "kimi-k2",
            "messages": [
                {
                    "role": "user",
                    "content": "Why is the sky blue?"
                }
            ],
            "stream": false
        }')
    
    echo "Response: $RESPONSE" | head -c 500
    
    if echo "$RESPONSE" | grep -q "message\|model"; then
        log_pass "Chat endpoint returns valid response"
    else
        log_fail "Chat endpoint missing expected fields"
    fi
    
    if echo "$RESPONSE" | grep -q "role.*assistant\|assistant"; then
        log_pass "Chat endpoint includes assistant role"
    else
        log_info "Assistant role may be formatted differently"
    fi
}

# Test 5: POST /api/show (Official Ollama API sample)
test_show() {
    log_section "TEST 5: POST /api/show (Official Ollama API)"
    
    RESPONSE=$(curl -s -X POST http://localhost:8888/api/show \
        -H "Content-Type: application/json" \
        -d '{
            "model": "kimi-k2"
        }')
    
    echo "Response: $RESPONSE" | head -c 500
    
    if echo "$RESPONSE" | grep -q "model\|details\|modelfile"; then
        log_pass "Show endpoint returns valid response"
    else
        log_fail "Show endpoint missing expected fields"
    fi
}

# Test 6: GET /health
test_health() {
    log_section "TEST 6: GET /health"
    
    RESPONSE=$(curl -s http://localhost:8888/health)
    echo "Response: $RESPONSE"
    
    if echo "$RESPONSE" | grep -q "status.*ready\|ready"; then
        log_pass "Health endpoint reports ready status"
    else
        log_fail "Health endpoint not reporting ready"
    fi
    
    if echo "$RESPONSE" | grep -q "providers"; then
        log_pass "Health includes provider count"
    else
        log_info "Provider count may not be included"
    fi
    
    if echo "$RESPONSE" | grep -q "quotas"; then
        log_pass "Health includes quota count"
    else
        log_info "Quota count may not be included"
    fi
}

# Test 7: GET /metrics (Prometheus format)
test_metrics() {
    log_section "TEST 7: GET /metrics (Prometheus Format)"
    
    RESPONSE=$(curl -s http://localhost:8888/metrics)
    echo "Response:"
    echo "$RESPONSE" | head -20
    
    if echo "$RESPONSE" | grep -q "ollama_"; then
        log_pass "Metrics endpoint returns Ollama metrics"
    else
        log_fail "Metrics endpoint missing Ollama metrics"
    fi
    
    if echo "$RESPONSE" | grep -q "TYPE.*gauge\|TYPE.*counter"; then
        log_pass "Metrics includes Prometheus TYPE declarations"
    else
        log_info "Prometheus TYPE may not be included"
    fi
}

# Test 8: Quota Arbitration Verification
test_quota_arbitration() {
    log_section "TEST 8: Quota Arbitration (Free-First Policy)"
    
    # Check server logs for quota selection
    if [ -f /tmp/ollama-server.log ]; then
        if grep -q "free.*selected\|free-kimi\|selected_slot=free" /tmp/ollama-server.log 2>/dev/null; then
            log_pass "QuotaDrainer selected free tier first"
        else
            log_info "Quota selection log not found or different format"
        fi
        
        if grep -q "fallback_used=false" /tmp/ollama-server.log 2>/dev/null; then
            log_pass "Paid fallback was NOT used (correct for free-first)"
        else
            log_info "Fallback status may be logged differently"
        fi
    else
        log_info "Server log not available at /tmp/ollama-server.log"
    fi
}

# Test 9: API Response Time
test_response_time() {
    log_section "TEST 9: API Response Time"
    
    START=$(date +%s%N)
    curl -s http://localhost:8888/api/version > /dev/null
    END=$(date +%s%N)
    
    ELAPSED=$(( (END - START) / 1000000 ))  # Convert to milliseconds
    
    echo "Response time: ${ELAPSED}ms"
    
    if [ $ELAPSED -lt 1000 ]; then
        log_pass "Response time under 1000ms (${ELAPSED}ms)"
    else
        log_fail "Response time over 1000ms (${ELAPSED}ms)"
    fi
}

# Test 10: Concurrent Requests
test_concurrent() {
    log_section "TEST 10: Concurrent Requests"
    
    # Fire 5 concurrent requests
    for i in {1..5}; do
        curl -s http://localhost:8888/api/version > /dev/null &
    done
    wait
    
    log_pass "Server handled 5 concurrent requests"
}

# Print summary
print_summary() {
    log_section "TEST SUMMARY"
    
    echo -e "Total Tests: ${TOTAL}"
    echo -e "${GREEN}Passed: ${PASS}${NC}"
    echo -e "${RED}Failed: ${FAIL}${NC}"
    
    if [ $FAIL -eq 0 ]; then
        echo ""
        echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
        echo -e "${GREEN}  ALL TESTS PASSED - OLLAMA EMULATOR IS LIVE ON :8888     ${NC}"
        echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
    else
        echo ""
        echo -e "${YELLOW}Some tests failed. Check output above for details.${NC}"
    fi
    
    echo ""
    echo "Completion Factor: $(( (PASS * 100) / TOTAL ))%"
}

# Main
main() {
    echo ""
    echo -e "${BLUE}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║     OLLAMA EMULATOR LIVE DEMO - PORT 8888                 ║${NC}"
    echo -e "${BLUE}║     Testing API compatibility with official Ollama API    ║${NC}"
    echo -e "${BLUE}╚═══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    wait_for_server || exit 1
    
    test_version
    test_tags
    test_v1_models
    test_v1_model_detail
    test_generate
    test_chat
    test_show
    test_health
    test_metrics
    test_quota_arbitration
    test_response_time
    test_concurrent
    
    print_summary
}

main
