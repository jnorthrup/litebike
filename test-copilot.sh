#!/bin/bash
# Test script for copilot integration

PORT=${1:-8888}
BASE_URL="http://localhost:$PORT"

echo "=== Testing ModelMux Copilot Integration ==="
echo "Base URL: $BASE_URL"
echo

# Test 1: Health check
echo "1. Health Check..."
curl -s "$BASE_URL/health" | jq . 2>/dev/null || echo "   Failed"
echo

# Test 2: List models
echo "2. List Models..."
curl -s "$BASE_URL/v1/models" | jq '.data[:5]' 2>/dev/null || echo "   Failed"
echo

# Test 3: Chat completion (copilot-style)
echo "3. Chat Completion (Copilot-style)..."
curl -s -X POST "$BASE_URL/v1/chat/completions" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "kilo_code/minimax-minimax-m2.5:free",
    "messages": [
      {"role": "system", "content": "You are a coding assistant."},
      {"role": "user", "content": "Write a Rust function to add two numbers"}
    ],
    "max_tokens": 100
  }' | jq '.choices[0].message.content' 2>/dev/null || echo "   Failed"
echo

# Test 4: Streaming test
echo "4. Streaming Test..."
curl -s -X POST "$BASE_URL/v1/chat/completions" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "kilo_code/minimax-minimax-m2.5:free",
    "messages": [{"role": "user", "content": "Hello"}],
    "stream": true
  }' | head -5 || echo "   Failed"
echo

echo "=== Done ==="
