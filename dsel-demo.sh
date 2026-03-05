#!/bin/bash
# DSEL Demo - Show quota-aware provider selection

PORT=8889
BASE="http://localhost:$PORT"

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║  DSEL: Domain-Specific Expression Language Demo          ║"
echo "║  Quota-Aware Intelligent Provider Selection              ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo

echo "📊 HEALTH CHECK"
echo "─────────────────────────────────────────────────────────────"
curl -s "$BASE/health" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(f\"  Status:      {d.get('status', 'unknown')}\")
print(f\"  Providers:   {d.get('providers_available', 0)} available\")
print(f\"  Quota:       {d.get('quota_status', 'unknown')}\")
print(f\"  Models:      {d.get('models_cached', 0)} cached\")
"
echo

echo "🎯 DSEL PROVIDER SELECTION DEMO"
echo "─────────────────────────────────────────────────────────────"
echo "DSEL automatically selects the best provider based on:"
echo "  ✓ Quota availability (free tier limits)"
echo "  ✓ Cost optimization (cheapest first)"
echo "  ✓ Priority routing (fallback chains)"
echo "  ✓ Token ledger tracking"
echo

echo "💰 CONFIGURED PROVIDERS (from DSEL rule engine)"
echo "─────────────────────────────────────────────────────────────"
echo "  Provider      | Quota (daily)  | Priority | Cost/1M"
echo "  ──────────────┼────────────────┼──────────┼────────"
echo "  kilo_code     | 1,000,000      | 1 (best) | FREE"
echo "  moonshot      | 500,000        | 2        | FREE"
echo "  deepseek      | 500,000        | 2        | FREE"
echo "  openai        | 2,000,000      | 3        | \$5-15"
echo "  anthropic     | 2,000,000      | 3        | \$3-15"
echo

echo "🔄 DSEL FLOW FOR REQUEST: model='kilo_code/some-model'"
echo "─────────────────────────────────────────────────────────────"
echo "  1. Parse model ID → extract provider 'kilo_code'"
echo "  2. Check quota: has_sufficient_quota('kilo_code', 100)"
echo "  3. Quota OK? YES → Route to kilo_code API"
echo "  4. Track tokens used in ledger"
echo "  5. Return response"
echo
echo "  If quota exhausted:"
echo "  → Try fallback model"
echo "  → Return error if no fallback"
echo

echo "📈 QUOTA TRACKING (Token Ledger)"
echo "─────────────────────────────────────────────────────────────"
echo "DSEL tracks per-provider usage:"
echo "  - tokens_used_today"
echo "  - tokens_used_this_hour"  
echo "  - estimated_remaining_quota"
echo "  - quota_confidence (0.0-1.0)"
echo

echo "✅ DSEL BENEFITS"
echo "─────────────────────────────────────────────────────────────"
echo "  ✓ Automatic free-tier optimization"
echo "  ✓ No manual provider switching"
echo "  ✓ Cost-aware routing"
echo "  ✓ Quota exhaustion protection"
echo "  ✓ Transparent failover"
echo
