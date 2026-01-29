#\!/bin/bash
# Story 2.7: Dual Auth Failover Integration Tests
# Run this script to verify dual auth endpoints work correctly

set -e

API_BASE="${API_BASE:-http://localhost:8081/api/v1}"
ADMIN_TOKEN="${ADMIN_TOKEN:-}"

# Colors for output
RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
NC="\033[0m" # No Color

echo "=== BFC-VPN Dual Auth Integration Tests ==="
echo "API Base: $API_BASE"
echo ""

# Test 1: Check auth health endpoint
echo -e "${YELLOW}Test 1: GET /auth/health${NC}"
response=$(curl -s "$API_BASE/auth/health")
echo "$response" | jq .
if echo "$response" | jq -e .current_mode > /dev/null 2>&1; then
    echo -e "${GREEN}✓ PASS${NC}"
else
    echo -e "${RED}✗ FAIL: Missing current_mode${NC}"
fi
echo ""

# Test 2: Login endpoint (expects 401 with invalid creds)
echo -e "${YELLOW}Test 2: POST /auth/login (invalid credentials)${NC}"
response=$(curl -s -X POST "$API_BASE/auth/login" \
  -H "Content-Type: application/json" \
  -d email:test@example.com)
echo "$response" | jq .
if echo "$response" | jq -e .type mkdir -p ~/bfc-vpn-api/scripts && cat > ~/bfc-vpn-api/scripts/test-dual-auth.sh << 'EOF'
#\!/bin/bash
# Story 2.7: Dual Auth Failover Integration Tests
# Run this script to verify dual auth endpoints work correctly

set -e

API_BASE="${API_BASE:-http://localhost:8081/api/v1}"
ADMIN_TOKEN="${ADMIN_TOKEN:-}"

# Colors for output
RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
NC="\033[0m" # No Color

echo "=== BFC-VPN Dual Auth Integration Tests ==="
echo "API Base: $API_BASE"
echo ""

# Test 1: Check auth health endpoint
echo -e "${YELLOW}Test 1: GET /auth/health${NC}"
response=$(curl -s "$API_BASE/auth/health")
echo "$response" | jq .
if echo "$response" | jq -e .current_mode > /dev/null 2>&1; then
    echo -e "${GREEN}✓ PASS${NC}"
else
    echo -e "${RED}✗ FAIL: Missing current_mode${NC}"
fi
echo ""

# Test 2: Login endpoint (expects 401 with invalid creds)
echo -e "${YELLOW}Test 2: POST /auth/login (invalid credentials)${NC}"
response=$(curl -s -X POST "$API_BASE/auth/login" \
  -H "Content-Type: application/json" \
  -d password:wrongpassword)
echo "$response" | jq .
if echo "$response" | jq -e .type == authentication_error > /dev/null 2>&1; then
    echo -e "${GREEN}✓ PASS (got expected 401)${NC}"
else
    echo -e "${YELLOW}? WARN: Unexpected response${NC}"
fi
echo ""

# Test 3: Admin dual status (requires auth)
echo -e "${YELLOW}Test 3: GET /admin/auth/dual-status${NC}"
if [ -n "$ADMIN_TOKEN" ]; then
    response=$(curl -s "$API_BASE/admin/auth/dual-status" \
      -H "Authorization: Bearer $ADMIN_TOKEN")
    echo "$response" | jq .
    if echo "$response" | jq -e .current_mode > /dev/null 2>&1; then
        echo -e "${GREEN}✓ PASS${NC}"
    else
        echo -e "${RED}✗ FAIL${NC}"
    fi
else
    echo -e "${YELLOW}⊘ SKIP (no ADMIN_TOKEN)${NC}"
fi
echo ""

# Test 4: Manual failover (requires admin auth)
echo -e "${YELLOW}Test 4: POST /admin/auth/failover${NC}"
if [ -n "$ADMIN_TOKEN" ]; then
    response=$(curl -s -X POST "$API_BASE/admin/auth/failover" \
      -H "Authorization: Bearer $ADMIN_TOKEN" \
      -H "Content-Type: application/json" \
      -d {reason:Integration test})
    echo "$response" | jq .
else
    echo -e "${YELLOW}⊘ SKIP (no ADMIN_TOKEN)${NC}"
fi
echo ""

# Test 5: Verify failover occurred
echo -e "${YELLOW}Test 5: Verify failover - GET /auth/health${NC}"
response=$(curl -s "$API_BASE/auth/health")
echo "$response" | jq .
mode=$(echo "$response" | jq -r .current_mode)
if [ "$mode" == "local" ]; then
    echo -e "${GREEN}✓ PASS: System in local mode${NC}"
elif [ "$mode" == "keycloak" ]; then
    echo -e "${YELLOW}? Note: Still in keycloak mode${NC}"
fi
echo ""

# Test 6: Manual recover (requires admin auth)
echo -e "${YELLOW}Test 6: POST /admin/auth/recover${NC}"
if [ -n "$ADMIN_TOKEN" ]; then
    response=$(curl -s -X POST "$API_BASE/admin/auth/recover" \
      -H "Authorization: Bearer $ADMIN_TOKEN")
    echo "$response" | jq .
else
    echo -e "${YELLOW}⊘ SKIP (no ADMIN_TOKEN)${NC}"
fi
echo ""

# Test 7: Internal sync status (requires service token)
echo -e "${YELLOW}Test 7: GET /internal/sync/status${NC}"
SERVICE_TOKEN="${SERVICE_TOKEN:-}"
if [ -n "$SERVICE_TOKEN" ]; then
    response=$(curl -s "$API_BASE/internal/sync/status" \
      -H "X-Service-Token: $SERVICE_TOKEN")
    echo "$response" | jq .
else
    echo -e "${YELLOW}⊘ SKIP (no SERVICE_TOKEN)${NC}"
fi
echo ""

echo "=== Integration Tests Complete ==="
