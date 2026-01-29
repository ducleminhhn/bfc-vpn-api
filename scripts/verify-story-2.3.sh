#!/bin/bash
set -euo pipefail

API_URL="${API_URL:-http://localhost:8081}"
KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8080}"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║     Story 2.3: Keycloak Integration & Login Flow             ║"
echo "║                    Verification Script                       ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

PASS=0
FAIL=0
SKIP=0

check() {
    local name=$1
    local cmd=$2
    printf "  %-50s " "$name"
    if eval "$cmd" > /dev/null 2>&1; then
        echo "✅ PASS"
        ((PASS++))
    else
        echo "❌ FAIL"
        ((FAIL++))
    fi
}

skip() {
    local name=$1
    local reason=$2
    printf "  %-50s " "$name"
    echo "⏭️  SKIP ($reason)"
    ((SKIP++))
}

echo "📋 Phase 1: Infrastructure Checks"
echo "─────────────────────────────────────────────────────────────────"
check "API health endpoint" "curl -sf $API_URL/health"
check "API ready endpoint" "curl -sf $API_URL/health/ready | grep -q ok"
check "Keycloak OIDC discovery" "curl -sf $KEYCLOAK_URL/realms/bfc-vpn/.well-known/openid-configuration | grep -q issuer"

echo ""
echo "📋 Phase 2: Login Page Checks"
echo "─────────────────────────────────────────────────────────────────"
check "Login page accessible" "curl -sf $API_URL/login | grep -q 'Đăng nhập'"
check "Login page Vietnamese labels" "curl -sf $API_URL/login | grep -q 'Mật khẩu'"
check "Login page Retro Terminal Theme" "curl -sf $API_URL/login | grep -q 'BFC METAL VPN'"
check "Login page has amber color scheme" "curl -sf $API_URL/login | grep -q '#ff9500'"

echo ""
echo "📋 Phase 3: API Endpoint Checks"
echo "─────────────────────────────────────────────────────────────────"
check "Login endpoint exists" "curl -sf -o /dev/null -w '%{http_code}' -X POST $API_URL/api/v1/auth/login -H 'Content-Type: application/json' -d '{}' | grep -qE '40[01]'"
check "Validation error (empty body)" "curl -s -X POST $API_URL/api/v1/auth/login -H 'Content-Type: application/json' -d '{}' | grep -q 'không hợp lệ'"
check "RFC 7807 error format" "curl -s -X POST $API_URL/api/v1/auth/login -H 'Content-Type: application/json' -d '{}' | grep -q '\"type\"'"
check "Logout endpoint exists" "test \$(curl -sf -o /dev/null -w '%{http_code}' -X POST $API_URL/api/v1/auth/logout) -eq 204"

echo ""
echo "📋 Phase 4: Authentication Checks"
echo "─────────────────────────────────────────────────────────────────"
check "Invalid credentials returns 401" "test \$(curl -sf -o /dev/null -w '%{http_code}' -X POST $API_URL/api/v1/auth/login -H 'Content-Type: application/json' -d '{\"email\":\"bad@test.com\",\"password\":\"wrongpassword1\"}') -eq 401"
check "Error message in Vietnamese" "curl -s -X POST $API_URL/api/v1/auth/login -H 'Content-Type: application/json' -d '{\"email\":\"bad@test.com\",\"password\":\"wrongpassword1\"}' | grep -q 'không đúng'"

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "                        SUMMARY"
echo "═══════════════════════════════════════════════════════════════"
echo "  ✅ PASS: $PASS"
echo "  ❌ FAIL: $FAIL"
echo "  ⏭️  SKIP: $SKIP"
echo ""

if [ $FAIL -eq 0 ]; then
    echo "🎉 ALL CHECKS PASSED - Story 2.3 verification successful!"
    exit 0
else
    echo "⚠️  SOME CHECKS FAILED - Please review and fix issues"
    exit 1
fi
