#!/bin/bash
set -euo pipefail
API_URL="${API_URL:-http://localhost:8081}"

echo "Story 2.6: Local PostgreSQL Auth - Verification"
echo "═══════════════════════════════════════════════════"

PASS=0; FAIL=0
check() { printf "  %-50s " "$1"; if eval "$2" >/dev/null 2>&1; then echo "✅"; ((PASS++)); else echo "❌"; ((FAIL++)); fi; }

echo ""
echo "📋 Endpoint Checks"
check "Local login endpoint exists" "curl -sf -o /dev/null -w '%{http_code}' -X POST $API_URL/api/v1/auth/local/login -H 'Content-Type: application/json' -d '{}' | grep -qE '40[01]'"
check "Local TOTP verify endpoint exists" "curl -sf -o /dev/null -w '%{http_code}' -X POST $API_URL/api/v1/auth/local/totp/verify -H 'Content-Type: application/json' -d '{}' | grep -qE '40[01]'"
check "Local recovery verify endpoint exists" "curl -sf -o /dev/null -w '%{http_code}' -X POST $API_URL/api/v1/auth/local/recovery/verify -H 'Content-Type: application/json' -d '{}' | grep -qE '40[01]'"

echo ""
echo "📋 Error Response Checks"
check "Vietnamese error messages" "curl -s -X POST $API_URL/api/v1/auth/local/login -H 'Content-Type: application/json' -d '{\"email\":\"x@x.com\",\"password\":\"wrongpassword1\"}' | grep -q 'không đúng\|không hợp lệ'"
check "RFC 7807 format" "curl -s -X POST $API_URL/api/v1/auth/local/login -H 'Content-Type: application/json' -d '{}' | grep -q '\"type\"'"

echo ""
echo "📋 Database Checks"
check "password_hash column exists" "docker exec bfc-postgres psql -U postgres -d bfc_vpn -c '\d users' 2>/dev/null | grep -q 'password_hash'"
check "local_auth_enabled column exists" "docker exec bfc-postgres psql -U postgres -d bfc_vpn -c '\d users' 2>/dev/null | grep -q 'local_auth_enabled'"
check "locked_until column exists" "docker exec bfc-postgres psql -U postgres -d bfc_vpn -c '\d users' 2>/dev/null | grep -q 'locked_until'"
check "failed_attempts column exists" "docker exec bfc-postgres psql -U postgres -d bfc_vpn -c '\d users' 2>/dev/null | grep -q 'failed_attempts'"

echo ""
echo "📋 Code Checks"
check "Argon2id hasher exists" "test -f ~/bfc-vpn-api/internal/infrastructure/crypto/argon2.go"
check "Local auth service exists" "test -f ~/bfc-vpn-api/internal/service/localauth/service.go"
check "Local auth handler exists" "test -f ~/bfc-vpn-api/internal/handler/localauth_handler.go"
check "Prometheus metrics exists" "test -f ~/bfc-vpn-api/internal/service/localauth/metrics.go"

echo ""
echo "📋 Test Checks"
check "Argon2 tests pass" "go test ~/bfc-vpn-api/internal/infrastructure/crypto/... -v 2>&1 | grep -q PASS"

echo ""
echo "Summary: ✅ $PASS passed, ❌ $FAIL failed"
[ $FAIL -eq 0 ] && echo "🎉 Story 2.6 verification successful!" || echo "⚠️ Some checks failed"
exit $FAIL
