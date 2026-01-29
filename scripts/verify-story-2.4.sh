#\!/bin/bash
set -uo pipefail
API_URL="${API_URL:-http://localhost:8081}"

echo "Story 2.4: TOTP Setup & Verification - Verification"
echo ""

PASS=0; FAIL=0

test_endpoint() {
    local name="$1"
    local cmd="$2"
    printf "  %-50s " "$name"
    if eval "$cmd" >/dev/null 2>&1; then
        echo "OK"
        ((PASS++))
    else
        echo "FAIL"
        ((FAIL++))
    fi
}

echo "Endpoint Checks:"
test_endpoint "TOTP setup endpoint (400)" "curl -s -o /dev/null -w '%{http_code}' -X POST $API_URL/api/v1/auth/totp/setup -H 'Content-Type: application/json' -d '{}' | grep -q 400"
test_endpoint "TOTP verify endpoint (400)" "curl -s -o /dev/null -w '%{http_code}' -X POST $API_URL/api/v1/auth/totp/verify -H 'Content-Type: application/json' -d '{}' | grep -q 400"
test_endpoint "Vietnamese error msg" "curl -s -X POST $API_URL/api/v1/auth/totp/setup -H 'Content-Type: application/json' -d '{}' | grep -q Vui"
test_endpoint "RFC 7807 type field" "curl -s -X POST $API_URL/api/v1/auth/totp/setup -H 'Content-Type: application/json' -d '{}' | grep -q type"
test_endpoint "Invalid MFA returns 401" "curl -s -o /dev/null -w '%{http_code}' -X POST $API_URL/api/v1/auth/totp/verify -H 'Content-Type: application/json' -d '{\"mfa_token\":\"invalid\",\"code\":\"123456\"}' | grep -q 401"

echo ""
echo "File Checks:"
test_endpoint "crypto/aes.go exists" "ls ~/bfc-vpn-api/internal/pkg/crypto/aes.go"
test_endpoint "totp/generator.go exists" "ls ~/bfc-vpn-api/internal/infrastructure/totp/generator.go"
test_endpoint "totp/service.go exists" "ls ~/bfc-vpn-api/internal/service/totp/service.go"
test_endpoint "totp/interfaces.go exists" "ls ~/bfc-vpn-api/internal/service/totp/interfaces.go"
test_endpoint "totp_handler.go exists" "ls ~/bfc-vpn-api/internal/handler/totp_handler.go"

echo ""
echo "Test Coverage:"
cd ~/bfc-vpn-api
export PATH=$PATH:/usr/local/go/bin
go test ./internal/pkg/crypto/... -cover 2>&1 | grep coverage || echo "  crypto: N/A"
go test ./internal/infrastructure/totp/... -cover 2>&1 | grep coverage || echo "  totp-gen: N/A"
go test ./internal/service/totp/... -cover 2>&1 | grep coverage || echo "  totp-svc: N/A"

echo ""
echo "Summary: $PASS passed, $FAIL failed"
[ $FAIL -eq 0 ] && echo "Story 2.4 verification SUCCESS" || echo "Some checks failed"
exit $FAIL
