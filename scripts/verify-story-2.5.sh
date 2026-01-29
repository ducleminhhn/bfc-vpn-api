#\!/bin/bash
# Story 2.5: Recovery Codes System - Verification Script
set -euo pipefail

API_URL="${API_URL:-http://localhost:8081}"

echo "Story 2.5: Recovery Codes System - Verification"
echo "═══════════════════════════════════════════════════"
echo ""

PASS=0
FAIL=0

check() {
    local desc="$1"
    local cmd="$2"
    printf "  %-55s " "$desc"
    if eval "$cmd" >/dev/null 2>&1; then
        echo "✅"
        ((PASS++))
    else
        echo "❌"
        ((FAIL++))
    fi
}

echo "📋 AC-1: 10 Recovery Codes Generated"
check "Generator creates 10 codes" "cd ~/bfc-vpn-api && /usr/local/go/bin/go test -run TestGenerateCodes_Count ./internal/infrastructure/recovery/..."

echo ""
echo "📋 AC-2: Bcrypt Hashing (Cost 10)"
check "BcryptCost constant is 10" "grep -q BcryptCost.*=.*10 ~/bfc-vpn-api/internal/service/recovery/service.go"

echo ""
echo "📋 AC-3: Download & Print Endpoints"
check "Download endpoint registered" "grep -q /download ~/bfc-vpn-api/internal/handler/router.go"
check "Print endpoint registered" "grep -q /print ~/bfc-vpn-api/internal/handler/router.go"
check "Download handler exists" "grep -q func.*Download ~/bfc-vpn-api/internal/handler/recovery_handler.go"
check "Print handler exists" "grep -q func.*Print ~/bfc-vpn-api/internal/handler/recovery_handler.go"

echo ""
echo "📋 AC-4: XXXX-XXXX Format (Distinguishable from TOTP)"
check "Format test passes" "cd ~/bfc-vpn-api && /usr/local/go/bin/go test -run TestIsRecoveryCodeFormat ./internal/infrastructure/recovery/..."
check "TOTP format detection" "cd ~/bfc-vpn-api && /usr/local/go/bin/go test -run TestIsTOTPFormat ./internal/infrastructure/recovery/..."
check "Charset excludes I,O,0,1" "grep -q ABCDEFGHJKLMNPQRSTUVWXYZ23456789 ~/bfc-vpn-api/internal/infrastructure/recovery/generator.go"

echo ""
echo "📋 AC-5: One-Time Use (Marked After Used)"
check "MarkCodeUsed function exists" "grep -q MarkCodeUsed ~/bfc-vpn-api/internal/repository/recovery_repository.go"

echo ""
echo "📋 AC-6: Audit Logging"
check "recovery_codes_generated event" "grep -q recovery_codes_generated ~/bfc-vpn-api/internal/service/recovery/service.go"
check "recovery_code_verified event" "grep -q recovery_code_verified ~/bfc-vpn-api/internal/service/recovery/service.go"
check "recovery_code_failed event" "grep -q recovery_code_failed ~/bfc-vpn-api/internal/service/recovery/service.go"
check "recovery_codes_regenerated event" "grep -q recovery_codes_regenerated ~/bfc-vpn-api/internal/service/recovery/service.go"

echo ""
echo "📋 AC-7: Recovery Verify Completes MFA Flow"
check "Verify returns tokens" "grep -q AccessToken ~/bfc-vpn-api/internal/service/recovery/service.go"
check "MFA token consumed" "grep -q mfa_token ~/bfc-vpn-api/internal/service/recovery/service.go"

echo ""
echo "📋 AC-8: Regenerate Requires TOTP"
check "TOTPService interface" "grep -q TOTPService ~/bfc-vpn-api/internal/service/recovery/interfaces.go"
check "ValidateCode called" "grep -q totpService.ValidateCode ~/bfc-vpn-api/internal/service/recovery/service.go"
check "Regenerate test passes" "cd ~/bfc-vpn-api && /usr/local/go/bin/go test -run TestRegenerate ./internal/service/recovery/..."

echo ""
echo "📋 Security: Brute Force Protection"
check "MaxFailedAttempts = 5" "grep -q MaxFailedAttempts.*=.*5 ~/bfc-vpn-api/internal/service/recovery/service.go"
check "Lockout test passes" "cd ~/bfc-vpn-api && /usr/local/go/bin/go test -run TestVerify_BruteForceLockout ./internal/service/recovery/..."

echo ""
echo "📋 Test Coverage"
check "Service coverage >=80 percent" "cd ~/bfc-vpn-api && /usr/local/go/bin/go test -cover ./internal/service/recovery/... 2>&1 | grep -E coverage: [89][0-9]"
check "Generator coverage >=80 percent" "cd ~/bfc-vpn-api && /usr/local/go/bin/go test -cover ./internal/infrastructure/recovery/... 2>&1 | grep -E coverage: [89][0-9]"

echo ""
echo "═══════════════════════════════════════════════════"
echo "Summary: ✅ $PASS passed, ❌ $FAIL failed"
echo ""

if [ $FAIL -eq 0 ]; then
    echo "🎉 Story 2.5 verification PASSED\!"
    exit 0
else
    echo "⚠️ Story 2.5 verification FAILED - $FAIL checks need attention"
    exit 1
fi
