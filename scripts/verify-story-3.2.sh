#!/bin/bash
# Story 3.2: User Certificate Auto-Issue Verification Script

PASS=0
FAIL=0
TOTAL=0

check() {
    local description="$1"
    local result=$2
    ((TOTAL++))
    if [ $result -eq 0 ]; then
        echo "[PASS] $description"
        ((PASS++))
    else
        echo "[FAIL] $description"
        ((FAIL++))
    fi
}

check_file_exists() {
    local file="$1"
    local desc="$2"
    if [ -f "$file" ]; then
        check "$desc" 0
    else
        check "$desc" 1
    fi
}

echo "=================================================================="
echo "  Story 3.2: User Certificate Auto-Issue Verification"
echo "=================================================================="
echo ""

# ============================================================================
# Phase 1: File Structure Verification
# ============================================================================
echo "=== Phase 1: File Structure ==="

check_file_exists "internal/domain/certificate.go" "Certificate domain model exists"
check_file_exists "internal/domain/certificate_test.go" "Certificate domain tests exist"
check_file_exists "internal/infrastructure/stepca/client.go" "step-ca client exists"
check_file_exists "internal/infrastructure/stepca/client_test.go" "step-ca client tests exist"
check_file_exists "internal/infrastructure/stepca/circuit_breaker.go" "Circuit breaker exists"
check_file_exists "internal/infrastructure/crypto/certificate.go" "Crypto encryption exists"
check_file_exists "internal/infrastructure/crypto/certificate_test.go" "Crypto tests exist"
check_file_exists "internal/repository/certificate_repository.go" "Certificate repository exists"
check_file_exists "internal/service/certificate/service.go" "Certificate service exists"
check_file_exists "internal/service/certificate/service_test.go" "Certificate service tests exist"
check_file_exists "internal/service/certificate/metrics.go" "Certificate metrics exist"
check_file_exists "internal/handler/certificate_handler.go" "Certificate handler exists"
check_file_exists "db/migrations/000007_user_certificates.up.sql" "Migration UP file exists"
check_file_exists "db/migrations/000007_user_certificates.down.sql" "Migration DOWN file exists"

# ============================================================================
# Phase 2: Code Content Verification
# ============================================================================
echo ""
echo "=== Phase 2: Code Content ==="

# Check domain model
grep -q "ErrCodeCertNotFound" internal/domain/certificate.go && check "Error code CERT_NOT_FOUND defined" 0 || check "Error code CERT_NOT_FOUND defined" 1
grep -q "ErrCodeCertIssuanceFailed" internal/domain/certificate.go && check "Error code CERT_ISSUANCE_FAILED defined" 0 || check "Error code CERT_ISSUANCE_FAILED defined" 1
grep -q "ErrCodeCertCircuitOpen" internal/domain/certificate.go && check "Error code CERT_CIRCUIT_OPEN defined" 0 || check "Error code CERT_CIRCUIT_OPEN defined" 1
grep -q "MsgCertNotFound" internal/domain/certificate.go && check "Vietnamese message for CERT_NOT_FOUND defined" 0 || check "Vietnamese message for CERT_NOT_FOUND defined" 1
grep -q "CertStatusActive" internal/domain/certificate.go && check "Certificate status Active defined" 0 || check "Certificate status Active defined" 1
grep -q "CertStatusRevoked" internal/domain/certificate.go && check "Certificate status Revoked defined" 0 || check "Certificate status Revoked defined" 1

# Check step-ca client
grep -q "IssueCertificate" internal/infrastructure/stepca/client.go && check "IssueCertificate method exists" 0 || check "IssueCertificate method exists" 1
grep -q "HealthCheck" internal/infrastructure/stepca/client.go && check "HealthCheck method exists" 0 || check "HealthCheck method exists" 1
grep -q "CircuitBreaker" internal/infrastructure/stepca/client.go && check "Circuit breaker integrated" 0 || check "Circuit breaker integrated" 1

# Check crypto
grep -q "EncryptPrivateKey" internal/infrastructure/crypto/certificate.go && check "EncryptPrivateKey function exists" 0 || check "EncryptPrivateKey function exists" 1
grep -q "DecryptPrivateKey" internal/infrastructure/crypto/certificate.go && check "DecryptPrivateKey function exists" 0 || check "DecryptPrivateKey function exists" 1
grep -q "NewGCM" internal/infrastructure/crypto/certificate.go && check "AES-256-GCM encryption used" 0 || check "AES-256-GCM encryption used" 1

# Check service
grep -q "IssueForUser" internal/service/certificate/service.go && check "IssueForUser method exists" 0 || check "IssueForUser method exists" 1
grep -q "RevokeCertificate" internal/service/certificate/service.go && check "RevokeCertificate method exists" 0 || check "RevokeCertificate method exists" 1

# Check handler
grep -q "GetUserCertificate" internal/handler/certificate_handler.go && check "GetUserCertificate handler exists" 0 || check "GetUserCertificate handler exists" 1
grep -q "IssueCertificate" internal/handler/certificate_handler.go && check "IssueCertificate handler exists" 0 || check "IssueCertificate handler exists" 1
grep -q "StepCAHealthCheck" internal/handler/certificate_handler.go && check "StepCAHealthCheck handler exists" 0 || check "StepCAHealthCheck handler exists" 1

# Check metrics
grep -q "certIssuedTotal" internal/service/certificate/metrics.go && check "Certificate issued metric exists" 0 || check "Certificate issued metric exists" 1
grep -q "certIssuanceLatency" internal/service/certificate/metrics.go && check "Issuance latency metric exists" 0 || check "Issuance latency metric exists" 1
grep -q "stepCAHealthStatus" internal/service/certificate/metrics.go && check "step-ca health status metric exists" 0 || check "step-ca health status metric exists" 1

# ============================================================================
# Phase 3: Migration Content Verification
# ============================================================================
echo ""
echo "=== Phase 3: Database Migration ==="

grep -q "CREATE TABLE.*user_certificates" db/migrations/000007_user_certificates.up.sql && check "user_certificates table created" 0 || check "user_certificates table created" 1
grep -q "private_key_encrypted BYTEA" db/migrations/000007_user_certificates.up.sql && check "Private key encrypted field exists" 0 || check "Private key encrypted field exists" 1
grep -q "certificate_status" db/migrations/000007_user_certificates.up.sql && check "Certificate status enum defined" 0 || check "Certificate status enum defined" 1
grep -q "certificate_audit" db/migrations/000007_user_certificates.up.sql && check "Certificate audit table created" 0 || check "Certificate audit table created" 1
grep -q "tenant_isolation" db/migrations/000007_user_certificates.up.sql && check "RLS policy defined" 0 || check "RLS policy defined" 1

# ============================================================================
# Phase 4: Config Verification
# ============================================================================
echo ""
echo "=== Phase 4: Configuration ==="

grep -q "StepCAConfig" internal/config/config.go && check "StepCAConfig struct exists" 0 || check "StepCAConfig struct exists" 1
grep -q "SignURL" internal/config/config.go && check "sign_url config option exists" 0 || check "sign_url config option exists" 1
grep -q "FailureThreshold" internal/config/config.go && check "Circuit breaker threshold config exists" 0 || check "Circuit breaker threshold config exists" 1

# ============================================================================
# Phase 5: Test Coverage
# ============================================================================
echo ""
echo "=== Phase 5: Test Coverage ==="

go test ./internal/domain/... -v -run Certificate >/dev/null 2>&1 && check "Domain tests pass" 0 || check "Domain tests pass" 1
go test ./internal/infrastructure/crypto/... -v >/dev/null 2>&1 && check "Crypto tests pass" 0 || check "Crypto tests pass" 1
go test ./internal/infrastructure/stepca/... -v >/dev/null 2>&1 && check "step-ca client tests pass" 0 || check "step-ca client tests pass" 1
go test ./internal/service/certificate/... -v >/dev/null 2>&1 && check "Certificate service tests pass" 0 || check "Certificate service tests pass" 1

# ============================================================================
# Phase 6: Build Verification
# ============================================================================
echo ""
echo "=== Phase 6: Build ==="

go build ./... >/dev/null 2>&1 && check "Full build passes" 0 || check "Full build passes" 1
go vet ./internal/... >/dev/null 2>&1 && check "Go vet passes" 0 || check "Go vet passes" 1

# ============================================================================
# Summary
# ============================================================================
echo ""
echo "=================================================================="
echo "                  VERIFICATION SUMMARY"
echo "=================================================================="
echo "Total checks: $TOTAL"
echo "Passed: $PASS"
echo "Failed: $FAIL"
echo "=================================================================="

if [ $FAIL -eq 0 ]; then
    echo ""
    echo "All verification checks PASSED!"
    exit 0
else
    echo ""
    echo "Some verification checks FAILED."
    exit 1
fi
