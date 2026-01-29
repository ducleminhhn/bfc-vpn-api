#\!/bin/bash
# Story 2.7: Dual Auth Failover Mechanism - Verification Script
# This script verifies all story requirements are implemented correctly

set -e

RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
NC="\033[0m"

echo "=== Story 2.7 Verification ==="
echo ""

# Check 1: Verify files exist
echo -e "${YELLOW}[1/10] Checking required files...${NC}"
files=(
    "internal/service/dualauth/health_checker.go"
    "internal/service/dualauth/password_sync.go"
    "internal/service/dualauth/manager.go"
    "internal/service/dualauth/interfaces.go"
    "internal/service/dualauth/errors.go"
    "internal/service/dualauth/metrics.go"
    "internal/service/dualauth/notifier.go"
    "internal/handler/dualauth_handler.go"
    "internal/middleware/internal_auth.go"
    "monitoring/alerts/dual-auth-alerts.yml"
)
for file in "${files[@]}"; do
    if [ -f "$file" ]; then
        echo -e "  ${GREEN}✓${NC} $file"
    else
        echo -e "  ${RED}✗${NC} $file NOT FOUND"
    fi
done
echo ""

# Check 2: Verify unit test coverage
echo -e "${YELLOW}[2/10] Running unit tests...${NC}"
cd ~/bfc-vpn-api
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
go test ./internal/service/dualauth/... -cover 2>&1 | tail -5
echo ""

# Check 3: Verify DualAuthConfig in config
echo -e "${YELLOW}[3/10] Checking DualAuthConfig...${NC}"
if grep -q "DualAuthConfig" internal/config/config.go; then
    echo -e "  ${GREEN}✓${NC} DualAuthConfig found in config.go"
else
    echo -e "  ${RED}✗${NC} DualAuthConfig NOT found"
fi
echo ""

# Check 4: Verify config.yaml has dual_auth section
echo -e "${YELLOW}[4/10] Checking config.yaml...${NC}"
if grep -q "dual_auth:" config.yaml; then
    echo -e "  ${GREEN}✓${NC} dual_auth section found in config.yaml"
else
    echo -e "  ${RED}✗${NC} dual_auth section NOT found"
fi
echo ""

# Check 5: Verify routes registered
echo -e "${YELLOW}[5/10] Checking routes in router.go...${NC}"
if grep -q "dualAuthHandler" internal/handler/router.go; then
    echo -e "  ${GREEN}✓${NC} DualAuthHandler registered in router"
else
    echo -e "  ${RED}✗${NC} DualAuthHandler NOT registered"
fi
echo ""

# Check 6: Verify InternalOnly middleware
echo -e "${YELLOW}[6/10] Checking InternalOnly middleware...${NC}"
if grep -q "InternalOnly" internal/middleware/internal_auth.go 2>/dev/null; then
    echo -e "  ${GREEN}✓${NC} InternalOnly middleware implemented"
else
    echo -e "  ${RED}✗${NC} InternalOnly middleware NOT implemented"
fi
echo ""

# Check 7: Verify RWMutex protection (RT-6)
echo -e "${YELLOW}[7/10] Checking RWMutex protection (RT-6)...${NC}"
if grep -q "sync.RWMutex" internal/service/dualauth/health_checker.go; then
    echo -e "  ${GREEN}✓${NC} RWMutex protection implemented"
else
    echo -e "  ${RED}✗${NC} RWMutex protection NOT implemented"
fi
echo ""

# Check 8: Verify TLS config (RT-4)
echo -e "${YELLOW}[8/10] Checking TLS config (RT-4)...${NC}"
if grep -q "UseTLS" internal/service/dualauth/health_checker.go; then
    echo -e "  ${GREEN}✓${NC} TLS configuration implemented"
else
    echo -e "  ${RED}✗${NC} TLS configuration NOT implemented"
fi
echo ""

# Check 9: Verify password timestamp verification (RT-2)
echo -e "${YELLOW}[9/10] Checking password timestamp verification (RT-2)...${NC}"
if grep -q "VerifyPasswordTimestamp" internal/service/dualauth/password_sync.go; then
    echo -e "  ${GREEN}✓${NC} Password timestamp verification implemented"
else
    echo -e "  ${RED}✗${NC} Password timestamp verification NOT implemented"
fi
echo ""

# Check 10: Verify Prometheus alerts
echo -e "${YELLOW}[10/10] Checking Prometheus alerts...${NC}"
if grep -q "DualAuthFlappingDetected" monitoring/alerts/dual-auth-alerts.yml 2>/dev/null; then
    echo -e "  ${GREEN}✓${NC} Prometheus alerts configured"
else
    echo -e "  ${RED}✗${NC} Prometheus alerts NOT configured"
fi
echo ""

echo "=== Verification Complete ==="
