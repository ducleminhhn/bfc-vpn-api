package dualauth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInitMetrics(t *testing.T) {
	// Should not panic
	InitMetrics()
}

func TestSetCurrentMode(t *testing.T) {
	// Test Keycloak mode
	SetCurrentMode(AuthModeKeycloak)
	
	// Test Local mode
	SetCurrentMode(AuthModeLocal)
}

func TestRecordHealthCheckFailure(t *testing.T) {
	RecordHealthCheckFailure()
}

func TestRecordFailover(t *testing.T) {
	RecordFailover()
}

func TestRecordRecovery(t *testing.T) {
	RecordRecovery()
}

func TestRecordPasswordSync(t *testing.T) {
	RecordPasswordSync(true)
	RecordPasswordSync(false)
}

func TestRecordSyncLatency(t *testing.T) {
	RecordSyncLatency(0.5)
}

func TestRecordHealthCheckLatency(t *testing.T) {
	RecordHealthCheckLatency(0.1)
}

func TestRecordCompleteOutage(t *testing.T) {
	RecordCompleteOutage()
}

func TestDefaultConfigs(t *testing.T) {
	hc := DefaultHealthCheckConfig()
	assert.NotNil(t, hc)
	assert.Equal(t, 3, hc.FailureThreshold)
	assert.Equal(t, 3, hc.RecoveryThreshold)
	assert.Equal(t, 3, hc.MaxFailoversPerHour)
	
	pc := DefaultPasswordSyncConfig()
	assert.NotNil(t, pc)
	assert.Equal(t, "bfc-vpn", pc.KeycloakRealm)
	
	mc := DefaultDualAuthManagerConfig()
	assert.NotNil(t, mc)
	assert.Equal(t, 10, mc.HealthCheckIntervalSecs)
}
