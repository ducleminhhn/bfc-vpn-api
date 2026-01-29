package dualauth

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// CurrentModeGauge indicates current auth mode (1 for active)
	CurrentModeGauge = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "dual_auth_current_mode",
			Help: "Current authentication mode (1 for active)",
		},
		[]string{"mode"},
	)

	// HealthCheckFailuresTotal counts health check failures
	HealthCheckFailuresTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "dual_auth_health_check_failures_total",
			Help: "Total number of Keycloak health check failures",
		},
	)

	// FailoverTotal counts total failovers
	FailoverTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "dual_auth_failover_total",
			Help: "Total number of failovers to local auth",
		},
	)

	// RecoveryTotal counts total recoveries
	RecoveryTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "dual_auth_recovery_total",
			Help: "Total number of recoveries to Keycloak",
		},
	)

	// PasswordSyncTotal counts password sync operations
	PasswordSyncTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dual_auth_password_sync_total",
			Help: "Total password sync operations",
		},
		[]string{"status"},
	)

	// SyncLatencySeconds measures sync operation latency
	SyncLatencySeconds = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "dual_auth_sync_latency_seconds",
			Help:    "Password sync latency in seconds",
			Buckets: prometheus.DefBuckets,
		},
	)

	// HealthCheckLatencySeconds measures health check latency
	HealthCheckLatencySeconds = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "dual_auth_health_check_latency_seconds",
			Help:    "Keycloak health check latency in seconds",
			Buckets: prometheus.DefBuckets,
		},
	)

	// CompleteOutageTotal counts complete outage events
	CompleteOutageTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "dual_auth_complete_outage_total",
			Help: "Total number of complete auth outages (both providers down)",
		},
	)
)

// InitMetrics initializes metrics with default values
func InitMetrics() {
	// Set initial mode to Keycloak
	CurrentModeGauge.WithLabelValues("keycloak").Set(1)
	CurrentModeGauge.WithLabelValues("local").Set(0)
}

// SetCurrentMode updates the current mode metric
func SetCurrentMode(mode AuthMode) {
	if mode == AuthModeKeycloak {
		CurrentModeGauge.WithLabelValues("keycloak").Set(1)
		CurrentModeGauge.WithLabelValues("local").Set(0)
	} else {
		CurrentModeGauge.WithLabelValues("keycloak").Set(0)
		CurrentModeGauge.WithLabelValues("local").Set(1)
	}
}

// RecordHealthCheckFailure increments the health check failure counter
func RecordHealthCheckFailure() {
	HealthCheckFailuresTotal.Inc()
}

// RecordFailover increments the failover counter and updates mode
func RecordFailover() {
	FailoverTotal.Inc()
	SetCurrentMode(AuthModeLocal)
}

// RecordRecovery increments the recovery counter and updates mode
func RecordRecovery() {
	RecoveryTotal.Inc()
	SetCurrentMode(AuthModeKeycloak)
}

// RecordPasswordSync records a password sync operation
func RecordPasswordSync(success bool) {
	if success {
		PasswordSyncTotal.WithLabelValues("success").Inc()
	} else {
		PasswordSyncTotal.WithLabelValues("failure").Inc()
	}
}

// RecordSyncLatency records sync operation latency
func RecordSyncLatency(seconds float64) {
	SyncLatencySeconds.Observe(seconds)
}

// RecordHealthCheckLatency records health check latency
func RecordHealthCheckLatency(seconds float64) {
	HealthCheckLatencySeconds.Observe(seconds)
}

// RecordCompleteOutage increments the complete outage counter
func RecordCompleteOutage() {
	CompleteOutageTotal.Inc()
}
