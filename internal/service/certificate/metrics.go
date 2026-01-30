package certificate

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// certIssuedTotal tracks total certificates issued
	certIssuedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "bfc_vpn",
			Subsystem: "certificate",
			Name:      "issued_total",
			Help:      "Total certificates issued",
		},
		[]string{"status"}, // success, failed
	)

	// certRevokedTotal tracks total certificates revoked
	certRevokedTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Namespace: "bfc_vpn",
			Subsystem: "certificate",
			Name:      "revoked_total",
			Help:      "Total certificates revoked",
		},
	)

	// certIssuanceLatency tracks certificate issuance latency
	certIssuanceLatency = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: "bfc_vpn",
			Subsystem: "certificate",
			Name:      "issuance_latency_seconds",
			Help:      "Certificate issuance latency in seconds",
			Buckets:   []float64{0.1, 0.5, 1, 2, 5, 10, 30},
		},
	)

	// certActiveGauge tracks number of active certificates
	certActiveGauge = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "bfc_vpn",
			Subsystem: "certificate",
			Name:      "active_count",
			Help:      "Number of active certificates",
		},
	)

	// certExpiringGauge tracks certificates expiring soon (within 30 days)
	certExpiringGauge = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "bfc_vpn",
			Subsystem: "certificate",
			Name:      "expiring_soon_count",
			Help:      "Number of certificates expiring within 30 days",
		},
	)

	// certCircuitBreakerState tracks step-ca circuit breaker state
	certCircuitBreakerState = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "bfc_vpn",
			Subsystem: "certificate",
			Name:      "circuit_breaker_state",
			Help:      "step-ca circuit breaker state (1=active)",
		},
		[]string{"state"}, // closed, open, half_open
	)

	// stepCAHealthStatus tracks step-ca health (1=healthy, 0=unhealthy)
	stepCAHealthStatus = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "bfc_vpn",
			Subsystem: "stepca",
			Name:      "health_status",
			Help:      "step-ca health status (1=healthy, 0=unhealthy)",
		},
	)

	// stepCALatency tracks step-ca API latency
	stepCALatency = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: "bfc_vpn",
			Subsystem: "stepca",
			Name:      "latency_seconds",
			Help:      "step-ca API latency in seconds",
			Buckets:   []float64{0.01, 0.05, 0.1, 0.5, 1, 2, 5},
		},
	)

	// certRequestsTotal tracks certificate API requests
	certRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "bfc_vpn",
			Subsystem: "certificate",
			Name:      "requests_total",
			Help:      "Total certificate API requests",
		},
		[]string{"operation", "status"}, // operation: issue, get, revoke; status: success, failed
	)
)

// RecordCertificateIssued records a certificate issuance result
func RecordCertificateIssued(success bool) {
	if success {
		certIssuedTotal.WithLabelValues("success").Inc()
	} else {
		certIssuedTotal.WithLabelValues("failed").Inc()
	}
}

// RecordCertificateRevoked records a certificate revocation
func RecordCertificateRevoked() {
	certRevokedTotal.Inc()
}

// RecordIssuanceLatency records certificate issuance latency
func RecordIssuanceLatency(seconds float64) {
	certIssuanceLatency.Observe(seconds)
}

// SetActiveCertificates sets the active certificate count
func SetActiveCertificates(count int64) {
	certActiveGauge.Set(float64(count))
}

// SetExpiringCertificates sets the expiring certificate count
func SetExpiringCertificates(count int) {
	certExpiringGauge.Set(float64(count))
}

// SetCircuitBreakerState sets the circuit breaker state
func SetCircuitBreakerState(state string) {
	// Reset all states
	certCircuitBreakerState.WithLabelValues("closed").Set(0)
	certCircuitBreakerState.WithLabelValues("open").Set(0)
	certCircuitBreakerState.WithLabelValues("half_open").Set(0)

	// Set current state
	certCircuitBreakerState.WithLabelValues(state).Set(1)
}

// SetStepCAHealthStatus sets the step-ca health status
func SetStepCAHealthStatus(healthy bool) {
	if healthy {
		stepCAHealthStatus.Set(1)
	} else {
		stepCAHealthStatus.Set(0)
	}
}

// RecordStepCALatency records step-ca API latency
func RecordStepCALatency(seconds float64) {
	stepCALatency.Observe(seconds)
}

// RecordCertificateRequest records a certificate API request
func RecordCertificateRequest(operation string, success bool) {
	status := "success"
	if !success {
		status = "failed"
	}
	certRequestsTotal.WithLabelValues(operation, status).Inc()
}
