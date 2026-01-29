package localauth

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	localAuthSuccessTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "local_auth_success_total",
			Help: "Total successful local authentications",
		},
		[]string{"mfa_type"},
	)

	localAuthFailedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "local_auth_failed_total",
			Help: "Total failed local authentications",
		},
		[]string{"reason"},
	)

	localAuthLockoutTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "local_auth_lockout_total",
			Help: "Total account lockouts triggered",
		},
	)

	localAuthIPBlockedTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "local_auth_ip_blocked_total",
			Help: "Total IPs blocked for rate limiting",
		},
	)

	credentialStuffingDetectedTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "credential_stuffing_detected_total",
			Help: "Total credential stuffing attacks detected",
		},
	)

	localAuthDependencyFailureTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "local_auth_dependency_failure_total",
			Help: "Total local auth failures due to dependency unavailability",
		},
		[]string{"dependency"},
	)

	localAuthDurationHistogram = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "local_auth_duration_seconds",
			Help:    "Local auth request duration in seconds",
			Buckets: []float64{0.1, 0.3, 0.5, 0.8, 1.0, 2.0},
		},
		[]string{"endpoint", "status"},
	)
)

// RecordDuration records the duration of a local auth request
func RecordDuration(endpoint, status string, duration float64) {
	localAuthDurationHistogram.WithLabelValues(endpoint, status).Observe(duration)
}
