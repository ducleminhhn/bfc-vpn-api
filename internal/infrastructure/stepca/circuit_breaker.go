package stepca

import (
	"sync"
	"time"
)

// CircuitState represents the current state of the circuit breaker
type CircuitState int

const (
	StateClosed CircuitState = iota
	StateOpen
	StateHalfOpen
)

func (s CircuitState) String() string {
	switch s {
	case StateClosed:
		return "closed"
	case StateOpen:
		return "open"
	case StateHalfOpen:
		return "half_open"
	default:
		return "unknown"
	}
}

// CircuitBreaker implements the circuit breaker pattern for step-ca communication
type CircuitBreaker struct {
	mu               sync.RWMutex
	state            CircuitState
	failures         int
	failureThreshold int
	resetTimeout     time.Duration
	lastFailure      time.Time
	onStateChange    func(from, to CircuitState)
}

// CircuitBreakerConfig contains configuration for the circuit breaker
type CircuitBreakerConfig struct {
	FailureThreshold int           // Number of failures before opening (default 5)
	ResetTimeout     time.Duration // Time to wait before half-open (default 30s)
	OnStateChange    func(from, to CircuitState)
}

// NewCircuitBreaker creates a new circuit breaker with the given configuration
func NewCircuitBreaker(cfg CircuitBreakerConfig) *CircuitBreaker {
	if cfg.FailureThreshold <= 0 {
		cfg.FailureThreshold = 5
	}
	if cfg.ResetTimeout <= 0 {
		cfg.ResetTimeout = 30 * time.Second
	}
	return &CircuitBreaker{
		state:            StateClosed,
		failureThreshold: cfg.FailureThreshold,
		resetTimeout:     cfg.ResetTimeout,
		onStateChange:    cfg.OnStateChange,
	}
}

// Allow checks if a request should be allowed
func (cb *CircuitBreaker) Allow() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case StateClosed:
		return true
	case StateOpen:
		// Check if enough time has passed to try half-open
		if time.Since(cb.lastFailure) > cb.resetTimeout {
			cb.transitionTo(StateHalfOpen)
			return true
		}
		return false
	case StateHalfOpen:
		// Only allow one request in half-open state
		return true
	default:
		return false
	}
}

// RecordSuccess records a successful request
func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.failures = 0
	if cb.state != StateClosed {
		cb.transitionTo(StateClosed)
	}
}

// RecordFailure records a failed request
func (cb *CircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.failures++
	cb.lastFailure = time.Now()

	if cb.state == StateHalfOpen {
		cb.transitionTo(StateOpen)
		return
	}

	if cb.state == StateClosed && cb.failures >= cb.failureThreshold {
		cb.transitionTo(StateOpen)
	}
}

// State returns the current state of the circuit breaker
func (cb *CircuitBreaker) State() CircuitState {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.state
}

// Failures returns the current failure count
func (cb *CircuitBreaker) Failures() int {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.failures
}

// transitionTo changes the state (must be called with lock held)
func (cb *CircuitBreaker) transitionTo(newState CircuitState) {
	oldState := cb.state
	cb.state = newState
	if cb.onStateChange != nil && oldState != newState {
		cb.onStateChange(oldState, newState)
	}
}

// Reset manually resets the circuit breaker to closed state
func (cb *CircuitBreaker) Reset() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failures = 0
	cb.transitionTo(StateClosed)
}

// ResetTimeout returns the configured reset timeout
func (cb *CircuitBreaker) ResetTimeout() time.Duration {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.resetTimeout
}

// TimeUntilReset returns how long until the circuit breaker might reset
// Returns 0 if circuit is closed or already in half-open
func (cb *CircuitBreaker) TimeUntilReset() time.Duration {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	if cb.state != StateOpen {
		return 0
	}

	elapsed := time.Since(cb.lastFailure)
	if elapsed >= cb.resetTimeout {
		return 0
	}
	return cb.resetTimeout - elapsed
}
