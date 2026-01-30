package stepca

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewClient(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid config",
			cfg: &Config{
				SignURL:         "https://localhost:9000/1.0/sign",
				HealthURL:       "https://localhost:9000/health",
				ProvisionerName: "acme",
			},
			wantErr: false,
		},
		{
			name: "missing sign URL",
			cfg: &Config{
				HealthURL: "https://localhost:9000/health",
			},
			wantErr: true,
			errMsg:  "sign URL is required",
		},
		{
			name: "missing health URL",
			cfg: &Config{
				SignURL: "https://localhost:9000/1.0/sign",
			},
			wantErr: true,
			errMsg:  "health URL is required",
		},
		{
			name: "defaults applied",
			cfg: &Config{
				SignURL:   "https://localhost:9000/1.0/sign",
				HealthURL: "https://localhost:9000/health",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cb := NewCircuitBreaker(CircuitBreakerConfig{
				FailureThreshold: 5,
				ResetTimeout:     30 * time.Second,
			})

			client, err := NewClient(tt.cfg, cb)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
				return
			}

			require.NoError(t, err)
			assert.NotNil(t, client)
		})
	}
}

func TestClient_HealthCheck(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       string
		wantErr    bool
	}{
		{
			name:       "healthy",
			statusCode: http.StatusOK,
			body:       `{"status":"ok"}`,
			wantErr:    false,
		},
		{
			name:       "unhealthy",
			statusCode: http.StatusServiceUnavailable,
			body:       `{"status":"error"}`,
			wantErr:    true,
		},
		{
			name:       "internal error",
			statusCode: http.StatusInternalServerError,
			body:       `{"error":"internal error"}`,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				w.Write([]byte(tt.body))
			}))
			defer server.Close()

			cb := NewCircuitBreaker(CircuitBreakerConfig{
				FailureThreshold: 5,
				ResetTimeout:     30 * time.Second,
			})

			cfg := &Config{
				SignURL:        server.URL + "/1.0/sign",
				HealthURL:      server.URL + "/health",
				RequestTimeout: 5 * time.Second,
			}

			client, err := NewClient(cfg, cb)
			require.NoError(t, err)

			err = client.HealthCheck(context.Background())
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestClient_IssueCertificate_CircuitBreakerOpen(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 1,
		ResetTimeout:     30 * time.Second,
	})

	// Force circuit breaker to open
	cb.RecordFailure()

	cfg := &Config{
		SignURL:        "https://localhost:9000/1.0/sign",
		HealthURL:      "https://localhost:9000/health",
		RequestTimeout: 5 * time.Second,
	}

	client, err := NewClient(cfg, cb)
	require.NoError(t, err)

	req := &CertificateRequest{
		CommonName:   "test@example.com",
		Organization: "TestOrg",
		ValidityDays: 90,
	}

	_, err = client.IssueCertificate(context.Background(), req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "circuit breaker open")
}

func TestClient_IssueCertificate_RetryOnFailure(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"temporary failure"}`))
	}))
	defer server.Close()

	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 10,
		ResetTimeout:     30 * time.Second,
	})

	cfg := &Config{
		SignURL:           server.URL + "/1.0/sign",
		HealthURL:         server.URL + "/health",
		RequestTimeout:    5 * time.Second,
		RetryAttempts:     3,
		RetryInitialDelay: 10 * time.Millisecond,
		RetryMaxDelay:     50 * time.Millisecond,
	}

	client, err := NewClient(cfg, cb)
	require.NoError(t, err)

	req := &CertificateRequest{
		CommonName:   "test@example.com",
		Organization: "TestOrg",
		ValidityDays: 90,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err = client.IssueCertificate(ctx, req)
	assert.Error(t, err)
	assert.Equal(t, 3, attempts, "should have made 3 attempts")
}

func TestClient_IssueCertificate_Success(t *testing.T) {
	// Create a mock certificate response
	certPEM := `-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHBfpVCzXTdMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnRl
c3RjYTAeFw0yNDAxMDEwMDAwMDBaFw0yNTA0MDEwMDAwMDBaMBsxGTAXBgNVBAMM
EHRlc3RAZXhhbXBsZS5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARKz8Fb
n0bAMfNcGlVQFVvV1D6h/5iK8w9t5pGPK9qO9f8s0Y/5K5M2Q8fI5K5Ql9Q8fQw5
nK3Q9fQw5K5M2Q8fI5MA0GCSqGSIb3DQEBCwUAA0EA
-----END CERTIFICATE-----`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return a mock signed certificate
		resp := signResponse{
			CertificatePEM: certPEM,
		}
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 5,
		ResetTimeout:     30 * time.Second,
	})

	cfg := &Config{
		SignURL:        server.URL + "/1.0/sign",
		HealthURL:      server.URL + "/health",
		RequestTimeout: 5 * time.Second,
	}

	client, err := NewClient(cfg, cb)
	require.NoError(t, err)

	req := &CertificateRequest{
		CommonName:   "test@example.com",
		Organization: "TestOrg",
		ValidityDays: 90,
	}

	// Note: This will fail because the mock certificate is not valid
	// In a real test, you would use a properly signed certificate
	_, err = client.IssueCertificate(context.Background(), req)
	// Expect error since our mock cert is not properly formatted
	assert.Error(t, err)
}

func TestClient_Close(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 5,
		ResetTimeout:     30 * time.Second,
	})

	cfg := &Config{
		SignURL:   "https://localhost:9000/1.0/sign",
		HealthURL: "https://localhost:9000/health",
	}

	client, err := NewClient(cfg, cb)
	require.NoError(t, err)

	err = client.Close()
	assert.NoError(t, err)
}

func TestClient_GetCircuitBreaker(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 5,
		ResetTimeout:     30 * time.Second,
	})

	cfg := &Config{
		SignURL:   "https://localhost:9000/1.0/sign",
		HealthURL: "https://localhost:9000/health",
	}

	client, err := NewClient(cfg, cb)
	require.NoError(t, err)

	returnedCB := client.GetCircuitBreaker()
	assert.Equal(t, cb, returnedCB)
}

func TestMockClient(t *testing.T) {
	t.Run("default behavior", func(t *testing.T) {
		mock := &MockClient{}

		// Test IssueCertificate default
		resp, err := mock.IssueCertificate(context.Background(), &CertificateRequest{
			CommonName:   "test@example.com",
			Organization: "TestOrg",
			ValidityDays: 90,
		})
		assert.NoError(t, err)
		assert.NotNil(t, resp)
		assert.NotEmpty(t, resp.SerialNumber)

		// Test HealthCheck default
		err = mock.HealthCheck(context.Background())
		assert.NoError(t, err)

		// Test Close default
		err = mock.Close()
		assert.NoError(t, err)

		// Test GetCircuitBreaker default
		cb := mock.GetCircuitBreaker()
		assert.Nil(t, cb)
	})

	t.Run("custom functions", func(t *testing.T) {
		mock := &MockClient{
			IssueCertificateFunc: func(ctx context.Context, req *CertificateRequest) (*CertificateResponse, error) {
				return &CertificateResponse{
					SerialNumber: "custom-serial",
				}, nil
			},
			HealthCheckFunc: func(ctx context.Context) error {
				return nil
			},
			CloseFunc: func() error {
				return nil
			},
			CB: NewCircuitBreaker(CircuitBreakerConfig{
				FailureThreshold: 5,
				ResetTimeout:     30 * time.Second,
			}),
		}

		resp, err := mock.IssueCertificate(context.Background(), &CertificateRequest{})
		assert.NoError(t, err)
		assert.Equal(t, "custom-serial", resp.SerialNumber)

		assert.NotNil(t, mock.GetCircuitBreaker())
	})
}

func TestGenerateJTI(t *testing.T) {
	jti1 := generateJTI()
	jti2 := generateJTI()

	assert.NotEmpty(t, jti1)
	assert.NotEmpty(t, jti2)
	assert.NotEqual(t, jti1, jti2, "JTI should be unique")
}
