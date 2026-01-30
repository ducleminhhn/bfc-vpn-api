package stepca

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Client interface for step-ca communication
type Client interface {
	// IssueCertificate issues a new certificate for the given user
	IssueCertificate(ctx context.Context, req *CertificateRequest) (*CertificateResponse, error)
	// HealthCheck verifies step-ca is reachable
	HealthCheck(ctx context.Context) error
	// Close releases resources
	Close() error
	// GetCircuitBreaker returns the circuit breaker for metrics
	GetCircuitBreaker() *CircuitBreaker
}

// CertificateRequest contains the parameters for issuing a certificate
type CertificateRequest struct {
	CommonName   string // User email
	Organization string // Tenant name
	ValidityDays int    // Certificate validity in days
}

// CertificateResponse contains the issued certificate and private key
type CertificateResponse struct {
	CertificatePEM string    // PEM-encoded certificate
	PrivateKeyPEM  []byte    // PEM-encoded private key (plain text - encrypt before storing!)
	SerialNumber   string    // Certificate serial number
	IssuedAt       time.Time // Certificate not before time
	ExpiresAt      time.Time // Certificate not after time
}

// Config contains the configuration for the step-ca client
type Config struct {
	SignURL           string        // step-ca sign endpoint (e.g., https://localhost:9000/1.0/sign)
	HealthURL         string        // step-ca health endpoint (e.g., https://localhost:9000/health)
	ProvisionerName   string        // Provisioner name (e.g., "acme")
	ProvisionerKey    []byte        // Provisioner JWK private key (PEM or JWK format)
	SkipTLSVerify     bool          // Skip TLS verification (dev only)
	CABundle          string        // Path to CA bundle for TLS verification
	ConnectTimeout    time.Duration // Connection timeout
	RequestTimeout    time.Duration // Request timeout
	RetryAttempts     int           // Number of retry attempts
	RetryInitialDelay time.Duration // Initial delay between retries
	RetryMaxDelay     time.Duration // Maximum delay between retries
}

// client implements the Client interface
type client struct {
	config         *Config
	httpClient     *http.Client
	circuitBreaker *CircuitBreaker
	provisionerKey *ecdsa.PrivateKey
}

// NewClient creates a new step-ca client
func NewClient(cfg *Config, cb *CircuitBreaker) (Client, error) {
	if cfg.SignURL == "" {
		return nil, fmt.Errorf("sign URL is required")
	}
	if cfg.HealthURL == "" {
		return nil, fmt.Errorf("health URL is required")
	}
	if cfg.ProvisionerName == "" {
		cfg.ProvisionerName = "acme"
	}
	if cfg.ConnectTimeout <= 0 {
		cfg.ConnectTimeout = 10 * time.Second
	}
	if cfg.RequestTimeout <= 0 {
		cfg.RequestTimeout = 30 * time.Second
	}
	if cfg.RetryAttempts <= 0 {
		cfg.RetryAttempts = 3
	}
	if cfg.RetryInitialDelay <= 0 {
		cfg.RetryInitialDelay = 1 * time.Second
	}
	if cfg.RetryMaxDelay <= 0 {
		cfg.RetryMaxDelay = 10 * time.Second
	}

	// Configure TLS
	tlsConfig := &tls.Config{
		InsecureSkipVerify: cfg.SkipTLSVerify,
	}

	// Security warning for insecure TLS configuration
	if cfg.SkipTLSVerify {
		slog.Warn("step-ca client configured with SkipTLSVerify=true - THIS IS INSECURE AND SHOULD ONLY BE USED IN DEVELOPMENT",
			slog.String("sign_url", cfg.SignURL))
	}

	// Create HTTP client
	httpClient := &http.Client{
		Timeout: cfg.RequestTimeout,
		Transport: &http.Transport{
			TLSClientConfig:     tlsConfig,
			TLSHandshakeTimeout: cfg.ConnectTimeout,
		},
	}

	// Parse provisioner key if provided
	var provKey *ecdsa.PrivateKey
	if len(cfg.ProvisionerKey) > 0 {
		var err error
		provKey, err = parseProvisionerKey(cfg.ProvisionerKey)
		if err != nil {
			return nil, fmt.Errorf("parse provisioner key: %w", err)
		}
	}

	return &client{
		config:         cfg,
		httpClient:     httpClient,
		circuitBreaker: cb,
		provisionerKey: provKey,
	}, nil
}

// IssueCertificate issues a new certificate for the given user
func (c *client) IssueCertificate(ctx context.Context, req *CertificateRequest) (*CertificateResponse, error) {
	// Check circuit breaker
	if !c.circuitBreaker.Allow() {
		return nil, fmt.Errorf("circuit breaker open")
	}

	var lastErr error
	delay := c.config.RetryInitialDelay

	for attempt := 1; attempt <= c.config.RetryAttempts; attempt++ {
		resp, err := c.issueWithRetry(ctx, req)
		if err == nil {
			c.circuitBreaker.RecordSuccess()
			return resp, nil
		}

		lastErr = err

		// Don't retry on context cancellation
		if ctx.Err() != nil {
			break
		}

		// Wait before retry with exponential backoff
		if attempt < c.config.RetryAttempts {
			select {
			case <-ctx.Done():
				break
			case <-time.After(delay):
				delay *= 2
				if delay > c.config.RetryMaxDelay {
					delay = c.config.RetryMaxDelay
				}
			}
		}
	}

	c.circuitBreaker.RecordFailure()
	return nil, fmt.Errorf("certificate issuance failed after %d attempts: %w", c.config.RetryAttempts, lastErr)
}

// issueWithRetry performs a single certificate issuance attempt
func (c *client) issueWithRetry(ctx context.Context, req *CertificateRequest) (*CertificateResponse, error) {
	// 1. Generate ECDSA P-256 key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	// 2. Create CSR
	csrTemplate := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   req.CommonName,
			Organization: []string{req.Organization},
		},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, privateKey)
	if err != nil {
		return nil, fmt.Errorf("create CSR: %w", err)
	}

	// 3. Encode CSR to PEM
	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	// 4. Generate provisioner token (JWT)
	token, err := c.generateProvisionerToken(req.CommonName, req.ValidityDays)
	if err != nil {
		return nil, fmt.Errorf("generate token: %w", err)
	}

	// 5. Call step-ca Sign API
	signReq := &signRequest{
		CSR:      base64.StdEncoding.EncodeToString(csrPEM),
		OTT:      token,
		NotAfter: fmt.Sprintf("%dh", req.ValidityDays*24),
	}

	signResp, err := c.callSignAPI(ctx, signReq)
	if err != nil {
		return nil, fmt.Errorf("sign certificate: %w", err)
	}

	// 6. Parse certificate to extract metadata
	certBlock, _ := pem.Decode([]byte(signResp.CertificatePEM))
	if certBlock == nil {
		return nil, fmt.Errorf("failed to decode certificate PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}

	// 7. Encode private key to PEM
	privateKeyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateKeyDER,
	})

	return &CertificateResponse{
		CertificatePEM: signResp.CertificatePEM,
		PrivateKeyPEM:  privateKeyPEM,
		SerialNumber:   cert.SerialNumber.String(),
		IssuedAt:       cert.NotBefore,
		ExpiresAt:      cert.NotAfter,
	}, nil
}

// signRequest is the request body for step-ca sign API
type signRequest struct {
	CSR      string `json:"csr"`
	OTT      string `json:"ott"` // One-time token
	NotAfter string `json:"notAfter,omitempty"`
}

// signResponse is the response from step-ca sign API
type signResponse struct {
	CertificatePEM string `json:"crt"`
	CaChainPEM     string `json:"ca,omitempty"`
}

// callSignAPI calls the step-ca sign API
func (c *client) callSignAPI(ctx context.Context, req *signRequest) (*signResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.config.SignURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("HTTP request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("sign API returned %d: %s", resp.StatusCode, string(respBody))
	}

	var signResp signResponse
	if err := json.Unmarshal(respBody, &signResp); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	if signResp.CertificatePEM == "" {
		return nil, fmt.Errorf("empty certificate in response")
	}

	return &signResp, nil
}

// generateProvisionerToken generates a JWT token for the provisioner
func (c *client) generateProvisionerToken(subject string, validityDays int) (string, error) {
	now := time.Now()

	claims := jwt.MapClaims{
		"aud":  c.config.SignURL,
		"sub":  subject,
		"iat":  now.Unix(),
		"nbf":  now.Unix(),
		"exp":  now.Add(5 * time.Minute).Unix(),
		"jti":  generateJTI(),
		"sans": []string{subject},
		"step": map[string]interface{}{
			"ra": map[string]interface{}{
				"provisioner": c.config.ProvisionerName,
			},
		},
	}

	// If we have a provisioner key, sign the token
	if c.provisionerKey != nil {
		token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
		return token.SignedString(c.provisionerKey)
	}

	// For testing without a provisioner key, return a placeholder
	// In production, this should always use a real key
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	// Generate a temporary key for signing (dev/test mode)
	tempKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", fmt.Errorf("generate temp key: %w", err)
	}
	return token.SignedString(tempKey)
}

// generateJTI generates a unique JWT ID
func generateJTI() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// HealthCheck verifies step-ca is reachable
func (c *client) HealthCheck(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.config.HealthURL, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("health check returned %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// Close releases resources
func (c *client) Close() error {
	c.httpClient.CloseIdleConnections()
	return nil
}

// GetCircuitBreaker returns the circuit breaker for metrics
func (c *client) GetCircuitBreaker() *CircuitBreaker {
	return c.circuitBreaker
}

// parseProvisionerKey parses a PEM-encoded ECDSA private key
func parseProvisionerKey(keyData []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	switch block.Type {
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		ecKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("not an EC private key")
		}
		return ecKey, nil
	default:
		return nil, fmt.Errorf("unsupported key type: %s", block.Type)
	}
}

// MockClient is a mock implementation for testing
type MockClient struct {
	IssueCertificateFunc func(ctx context.Context, req *CertificateRequest) (*CertificateResponse, error)
	HealthCheckFunc      func(ctx context.Context) error
	CloseFunc            func() error
	CB                   *CircuitBreaker
}

func (m *MockClient) IssueCertificate(ctx context.Context, req *CertificateRequest) (*CertificateResponse, error) {
	if m.IssueCertificateFunc != nil {
		return m.IssueCertificateFunc(ctx, req)
	}
	// Return a mock certificate
	return &CertificateResponse{
		CertificatePEM: "-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----",
		PrivateKeyPEM:  []byte("-----BEGIN EC PRIVATE KEY-----\nMOCK\n-----END EC PRIVATE KEY-----"),
		SerialNumber:   fmt.Sprintf("%d", big.NewInt(time.Now().UnixNano())),
		IssuedAt:       time.Now(),
		ExpiresAt:      time.Now().Add(90 * 24 * time.Hour),
	}, nil
}

func (m *MockClient) HealthCheck(ctx context.Context) error {
	if m.HealthCheckFunc != nil {
		return m.HealthCheckFunc(ctx)
	}
	return nil
}

func (m *MockClient) Close() error {
	if m.CloseFunc != nil {
		return m.CloseFunc()
	}
	return nil
}

func (m *MockClient) GetCircuitBreaker() *CircuitBreaker {
	return m.CB
}
