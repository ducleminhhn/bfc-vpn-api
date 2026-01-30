package certificate

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/bfc-vpn/api/internal/domain"
	"github.com/bfc-vpn/api/internal/infrastructure/crypto"
	"github.com/bfc-vpn/api/internal/infrastructure/stepca"
	"github.com/google/uuid"
)

// CertificateRepository interface for certificate persistence
type CertificateRepository interface {
	Create(ctx context.Context, cert *domain.UserCertificate) error
	GetByUserID(ctx context.Context, userID, tenantID uuid.UUID) (*domain.UserCertificate, error)
	GetByID(ctx context.Context, certID, tenantID uuid.UUID) (*domain.UserCertificate, error)
	UpdateStatus(ctx context.Context, certID, tenantID uuid.UUID, status domain.CertificateStatus, reason string) error
	CountActive(ctx context.Context, tenantID uuid.UUID) (int64, error)
}

// CertificateAuditRepository interface for audit logging
type CertificateAuditRepository interface {
	Log(ctx context.Context, audit *domain.CertificateAudit) error
}

// Service handles certificate business logic
type Service struct {
	stepCAClient   stepca.Client
	certRepo       CertificateRepository
	auditRepo      CertificateAuditRepository
	encryptionKey  []byte
	validityDays   int
	logger         *slog.Logger
}

// Config contains certificate service configuration
type Config struct {
	EncryptionKey     string        // Base64-encoded 32-byte key
	ValidityDays      int           // Default certificate validity
	StepCASignURL     string        // step-ca sign endpoint
	StepCAHealthURL   string        // step-ca health endpoint
	ProvisionerName   string        // step-ca provisioner name
	SkipTLSVerify     bool          // Skip TLS verification (dev only)
	ConnectTimeout    time.Duration
	RequestTimeout    time.Duration
	RetryAttempts     int
	RetryInitialDelay time.Duration
	RetryMaxDelay     time.Duration
	FailureThreshold  int           // Circuit breaker threshold
	ResetTimeout      time.Duration // Circuit breaker reset timeout
}

// NewService creates a new certificate service
func NewService(
	cfg *Config,
	certRepo CertificateRepository,
	auditRepo CertificateAuditRepository,
	logger *slog.Logger,
) (*Service, error) {
	// Decode encryption key
	encKey, err := crypto.DecodeEncryptionKey(cfg.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("invalid encryption key: %w", err)
	}

	// Set defaults
	if cfg.ValidityDays <= 0 || cfg.ValidityDays > 365 {
		cfg.ValidityDays = 90
	}

	// Create circuit breaker
	cb := stepca.NewCircuitBreaker(stepca.CircuitBreakerConfig{
		FailureThreshold: cfg.FailureThreshold,
		ResetTimeout:     cfg.ResetTimeout,
		OnStateChange: func(from, to stepca.CircuitState) {
			logger.Info("Certificate circuit breaker state changed",
				slog.String("from", from.String()),
				slog.String("to", to.String()))
			SetCircuitBreakerState(to.String())
		},
	})

	// Create step-ca client
	stepCAClient, err := stepca.NewClient(&stepca.Config{
		SignURL:           cfg.StepCASignURL,
		HealthURL:         cfg.StepCAHealthURL,
		ProvisionerName:   cfg.ProvisionerName,
		SkipTLSVerify:     cfg.SkipTLSVerify,
		ConnectTimeout:    cfg.ConnectTimeout,
		RequestTimeout:    cfg.RequestTimeout,
		RetryAttempts:     cfg.RetryAttempts,
		RetryInitialDelay: cfg.RetryInitialDelay,
		RetryMaxDelay:     cfg.RetryMaxDelay,
	}, cb)
	if err != nil {
		return nil, fmt.Errorf("create step-ca client: %w", err)
	}

	return &Service{
		stepCAClient:  stepCAClient,
		certRepo:      certRepo,
		auditRepo:     auditRepo,
		encryptionKey: encKey,
		validityDays:  cfg.ValidityDays,
		logger:        logger,
	}, nil
}

// NewServiceWithClient creates a service with a custom step-ca client (for testing)
func NewServiceWithClient(
	client stepca.Client,
	certRepo CertificateRepository,
	auditRepo CertificateAuditRepository,
	encryptionKey []byte,
	validityDays int,
	logger *slog.Logger,
) *Service {
	if validityDays <= 0 || validityDays > 365 {
		validityDays = 90
	}
	return &Service{
		stepCAClient:  client,
		certRepo:      certRepo,
		auditRepo:     auditRepo,
		encryptionKey: encryptionKey,
		validityDays:  validityDays,
		logger:        logger,
	}
}

// IssueForUser issues a new certificate for a user
// If validityDays is nil or 0, uses the default from service config
func (s *Service) IssueForUser(
	ctx context.Context,
	userID, tenantID uuid.UUID,
	email, tenantName, clientIP string,
	actorID *uuid.UUID,
	validityDays *int,
) (*domain.UserCertificate, error) {
	start := time.Now()

	// Check if user already has an active certificate
	existingCert, err := s.certRepo.GetByUserID(ctx, userID, tenantID)
	if err != nil {
		s.logger.Error("Failed to check existing certificate",
			slog.String("user_id", userID.String()),
			slog.Any("error", err))
	}

	// Revoke existing certificate if any
	if existingCert != nil && existingCert.Status == domain.CertStatusActive {
		if err := s.certRepo.UpdateStatus(ctx, existingCert.ID, tenantID, domain.CertStatusRevoked, "Reissued"); err != nil {
			s.logger.Error("Failed to revoke existing certificate",
				slog.String("cert_id", existingCert.ID.String()),
				slog.Any("error", err))
			// Continue with issuance - old cert will expire anyway
		} else {
			s.logger.Info("Revoked existing certificate for reissue",
				slog.String("cert_id", existingCert.ID.String()),
				slog.String("user_id", userID.String()))
		}
	}

	// Determine validity days: use request value if provided, otherwise use default
	certValidityDays := s.validityDays
	if validityDays != nil && *validityDays > 0 {
		certValidityDays = *validityDays
	}

	// Issue new certificate from step-ca
	req := &stepca.CertificateRequest{
		CommonName:   email,
		Organization: tenantName,
		ValidityDays: certValidityDays,
	}

	certResp, err := s.stepCAClient.IssueCertificate(ctx, req)
	if err != nil {
		RecordCertificateIssued(false)
		RecordIssuanceLatency(time.Since(start).Seconds())
		s.logger.Error("Failed to issue certificate from step-ca",
			slog.String("user_id", userID.String()),
			slog.String("email", email),
			slog.Any("error", err))
		return nil, fmt.Errorf("issue certificate: %w", err)
	}

	// Encrypt private key
	encryptedKey, err := crypto.EncryptPrivateKey(certResp.PrivateKeyPEM, s.encryptionKey)
	if err != nil {
		RecordCertificateIssued(false)
		RecordIssuanceLatency(time.Since(start).Seconds())
		s.logger.Error("Failed to encrypt private key",
			slog.String("user_id", userID.String()),
			slog.Any("error", err))
		return nil, fmt.Errorf("encrypt private key: %w", err)
	}

	// Create certificate record
	cert := &domain.UserCertificate{
		ID:                  uuid.New(),
		UserID:              userID,
		TenantID:            tenantID,
		SerialNumber:        certResp.SerialNumber,
		SubjectCN:           email,
		SubjectO:            tenantName,
		CertificatePEM:      certResp.CertificatePEM,
		PrivateKeyEncrypted: encryptedKey,
		Status:              domain.CertStatusActive,
		IssuedAt:            certResp.IssuedAt,
		ExpiresAt:           certResp.ExpiresAt,
	}

	// Save to database
	if err := s.certRepo.Create(ctx, cert); err != nil {
		RecordCertificateIssued(false)
		RecordIssuanceLatency(time.Since(start).Seconds())
		s.logger.Error("Failed to save certificate",
			slog.String("user_id", userID.String()),
			slog.Any("error", err))
		return nil, fmt.Errorf("save certificate: %w", err)
	}

	// Audit log
	if err := s.auditRepo.Log(ctx, &domain.CertificateAudit{
		CertificateID: &cert.ID,
		UserID:        userID,
		TenantID:      tenantID,
		Action:        domain.CertAuditIssued,
		ActorID:       actorID,
		ClientIP:      clientIP,
		Details: map[string]interface{}{
			"serial_number":  cert.SerialNumber,
			"validity_days":  s.validityDays,
			"subject_cn":     email,
			"subject_o":      tenantName,
			"expires_at":     cert.ExpiresAt.Format(time.RFC3339),
		},
	}); err != nil {
		s.logger.Error("Failed to log certificate audit",
			slog.String("cert_id", cert.ID.String()),
			slog.Any("error", err))
		// Don't fail issuance for audit failure
	}

	// Record metrics
	RecordCertificateIssued(true)
	RecordIssuanceLatency(time.Since(start).Seconds())

	s.logger.Info("Certificate issued successfully",
		slog.String("cert_id", cert.ID.String()),
		slog.String("user_id", userID.String()),
		slog.String("serial", cert.SerialNumber),
		slog.Int("validity_days", s.validityDays))

	return cert, nil
}

// GetUserCertificate retrieves the active certificate for a user
func (s *Service) GetUserCertificate(ctx context.Context, userID, tenantID uuid.UUID) (*domain.UserCertificate, error) {
	cert, err := s.certRepo.GetByUserID(ctx, userID, tenantID)
	if err != nil {
		RecordCertificateRequest("get", false)
		return nil, err
	}
	if cert == nil {
		RecordCertificateRequest("get", false)
		return nil, nil
	}

	RecordCertificateRequest("get", true)
	return cert, nil
}

// RevokeCertificate revokes a user's certificate
func (s *Service) RevokeCertificate(
	ctx context.Context,
	userID, tenantID uuid.UUID,
	reason, clientIP string,
	actorID *uuid.UUID,
) error {
	// Get existing certificate
	cert, err := s.certRepo.GetByUserID(ctx, userID, tenantID)
	if err != nil {
		RecordCertificateRequest("revoke", false)
		return fmt.Errorf("get certificate: %w", err)
	}
	if cert == nil {
		RecordCertificateRequest("revoke", false)
		return fmt.Errorf("no active certificate found")
	}

	// Update status to revoked
	if err := s.certRepo.UpdateStatus(ctx, cert.ID, tenantID, domain.CertStatusRevoked, reason); err != nil {
		RecordCertificateRequest("revoke", false)
		return fmt.Errorf("revoke certificate: %w", err)
	}

	// Audit log
	if err := s.auditRepo.Log(ctx, &domain.CertificateAudit{
		CertificateID: &cert.ID,
		UserID:        userID,
		TenantID:      tenantID,
		Action:        domain.CertAuditRevoked,
		ActorID:       actorID,
		ClientIP:      clientIP,
		Details: map[string]interface{}{
			"serial_number": cert.SerialNumber,
			"reason":        reason,
		},
	}); err != nil {
		s.logger.Error("Failed to log certificate audit",
			slog.String("cert_id", cert.ID.String()),
			slog.Any("error", err))
	}

	RecordCertificateRevoked()
	RecordCertificateRequest("revoke", true)

	s.logger.Info("Certificate revoked",
		slog.String("cert_id", cert.ID.String()),
		slog.String("user_id", userID.String()),
		slog.String("reason", reason))

	return nil
}

// HealthCheck checks step-ca health
func (s *Service) HealthCheck(ctx context.Context) (*domain.StepCAHealthCheck, error) {
	start := time.Now()

	err := s.stepCAClient.HealthCheck(ctx)
	latencyMS := time.Since(start).Milliseconds()

	RecordStepCALatency(time.Since(start).Seconds())

	cb := s.stepCAClient.GetCircuitBreaker()
	cbState := "unknown"
	if cb != nil {
		cbState = cb.State().String()
	}

	if err != nil {
		SetStepCAHealthStatus(false)
		return &domain.StepCAHealthCheck{
			Status:         domain.StepCAUnhealthy,
			LatencyMS:      latencyMS,
			CircuitBreaker: cbState,
			Error:          err.Error(),
			ErrorCode:      domain.ErrCodeCertIssuanceFailed,
			MessageVI:      domain.MsgCertIssuanceFailed,
		}, nil
	}

	SetStepCAHealthStatus(true)
	return &domain.StepCAHealthCheck{
		Status:         domain.StepCAHealthy,
		LatencyMS:      latencyMS,
		CircuitBreaker: cbState,
	}, nil
}

// GetCircuitBreakerState returns the current circuit breaker state
func (s *Service) GetCircuitBreakerState() string {
	cb := s.stepCAClient.GetCircuitBreaker()
	if cb == nil {
		return "unknown"
	}
	return cb.State().String()
}

// GetCircuitBreakerResetTimeout returns the time until circuit breaker might reset
func (s *Service) GetCircuitBreakerResetTimeout() time.Duration {
	cb := s.stepCAClient.GetCircuitBreaker()
	if cb == nil {
		return 0
	}
	return cb.TimeUntilReset()
}

// DecryptPrivateKey decrypts the private key of a certificate
func (s *Service) DecryptPrivateKey(encryptedKey []byte) ([]byte, error) {
	return crypto.DecryptPrivateKey(encryptedKey, s.encryptionKey)
}

// Close releases resources
func (s *Service) Close() error {
	if s.stepCAClient != nil {
		return s.stepCAClient.Close()
	}
	return nil
}

// UpdateActiveCertificateCount updates the active certificate count metric
func (s *Service) UpdateActiveCertificateCount(ctx context.Context, tenantID uuid.UUID) {
	count, err := s.certRepo.CountActive(ctx, tenantID)
	if err != nil {
		s.logger.Error("Failed to count active certificates", slog.Any("error", err))
		return
	}
	SetActiveCertificates(count)
}
