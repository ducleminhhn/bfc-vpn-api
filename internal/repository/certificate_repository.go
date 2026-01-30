package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/bfc-vpn/api/internal/domain"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// CertificateRepository handles certificate persistence
type CertificateRepository struct {
	db *pgxpool.Pool
}

// NewCertificateRepository creates a new certificate repository
func NewCertificateRepository(db *pgxpool.Pool) *CertificateRepository {
	return &CertificateRepository{db: db}
}

// Create creates a new certificate record
func (r *CertificateRepository) Create(ctx context.Context, cert *domain.UserCertificate) error {
	// Set tenant context for RLS
	if err := r.setTenantContext(ctx, cert.TenantID); err != nil {
		return err
	}

	query := `
		INSERT INTO user_certificates (
			id, user_id, tenant_id, serial_number, subject_cn, subject_o,
			certificate_pem, private_key_encrypted, status,
			issued_at, expires_at, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
	`

	now := time.Now()
	if cert.ID == uuid.Nil {
		cert.ID = uuid.New()
	}
	cert.CreatedAt = now
	cert.UpdatedAt = now

	_, err := r.db.Exec(ctx, query,
		cert.ID,
		cert.UserID,
		cert.TenantID,
		cert.SerialNumber,
		cert.SubjectCN,
		nullString(cert.SubjectO),
		cert.CertificatePEM,
		cert.PrivateKeyEncrypted,
		cert.Status,
		cert.IssuedAt,
		cert.ExpiresAt,
		cert.CreatedAt,
		cert.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	return nil
}

// GetByUserID retrieves the active certificate for a user
func (r *CertificateRepository) GetByUserID(ctx context.Context, userID, tenantID uuid.UUID) (*domain.UserCertificate, error) {
	// Set tenant context for RLS
	if err := r.setTenantContext(ctx, tenantID); err != nil {
		return nil, err
	}

	query := `
		SELECT id, user_id, tenant_id, serial_number, subject_cn, subject_o,
			   certificate_pem, private_key_encrypted, status,
			   issued_at, expires_at, revoked_at, revoke_reason,
			   created_at, updated_at
		FROM user_certificates
		WHERE user_id = $1 AND status = 'active'
		ORDER BY created_at DESC
		LIMIT 1
	`

	row := r.db.QueryRow(ctx, query, userID)
	return r.scanCertificate(row)
}

// GetByID retrieves a certificate by its ID
func (r *CertificateRepository) GetByID(ctx context.Context, certID, tenantID uuid.UUID) (*domain.UserCertificate, error) {
	// Set tenant context for RLS
	if err := r.setTenantContext(ctx, tenantID); err != nil {
		return nil, err
	}

	query := `
		SELECT id, user_id, tenant_id, serial_number, subject_cn, subject_o,
			   certificate_pem, private_key_encrypted, status,
			   issued_at, expires_at, revoked_at, revoke_reason,
			   created_at, updated_at
		FROM user_certificates
		WHERE id = $1
	`

	row := r.db.QueryRow(ctx, query, certID)
	return r.scanCertificate(row)
}

// GetBySerialNumber retrieves a certificate by its serial number
func (r *CertificateRepository) GetBySerialNumber(ctx context.Context, serialNumber string, tenantID uuid.UUID) (*domain.UserCertificate, error) {
	// Set tenant context for RLS
	if err := r.setTenantContext(ctx, tenantID); err != nil {
		return nil, err
	}

	query := `
		SELECT id, user_id, tenant_id, serial_number, subject_cn, subject_o,
			   certificate_pem, private_key_encrypted, status,
			   issued_at, expires_at, revoked_at, revoke_reason,
			   created_at, updated_at
		FROM user_certificates
		WHERE serial_number = $1
	`

	row := r.db.QueryRow(ctx, query, serialNumber)
	return r.scanCertificate(row)
}

// UpdateStatus updates the status of a certificate
func (r *CertificateRepository) UpdateStatus(ctx context.Context, certID, tenantID uuid.UUID, status domain.CertificateStatus, reason string) error {
	// Set tenant context for RLS
	if err := r.setTenantContext(ctx, tenantID); err != nil {
		return err
	}

	var query string
	var args []interface{}

	if status == domain.CertStatusRevoked {
		query = `
			UPDATE user_certificates
			SET status = $1, revoked_at = $2, revoke_reason = $3, updated_at = $4
			WHERE id = $5
		`
		now := time.Now()
		args = []interface{}{status, now, reason, now, certID}
	} else {
		query = `
			UPDATE user_certificates
			SET status = $1, updated_at = $2
			WHERE id = $3
		`
		args = []interface{}{status, time.Now(), certID}
	}

	result, err := r.db.Exec(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("failed to update certificate status: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("certificate not found")
	}

	return nil
}

// RevokeByUserID revokes all active certificates for a user
func (r *CertificateRepository) RevokeByUserID(ctx context.Context, userID, tenantID uuid.UUID, reason string) error {
	// Set tenant context for RLS
	if err := r.setTenantContext(ctx, tenantID); err != nil {
		return err
	}

	query := `
		UPDATE user_certificates
		SET status = 'revoked', revoked_at = $1, revoke_reason = $2, updated_at = $1
		WHERE user_id = $3 AND status = 'active'
	`

	now := time.Now()
	_, err := r.db.Exec(ctx, query, now, reason, userID)
	if err != nil {
		return fmt.Errorf("failed to revoke certificates: %w", err)
	}

	return nil
}

// ListExpiring retrieves certificates expiring within the specified number of days
func (r *CertificateRepository) ListExpiring(ctx context.Context, tenantID uuid.UUID, days int) ([]domain.UserCertificate, error) {
	// Set tenant context for RLS
	if err := r.setTenantContext(ctx, tenantID); err != nil {
		return nil, err
	}

	query := `
		SELECT id, user_id, tenant_id, serial_number, subject_cn, subject_o,
			   certificate_pem, private_key_encrypted, status,
			   issued_at, expires_at, revoked_at, revoke_reason,
			   created_at, updated_at
		FROM user_certificates
		WHERE status = 'active'
		  AND expires_at <= NOW() + INTERVAL '1 day' * $1
		ORDER BY expires_at ASC
	`

	rows, err := r.db.Query(ctx, query, days)
	if err != nil {
		return nil, fmt.Errorf("failed to query expiring certificates: %w", err)
	}
	defer rows.Close()

	var certs []domain.UserCertificate
	for rows.Next() {
		cert, err := r.scanCertificateRow(rows)
		if err != nil {
			return nil, err
		}
		certs = append(certs, *cert)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating certificates: %w", err)
	}

	return certs, nil
}

// CountActive counts the number of active certificates for a tenant
func (r *CertificateRepository) CountActive(ctx context.Context, tenantID uuid.UUID) (int64, error) {
	// Set tenant context for RLS
	if err := r.setTenantContext(ctx, tenantID); err != nil {
		return 0, err
	}

	query := `SELECT COUNT(*) FROM user_certificates WHERE status = 'active'`

	var count int64
	err := r.db.QueryRow(ctx, query).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count active certificates: %w", err)
	}

	return count, nil
}

// setTenantContext sets the tenant context for RLS
func (r *CertificateRepository) setTenantContext(ctx context.Context, tenantID uuid.UUID) error {
	_, err := r.db.Exec(ctx,
		"SELECT set_config('app.current_tenant_id', $1, true)",
		tenantID.String())
	if err != nil {
		return fmt.Errorf("failed to set tenant context: %w", err)
	}
	return nil
}

// scanCertificate scans a certificate from a single row
func (r *CertificateRepository) scanCertificate(row pgx.Row) (*domain.UserCertificate, error) {
	var cert domain.UserCertificate
	var subjectO, revokeReason *string
	var revokedAt *time.Time

	err := row.Scan(
		&cert.ID,
		&cert.UserID,
		&cert.TenantID,
		&cert.SerialNumber,
		&cert.SubjectCN,
		&subjectO,
		&cert.CertificatePEM,
		&cert.PrivateKeyEncrypted,
		&cert.Status,
		&cert.IssuedAt,
		&cert.ExpiresAt,
		&revokedAt,
		&revokeReason,
		&cert.CreatedAt,
		&cert.UpdatedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to scan certificate: %w", err)
	}

	if subjectO != nil {
		cert.SubjectO = *subjectO
	}
	if revokedAt != nil {
		cert.RevokedAt = revokedAt
	}
	if revokeReason != nil {
		cert.RevokeReason = *revokeReason
	}

	return &cert, nil
}

// scanCertificateRow scans a certificate from rows iterator
func (r *CertificateRepository) scanCertificateRow(rows pgx.Rows) (*domain.UserCertificate, error) {
	var cert domain.UserCertificate
	var subjectO, revokeReason *string
	var revokedAt *time.Time

	err := rows.Scan(
		&cert.ID,
		&cert.UserID,
		&cert.TenantID,
		&cert.SerialNumber,
		&cert.SubjectCN,
		&subjectO,
		&cert.CertificatePEM,
		&cert.PrivateKeyEncrypted,
		&cert.Status,
		&cert.IssuedAt,
		&cert.ExpiresAt,
		&revokedAt,
		&revokeReason,
		&cert.CreatedAt,
		&cert.UpdatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to scan certificate: %w", err)
	}

	if subjectO != nil {
		cert.SubjectO = *subjectO
	}
	if revokedAt != nil {
		cert.RevokedAt = revokedAt
	}
	if revokeReason != nil {
		cert.RevokeReason = *revokeReason
	}

	return &cert, nil
}

// ============================================================================
// CERTIFICATE AUDIT REPOSITORY
// ============================================================================

// CertificateAuditRepository handles certificate audit log persistence
type CertificateAuditRepository struct {
	db *pgxpool.Pool
}

// NewCertificateAuditRepository creates a new certificate audit repository
func NewCertificateAuditRepository(db *pgxpool.Pool) *CertificateAuditRepository {
	return &CertificateAuditRepository{db: db}
}

// Log inserts a certificate audit log entry
func (r *CertificateAuditRepository) Log(ctx context.Context, audit *domain.CertificateAudit) error {
	// Set tenant context for RLS
	if err := r.setTenantContext(ctx, audit.TenantID); err != nil {
		return err
	}

	query := `
		INSERT INTO certificate_audit (
			id, certificate_id, user_id, tenant_id, action,
			actor_id, details, client_ip, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`

	if audit.ID == uuid.Nil {
		audit.ID = uuid.New()
	}
	if audit.CreatedAt.IsZero() {
		audit.CreatedAt = time.Now()
	}

	var detailsJSON []byte
	if audit.Details != nil {
		var err error
		detailsJSON, err = json.Marshal(audit.Details)
		if err != nil {
			return fmt.Errorf("failed to marshal audit details: %w", err)
		}
	}

	_, err := r.db.Exec(ctx, query,
		audit.ID,
		audit.CertificateID,
		audit.UserID,
		audit.TenantID,
		audit.Action,
		audit.ActorID,
		detailsJSON,
		audit.ClientIP,
		audit.CreatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to insert certificate audit log: %w", err)
	}

	return nil
}

// GetByCertificateID retrieves audit logs for a certificate
func (r *CertificateAuditRepository) GetByCertificateID(ctx context.Context, certID, tenantID uuid.UUID, limit int) ([]domain.CertificateAudit, error) {
	// Set tenant context for RLS
	if err := r.setTenantContext(ctx, tenantID); err != nil {
		return nil, err
	}

	if limit <= 0 {
		limit = 50
	}

	query := `
		SELECT id, certificate_id, user_id, tenant_id, action,
			   actor_id, details, client_ip, created_at
		FROM certificate_audit
		WHERE certificate_id = $1
		ORDER BY created_at DESC
		LIMIT $2
	`

	rows, err := r.db.Query(ctx, query, certID, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query certificate audit logs: %w", err)
	}
	defer rows.Close()

	return r.scanAuditLogs(rows)
}

// GetByUserID retrieves audit logs for a user
func (r *CertificateAuditRepository) GetByUserID(ctx context.Context, userID, tenantID uuid.UUID, limit int) ([]domain.CertificateAudit, error) {
	// Set tenant context for RLS
	if err := r.setTenantContext(ctx, tenantID); err != nil {
		return nil, err
	}

	if limit <= 0 {
		limit = 50
	}

	query := `
		SELECT id, certificate_id, user_id, tenant_id, action,
			   actor_id, details, client_ip, created_at
		FROM certificate_audit
		WHERE user_id = $1
		ORDER BY created_at DESC
		LIMIT $2
	`

	rows, err := r.db.Query(ctx, query, userID, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query certificate audit logs: %w", err)
	}
	defer rows.Close()

	return r.scanAuditLogs(rows)
}

// setTenantContext sets the tenant context for RLS
func (r *CertificateAuditRepository) setTenantContext(ctx context.Context, tenantID uuid.UUID) error {
	_, err := r.db.Exec(ctx,
		"SELECT set_config('app.current_tenant_id', $1, true)",
		tenantID.String())
	if err != nil {
		return fmt.Errorf("failed to set tenant context: %w", err)
	}
	return nil
}

// scanAuditLogs scans audit logs from rows
func (r *CertificateAuditRepository) scanAuditLogs(rows pgx.Rows) ([]domain.CertificateAudit, error) {
	var logs []domain.CertificateAudit

	for rows.Next() {
		var log domain.CertificateAudit
		var certID, actorID *uuid.UUID
		var detailsJSON []byte

		err := rows.Scan(
			&log.ID,
			&certID,
			&log.UserID,
			&log.TenantID,
			&log.Action,
			&actorID,
			&detailsJSON,
			&log.ClientIP,
			&log.CreatedAt,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan certificate audit log: %w", err)
		}

		if certID != nil {
			log.CertificateID = certID
		}
		if actorID != nil {
			log.ActorID = actorID
		}
		if detailsJSON != nil {
			if err := json.Unmarshal(detailsJSON, &log.Details); err != nil {
				// Log error but continue - don't fail on details parsing
				log.Details = map[string]interface{}{"error": "failed to parse details"}
			}
		}

		logs = append(logs, log)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating certificate audit logs: %w", err)
	}

	return logs, nil
}
