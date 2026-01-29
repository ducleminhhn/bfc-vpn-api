package repository

import (
	"context"
	"encoding/json"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/bfc-vpn/api/internal/repository/sqlc"
)

// AuditEvent represents a generic audit event (TOTP, auth, etc.)
type AuditEvent struct {
	EventType     string                 // totp_setup_initiated, totp_verify_success, totp_verify_failed, etc.
	ActorID       string                 // User ID
	ActorEmail    string                 // User email
	ClientIP      string                 // Client IP address
	UserAgent     string                 // Browser/client UA
	Success       bool                   // Event succeeded?
	FailureReason string                 // Reason for failure (if any)
	Metadata      map[string]interface{} // Additional data (severity, attempt_count, etc.)
}

// AuditRepository defines audit logging operations
type AuditRepository interface {
	LogLoginAttempt(ctx context.Context, tenantID uuid.UUID, actorID *uuid.UUID, email, clientIP, userAgent string, success bool, failureReason string) error
	GetLoginAttemptsByActorID(ctx context.Context, actorID uuid.UUID, limit int32) ([]sqlc.AuditLog, error)
	CountFailedLoginAttemptsByActorID(ctx context.Context, actorID uuid.UUID, since time.Time) (int64, error)
	LogEvent(ctx context.Context, event AuditEvent) error
	LogTOTPEvent(ctx context.Context, tenantID *uuid.UUID, actorID *uuid.UUID, eventType, clientIP, userAgent string, details map[string]interface{}) error
}

type auditRepository struct {
	pool    *pgxpool.Pool
	queries *sqlc.Queries
}

// NewAuditRepository creates a new audit repository
func NewAuditRepository(pool *pgxpool.Pool) AuditRepository {
	return &auditRepository{
		pool:    pool,
		queries: sqlc.New(pool),
	}
}

func (r *auditRepository) LogLoginAttempt(ctx context.Context, tenantID uuid.UUID, actorID *uuid.UUID, email, clientIP, userAgent string, success bool, failureReason string) error {
	details, _ := json.Marshal(map[string]interface{}{
		"email":          email,
		"success":        success,
		"failure_reason": failureReason,
	})

	// Parse client IP
	var clientIPAddr *netip.Addr
	if ip, err := netip.ParseAddr(clientIP); err == nil {
		clientIPAddr = &ip
	}

	// Actor ID
	var actorUUID pgtype.UUID
	if actorID != nil {
		actorUUID = pgtype.UUID{Bytes: *actorID, Valid: true}
	}

	return r.queries.LogLoginAttempt(ctx, sqlc.LogLoginAttemptParams{
		TenantID:  pgtype.UUID{Bytes: tenantID, Valid: true},
		ActorID:   actorUUID,
		Details:   details,
		IpAddress: clientIPAddr,
		UserAgent: pgtype.Text{String: userAgent, Valid: true},
	})
}

func (r *auditRepository) GetLoginAttemptsByActorID(ctx context.Context, actorID uuid.UUID, limit int32) ([]sqlc.AuditLog, error) {
	return r.queries.GetLoginAttemptsByActorID(ctx, sqlc.GetLoginAttemptsByActorIDParams{
		ActorID: pgtype.UUID{Bytes: actorID, Valid: true},
		Limit:   limit,
	})
}

func (r *auditRepository) CountFailedLoginAttemptsByActorID(ctx context.Context, actorID uuid.UUID, since time.Time) (int64, error) {
	return r.queries.CountFailedLoginAttemptsByActorID(ctx, sqlc.CountFailedLoginAttemptsByActorIDParams{
		ActorID:   pgtype.UUID{Bytes: actorID, Valid: true},
		CreatedAt: pgtype.Timestamptz{Time: since, Valid: true},
	})
}

// LogEvent logs a generic audit event
func (r *auditRepository) LogEvent(ctx context.Context, event AuditEvent) error {
	details := map[string]interface{}{
		"email":          event.ActorEmail,
		"success":        event.Success,
		"failure_reason": event.FailureReason,
	}
	// Merge metadata
	for k, v := range event.Metadata {
		details[k] = v
	}

	var actorUUID *uuid.UUID
	if event.ActorID != "" {
		if parsed, err := uuid.Parse(event.ActorID); err == nil {
			actorUUID = &parsed
		}
	}

	return r.LogTOTPEvent(ctx, nil, actorUUID, event.EventType, event.ClientIP, event.UserAgent, details)
}

// LogTOTPEvent logs TOTP-specific events
func (r *auditRepository) LogTOTPEvent(ctx context.Context, tenantID *uuid.UUID, actorID *uuid.UUID, eventType, clientIP, userAgent string, details map[string]interface{}) error {
	detailsJSON, _ := json.Marshal(details)

	// Parse client IP
	var clientIPAddr *netip.Addr
	if ip, err := netip.ParseAddr(clientIP); err == nil {
		clientIPAddr = &ip
	}

	// Tenant ID (use COALESCE in SQL for default)
	var tenantValue interface{}
	if tenantID != nil {
		tenantValue = pgtype.UUID{Bytes: *tenantID, Valid: true}
	}

	// Actor ID
	var actorUUID pgtype.UUID
	if actorID != nil {
		actorUUID = pgtype.UUID{Bytes: *actorID, Valid: true}
	}

	return r.queries.LogTOTPEvent(ctx, sqlc.LogTOTPEventParams{
		Column1:   tenantValue,
		Action:    eventType,
		ActorID:   actorUUID,
		Details:   detailsJSON,
		IpAddress: clientIPAddr,
		UserAgent: pgtype.Text{String: userAgent, Valid: true},
	})
}
