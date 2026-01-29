package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/bfc-vpn/api/internal/domain"
	"github.com/bfc-vpn/api/internal/repository/sqlc"
)

// RecoveryRepository defines recovery codes data operations
type RecoveryRepository interface {
	CreateCodes(ctx context.Context, userID uuid.UUID, codeHashes []string) error
	GetUnusedCodes(ctx context.Context, userID uuid.UUID) ([]*domain.RecoveryCode, error)
	GetAllCodes(ctx context.Context, userID uuid.UUID) ([]*domain.RecoveryCode, error)
	MarkCodeUsed(ctx context.Context, userID, codeID uuid.UUID) (bool, error)
	DeleteAllCodes(ctx context.Context, userID uuid.UUID) error
	CountUnusedCodes(ctx context.Context, userID uuid.UUID) (int64, error)
}

type recoveryRepository struct {
	pool    *pgxpool.Pool
	queries *sqlc.Queries
}

// NewRecoveryRepository creates a new recovery codes repository
func NewRecoveryRepository(pool *pgxpool.Pool) RecoveryRepository {
	return &recoveryRepository{
		pool:    pool,
		queries: sqlc.New(pool),
	}
}

// CreateCodes creates 10 recovery codes for a user (batch insert)
func (r *recoveryRepository) CreateCodes(ctx context.Context, userID uuid.UUID, codeHashes []string) error {
	for i, hash := range codeHashes {
		err := r.queries.CreateRecoveryCode(ctx, sqlc.CreateRecoveryCodeParams{
			UserID:    uuidToPgtype(userID),
			CodeHash:  hash,
			CodeIndex: int16(i),
		})
		if err != nil {
			return fmt.Errorf("failed to create recovery code %d: %w", i, err)
		}
	}
	return nil
}

// GetUnusedCodes returns all unused recovery codes for a user
func (r *recoveryRepository) GetUnusedCodes(ctx context.Context, userID uuid.UUID) ([]*domain.RecoveryCode, error) {
	rows, err := r.queries.GetUnusedRecoveryCodesByUserID(ctx, uuidToPgtype(userID))
	if err != nil {
		return nil, fmt.Errorf("failed to get unused recovery codes: %w", err)
	}
	return r.mapRowsToDomain(rows), nil
}

// GetAllCodes returns all recovery codes for a user (for admin view)
func (r *recoveryRepository) GetAllCodes(ctx context.Context, userID uuid.UUID) ([]*domain.RecoveryCode, error) {
	rows, err := r.queries.GetAllRecoveryCodesByUserID(ctx, uuidToPgtype(userID))
	if err != nil {
		return nil, fmt.Errorf("failed to get all recovery codes: %w", err)
	}
	return r.mapRowsToDomain(rows), nil
}

// MarkCodeUsed marks a recovery code as used (one-time use)
func (r *recoveryRepository) MarkCodeUsed(ctx context.Context, userID, codeID uuid.UUID) (bool, error) {
	rows, err := r.queries.MarkRecoveryCodeUsed(ctx, sqlc.MarkRecoveryCodeUsedParams{
		UserID: uuidToPgtype(userID),
		ID:     uuidToPgtype(codeID),
	})
	if err != nil {
		return false, fmt.Errorf("failed to mark recovery code used: %w", err)
	}
	return rows > 0, nil
}

// DeleteAllCodes deletes all recovery codes for a user (before regeneration)
func (r *recoveryRepository) DeleteAllCodes(ctx context.Context, userID uuid.UUID) error {
	err := r.queries.DeleteRecoveryCodesByUserID(ctx, uuidToPgtype(userID))
	if err != nil {
		return fmt.Errorf("failed to delete recovery codes: %w", err)
	}
	return nil
}

// CountUnusedCodes counts remaining unused recovery codes
func (r *recoveryRepository) CountUnusedCodes(ctx context.Context, userID uuid.UUID) (int64, error) {
	count, err := r.queries.CountUnusedRecoveryCodes(ctx, uuidToPgtype(userID))
	if err != nil {
		return 0, fmt.Errorf("failed to count unused recovery codes: %w", err)
	}
	return count, nil
}

// mapRowsToDomain converts sqlc rows to domain models
func (r *recoveryRepository) mapRowsToDomain(rows []sqlc.RecoveryCode) []*domain.RecoveryCode {
	codes := make([]*domain.RecoveryCode, len(rows))
	for i, row := range rows {
		codes[i] = &domain.RecoveryCode{
			ID:        pgtypeToUUID(row.ID),
			UserID:    pgtypeToUUID(row.UserID),
			CodeHash:  row.CodeHash,
			CodeIndex: int(row.CodeIndex),
			UsedAt:    pgtypeTimestamptzToPtr(row.UsedAt),
			CreatedAt: row.CreatedAt.Time,
		}
	}
	return codes
}

// pgtypeTimestamptzToPtr converts pgtype.Timestamptz to *time.Time
func pgtypeTimestamptzToPtr(ts pgtype.Timestamptz) *time.Time {
	if !ts.Valid {
		return nil
	}
	return &ts.Time
}
