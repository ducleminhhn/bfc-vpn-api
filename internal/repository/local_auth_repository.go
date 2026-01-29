package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/bfc-vpn/api/internal/repository/sqlc"
)

// LocalAuthUserData represents user data for local authentication
type LocalAuthUserData struct {
	ID                  uuid.UUID
	TenantID            uuid.UUID
	Email               string
	PasswordHash        string
	TOTPEnabled         bool
	TOTPSecretEncrypted []byte
	Status              string
	LocalAuthEnabled    bool
	LockedAt            *time.Time
	LockedUntil         *time.Time
	FailedAttempts      int
	LastFailedAt        *time.Time
}

// LocalAuthRepository defines local auth user operations
type LocalAuthRepository interface {
	GetByEmailForLocalAuth(ctx context.Context, email string) (*LocalAuthUserData, error)
	IncrementLocalFailedAttempts(ctx context.Context, userID uuid.UUID) error
	ResetLocalFailedAttempts(ctx context.Context, userID uuid.UUID) error
	LockUserAccount(ctx context.Context, userID uuid.UUID, lockedUntil time.Time) error
	UnlockUserAccount(ctx context.Context, userID uuid.UUID) error
	IsUserLockedForLocalAuth(ctx context.Context, userID uuid.UUID) (bool, error)
	UpdateUserPasswordHash(ctx context.Context, userID uuid.UUID, hash string) error
	Ping(ctx context.Context) error
}

type localAuthRepository struct {
	pool    *pgxpool.Pool
	queries *sqlc.Queries
}

// NewLocalAuthRepository creates a new local auth repository
func NewLocalAuthRepository(pool *pgxpool.Pool) LocalAuthRepository {
	return &localAuthRepository{
		pool:    pool,
		queries: sqlc.New(pool),
	}
}

func (r *localAuthRepository) GetByEmailForLocalAuth(ctx context.Context, email string) (*LocalAuthUserData, error) {
	row, err := r.queries.GetUserByEmailForLocalAuth(ctx, email)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("user not found: %s", email)
		}
		return nil, fmt.Errorf("failed to get user for local auth: %w", err)
	}

	return &LocalAuthUserData{
		ID:                  pgtypeToUUID(row.ID),
		TenantID:            pgtypeToUUID(row.TenantID),
		Email:               row.Email,
		PasswordHash:        textToString(row.PasswordHash),
		TOTPEnabled:         row.TotpEnabled,
		TOTPSecretEncrypted: row.TotpSecretEncrypted,
		Status:              row.Status,
		LocalAuthEnabled:    row.LocalAuthEnabled,
		LockedAt:            timestampToPtr(row.LockedAt),
		LockedUntil:         timestampToPtr(row.LockedUntil),
		FailedAttempts:      int(row.FailedAttempts),
		LastFailedAt:        timestampToPtr(row.LastFailedAt),
	}, nil
}

func (r *localAuthRepository) IncrementLocalFailedAttempts(ctx context.Context, userID uuid.UUID) error {
	return r.queries.IncrementLocalFailedAttempts(ctx, uuidToPgtype(userID))
}

func (r *localAuthRepository) ResetLocalFailedAttempts(ctx context.Context, userID uuid.UUID) error {
	return r.queries.ResetLocalFailedAttempts(ctx, uuidToPgtype(userID))
}

func (r *localAuthRepository) LockUserAccount(ctx context.Context, userID uuid.UUID, lockedUntil time.Time) error {
	return r.queries.LockUserAccount(ctx, sqlc.LockUserAccountParams{
		ID:          uuidToPgtype(userID),
		LockedUntil: pgtype.Timestamptz{Time: lockedUntil, Valid: true},
	})
}

func (r *localAuthRepository) UnlockUserAccount(ctx context.Context, userID uuid.UUID) error {
	return r.queries.UnlockUserAccount(ctx, uuidToPgtype(userID))
}

func (r *localAuthRepository) IsUserLockedForLocalAuth(ctx context.Context, userID uuid.UUID) (bool, error) {
	isLocked, err := r.queries.IsUserLockedForLocalAuth(ctx, uuidToPgtype(userID))
	if err != nil {
		return false, fmt.Errorf("failed to check user lock status: %w", err)
	}
	return isLocked.Bool, nil
}

func (r *localAuthRepository) UpdateUserPasswordHash(ctx context.Context, userID uuid.UUID, hash string) error {
	return r.queries.UpdateUserPasswordHash(ctx, sqlc.UpdateUserPasswordHashParams{
		ID:           uuidToPgtype(userID),
		PasswordHash: pgtype.Text{String: hash, Valid: true},
	})
}

func (r *localAuthRepository) Ping(ctx context.Context) error {
	return r.pool.Ping(ctx)
}
