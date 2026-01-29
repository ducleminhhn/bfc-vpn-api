package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/bfc-vpn/api/internal/domain"
	"github.com/bfc-vpn/api/internal/repository/sqlc"
)

// UserRepository defines user data operations
type UserRepository interface {
	GetByEmail(ctx context.Context, email string) (*domain.User, error)
	GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error)
	GetByKeycloakID(ctx context.Context, keycloakID string) (*domain.User, error)
	Create(ctx context.Context, user *domain.User) error
	UpdateKeycloakID(ctx context.Context, userID uuid.UUID, keycloakID string) error
	UpdateLastLogin(ctx context.Context, userID uuid.UUID) error
	EnableTOTP(ctx context.Context, userID uuid.UUID, encryptedSecret []byte) error
	DisableTOTP(ctx context.Context, userID uuid.UUID) error
}

type userRepository struct {
	pool    *pgxpool.Pool
	queries *sqlc.Queries
}

// NewUserRepository creates a new user repository
func NewUserRepository(pool *pgxpool.Pool) UserRepository {
	return &userRepository{
		pool:    pool,
		queries: sqlc.New(pool),
	}
}

func (r *userRepository) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	row, err := r.queries.GetUserByEmail(ctx, email)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("user not found: %s", email)
		}
		return nil, fmt.Errorf("failed to get user by email: %w", err)
	}
	return mapEmailRowToUser(row), nil
}

func (r *userRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	row, err := r.queries.GetUserByID(ctx, uuidToPgtype(id))
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("user not found: %s", id.String())
		}
		return nil, fmt.Errorf("failed to get user by id: %w", err)
	}
	return mapIDRowToUser(row), nil
}

func (r *userRepository) GetByKeycloakID(ctx context.Context, keycloakID string) (*domain.User, error) {
	// Parse keycloakID as UUID
	kcID, err := uuid.Parse(keycloakID)
	if err != nil {
		return nil, fmt.Errorf("invalid keycloak_id format: %w", err)
	}
	
	row, err := r.queries.GetUserByKeycloakID(ctx, uuidToPgtype(kcID))
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("user not found with keycloak_id: %s", keycloakID)
		}
		return nil, fmt.Errorf("failed to get user by keycloak_id: %w", err)
	}
	return mapKeycloakRowToUser(row), nil
}

func (r *userRepository) Create(ctx context.Context, user *domain.User) error {
	// Parse KeycloakID as UUID
	var keycloakUUID pgtype.UUID
	if user.KeycloakID != "" {
		if kcID, err := uuid.Parse(user.KeycloakID); err == nil {
			keycloakUUID = uuidToPgtype(kcID)
		}
	}
	
	_, err := r.queries.CreateUser(ctx, sqlc.CreateUserParams{
		ID:         uuidToPgtype(user.ID),
		TenantID:   uuidToPgtype(user.TenantID),
		Email:      user.Email,
		FullName:   pgtype.Text{String: user.FullName, Valid: user.FullName != ""},
		KeycloakID: keycloakUUID,
		Status:     string(user.Status),
	})
	return err
}

func (r *userRepository) UpdateKeycloakID(ctx context.Context, userID uuid.UUID, keycloakID string) error {
	// Parse keycloakID as UUID
	var keycloakUUID pgtype.UUID
	if keycloakID != "" {
		if kcID, err := uuid.Parse(keycloakID); err == nil {
			keycloakUUID = uuidToPgtype(kcID)
		}
	}
	
	return r.queries.UpdateUserKeycloakID(ctx, sqlc.UpdateUserKeycloakIDParams{
		ID:         uuidToPgtype(userID),
		KeycloakID: keycloakUUID,
	})
}

func (r *userRepository) UpdateLastLogin(ctx context.Context, userID uuid.UUID) error {
	return r.queries.UpdateLastLogin(ctx, uuidToPgtype(userID))
}

func (r *userRepository) EnableTOTP(ctx context.Context, userID uuid.UUID, encryptedSecret []byte) error {
	return r.queries.EnableTOTP(ctx, sqlc.EnableTOTPParams{
		ID:                  uuidToPgtype(userID),
		TotpSecretEncrypted: encryptedSecret,
	})
}

func (r *userRepository) DisableTOTP(ctx context.Context, userID uuid.UUID) error {
	return r.queries.DisableTOTP(ctx, uuidToPgtype(userID))
}

func uuidToPgtype(u uuid.UUID) pgtype.UUID {
	return pgtype.UUID{Bytes: u, Valid: true}
}

func pgtypeToUUID(p pgtype.UUID) uuid.UUID {
	if !p.Valid {
		return uuid.Nil
	}
	return uuid.UUID(p.Bytes)
}

func pgtypeUUIDToString(p pgtype.UUID) string {
	if !p.Valid {
		return ""
	}
	return uuid.UUID(p.Bytes).String()
}

func mapEmailRowToUser(row sqlc.GetUserByEmailRow) *domain.User {
	return &domain.User{
		ID:                  pgtypeToUUID(row.ID),
		TenantID:            pgtypeToUUID(row.TenantID),
		Email:               row.Email,
		PasswordHash:        textToString(row.PasswordHash),
		TOTPSecretEncrypted: row.TotpSecretEncrypted,
		TOTPEnabled:         row.TotpEnabled,
		Status:              domain.UserStatus(row.Status),
		FullName:            textToString(row.FullName),
		KeycloakID:          pgtypeUUIDToString(row.KeycloakID),
		FailedLoginAttempts: int(row.FailedLoginAttempts),
		LockedUntil:         timestampToPtr(row.LockedUntil),
		PasswordChangedAt:   timestampToPtr(row.PasswordChangedAt),
		LastLoginAt:         timestampToPtr(row.LastLoginAt),
		CreatedAt:           row.CreatedAt.Time,
		UpdatedAt:           row.UpdatedAt.Time,
	}
}

func mapIDRowToUser(row sqlc.GetUserByIDRow) *domain.User {
	return &domain.User{
		ID:                  pgtypeToUUID(row.ID),
		TenantID:            pgtypeToUUID(row.TenantID),
		Email:               row.Email,
		PasswordHash:        textToString(row.PasswordHash),
		TOTPSecretEncrypted: row.TotpSecretEncrypted,
		TOTPEnabled:         row.TotpEnabled,
		Status:              domain.UserStatus(row.Status),
		FullName:            textToString(row.FullName),
		KeycloakID:          pgtypeUUIDToString(row.KeycloakID),
		FailedLoginAttempts: int(row.FailedLoginAttempts),
		LockedUntil:         timestampToPtr(row.LockedUntil),
		PasswordChangedAt:   timestampToPtr(row.PasswordChangedAt),
		LastLoginAt:         timestampToPtr(row.LastLoginAt),
		CreatedAt:           row.CreatedAt.Time,
		UpdatedAt:           row.UpdatedAt.Time,
	}
}

func mapKeycloakRowToUser(row sqlc.GetUserByKeycloakIDRow) *domain.User {
	return &domain.User{
		ID:                  pgtypeToUUID(row.ID),
		TenantID:            pgtypeToUUID(row.TenantID),
		Email:               row.Email,
		PasswordHash:        textToString(row.PasswordHash),
		TOTPSecretEncrypted: row.TotpSecretEncrypted,
		TOTPEnabled:         row.TotpEnabled,
		Status:              domain.UserStatus(row.Status),
		FullName:            textToString(row.FullName),
		KeycloakID:          pgtypeUUIDToString(row.KeycloakID),
		FailedLoginAttempts: int(row.FailedLoginAttempts),
		LockedUntil:         timestampToPtr(row.LockedUntil),
		PasswordChangedAt:   timestampToPtr(row.PasswordChangedAt),
		LastLoginAt:         timestampToPtr(row.LastLoginAt),
		CreatedAt:           row.CreatedAt.Time,
		UpdatedAt:           row.UpdatedAt.Time,
	}
}

func textToString(t pgtype.Text) string {
	if t.Valid {
		return t.String
	}
	return ""
}

func timestampToPtr(t pgtype.Timestamptz) *time.Time {
	if !t.Valid {
		return nil
	}
	return &t.Time
}
