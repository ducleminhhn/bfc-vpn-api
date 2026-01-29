package repository_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/bfc-vpn/api/internal/config"
	"github.com/bfc-vpn/api/internal/repository"
)

// Integration test - requires running database
// Skip in CI if DATABASE_URL not set
func TestDB_HealthCheck(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test")
	}

	password := os.Getenv("DB_PASSWORD")
	if password == "" {
		t.Skip("DB_PASSWORD not set, skipping integration test")
	}

	cfg := config.DatabaseConfig{
		Host:             "localhost",
		Port:             6432,
		Name:             "bfc_vpn",
		User:             "app_user",
		Password:         password,
		SSLMode:          "require",
		MaxOpenConns:     5,
		MaxIdleConns:     2,
		ConnMaxLifetime:  5 * time.Minute,
		StatementTimeout: 10 * time.Second,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	db, err := repository.NewDB(ctx, cfg)
	require.NoError(t, err)
	defer db.Close()

	err = db.HealthCheck(ctx)
	assert.NoError(t, err)
}

func TestDB_SetTenant(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test")
	}

	password := os.Getenv("DB_PASSWORD")
	if password == "" {
		t.Skip("DB_PASSWORD not set, skipping integration test")
	}

	cfg := config.DatabaseConfig{
		Host:             "localhost",
		Port:             6432,
		Name:             "bfc_vpn",
		User:             "app_user",
		Password:         password,
		SSLMode:          "require",
		MaxOpenConns:     5,
		MaxIdleConns:     2,
		ConnMaxLifetime:  5 * time.Minute,
		StatementTimeout: 10 * time.Second,
	}

	ctx := context.Background()
	db, err := repository.NewDB(ctx, cfg)
	require.NoError(t, err)
	defer db.Close()

	// Test setting tenant context
	err = db.SetTenant(ctx, "test-tenant-id")
	assert.NoError(t, err)
}
