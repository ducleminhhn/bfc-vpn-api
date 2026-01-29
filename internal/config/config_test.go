package config_test

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/bfc-vpn/api/internal/config"
)

func TestLoadConfig_RequiresCredentials(t *testing.T) {
	// Clear env vars
	os.Unsetenv("DB_PASSWORD")
	os.Unsetenv("REDIS_PASSWORD")
	os.Unsetenv("KEYCLOAK_CLIENT_SECRET")

	_, err := config.Load()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "DB_PASSWORD")
}

func TestLoadConfig_WithEnvVars(t *testing.T) {
	os.Setenv("DB_PASSWORD", "test-pass")
	os.Setenv("REDIS_PASSWORD", "test-pass")
	os.Setenv("KEYCLOAK_CLIENT_SECRET", "test-secret")
	defer func() {
		os.Unsetenv("DB_PASSWORD")
		os.Unsetenv("REDIS_PASSWORD")
		os.Unsetenv("KEYCLOAK_CLIENT_SECRET")
	}()

	cfg, err := config.Load()
	require.NoError(t, err)
	assert.Equal(t, "test-pass", cfg.Database.Password)
	assert.Equal(t, "require", cfg.Database.SSLMode) // default
	assert.Equal(t, "test-secret", cfg.Keycloak.ClientSecret)
}

func TestDSN(t *testing.T) {
	cfg := config.DatabaseConfig{
		Host:             "localhost",
		Port:             6432,
		Name:             "bfc_vpn",
		User:             "app_user",
		Password:         "secret",
		SSLMode:          "require",
		StatementTimeout: 25 * time.Second,
	}

	dsn := cfg.DSN()
	assert.Contains(t, dsn, "sslmode=require")
	assert.Contains(t, dsn, "postgres://app_user:")
	assert.Contains(t, dsn, "@localhost:6432/bfc_vpn")
	assert.NotContains(t, dsn, "statement_timeout")
}

func TestDSN_WithSSLRootCert(t *testing.T) {
	cfg := config.DatabaseConfig{
		Host:             "localhost",
		Port:             6432,
		Name:             "bfc_vpn",
		User:             "app_user",
		Password:         "secret",
		SSLMode:          "verify-full",
		SSLRootCert:      "/etc/ssl/certs/ca.crt",
		StatementTimeout: 25 * time.Second,
	}

	dsn := cfg.DSN()
	assert.Contains(t, dsn, "sslmode=verify-full")
	assert.Contains(t, dsn, "sslrootcert=/etc/ssl/certs/ca.crt")
}
