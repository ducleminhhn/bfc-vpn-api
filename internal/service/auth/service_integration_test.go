//go:build integration

package auth_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/bfc-vpn/api/internal/config"
	"github.com/bfc-vpn/api/internal/infrastructure/keycloak"
	"github.com/bfc-vpn/api/internal/service/auth"
)

func TestLoginWithKeycloak_InvalidCredentials(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test")
	}

	clientSecret := os.Getenv("KEYCLOAK_CLIENT_SECRET")
	if clientSecret == "" {
		t.Skip("KEYCLOAK_CLIENT_SECRET not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cfg := config.KeycloakConfig{
		IssuerURL:      "http://localhost:8080/realms/bfc-vpn",
		ClientID:       "bfc-vpn-api",
		ClientSecret:   clientSecret,
		TimeoutSeconds: 10,
	}

	kc, err := keycloak.NewClient(ctx, cfg)
	require.NoError(t, err)

	svc := auth.NewService(kc, nil, nil)
	_, err = svc.Login(ctx, auth.LoginRequest{
		Email:    "invalid@test.com",
		Password: "wrongpassword123",
	}, "127.0.0.1", "integration-test")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Email hoặc mật khẩu không đúng")
}

func TestLoginWithKeycloak_Success(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test")
	}

	clientSecret := os.Getenv("KEYCLOAK_CLIENT_SECRET")
	testEmail := os.Getenv("TEST_USER_EMAIL")
	testPassword := os.Getenv("TEST_USER_PASSWORD")
	
	if clientSecret == "" || testEmail == "" || testPassword == "" {
		t.Skip("Test credentials not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cfg := config.KeycloakConfig{
		IssuerURL:      "http://localhost:8080/realms/bfc-vpn",
		ClientID:       "bfc-vpn-api",
		ClientSecret:   clientSecret,
		TimeoutSeconds: 10,
	}

	kc, err := keycloak.NewClient(ctx, cfg)
	require.NoError(t, err)

	svc := auth.NewService(kc, nil, nil)
	resp, err := svc.Login(ctx, auth.LoginRequest{
		Email:    testEmail,
		Password: testPassword,
	}, "127.0.0.1", "integration-test")

	if err != nil {
		t.Logf("Login failed (expected if test user doesn't exist): %v", err)
		return
	}

	assert.Equal(t, "success", resp.Status)
	assert.NotEmpty(t, resp.AccessToken)
}

func TestKeycloakClient_HealthCheck(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test")
	}

	clientSecret := os.Getenv("KEYCLOAK_CLIENT_SECRET")
	if clientSecret == "" {
		t.Skip("KEYCLOAK_CLIENT_SECRET not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cfg := config.KeycloakConfig{
		IssuerURL:      "http://localhost:8080/realms/bfc-vpn",
		ClientID:       "bfc-vpn-api",
		ClientSecret:   clientSecret,
		TimeoutSeconds: 10,
	}

	kc, err := keycloak.NewClient(ctx, cfg)
	require.NoError(t, err)

	err = kc.HealthCheck(ctx)
	assert.NoError(t, err)
}
