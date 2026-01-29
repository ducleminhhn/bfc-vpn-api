package keycloak_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/bfc-vpn/api/internal/config"
	"github.com/bfc-vpn/api/internal/infrastructure/keycloak"
)

func TestNewClient_InvalidIssuer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	cfg := config.KeycloakConfig{
		IssuerURL:      "http://invalid-host:9999/realms/test",
		ClientID:       "test",
		ClientSecret:   "secret",
		TimeoutSeconds: 2,
	}

	_, err := keycloak.NewClient(ctx, cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create OIDC provider")
}

func TestNewClient_DefaultTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	cfg := config.KeycloakConfig{
		IssuerURL:      "http://invalid-host:9999/realms/test",
		ClientID:       "test",
		ClientSecret:   "secret",
		TimeoutSeconds: 0, // Should default to 10s
	}

	_, err := keycloak.NewClient(ctx, cfg)
	assert.Error(t, err) // Will fail due to invalid host, but tests default timeout path
}

func TestUserClaims_Structure(t *testing.T) {
	claims := keycloak.UserClaims{
		Subject:           "user-123",
		Email:             "test@bfc.vn",
		EmailVerified:     true,
		PreferredUsername: "testuser",
		Name:              "Test User",
		GivenName:         "Test",
		FamilyName:        "User",
	}

	assert.Equal(t, "user-123", claims.Subject)
	assert.Equal(t, "test@bfc.vn", claims.Email)
	assert.True(t, claims.EmailVerified)
	assert.Equal(t, "testuser", claims.PreferredUsername)
	assert.Equal(t, "Test User", claims.Name)
	assert.Equal(t, "Test", claims.GivenName)
	assert.Equal(t, "User", claims.FamilyName)
}

func TestUserClaims_EmptyFields(t *testing.T) {
	claims := keycloak.UserClaims{
		Subject: "user-123",
		Email:   "test@bfc.vn",
	}

	assert.Equal(t, "user-123", claims.Subject)
	assert.Equal(t, "test@bfc.vn", claims.Email)
	assert.False(t, claims.EmailVerified)
	assert.Empty(t, claims.PreferredUsername)
	assert.Empty(t, claims.Name)
}

func TestTokenResponse_Structure(t *testing.T) {
	resp := keycloak.TokenResponse{
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
		IDToken:      "id-token",
		ExpiresIn:    3600,
	}

	assert.Equal(t, "access-token", resp.AccessToken)
	assert.Equal(t, "refresh-token", resp.RefreshToken)
	assert.Equal(t, "id-token", resp.IDToken)
	assert.Equal(t, 3600, resp.ExpiresIn)
}

func TestTokenResponse_MinimalFields(t *testing.T) {
	resp := keycloak.TokenResponse{
		AccessToken: "access-token",
		ExpiresIn:   900, // 15 minutes
	}

	assert.Equal(t, "access-token", resp.AccessToken)
	assert.Equal(t, 900, resp.ExpiresIn)
	assert.Empty(t, resp.RefreshToken)
	assert.Empty(t, resp.IDToken)
}

func TestKeycloakConfig_Required(t *testing.T) {
	cfg := config.KeycloakConfig{
		IssuerURL:      "http://localhost:8080/realms/bfc-vpn",
		ClientID:       "bfc-vpn-api",
		ClientSecret:   "secret",
		RedirectURL:    "http://localhost:8081/callback",
		Scopes:         []string{"openid", "profile", "email"},
		TimeoutSeconds: 10,
	}

	assert.NotEmpty(t, cfg.IssuerURL)
	assert.NotEmpty(t, cfg.ClientID)
	assert.NotEmpty(t, cfg.ClientSecret)
	assert.Len(t, cfg.Scopes, 3)
}
