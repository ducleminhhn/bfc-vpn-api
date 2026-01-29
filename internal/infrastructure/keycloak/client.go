package keycloak

import (
	"context"
	"fmt"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"github.com/bfc-vpn/api/internal/config"
)

type Client struct {
	provider     *oidc.Provider
	verifier     *oidc.IDTokenVerifier
	oauth2Config oauth2.Config
	cfg          config.KeycloakConfig
	timeout      time.Duration
}

func NewClient(ctx context.Context, cfg config.KeycloakConfig) (*Client, error) {
	// Apply timeout for provider initialization
	timeout := time.Duration(cfg.TimeoutSeconds) * time.Second
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	initCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	provider, err := oidc.NewProvider(initCtx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC provider: %w", err)
	}

	verifier := provider.Verifier(&oidc.Config{
		ClientID: cfg.ClientID,
	})

	oauth2Config := oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       cfg.Scopes,
	}

	return &Client{
		provider:     provider,
		verifier:     verifier,
		oauth2Config: oauth2Config,
		cfg:          cfg,
		timeout:      timeout,
	}, nil
}

// TokenResponse holds the authentication result
type TokenResponse struct {
	AccessToken  string
	RefreshToken string
	IDToken      string
	ExpiresIn    int
}

// UserClaims holds extracted user info from ID token
type UserClaims struct {
	Subject           string `json:"sub"`
	Email             string `json:"email"`
	EmailVerified     bool   `json:"email_verified"`
	PreferredUsername string `json:"preferred_username"`
	Name              string `json:"name"`
	GivenName         string `json:"given_name"`
	FamilyName        string `json:"family_name"`
}

// ExchangePassword performs Resource Owner Password Credentials grant
func (c *Client) ExchangePassword(ctx context.Context, username, password string) (*TokenResponse, error) {
	// Apply timeout for token exchange
	timeoutCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	token, err := c.oauth2Config.PasswordCredentialsToken(timeoutCtx, username, password)
	if err != nil {
		return nil, fmt.Errorf("password credentials exchange failed: %w", err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("no id_token in response")
	}

	return &TokenResponse{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		IDToken:      rawIDToken,
		ExpiresIn:    int(time.Until(token.Expiry).Seconds()),
	}, nil
}

// VerifyIDToken verifies and extracts claims from ID token
func (c *Client) VerifyIDToken(ctx context.Context, rawIDToken string) (*UserClaims, error) {
	// Apply timeout for token verification
	timeoutCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	idToken, err := c.verifier.Verify(timeoutCtx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("ID token verification failed: %w", err)
	}

	var claims UserClaims
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to extract claims: %w", err)
	}

	return &claims, nil
}

// HealthCheck verifies Keycloak is accessible by fetching OIDC discovery
func (c *Client) HealthCheck(ctx context.Context) error {
	timeoutCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// Re-fetch provider to verify Keycloak is reachable
	_, err := oidc.NewProvider(timeoutCtx, c.cfg.IssuerURL)
	if err != nil {
		return fmt.Errorf("keycloak health check failed: %w", err)
	}
	return nil
}

// GetIssuerURL returns the configured issuer URL
func (c *Client) GetIssuerURL() string {
	return c.cfg.IssuerURL
}
