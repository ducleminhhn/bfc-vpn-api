package dualauth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"go.uber.org/zap"
)

// WebhookNotifier sends alerts to webhook endpoints
type WebhookNotifier struct {
	webhookURL string
	httpClient *http.Client
	logger     *zap.Logger
}

// NewWebhookNotifier creates a new webhook notifier
func NewWebhookNotifier(webhookURL string, logger *zap.Logger) *WebhookNotifier {
	return &WebhookNotifier{
		webhookURL: webhookURL,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		logger: logger,
	}
}

// SendAlert sends an alert to the configured webhook
func (n *WebhookNotifier) SendAlert(ctx context.Context, alert AlertConfig) error {
	if n.webhookURL == "" {
		n.logger.Warn("Webhook URL not configured, skipping alert",
			zap.String("title", alert.Title))
		return nil
	}

	payload := map[string]interface{}{
		"level":     alert.Level,
		"title":     alert.Title,
		"message":   alert.Message,
		"channel":   alert.Channel,
		"timestamp": time.Now().Format(time.RFC3339),
		"source":    "bfc-vpn-api-dualauth",
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal alert: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.webhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := n.httpClient.Do(req)
	if err != nil {
		n.logger.Error("Failed to send alert webhook",
			zap.String("title", alert.Title),
			zap.Error(err))
		return fmt.Errorf("failed to send webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}

	n.logger.Info("Alert sent successfully",
		zap.String("title", alert.Title),
		zap.String("level", alert.Level))

	return nil
}

// NoOpNotifier is a notifier that does nothing (for testing/fallback)
type NoOpNotifier struct {
	logger *zap.Logger
}

// NewNoOpNotifier creates a no-op notifier
func NewNoOpNotifier(logger *zap.Logger) *NoOpNotifier {
	return &NoOpNotifier{logger: logger}
}

// SendAlert logs the alert but does not send it
func (n *NoOpNotifier) SendAlert(ctx context.Context, alert AlertConfig) error {
	n.logger.Info("Alert (no-op)",
		zap.String("level", alert.Level),
		zap.String("title", alert.Title),
		zap.String("message", alert.Message))
	return nil
}
