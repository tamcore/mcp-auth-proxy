// Package ntfy publishes the one-time-code challenge to the key owner's own
// ntfy topic, carrying Approve/Deny action buttons. Keys without an owner fall
// back to a log-only publisher.
package ntfy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

// Action is one ntfy http action button.
type Action struct {
	Action  string            `json:"action"`
	Label   string            `json:"label"`
	Method  string            `json:"method,omitempty"`
	URL     string            `json:"url,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	Clear   bool              `json:"clear,omitempty"`
}

// Message is the ntfy JSON publish payload.
type Message struct {
	Topic   string   `json:"topic"`
	Title   string   `json:"title"`
	Message string   `json:"message"`
	Actions []Action `json:"actions,omitempty"`
}

// Publisher sends a message.
type Publisher interface {
	Publish(ctx context.Context, m Message) error
}

// HTTPPublisher posts JSON to a ntfy server.
type HTTPPublisher struct {
	url    string
	token  string
	client *http.Client
	logger *slog.Logger
}

// NewHTTPPublisher builds a publisher posting to url (e.g. https://ntfy.sh).
// A non-empty token is sent as a Bearer access token.
func NewHTTPPublisher(url, token string, client *http.Client, logger *slog.Logger) *HTTPPublisher {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &HTTPPublisher{url: url, token: token, client: client, logger: logger}
}

// Publish POSTs the message as JSON to the ntfy server.
func (p *HTTPPublisher) Publish(ctx context.Context, m Message) error {
	body, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("ntfy: marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("ntfy: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if p.token != "" {
		req.Header.Set("Authorization", "Bearer "+p.token)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		p.logger.Warn("ntfy publish failed", "url", p.url, "topic_set", m.Topic != "", "error", err)
		return fmt.Errorf("ntfy: post: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		p.logger.Warn("ntfy publish rejected", "status", resp.StatusCode, "url", p.url,
			"token_set", p.token != "")
		return fmt.Errorf("ntfy: server returned %s", resp.Status)
	}
	return nil
}

// LogPublisher is the fallback when ntfy is disabled: it logs the payload
// (including the short-lived code and the signed action URLs) at info level.
type LogPublisher struct {
	logger *slog.Logger
}

// NewLogPublisher builds the log-only publisher.
func NewLogPublisher(logger *slog.Logger) *LogPublisher {
	if logger == nil {
		logger = slog.Default()
	}
	return &LogPublisher{logger: logger}
}

// Publish logs the message.
func (p *LogPublisher) Publish(_ context.Context, m Message) error {
	p.logger.Info("ntfy disabled: notification", "title", m.Title, "message", m.Message, "actions", m.Actions)
	return nil
}
