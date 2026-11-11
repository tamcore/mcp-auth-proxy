// Package ntfy publishes the one-time-code challenge to the owner's phone via
// ntfy, carrying Approve/Deny action buttons. When disabled it falls back to a
// log-only publisher so the flow is still observable without a phone.
package ntfy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/tamcore/mcp-auth-proxy/internal/store"
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
		return fmt.Errorf("ntfy: post: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		p.logger.Warn("ntfy publish rejected", "status", resp.StatusCode, "topic", m.Topic,
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

// Notifier adapts a Publisher to the gate.Notifier shape, building the push for
// a challenge: the code in the message text plus Approve/Deny buttons.
type Notifier struct {
	pub       Publisher
	topic     string
	approveFn func(id string) string
	denyFn    func(id string) string
}

// NewNotifier builds the gate notifier. approveFn/denyFn produce the signed
// button URLs for a challenge id.
func NewNotifier(pub Publisher, topic string, approveFn, denyFn func(id string) string) *Notifier {
	return &Notifier{pub: pub, topic: topic, approveFn: approveFn, denyFn: denyFn}
}

// Notify sends the challenge push. The plaintext code rides only in this
// message and in memory.
func (n *Notifier) Notify(ctx context.Context, ch *store.Challenge, keyLabel string) error {
	m := Message{
		Title: "MCP auth request",
		Message: fmt.Sprintf("Key %q wants to call tool %q. One-time code: %s (expires %s).",
			keyLabel, ch.ToolName, ch.PendingOTP, ch.ExpiresAt.Format("15:04:05")),
		Actions: []Action{
			{Action: "http", Label: "Approve", Method: "POST", URL: n.approveFn(ch.ID), Clear: true},
			{Action: "http", Label: "Deny", Method: "POST", URL: n.denyFn(ch.ID), Clear: true},
		},
	}
	m.Topic = n.topic
	return n.pub.Publish(ctx, m)
}
