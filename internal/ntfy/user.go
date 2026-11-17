package ntfy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/tamcore/mcp-auth-proxy/internal/store"
	"github.com/tamcore/mcp-auth-proxy/internal/webpush"
)

// ErrNoTarget means the key's owner has not configured a push target.
var ErrNoTarget = errors.New("ntfy: no push target configured")

// DevicePusher delivers a challenge to a user's Web Push subscriptions and
// returns how many devices it reached.
type DevicePusher interface {
	Push(ctx context.Context, userID string, p webpush.Payload) (int, error)
}

// UserNotifier pushes a challenge to the push target of the key's owner and
// to their subscribed devices. Keys without an owner (created via the CLI)
// fall back to the log.
type UserNotifier struct {
	store     *store.Store
	client    *http.Client
	logger    *slog.Logger
	devices   DevicePusher
	approveFn func(id string) string
	denyFn    func(id string) string
}

// WithDevices also pushes every challenge to the owner's subscribed devices.
func (n *UserNotifier) WithDevices(d DevicePusher) *UserNotifier {
	n.devices = d
	return n
}

// NewUserNotifier builds the gate notifier. approveFn/denyFn produce the
// signed button URLs for a challenge id.
func NewUserNotifier(st *store.Store, client *http.Client, logger *slog.Logger,
	approveFn, denyFn func(id string) string) *UserNotifier {
	if logger == nil {
		logger = slog.Default()
	}
	return &UserNotifier{store: st, client: client, logger: logger, approveFn: approveFn, denyFn: denyFn}
}

// Notify sends the challenge push. The plaintext code rides only in this
// message and in memory.
func (n *UserNotifier) Notify(ctx context.Context, ch *store.Challenge, keyLabel string) error {
	m := challengeMessage(ch, keyLabel, n.approveFn, n.denyFn)
	key, err := n.store.KeyByID(ctx, ch.KeyID)
	if err != nil {
		return err
	}
	if key.UserID == nil {
		return NewLogPublisher(n.logger).Publish(ctx, m)
	}
	reached := n.pushDevices(ctx, *key.UserID, ch.ID, m)
	target, err := n.store.GetUserNotify(ctx, *key.UserID)
	if errors.Is(err, store.ErrNotFound) {
		if reached > 0 {
			return nil
		}
		n.logger.Info("no push target configured; code only in the portal", "user_id", *key.UserID, "key", key.ID)
		return ErrNoTarget
	}
	if err != nil {
		return err
	}
	m.Topic = target.Topic
	return NewHTTPPublisher(target.URL, target.Token, n.client, n.logger).Publish(ctx, m)
}

// pushDevices sends m to the user's devices; failures are logged, since ntfy
// and the portal still carry the code.
func (n *UserNotifier) pushDevices(ctx context.Context, userID, challengeID string, m Message) int {
	if n.devices == nil {
		return 0
	}
	reached, err := n.devices.Push(ctx, userID, webpush.Payload{Title: m.Title, Body: m.Message,
		Approve: n.approveFn(challengeID), Deny: n.denyFn(challengeID)})
	if err != nil {
		n.logger.Warn("web push failed", "user_id", userID, "reached", reached, "error", err)
	}
	return reached
}

func challengeMessage(ch *store.Challenge, keyLabel string, approveFn, denyFn func(string) string) Message {
	return Message{
		Title: "MCP auth request",
		Message: fmt.Sprintf("Key %q wants to call tool %q. One-time code: %s (expires %s).",
			keyLabel, ch.ToolName, ch.PendingOTP, ch.ExpiresAt.Format("15:04:05")),
		Actions: []Action{
			{Action: actionHTTP, Label: "Approve", Method: http.MethodPost, URL: approveFn(ch.ID), Clear: true},
			{Action: actionHTTP, Label: "Deny", Method: http.MethodPost, URL: denyFn(ch.ID), Clear: true},
		},
	}
}

const (
	validateTimeout = 10 * time.Second
	actionHTTP      = "http"
)

// Validate checks a user-entered push target: an https ntfy base URL (plain
// http only for loopback hosts) that answers /v1/health, and a topic the
// token may publish to, proven by sending a test push. It returns the
// normalized base URL.
func Validate(ctx context.Context, client *http.Client, rawURL, topic, token string) (string, error) {
	base, err := baseURL(rawURL)
	if err != nil {
		return "", err
	}
	if !regexp.MustCompile(`^[-_A-Za-z0-9]{1,64}$`).MatchString(topic) {
		return "", errors.New("topic must be 1-64 letters, digits, - or _")
	}
	if client == nil {
		client = &http.Client{Timeout: validateTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	if err := checkHealth(ctx, client, base); err != nil {
		return "", err
	}
	quiet := slog.New(slog.DiscardHandler)
	test := Message{Topic: topic, Title: "mcp-auth-proxy", Message: "Push notifications for your MCP keys are set up."}
	if err := NewHTTPPublisher(base, token, client, quiet).Publish(ctx, test); err != nil {
		return "", fmt.Errorf("test push failed: %w", err)
	}
	return base, nil
}

func baseURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("enter the ntfy server's base URL, e.g. https://ntfy.sh")
	}
	if u.Scheme != "https" && (u.Scheme != actionHTTP || !isLoopback(u.Hostname())) {
		return "", errors.New("the ntfy URL must use https")
	}
	return u.Scheme + "://" + u.Host + strings.TrimRight(u.Path, "/"), nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func checkHealth(ctx context.Context, client *http.Client, base string) error {
	notNtfy := fmt.Errorf("%s is not an ntfy server (no healthy /v1/health)", base)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/v1/health", nil)
	if err != nil {
		return notNtfy
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("could not reach %s: %w", base, err)
	}
	defer func() { _ = resp.Body.Close() }()
	var health struct {
		Healthy bool `json:"healthy"`
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK || json.Unmarshal(body, &health) != nil || !health.Healthy {
		return notNtfy
	}
	return nil
}
