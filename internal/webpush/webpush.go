// Package webpush sends the one-time-code challenge to a user's browsers and
// devices via Web Push (RFC 8030), encrypted per RFC 8291 and signed with the
// proxy's VAPID key (RFC 8292).
package webpush

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	wp "github.com/SherClockHolmes/webpush-go"

	"github.com/tamcore/mcp-auth-proxy/internal/store"
)

// KeysFile holds the VAPID key pair under the state directory.
const KeysFile = "vapid.json"

// ttl is how long the push service keeps an undelivered message; a code
// expires after 3 minutes anyway.
const ttl = 180

// Keys is the VAPID key pair, base64url as the browser Push API expects.
type Keys struct {
	Public  string `json:"public"`
	Private string `json:"private"`
}

// Payload is the JSON the service worker receives.
type Payload struct {
	Title   string `json:"title"`
	Body    string `json:"body"`
	Approve string `json:"approve,omitempty"`
	Deny    string `json:"deny,omitempty"`
}

// EnsureKeys loads {stateDir}/vapid.json, creating it with mode 0600 if absent.
func EnsureKeys(stateDir string) (Keys, error) {
	path := filepath.Join(stateDir, KeysFile)
	var k Keys
	b, err := os.ReadFile(path)
	if err == nil {
		if json.Unmarshal(b, &k) != nil || k.Public == "" || k.Private == "" {
			return Keys{}, fmt.Errorf("webpush: %s is not a valid key file", path)
		}
		return k, os.Chmod(path, 0o600)
	}
	if !os.IsNotExist(err) {
		return Keys{}, fmt.Errorf("webpush: read %s: %w", path, err)
	}
	if k.Private, k.Public, err = wp.GenerateVAPIDKeys(); err != nil {
		return Keys{}, fmt.Errorf("webpush: generate keys: %w", err)
	}
	b, _ = json.Marshal(k)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return Keys{}, fmt.Errorf("webpush: create %s: %w", path, err)
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return Keys{}, fmt.Errorf("webpush: write %s: %w", path, err)
	}
	return k, f.Close()
}

// Sender pushes to the subscriptions stored for a user.
type Sender struct {
	store      *store.Store
	client     *http.Client
	keys       Keys
	subscriber string
	logger     *slog.Logger
}

// New builds a sender. subscriber identifies the proxy to push services
// (its https base URL).
func New(st *store.Store, client *http.Client, keys Keys, subscriber string, logger *slog.Logger) *Sender {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Sender{store: st, client: client, keys: keys, subscriber: subscriber, logger: logger}
}

// PublicKey is the applicationServerKey for PushManager.subscribe.
func (s *Sender) PublicKey() string { return s.keys.Public }

// errGone means the push service dropped the subscription (404/410).
var errGone = errors.New("webpush: subscription gone")

// Send delivers one payload to one subscription.
func (s *Sender) Send(ctx context.Context, sub *store.PushSubscription, p Payload) error {
	body, err := json.Marshal(p)
	if err != nil {
		return err
	}
	resp, err := wp.SendNotificationWithContext(ctx, body, &wp.Subscription{
		Endpoint: sub.Endpoint, Keys: wp.Keys{P256dh: sub.P256dh, Auth: sub.Auth},
	}, &wp.Options{
		HTTPClient: s.client, Subscriber: s.subscriber, TTL: ttl, Urgency: wp.UrgencyHigh,
		VAPIDPublicKey: s.keys.Public, VAPIDPrivateKey: s.keys.Private,
	})
	if err != nil {
		return fmt.Errorf("webpush: send: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	switch {
	case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone:
		return errGone
	case resp.StatusCode/100 != 2:
		return fmt.Errorf("webpush: push service answered %d", resp.StatusCode)
	}
	return nil
}

// Push sends to every subscription of the user and returns how many were
// delivered. Subscriptions the push service reports gone are deleted.
func (s *Sender) Push(ctx context.Context, userID string, p Payload) (int, error) {
	subs, err := s.store.ListPushSubscriptions(ctx, userID)
	if err != nil {
		return 0, err
	}
	sent := 0
	var errs []error
	for _, sub := range subs {
		err := s.Send(ctx, sub, p)
		switch {
		case err == nil:
			sent++
		case errors.Is(err, errGone):
			s.logger.Info("push subscription gone; removed", "user_id", userID, "subscription", sub.ID)
			if err := s.store.DeletePushSubscriptionByEndpoint(ctx, sub.Endpoint); err != nil {
				errs = append(errs, err)
			}
		default:
			errs = append(errs, fmt.Errorf("subscription %s: %w", sub.ID, err))
		}
	}
	return sent, errors.Join(errs...)
}
