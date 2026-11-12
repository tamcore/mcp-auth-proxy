// Package gate is the one-time-code authorization state machine: it creates
// challenges, pushes them via a Notifier, verifies codes, grants sessions, and
// handles the HMAC-signed approve/deny URLs. The clock and randomness are
// injectable for tests.
package gate

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"
	"time"

	"github.com/tamcore/mcp-auth-proxy/internal/store"
)

// Sentinel errors.
var (
	ErrNoChallenge  = errors.New("gate: no pending challenge for this key")
	ErrWrongCode    = errors.New("gate: wrong one-time code")
	ErrExpired      = errors.New("gate: challenge expired")
	ErrExhausted    = errors.New("gate: challenge exhausted")
	ErrBadSignature = errors.New("gate: missing or invalid signature")
	ErrNotPending   = errors.New("gate: challenge is not pending")
)

// Notifier pushes a challenge to the owner's phone.
type Notifier interface {
	Notify(ctx context.Context, ch *store.Challenge, keyLabel string) error
}

// Gate is the OTP challenge/session state machine.
type Gate struct {
	store         *store.Store
	digits        int
	expiry        time.Duration
	maxAttempts   int
	renotifyFloor time.Duration
	defaultTTL    time.Duration
	baseURL       string
	secret        []byte
	notifier      Notifier
	now           func() time.Time
	newID         func() string
	rand          io.Reader

	// codes holds the plaintext code of open challenges for the portal; it is
	// never persisted, so a restart only loses the portal display.
	codesMu sync.Mutex
	codes   map[string]pendingCode

	// OnChallenge fires once per newly created challenge (metrics hook).
	OnChallenge func()
}

// Options configures a Gate.
type Options struct {
	Store         *store.Store
	Digits        int
	Expiry        time.Duration
	MaxAttempts   int
	RenotifyFloor time.Duration
	DefaultTTL    time.Duration
	BaseURL       string
	SignSecret    []byte
	Notifier      Notifier
	Now           func() time.Time
	NewID         func() string
	Rand          io.Reader
}

// New builds a Gate. Zero Now/NewID/Rand get production defaults.
func New(o Options) *Gate {
	g := &Gate{
		store:         o.Store,
		digits:        o.Digits,
		expiry:        o.Expiry,
		maxAttempts:   o.MaxAttempts,
		renotifyFloor: o.RenotifyFloor,
		defaultTTL:    o.DefaultTTL,
		baseURL:       o.BaseURL,
		secret:        o.SignSecret,
		notifier:      o.Notifier,
		now:           o.Now,
		newID:         o.NewID,
		rand:          o.Rand,
		codes:         map[string]pendingCode{},
	}
	if g.now == nil {
		g.now = func() time.Time { return time.Now().UTC() }
	}
	if g.newID == nil {
		g.newID = func() string { return randomHex(g.randOrDefault(), 16) }
	}
	if g.rand == nil {
		g.rand = rand.Reader
	}
	return g
}

func (g *Gate) randOrDefault() io.Reader {
	if g.rand != nil {
		return g.rand
	}
	return rand.Reader
}

// SetNotifier wires the push notifier after construction, so the notifier can
// close over this gate's ApproveURL/DenyURL.
func (g *Gate) SetNotifier(n Notifier) { g.notifier = n }

// Check reports whether the key has a live session.
func (g *Gate) Check(ctx context.Context, keyID string) bool {
	_, err := g.store.GetSession(ctx, keyID, g.now())
	return err == nil
}

// Block gates a tool call: it creates (or reuses, respecting the re-notify
// floor) a challenge, pushes the notification, and returns the LLM-readable
// contract message.
func (g *Gate) Block(ctx context.Context, key *store.Key, toolName string) (string, error) {
	now := g.now()
	if ch, err := g.store.PendingChallenge(ctx, key.ID, now); err == nil {
		if now.Sub(ch.CreatedAt) < g.renotifyFloor {
			return blockedMessage(key.Label, toolName, g.digits, ch.ExpiresAt, false), nil
		}
	}
	ch, err := g.newChallenge(ctx, key, toolName, now)
	if err != nil {
		return "", err
	}
	if g.OnChallenge != nil {
		g.OnChallenge()
	}
	pushFailed := false
	if g.notifier != nil {
		if err := g.notifier.Notify(ctx, ch, key.Label); err != nil {
			pushFailed = true
		}
	}
	return blockedMessage(key.Label, toolName, g.digits, ch.ExpiresAt, pushFailed), nil
}

func (g *Gate) newChallenge(ctx context.Context, key *store.Key,
	toolName string, now time.Time) (*store.Challenge, error) {
	otp, err := g.genOTP()
	if err != nil {
		return nil, err
	}
	ch := &store.Challenge{
		ID:         g.newID(),
		KeyID:      key.ID,
		OTPHash:    store.HashSecret(otp),
		ToolName:   toolName,
		Status:     store.ChallengePending,
		Attempts:   0,
		CreatedAt:  now,
		ExpiresAt:  now.Add(g.expiry),
		PendingOTP: otp,
	}
	if err := g.store.CreateChallenge(ctx, ch); err != nil {
		return nil, err
	}
	g.rememberCode(ch.ID, otp, ch.ExpiresAt, now)
	return ch, nil
}

type pendingCode struct {
	otp     string
	expires time.Time
}

func (g *Gate) rememberCode(id, otp string, expires, now time.Time) {
	g.codesMu.Lock()
	defer g.codesMu.Unlock()
	for k, c := range g.codes {
		if !now.Before(c.expires) {
			delete(g.codes, k)
		}
	}
	g.codes[id] = pendingCode{otp: otp, expires: expires}
}

// PendingCode returns the plaintext code of an open challenge, if this
// process created it and it has not expired.
func (g *Gate) PendingCode(id string) (string, bool) {
	g.codesMu.Lock()
	defer g.codesMu.Unlock()
	c, ok := g.codes[id]
	if !ok || !g.now().Before(c.expires) {
		return "", false
	}
	return c.otp, true
}

// Verify checks an OTP against the key's pending challenge and, on success,
// grants a session (origin otp) and returns its expiry.
func (g *Gate) Verify(ctx context.Context, key *store.Key, otp string) (time.Time, error) {
	now := g.now()
	ch, err := g.store.PendingChallengeAny(ctx, key.ID)
	if err != nil {
		return time.Time{}, ErrNoChallenge
	}
	if !now.Before(ch.ExpiresAt) {
		_ = g.store.ResolveChallenge(ctx, ch.ID, store.ChallengeExhausted)
		return time.Time{}, ErrExpired
	}
	attempts, err := g.store.ReserveAttempt(ctx, ch.ID, g.maxAttempts)
	if err != nil {
		return time.Time{}, notPending(err, ErrExhausted)
	}
	if !hmac.Equal([]byte(store.HashSecret(otp)), []byte(ch.OTPHash)) {
		return time.Time{}, g.recordWrongAttempt(ctx, ch.ID, attempts)
	}
	if err := g.store.ResolveChallenge(ctx, ch.ID, store.ChallengeApproved); err != nil {
		return time.Time{}, notPending(err, ErrNotPending)
	}
	return g.grantSession(ctx, key, store.OriginOTP, now)
}

func (g *Gate) recordWrongAttempt(ctx context.Context, id string, attempts int) error {
	if attempts < g.maxAttempts {
		return ErrWrongCode
	}
	if err := g.store.ResolveChallenge(ctx, id, store.ChallengeExhausted); err != nil {
		return notPending(err, ErrExhausted)
	}
	return ErrExhausted
}

// notPending maps the store's lost-race error to the gate error callers see.
func notPending(err, as error) error {
	if errors.Is(err, store.ErrNotPending) {
		return as
	}
	return err
}

func (g *Gate) grantSession(ctx context.Context, key *store.Key, origin string, now time.Time) (time.Time, error) {
	ttl := time.Duration(key.TTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = g.defaultTTL
	}
	expires := now.Add(ttl)
	sess := &store.Session{KeyID: key.ID, CreatedAt: now, ExpiresAt: expires, Origin: origin}
	if err := g.store.UpsertSession(ctx, sess); err != nil {
		return time.Time{}, err
	}
	return expires, nil
}

// Approve handles the Approve button: sig must be the lowercase hex
// HMAC-SHA256 of the challenge id under the sign secret. On success the
// challenge is approved and a session is granted (origin approve).
func (g *Gate) Approve(ctx context.Context, id, sig string) error {
	return g.resolve(ctx, id, sig, store.ChallengeApproved, true)
}

// Deny handles the Deny button with the same signature rule.
func (g *Gate) Deny(ctx context.Context, id, sig string) error {
	return g.resolve(ctx, id, sig, store.ChallengeDenied, false)
}

func (g *Gate) resolve(ctx context.Context, id, sig, status string, grant bool) error {
	if !g.validSig(id, sig) {
		return ErrBadSignature
	}
	ch, err := g.store.ChallengeByID(ctx, id)
	if err != nil {
		return err
	}
	if ch.Status != store.ChallengePending {
		return ErrNotPending
	}
	if !g.now().Before(ch.ExpiresAt) {
		_ = g.store.ResolveChallenge(ctx, ch.ID, store.ChallengeExhausted)
		return ErrExpired
	}
	if err := g.store.ResolveChallenge(ctx, ch.ID, status); err != nil {
		return notPending(err, ErrNotPending)
	}
	if !grant {
		return nil
	}
	key, err := g.store.KeyByID(ctx, ch.KeyID)
	if err != nil {
		return err
	}
	_, err = g.grantSession(ctx, key, store.OriginApprove, g.now())
	return err
}

// ApproveURL / DenyURL build the signed button URLs carried in the ntfy push.
func (g *Gate) ApproveURL(id string) string {
	return fmt.Sprintf("%s/approve/%s?sig=%s", g.baseURL, id, g.sig(id))
}
func (g *Gate) DenyURL(id string) string {
	return fmt.Sprintf("%s/deny/%s?sig=%s", g.baseURL, id, g.sig(id))
}

func (g *Gate) sig(id string) string {
	mac := hmac.New(sha256.New, g.secret)
	mac.Write([]byte(id))
	return hex.EncodeToString(mac.Sum(nil))
}

func (g *Gate) validSig(id, sig string) bool {
	if sig == "" {
		return false
	}
	return hmac.Equal([]byte(g.sig(id)), []byte(sig))
}

func (g *Gate) genOTP() (string, error) {
	mod := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(g.digits)), nil)
	n, err := rand.Int(g.randOrDefault(), mod)
	if err != nil {
		return "", fmt.Errorf("gate: generate otp: %w", err)
	}
	return fmt.Sprintf("%0*d", g.digits, n.Int64()), nil
}

// blockedMessage is the LLM-readable contract for a blocked call. It always
// names the key label, the tool, the code length and the expiry; pushFailed
// marks the variant used when the notification may not have been delivered.
func blockedMessage(keyLabel, toolName string, digits int, expires time.Time, pushFailed bool) string {
	msg := fmt.Sprintf("Blocked: tool %q on key %q requires a one-time code. "+
		"Ask the owner for the %d-digit code from their phone notification or the web portal (expires %s). "+
		"Then call the `auth` tool with that code (argument `otp`) and retry this exact tool call.",
		toolName, keyLabel, digits, expires.Format(time.RFC3339))
	if pushFailed {
		msg += " No phone notification went out; the owner finds the code in the web portal."
	}
	return msg
}

// AuthorizedMessage is the auth tool's success contract.
func AuthorizedMessage(expires time.Time) string {
	return fmt.Sprintf("Session authorized until %s. Retry the tool call you were blocked on.",
		expires.Format(time.RFC3339))
}

func randomHex(r io.Reader, n int) string {
	b := make([]byte, n)
	if _, err := r.Read(b); err != nil {
		// crypto/rand failure is unrecoverable for id generation; panic-free fallback
		// still yields a unique-enough id via timestamp.
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}
