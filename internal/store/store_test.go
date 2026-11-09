package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/tamcore/mcp-auth-proxy/migrations"
)

const (
	testKeyID    = "k_1"
	testUpstream = "echo"
)

func newTestKey(id, hash string, now time.Time) *Key {
	return &Key{ID: id, Kind: KeyKindStatic, Label: "l", SecretHash: hash,
		Upstreams: []string{testUpstream}, TTLSeconds: 60, CreatedAt: now}
}

func newTestChallenge(id, hash, tool string, created, expires time.Time) *Challenge {
	return &Challenge{ID: id, KeyID: testKeyID, OTPHash: hash, ToolName: tool,
		Status: ChallengePending, CreatedAt: created, ExpiresAt: expires}
}

func openTest(t *testing.T) *Store {
	t.Helper()
	st, err := Open(context.Background(), filepath.Join(t.TempDir(), "proxy.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestKeyLifecycle(t *testing.T) {
	ctx := context.Background()
	st := openTest(t)
	k := &Key{ID: testKeyID, Kind: KeyKindStatic, Label: "laptop",
		SecretHash: HashSecret("mak_secret"), Upstreams: []string{testUpstream},
		TTLSeconds: 3600, CreatedAt: nowUTC()}
	if err := st.CreateKey(ctx, k); err != nil {
		t.Fatal(err)
	}
	got, err := st.KeyByHash(ctx, HashSecret("mak_secret"))
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "k_1" || got.Label != "laptop" || len(got.Upstreams) != 1 || got.Upstreams[0] != testUpstream {
		t.Fatalf("unexpected key: %+v", got)
	}
	if _, err := st.KeyByHash(ctx, HashSecret("mak_wrong")); err != ErrNotFound {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	if err := st.RevokeKey(ctx, testKeyID, nowUTC()); err != nil {
		t.Fatal(err)
	}
	got, _ = st.KeyByID(ctx, testKeyID)
	if !got.Revoked() {
		t.Fatal("key not revoked")
	}
}

func TestSessionExpiryReadsNotFound(t *testing.T) {
	ctx := context.Background()
	st := openTest(t)
	now := nowUTC()
	k := newTestKey(testKeyID, "h", now)
	if err := st.CreateKey(ctx, k); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetSession(ctx, testKeyID, now); err != ErrNotFound {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	sess := &Session{KeyID: testKeyID, CreatedAt: now, ExpiresAt: now.Add(time.Hour), Origin: OriginOTP}
	if err := st.UpsertSession(ctx, sess); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetSession(ctx, testKeyID, now.Add(30*time.Minute)); err != nil {
		t.Fatalf("live session: %v", err)
	}
	if _, err := st.GetSession(ctx, testKeyID, now.Add(2*time.Hour)); err != ErrNotFound {
		t.Fatalf("expired session must read not-found, got %v", err)
	}
	// Upsert replaces.
	sess2 := &Session{KeyID: testKeyID, CreatedAt: now, ExpiresAt: now.Add(3 * time.Hour), Origin: OriginApprove}
	if err := st.UpsertSession(ctx, sess2); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetSession(ctx, testKeyID, now.Add(2*time.Hour))
	if err != nil || got.Origin != OriginApprove {
		t.Fatalf("upsert did not replace: %+v %v", got, err)
	}
}

func TestChallengeSupersedeAndStatus(t *testing.T) {
	ctx := context.Background()
	st := openTest(t)
	now := nowUTC()
	k := newTestKey(testKeyID, "h", now)
	if err := st.CreateKey(ctx, k); err != nil {
		t.Fatal(err)
	}
	c1 := newTestChallenge("c1", "h1", testUpstream+"__echo", now, now.Add(3*time.Minute))
	if err := st.CreateChallenge(ctx, c1); err != nil {
		t.Fatal(err)
	}
	c2 := newTestChallenge("c2", "h2", testUpstream+"__echo", now, now.Add(3*time.Minute))
	if err := st.CreateChallenge(ctx, c2); err != nil {
		t.Fatal(err)
	}
	// At most one pending: c1 superseded.
	got, err := st.PendingChallenge(ctx, testKeyID, now)
	if err != nil || got.ID != "c2" {
		t.Fatalf("want c2 pending, got %+v %v", got, err)
	}
	old, err := st.ChallengeByID(ctx, "c1")
	if err != nil || old.Status != ChallengeExhausted {
		t.Fatalf("c1 should be superseded, got %+v %v", old, err)
	}
	// Expired pending reads not-found.
	c3 := newTestChallenge("c3", "h3", "t", now.Add(-10*time.Minute), now.Add(-5*time.Minute))
	if err := st.CreateChallenge(ctx, c3); err != nil {
		t.Fatal(err)
	}
	if _, err := st.PendingChallenge(ctx, testKeyID, now); err != ErrNotFound {
		t.Fatalf("expired pending must read not-found, got %v", err)
	}
	if err := st.UpdateChallenge(ctx, "c3", ChallengeApproved, 1); err != nil {
		t.Fatal(err)
	}
	got3, _ := st.ChallengeByID(ctx, "c3")
	if got3.Status != ChallengeApproved || got3.Attempts != 1 {
		t.Fatalf("update failed: %+v", got3)
	}
}

func TestRevokeKillsSessionAndChallenge(t *testing.T) {
	ctx := context.Background()
	st := openTest(t)
	now := nowUTC()
	k := newTestKey(testKeyID, "h", now)
	if err := st.CreateKey(ctx, k); err != nil {
		t.Fatal(err)
	}
	_ = st.UpsertSession(ctx, &Session{KeyID: testKeyID, CreatedAt: now, ExpiresAt: now.Add(time.Hour), Origin: OriginOTP})
	_ = st.CreateChallenge(ctx, newTestChallenge("c1", "h", "t", now, now.Add(time.Minute)))
	if err := st.RevokeKey(ctx, testKeyID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetSession(ctx, testKeyID, now); err != ErrNotFound {
		t.Fatalf("session survived revoke: %v", err)
	}
	if _, err := st.PendingChallenge(ctx, testKeyID, now); err != ErrNotFound {
		t.Fatalf("challenge survived revoke: %v", err)
	}
}

func TestOAuthClientAndAccessToken(t *testing.T) {
	ctx := context.Background()
	st := openTest(t)
	now := nowUTC()
	cl := &OAuthClient{ClientID: "claude", Name: "Claude",
		RedirectURIs: []string{"https://x/cb"}, CreatedAt: now}
	if err := st.UpsertOAuthClient(ctx, cl); err != nil {
		t.Fatal(err)
	}
	got, err := st.OAuthClientByID(ctx, "claude")
	if err != nil || got.RedirectURIs[0] != "https://x/cb" {
		t.Fatalf("client: %+v %v", got, err)
	}
	k := newTestKey("k_9", "h9", now)
	k.Kind = KeyKindOAuth
	if err := st.CreateKey(ctx, k); err != nil {
		t.Fatal(err)
	}
	at := &AccessToken{TokenHash: HashSecret("map_tok"), KeyID: "k_9", ClientID: "claude",
		ExpiresAt: now.Add(time.Hour), CreatedAt: now}
	if err := st.CreateAccessToken(ctx, at); err != nil {
		t.Fatal(err)
	}
	gotAT, err := st.AccessTokenByHash(ctx, HashSecret("map_tok"), now.Add(30*time.Minute))
	if err != nil || gotAT.KeyID != "k_9" {
		t.Fatalf("token: %+v %v", gotAT, err)
	}
	if _, err := st.AccessTokenByHash(ctx, HashSecret("map_tok"), now.Add(2*time.Hour)); err != ErrNotFound {
		t.Fatalf("expired token must read not-found, got %v", err)
	}
}

func TestUpstreamTokenRoundTrip(t *testing.T) {
	ctx := context.Background()
	st := openTest(t)
	now := nowUTC()
	exp := now.Add(time.Hour)
	tok := &UpstreamToken{Upstream: "echo", AccessToken: "at", RefreshToken: "rt", ExpiresAt: &exp}
	if err := st.SaveUpstreamToken(ctx, tok); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetUpstreamToken(ctx, "echo")
	if err != nil || got.AccessToken != "at" || got.RefreshToken != "rt" || got.ExpiresAt == nil {
		t.Fatalf("token: %+v %v", got, err)
	}
	// Rotation persists the new set.
	rotated := &UpstreamToken{Upstream: "echo", AccessToken: "at2", RefreshToken: "rt2", ExpiresAt: &exp}
	if err := st.SaveUpstreamToken(ctx, rotated); err != nil {
		t.Fatal(err)
	}
	got, _ = st.GetUpstreamToken(ctx, "echo")
	if got.AccessToken != "at2" || got.RefreshToken != "rt2" {
		t.Fatalf("rotation not persisted: %+v", got)
	}
	if _, err := st.GetUpstreamToken(ctx, "nope"); err != ErrNotFound {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestMigratorRefusesNewerDB(t *testing.T) {
	ctx := context.Background()
	st := openTest(t)
	// Simulate a DB from a newer build: record version 99.
	if _, err := st.db.ExecContext(ctx,
		`INSERT INTO schema_migrations (version, name, checksum, applied_at) VALUES (99, 'future', 'x', 'y')`); err != nil {
		t.Fatal(err)
	}
	if err := st.Migrate(ctx, migrations.FS()); err != ErrTooNew {
		t.Fatalf("want ErrTooNew, got %v", err)
	}
}

func TestSignSecretCreated0600(t *testing.T) {
	dir := t.TempDir()
	secret, err := EnsureSignSecret(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(secret) < 32 {
		t.Fatal("secret too short")
	}
	if err := CheckSignSecretPerms(dir); err != nil {
		t.Fatal(err)
	}
	again, err := EnsureSignSecret(dir)
	if err != nil || string(again) != string(secret) {
		t.Fatal("secret not stable across calls")
	}
}
