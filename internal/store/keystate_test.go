package store

import (
	"context"
	"testing"
	"time"
)

const metricsOwner = "u_metrics"

// seedKeyStates creates an owned live key (testKeyID) with a session and a
// revoked key, and returns the session.
func seedKeyStates(t *testing.T, st *Store, now time.Time) *Session {
	t.Helper()
	ctx := context.Background()
	if err := st.CreateUser(ctx, &User{ID: metricsOwner, Username: "Philipp", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	owner := metricsOwner
	live := newTestKey(testKeyID, "hm", now)
	live.Label, live.UserID = "Mistral", &owner
	gone := newTestKey("k_gone", "hg", now)
	for _, k := range []*Key{live, gone} {
		if err := st.CreateKey(ctx, k); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.RevokeKey(ctx, gone.ID, now); err != nil {
		t.Fatal(err)
	}
	sess := &Session{KeyID: live.ID, CreatedAt: now, ExpiresAt: now.Add(time.Hour), Origin: OriginOTP}
	if err := st.UpsertSession(ctx, sess); err != nil {
		t.Fatal(err)
	}
	return sess
}

func TestKeyStatesReportLiveKeysWithTheirSession(t *testing.T) {
	st := openTest(t)
	now := nowUTC()
	sess := seedKeyStates(t, st, now)
	states, err := st.KeyStates(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 1 {
		t.Fatalf("a revoked key must not be reported: %+v", states)
	}
	got := states[0]
	if got.Username != "Philipp" || got.Label != "Mistral" || got.AuthorizedUntil == nil ||
		!got.AuthorizedUntil.Equal(sess.ExpiresAt) || got.AuthPending {
		t.Fatalf("state: %+v", got)
	}
}

func TestKeyStatesShowOnlyAnOpenChallengeAsPending(t *testing.T) {
	ctx := context.Background()
	st := openTest(t)
	now := nowUTC()
	seedKeyStates(t, st, now)
	expired := newTestChallenge("c_old", "h1", "t", now.Add(-time.Hour), now.Add(-time.Minute))
	if err := st.CreateChallenge(ctx, expired); err != nil {
		t.Fatal(err)
	}
	if states, err := st.KeyStates(ctx, now); err != nil || states[0].AuthPending {
		t.Fatalf("an expired challenge is not pending: %+v %v", states, err)
	}
	if err := st.CreateChallenge(ctx, newTestChallenge("c_new", "h2", "t", now, now.Add(time.Minute))); err != nil {
		t.Fatal(err)
	}
	if states, err := st.KeyStates(ctx, now); err != nil || !states[0].AuthPending {
		t.Fatalf("an open challenge must show as pending: %+v %v", states, err)
	}
}
