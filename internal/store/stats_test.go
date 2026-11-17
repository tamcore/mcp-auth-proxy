package store

import (
	"context"
	"testing"
	"time"
)

const statsOwner = "u_stats"

type seedChallenge struct {
	id, key, status string
	created         time.Time
}

func insertChallenges(t *testing.T, st *Store, chs []seedChallenge) {
	t.Helper()
	for _, c := range chs {
		if _, err := st.db.ExecContext(context.Background(), `
INSERT INTO challenges (id, key_id, otp_hash, tool_name, status, attempts, created_at, expires_at)
VALUES (?, ?, 'h', 't', ?, 0, ?, ?)`,
			c.id, c.key, c.status, FormatTime(c.created), FormatTime(c.created.Add(time.Minute))); err != nil {
			t.Fatal(err)
		}
	}
}

// seedActivity creates a user with a live and a revoked key, an unowned CLI
// key, challenges in every state and three audit rows.
func seedActivity(t *testing.T, st *Store, now, used time.Time) {
	t.Helper()
	ctx := context.Background()
	if err := st.CreateUser(ctx, &User{ID: statsOwner, Username: "stats", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	owner := statsOwner
	k1, k2, cli := newTestKey("k_a1", "h1", now), newTestKey("k_a2", "h2", now), newTestKey("k_cli", "h3", now)
	k1.UserID, k2.UserID = &owner, &owner
	for _, k := range []*Key{k1, k2, cli} {
		if err := st.CreateKey(ctx, k); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.RevokeKey(ctx, k2.ID, now); err != nil {
		t.Fatal(err)
	}
	// The older key time has a fraction: RFC3339Nano text does not sort.
	if err := st.MarkKeyUsed(ctx, k1.ID, used); err != nil {
		t.Fatal(err)
	}
	if err := st.MarkKeyUsed(ctx, k2.ID, used.Add(-time.Hour).Add(500*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if err := st.MarkKeySuccess(ctx, k1.ID, used); err != nil {
		t.Fatal(err)
	}
	insertChallenges(t, st, []seedChallenge{
		{"c1", k1.ID, ChallengeApproved, now.Add(-3 * time.Hour)},
		{"c2", k1.ID, ChallengeApproved, now.Add(-2 * time.Hour).Add(100 * time.Millisecond)},
		{"c3", k1.ID, ChallengeDenied, now.Add(-30 * time.Minute)},
		{"c4", k1.ID, ChallengeExhausted, now.Add(-20 * time.Minute)},
		{"c5", k1.ID, ChallengePending, now.Add(-10 * time.Minute)},
		{"c6", cli.ID, ChallengePending, now},
	})
	for i, id := range []string{"a1", "a2", "a3"} {
		e := &AuditEntry{ID: id, UserID: owner, KeyID: k1.ID, KeyLabel: "l", ToolName: "t",
			CreatedAt: now.Add(-time.Duration(i) * time.Hour)}
		if err := st.AppendAudit(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
}

func TestActivityStatsPerUserAndTotal(t *testing.T) {
	st := openTest(t)
	now := nowUTC()
	used := now.Add(-time.Minute).Truncate(time.Second)
	seedActivity(t, st, now, used)

	stats, err := st.ActivityStats(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	a := stats.Users[statsOwner]
	if a.ActiveKeys != 1 || a.RevokedKeys != 1 || a.ToolCalls != 3 {
		t.Fatalf("user counts: %+v", a)
	}
	if a.Granted != 2 || a.Denied != 1 || a.Expired != 2 || a.Pending != 0 {
		t.Fatalf("user auth counts (an expired pending challenge counts as expired): %+v", a)
	}
	assertLatest(t, a, used, now)
	tot := stats.Total
	if tot.ActiveKeys != 2 || tot.RevokedKeys != 1 || tot.Pending != 1 || tot.Granted != 2 || tot.ToolCalls != 3 {
		t.Fatalf("total: %+v", tot)
	}
}

func assertLatest(t *testing.T, a *ActivityStat, used, now time.Time) {
	t.Helper()
	for name, c := range map[string]struct{ got, want *time.Time }{
		"last active":    {a.LastActive, &used},
		"last tool call": {a.LastToolCall, &used},
		"last granted":   {a.LastGranted, new(now.Add(-2 * time.Hour).Add(100 * time.Millisecond))},
		"last denied":    {a.LastDenied, new(now.Add(-30 * time.Minute))},
	} {
		if c.got == nil || !c.got.Equal(*c.want) {
			t.Errorf("%s: %v want %v", name, c.got, *c.want)
		}
	}
}
