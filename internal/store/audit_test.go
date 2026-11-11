package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestAuditAppendListGC(t *testing.T) {
	ctx := context.Background()
	st := openTest(t)
	now := nowUTC()
	u := &User{ID: "u_1", Username: "alice", PasswordHash: "x", CreatedAt: now}
	if err := st.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	k := newTestKey(testKeyID, "h", now)
	k.UserID = &u.ID
	if err := st.CreateKey(ctx, k); err != nil {
		t.Fatal(err)
	}
	resp := `{"ok":true}`
	for i, age := range []time.Duration{0, time.Hour, 31 * 24 * time.Hour} {
		e := &AuditEntry{
			ID:     "a_" + string(rune('1'+i)),
			UserID: u.ID, KeyID: k.ID, KeyLabel: testLabel,
			ToolName: "echo__echo", Arguments: `{"text":"x"}`, Response: &resp,
			CreatedAt: now.Add(-age),
		}
		if err := st.AppendAudit(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := st.ListAuditForUser(ctx, u.ID, 100)
	if err != nil || len(entries) != 3 {
		t.Fatalf("list: %d %v", len(entries), err)
	}
	if entries[0].Response == nil || *entries[0].Response != resp {
		t.Fatal("response not round-tripped")
	}
	auditGC(t, st, ctx, now, u, k)
}

func auditGC(t *testing.T, st *Store, ctx context.Context, now time.Time, u *User, k *Key) {
	t.Helper()
	// GC with 30d retention removes only the 31d-old entry.
	n, err := st.DeleteAuditOlderThan(ctx, now.Add(-30*24*time.Hour))
	if err != nil || n != 1 {
		t.Fatalf("gc: %d %v", n, err)
	}
	entries, _ := st.ListAuditForUser(ctx, u.ID, 100)
	if len(entries) != 2 {
		t.Fatalf("after gc: %d", len(entries))
	}
	// GC is global by age, across users.
	u2 := &User{ID: "u_2", Username: "bob", PasswordHash: "x", CreatedAt: now}
	if err := st.CreateUser(ctx, u2); err != nil {
		t.Fatal(err)
	}
	e := &AuditEntry{ID: "a_b", UserID: u2.ID, KeyID: k.ID,
		KeyLabel: "l", ToolName: "t", CreatedAt: now.Add(-40 * 24 * time.Hour)}
	if err := st.AppendAudit(ctx, e); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DeleteAuditOlderThan(ctx, now.Add(-30*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	entries, _ = st.ListAuditForUser(ctx, u2.ID, 100)
	if len(entries) != 0 {
		t.Fatalf("bob's old entry should also be gc'd by age: %d", len(entries))
	}
}

func TestUserUpstreamCRUD(t *testing.T) {
	ctx := context.Background()
	st, err := Open(ctx, filepath.Join(t.TempDir(), "proxy.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	now := nowUTC()
	u := &User{ID: "u_1", Username: "alice", PasswordHash: "x", CreatedAt: now}
	if err := st.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	up := &UserUpstream{ID: "us_1", UserID: u.ID, Name: "mine", URL: "http://x/mcp",
		Headers: map[string]string{"A": "b"}, CreatedAt: now}
	if err := st.CreateUserUpstream(ctx, up); err != nil {
		t.Fatal(err)
	}
	list, err := st.ListUserUpstreams(ctx, u.ID)
	if err != nil || len(list) != 1 || list[0].URL != "http://x/mcp" || list[0].Headers["A"] != "b" {
		t.Fatalf("list: %+v %v", list, err)
	}
	// duplicate name rejected by UNIQUE(user_id, name)
	if err := st.CreateUserUpstream(ctx, up); err == nil {
		t.Fatal("duplicate name must fail")
	}
	// delete scoped to owner
	if err := st.DeleteUserUpstream(ctx, "u_other", up.ID); err != ErrNotFound {
		t.Fatalf("other user delete: %v", err)
	}
	if err := st.DeleteUserUpstream(ctx, u.ID, up.ID); err != nil {
		t.Fatal(err)
	}
}
