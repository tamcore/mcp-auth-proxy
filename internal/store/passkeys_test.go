package store

import (
	"context"
	"testing"
	"time"
)

func TestPasskeysPerUser(t *testing.T) {
	ctx := context.Background()
	st := openTest(t)
	now := nowUTC()
	for _, uid := range []string{"u_pk", "u_other"} {
		if err := st.CreateUser(ctx, &User{ID: uid, Username: uid, CreatedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	pk := &Passkey{ID: []byte{1, 2, 3}, UserID: "u_pk", Name: testLabel, Credential: `{"id":"AQID"}`, CreatedAt: now}
	if err := st.AddPasskey(ctx, pk); err != nil {
		t.Fatal(err)
	}
	list, err := st.ListPasskeys(ctx, "u_pk")
	if err != nil || len(list) != 1 || list[0].Name != testLabel || list[0].LastUsedAt != nil {
		t.Fatalf("list: %+v %v", list, err)
	}
	assertPasskeyUseAndDelete(t, st, pk, now)
}

func TestSessionsSince(t *testing.T) {
	ctx := context.Background()
	st := openTest(t)
	now := nowUTC()
	if err := st.CreateUser(ctx, &User{ID: "u_ss", Username: "ss", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if u, _ := st.UserByID(ctx, "u_ss"); u.SessionsSince != nil {
		t.Fatal("new user has no session cutoff")
	}
	if err := st.SetSessionsSince(ctx, "u_ss", now); err != nil {
		t.Fatal(err)
	}
	if u, _ := st.UserByID(ctx, "u_ss"); u.SessionsSince == nil || !u.SessionsSince.Equal(now) {
		t.Fatalf("cutoff: %+v", u)
	}
}

func assertPasskeyUseAndDelete(t *testing.T, st *Store, pk *Passkey, now time.Time) {
	t.Helper()
	ctx := context.Background()
	used := now.Add(time.Minute)
	if err := st.MarkPasskeyUsed(ctx, pk.ID, `{"id":"AQID","n":2}`, used); err != nil {
		t.Fatal(err)
	}
	got, err := st.PasskeyByID(ctx, pk.ID)
	if err != nil || got.Credential != `{"id":"AQID","n":2}` || got.LastUsedAt == nil || !got.LastUsedAt.Equal(used) {
		t.Fatalf("after use: %+v %v", got, err)
	}
	if err := st.DeletePasskey(ctx, "u_other", pk.ID); err != ErrNotFound {
		t.Fatalf("foreign delete: want ErrNotFound, got %v", err)
	}
	if err := st.DeletePasskey(ctx, "u_pk", pk.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.PasskeyByID(ctx, pk.ID); err != ErrNotFound {
		t.Fatalf("deleted: %v", err)
	}
}
