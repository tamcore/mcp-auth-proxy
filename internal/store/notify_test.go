package store

import (
	"context"
	"testing"
	"time"
)

func TestUserNotifyRoundTrip(t *testing.T) {
	ctx := context.Background()
	st := openTest(t)
	now := nowUTC()
	if err := st.CreateUser(ctx, &User{ID: "u_n", Username: "n", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetUserNotify(ctx, "u_n"); err != ErrNotFound {
		t.Fatalf("unset: want ErrNotFound, got %v", err)
	}
	want := &UserNotify{UserID: "u_n", URL: "https://ntfy.example", Topic: "t1", Token: "tk_1"}
	if err := st.SaveUserNotify(ctx, want); err != nil {
		t.Fatal(err)
	}
	want.Topic = "t2"
	if err := st.SaveUserNotify(ctx, want); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetUserNotify(ctx, "u_n")
	if err != nil || got.URL != want.URL || got.Topic != "t2" || got.Token != "tk_1" {
		t.Fatalf("got %+v %v", got, err)
	}
	if err := st.DeleteUserNotify(ctx, "u_n"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetUserNotify(ctx, "u_n"); err != ErrNotFound {
		t.Fatalf("after delete: %v", err)
	}
}

func TestPendingChallengesForUser(t *testing.T) {
	ctx := context.Background()
	st := openTest(t)
	now := nowUTC()
	for _, uid := range []string{"u_p", "u_q"} {
		if err := st.CreateUser(ctx, &User{ID: uid, Username: uid, CreatedAt: now}); err != nil {
			t.Fatal(err)
		}
		owner := uid
		k := &Key{ID: "k_" + uid, Kind: KeyKindStatic, Label: "lbl_" + uid, SecretHash: "h_" + uid,
			Upstreams: []string{}, TTLSeconds: 60, CreatedAt: now, UserID: &owner}
		if err := st.CreateKey(ctx, k); err != nil {
			t.Fatal(err)
		}
	}
	pending := func(id, key string, ttl time.Duration) *Challenge {
		return &Challenge{ID: id, KeyID: key, OTPHash: "x", ToolName: "t", Status: ChallengePending,
			CreatedAt: now, ExpiresAt: now.Add(ttl)}
	}
	for _, ch := range []*Challenge{
		pending("c_old", "k_u_p", -time.Minute),
		pending("c_live", "k_u_p", time.Minute),
		pending("c_other", "k_u_q", time.Minute),
	} {
		if err := st.CreateChallenge(ctx, ch); err != nil {
			t.Fatal(err)
		}
	}
	got, err := st.PendingChallengesForUser(ctx, "u_p", now)
	if err != nil || len(got) != 1 || got[0].ID != "c_live" || got[0].KeyLabel != "lbl_u_p" {
		t.Fatalf("pending for u_p: %+v %v", got, err)
	}
}
