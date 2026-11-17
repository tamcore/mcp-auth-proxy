package store

import (
	"context"
	"errors"
	"testing"
)

func TestPushSubscriptions(t *testing.T) {
	ctx := context.Background()
	st := openTest(t)
	now := nowUTC()
	for _, id := range []string{"u_p1", "u_p2"} {
		if err := st.CreateUser(ctx, &User{ID: id, Username: id, CreatedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	sub := &PushSubscription{ID: "ps_1", UserID: "u_p1", Endpoint: "https://push.example/a", P256dh: "pk", Auth: "au",
		Label: "Firefox", CreatedAt: now}
	if err := st.SavePushSubscription(ctx, sub); err != nil {
		t.Fatal(err)
	}
	// The same browser re-subscribing under another login moves to that user.
	moved := *sub
	moved.ID, moved.UserID, moved.P256dh = "ps_2", "u_p2", "pk2"
	if err := st.SavePushSubscription(ctx, &moved); err != nil {
		t.Fatal(err)
	}
	if subs, _ := st.ListPushSubscriptions(ctx, "u_p1"); len(subs) != 0 {
		t.Fatalf("endpoint must belong to one user only: %+v", subs)
	}
	subs, err := st.ListPushSubscriptions(ctx, "u_p2")
	if err != nil || len(subs) != 1 || subs[0].P256dh != "pk2" || subs[0].Label != "Firefox" {
		t.Fatalf("list: %+v %v", subs, err)
	}
	id := subs[0].ID
	if err := st.DeletePushSubscription(ctx, id, "u_p1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign delete: want ErrNotFound, got %v", err)
	}
	if err := st.DeletePushSubscriptionByEndpoint(ctx, sub.Endpoint); err != nil {
		t.Fatal(err)
	}
	if subs, _ := st.ListPushSubscriptions(ctx, "u_p2"); len(subs) != 0 {
		t.Fatalf("delete by endpoint: %+v", subs)
	}
}
