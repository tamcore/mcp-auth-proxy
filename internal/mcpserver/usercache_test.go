package mcpserver

import (
	"context"
	"testing"
	"time"

	"github.com/tamcore/mcp-auth-proxy/internal/store"
)

const ownerID = "u_own"

func TestForgetUserDropsADeletedOwnUpstream(t *testing.T) {
	ctx := context.Background()
	p, _, _ := newTestProxy(t, echoUpstream(t).URL)
	now := time.Now().UTC()
	if err := p.store.CreateUser(ctx, &store.User{ID: ownerID, Username: "own", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	own := &store.UserUpstream{ID: "us_1", UserID: ownerID, Name: "mine", URL: echoUpstream(t).URL, CreatedAt: now}
	if err := p.store.CreateUserUpstream(ctx, own); err != nil {
		t.Fatal(err)
	}
	owner := ownerID
	key := &store.Key{ID: "k_a", UserID: &owner, Upstreams: []string{"mine"}}
	if _, err := p.resolveUpstream(ctx, key, "mine"); err != nil {
		t.Fatal(err)
	}
	if err := p.store.DeleteUserUpstream(ctx, ownerID, "us_1"); err != nil {
		t.Fatal(err)
	}
	p.ForgetUser(ownerID)
	if _, err := p.resolveUpstream(ctx, key, "mine"); err == nil {
		t.Fatal("a deleted own upstream is still proxied")
	}
}
