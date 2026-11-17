package mcpserver

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/tamcore/mcp-auth-proxy/internal/egress"
	"github.com/tamcore/mcp-auth-proxy/internal/store"
)

const (
	ownerID  = "u_own"
	mineName = "mine"
)

func TestForgetUserDropsADeletedOwnUpstream(t *testing.T) {
	ctx := context.Background()
	p, _, _ := newTestProxy(t, echoUpstream(t).URL)
	now := time.Now().UTC()
	if err := p.store.CreateUser(ctx, &store.User{ID: ownerID, Username: "own", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	own := &store.UserUpstream{ID: "us_1", UserID: ownerID, Name: mineName, URL: echoUpstream(t).URL, CreatedAt: now}
	if err := p.store.CreateUserUpstream(ctx, own); err != nil {
		t.Fatal(err)
	}
	owner := ownerID
	key := &store.Key{ID: "k_a", UserID: &owner, Upstreams: []string{mineName}}
	if _, err := p.resolveUpstream(ctx, key, mineName); err != nil {
		t.Fatal(err)
	}
	if err := p.store.DeleteUserUpstream(ctx, ownerID, "us_1"); err != nil {
		t.Fatal(err)
	}
	p.ForgetUser(ownerID)
	if _, err := p.resolveUpstream(ctx, key, mineName); err == nil {
		t.Fatal("a deleted own upstream is still proxied")
	}
}

func TestOwnUpstreamsDialThroughTheEgressGuard(t *testing.T) {
	ctx := context.Background()
	p, _, _ := newTestProxy(t, echoUpstream(t).URL)
	p.userClient = egress.New(egress.Allow{}).Client(0)
	now := time.Now().UTC()
	if err := p.store.CreateUser(ctx, &store.User{ID: ownerID, Username: "own", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	own := &store.UserUpstream{ID: "us_1", UserID: ownerID, Name: mineName, URL: echoUpstream(t).URL, CreatedAt: now}
	if err := p.store.CreateUserUpstream(ctx, own); err != nil {
		t.Fatal(err)
	}
	owner := ownerID
	u, err := p.resolveUpstream(ctx, &store.Key{ID: "k_a", UserID: &owner, Upstreams: []string{mineName}}, mineName)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := u.Tools(ctx); err == nil || !strings.Contains(err.Error(), "egress") {
		t.Fatalf("own upstream on loopback must be refused by the guard, got %v", err)
	}
}
