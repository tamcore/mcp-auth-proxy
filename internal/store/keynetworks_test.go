package store

import (
	"context"
	"fmt"
	"net/netip"
	"testing"
)

func TestKeyNetworksUpdate(t *testing.T) {
	ctx := context.Background()
	st := openTest(t)
	now := nowUTC()
	owner := "u_netowner"
	if err := st.CreateUser(ctx, &User{ID: owner, Username: "netowner", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	k := &Key{ID: "k_net", Kind: KeyKindStatic, Label: "l", SecretHash: "h_net", Upstreams: []string{"a"},
		TTLSeconds: 60, CreatedAt: now, UserID: &owner}
	if err := st.CreateKey(ctx, k); err != nil {
		t.Fatal(err)
	}
	assertNetworks(t, st, k.ID, "[] []")
	allowed := []netip.Prefix{netip.MustParsePrefix("192.168.69.0/24")}
	trusted := []netip.Prefix{netip.MustParsePrefix("192.168.69.211/32"), netip.MustParsePrefix("fd00::/8")}
	if err := st.UpdateKeyNetworks(ctx, k.ID, "u_other", allowed, trusted); err != ErrNotFound {
		t.Fatalf("non-owner update: want ErrNotFound, got %v", err)
	}
	if err := st.UpdateKeyNetworks(ctx, k.ID, owner, allowed, trusted); err != nil {
		t.Fatal(err)
	}
	assertNetworks(t, st, k.ID, "[192.168.69.0/24] [192.168.69.211/32 fd00::/8]")
	if err := st.UpdateKeyNetworks(ctx, k.ID, owner, nil, nil); err != nil {
		t.Fatal(err)
	}
	assertNetworks(t, st, k.ID, "[] []")
}

func assertNetworks(t *testing.T, st *Store, id, want string) {
	t.Helper()
	got, err := st.KeyByID(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if s := fmt.Sprint(got.AllowedCIDRs, " ", got.TrustedCIDRs); s != want {
		t.Fatalf("networks = %s, want %s", s, want)
	}
}
