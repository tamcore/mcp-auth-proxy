package store

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDatabaseIsOwnerOnly(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	fresh := filepath.Join(dir, "fresh.db")
	st, err := Open(ctx, fresh)
	if err != nil {
		t.Fatal(err)
	}
	_ = st.Close()
	legacy := filepath.Join(dir, "legacy.db")
	if err := os.WriteFile(legacy, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	st, err = Open(ctx, legacy)
	if err != nil {
		t.Fatal(err)
	}
	_ = st.Close()
	for _, p := range []string{fresh, legacy} {
		info, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if mode := info.Mode().Perm(); mode != 0o600 {
			t.Fatalf("%s: mode %o, want 600 (it holds tokens)", filepath.Base(p), mode)
		}
	}
}

func TestExistingSignSecretIsTightened(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, SignSecretFile)
	if err := os.WriteFile(path, []byte(strings.Repeat("a", 64)), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureSignSecret(dir); err != nil {
		t.Fatal(err)
	}
	if err := CheckSignSecretPerms(dir); err != nil {
		t.Fatalf("a readable signing secret lets other local users forge approvals: %v", err)
	}
}

func TestSignSecretRefusesASymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.WriteFile(target, []byte(strings.Repeat("a", 64)), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, SignSecretFile)); err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureSignSecret(dir); err == nil {
		t.Fatal("a symlinked signing secret must be refused")
	}
	if fi, _ := os.Stat(target); fi.Mode().Perm() != 0o644 {
		t.Fatalf("the symlink target must stay untouched: %v", fi.Mode())
	}
}
