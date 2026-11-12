package store

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"
)

const mig1 = "0001_a.sql"

func TestMigrateBacksUpAndReportsPendingMigrations(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "proxy.db")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	s := &Store{db: db, path: path}
	defer func() { _ = s.Close() }()
	v1 := fstest.MapFS{mig1: {Data: []byte("CREATE TABLE a (x TEXT) STRICT;")}}
	if err := s.Migrate(ctx, v1); err != nil {
		t.Fatal(err)
	}
	if got := s.MigrationsApplied(); len(got) != 1 || got[0] != "0001_a" {
		t.Fatalf("applied: %v", got)
	}
	if _, err := os.Stat(path + ".pre-v0001.bak"); !os.IsNotExist(err) {
		t.Fatal("a fresh database needs no backup")
	}
	v2 := fstest.MapFS{mig1: v1[mig1], "0002_b.sql": {Data: []byte("CREATE TABLE b (y TEXT) STRICT;")}}
	if err := s.Migrate(ctx, v2); err != nil {
		t.Fatal(err)
	}
	if got := s.MigrationsApplied(); len(got) != 1 || got[0] != "0002_b" {
		t.Fatalf("applied: %v", got)
	}
	if s.MigrationBackup() != path+".pre-v0002.bak" {
		t.Fatalf("backup path: %q", s.MigrationBackup())
	}
	assertOwnerOnly(t, s.MigrationBackup())
	v3 := fstest.MapFS{mig1: v1[mig1], "0002_b.sql": v2["0002_b.sql"],
		"0003_c.sql": {Data: []byte("CREATE TABLE c (z TEXT) STRICT;")}}
	if err := os.WriteFile(path+".pre-v0003.bak", []byte("old snapshot"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(ctx, v3); err != nil {
		t.Fatalf("an existing snapshot from a failed attempt must not block startup: %v", err)
	}
	assertOwnerOnly(t, path+".pre-v0003.bak")
	bak, err := sql.Open("sqlite", "file:"+path+".pre-v0002.bak?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = bak.Close() }()
	var n int
	q := `SELECT COUNT(*) FROM sqlite_master WHERE name IN ('a', 'b')`
	if err := bak.QueryRowContext(ctx, q).Scan(&n); err != nil || n != 1 {
		t.Fatalf("backup must hold the pre-migration schema (only table a): n=%d err=%v", n, err)
	}
}

func assertOwnerOnly(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("%s: mode %o, want 600 (it holds tokens)", filepath.Base(path), mode)
	}
}
