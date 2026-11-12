// Package store is the SQLite persistence layer of mcp-auth-proxy. It owns the
// database handle, the forward-only migrator, and one file per entity family:
// keys, gate state (sessions and challenges), OAuth clients and tokens, and
// per-upstream token sets.
//
// Only sha256-hex token hashes and OTP hashes ever cross this boundary. Plaintext
// token or OTP material lives exclusively in memory and in the single ntfy push.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	_ "modernc.org/sqlite" // pure-Go SQLite driver, CGO off

	"github.com/tamcore/mcp-auth-proxy/migrations"
)

// Sentinel errors. Package-level vars are allowed for sentinels.
var (
	ErrNotFound = errors.New("store: not found")
	ErrTooNew   = errors.New("store: database schema is newer than this build")
)

// Store wraps the SQLite handle. All methods take a context.
type Store struct {
	db       *sql.DB
	path     string
	migrated []string
	snapshot string
}

// Open opens (and creates if needed) the database at path, applies pending
// migrations, and verifies the recorded schema version is not newer than the
// build.
func Open(ctx context.Context, path string) (*Store, error) {
	if err := ensureDir(path); err != nil {
		return nil, err
	}
	if err := ownerOnly(path); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=foreign_keys(ON)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("store: open: %w", err)
	}
	db.SetMaxOpenConns(1) // SQLite serializes writers; one conn avoids SQLITE_BUSY
	s := &Store{db: db, path: path}
	if err := s.Migrate(ctx, migrations.FS()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// MigrationsApplied names the migrations the last Migrate applied, e.g.
// "0008_key_activity", so the caller can log them.
func (s *Store) MigrationsApplied() []string { return s.migrated }

// MigrationBackup is the snapshot taken before the last Migrate, if any.
func (s *Store) MigrationBackup() string { return s.snapshot }

// Close releases the database handle.
func (s *Store) Close() error { return s.db.Close() }

// DB exposes the raw handle for package-internal use only within this package's
// files; other packages go through the typed methods.
func (s *Store) DB() *sql.DB { return s.db }

// ownerOnly creates the database file 0600, or tightens an existing one: it
// holds upstream and push tokens. SQLite gives its WAL and SHM files the same
// mode as the database.
func ownerOnly(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return fmt.Errorf("store: open database file: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("store: open database file: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("store: restrict database file: %w", err)
	}
	return nil
}

func ensureDir(path string) error {
	dir := filepath.Dir(path)
	if err := mkdirAll(dir); err != nil {
		return fmt.Errorf("store: state dir: %w", err)
	}
	return nil
}

// --- migrator ---------------------------------------------------------------

const createMigrationsTable = `
CREATE TABLE IF NOT EXISTS schema_migrations (
    version    INTEGER PRIMARY KEY,
    name       TEXT NOT NULL,
    checksum   TEXT NOT NULL,
    applied_at TEXT NOT NULL
) STRICT;`

// migrationNamePattern is the only accepted file name shape.
var migrationNamePattern = regexp.MustCompile(`^(\d{4})_([a-z0-9]+(?:_[a-z0-9]+)*)\.sql$`)

// Migration is one forward-only schema step.
type Migration struct {
	Version    int
	Name       string
	Checksum   string
	statements string
}

// LoadMigrations reads and validates the migration set from fsys.
func LoadMigrations(fsys fs.FS) ([]Migration, error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, fmt.Errorf("store: read migrations: %w", err)
	}
	var ms []Migration
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		m := migrationNamePattern.FindStringSubmatch(e.Name())
		if m == nil {
			return nil, fmt.Errorf("store: invalid migration file name %q", e.Name())
		}
		body, err := fs.ReadFile(fsys, e.Name())
		if err != nil {
			return nil, fmt.Errorf("store: read migration %q: %w", e.Name(), err)
		}
		v, err := strconv.Atoi(m[1])
		if err != nil {
			return nil, fmt.Errorf("store: parse migration version %q: %w", e.Name(), err)
		}
		ms = append(ms, Migration{Version: v, Name: m[2], Checksum: checksumHex(body), statements: string(body)})
	}
	slices.SortFunc(ms, func(a, b Migration) int { return a.Version - b.Version })
	for i, m := range ms {
		if m.Version != i+1 {
			return nil, fmt.Errorf("store: migration versions must be 1..N with no gaps, got %d at index %d", m.Version, i)
		}
	}
	return ms, nil
}

// Migrate applies every migration newer than the recorded version, each in a
// transaction, and refuses a database recorded newer than the build.
func (s *Store) Migrate(ctx context.Context, fsys fs.FS) error {
	ms, err := LoadMigrations(fsys)
	if err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, createMigrationsTable); err != nil {
		return fmt.Errorf("store: create schema_migrations: %w", err)
	}
	applied, err := s.appliedVersions(ctx)
	if err != nil {
		return err
	}
	latest := 0
	for _, a := range applied {
		latest = max(latest, a)
	}
	if latest > len(ms) {
		return ErrTooNew
	}
	s.migrated = nil
	for _, m := range ms {
		if m.Version <= latest {
			continue
		}
		if len(s.migrated) == 0 && latest > 0 {
			if err := s.backup(ctx, m.Version); err != nil {
				return err
			}
		}
		if err := s.apply(ctx, m); err != nil {
			return err
		}
		s.migrated = append(s.migrated, fmt.Sprintf("%04d_%s", m.Version, m.Name))
	}
	return nil
}

// backup snapshots an existing database before it is migrated to version.
// ponytail: one file per upgrade is kept; prune by hand if the volume fills.
func (s *Store) backup(ctx context.Context, version int) error {
	if s.path == "" {
		return nil
	}
	dst := fmt.Sprintf("%s.pre-v%04d.bak", s.path, version)
	s.snapshot = dst
	if _, err := os.Stat(dst); err == nil {
		return nil // an earlier, failed attempt already took the snapshot
	}
	if _, err := s.db.ExecContext(ctx, `VACUUM INTO ?`, dst); err != nil {
		return fmt.Errorf("store: backup before migration %04d: %w", version, err)
	}
	return nil
}

func (s *Store) appliedVersions(ctx context.Context) ([]int, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT version FROM schema_migrations ORDER BY version`)
	if err != nil {
		return nil, fmt.Errorf("store: read schema_migrations: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []int
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Store) apply(ctx context.Context, m Migration) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin migration %d: %w", m.Version, err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, m.statements); err != nil {
		return fmt.Errorf("store: apply migration %04d_%s: %w", m.Version, m.Name, err)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO schema_migrations (version, name, checksum, applied_at) VALUES (?, ?, ?, ?)`,
		m.Version, m.Name, m.Checksum, nowUTC().Format(timeRFC3339Nano)); err != nil {
		return fmt.Errorf("store: record migration %d: %w", m.Version, err)
	}
	return tx.Commit()
}
