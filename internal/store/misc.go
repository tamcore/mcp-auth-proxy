package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"os"
	"time"
)

// timeRFC3339Nano is the single timestamp format used in the database.
const timeRFC3339Nano = time.RFC3339Nano

// nowUTC is the real clock.
func nowUTC() time.Time { return time.Now().UTC() }

// HashSecret returns the sha256-hex of a token or OTP. Only this hash is stored
// or logged.
func HashSecret(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func checksumHex(b []byte) string { return HashSecret(string(b)) }

// scanner is satisfied by both sql.Row and sql.Rows.
type scanner interface {
	Scan(dest ...any) error
}

// scanOne runs a query expected to yield exactly one row, mapping sql.ErrNoRows
// to ErrNotFound.
func scanOne(ctx context.Context, s *Store, query string, args []any, dest ...any) error {
	row := s.db.QueryRowContext(ctx, query, args...)
	if err := row.Scan(dest...); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	return nil
}

func isNoRows(err error) bool { return errors.Is(err, sql.ErrNoRows) }

func mkdirAll(dir string) error { return os.MkdirAll(dir, 0o700) }

// FormatTime / ParseTime convert between time.Time and the stored text form.
func FormatTime(t time.Time) string { return t.UTC().Format(timeRFC3339Nano) }

func ParseTime(s string) (time.Time, error) { return time.Parse(timeRFC3339Nano, s) }
