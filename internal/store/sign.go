package store

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

// SignSecretFile is the name of the HMAC signing secret inside the state dir.
const SignSecretFile = "sign.secret"

// EnsureSignSecret returns the HMAC signing secret for approve/deny URLs,
// creating {state_dir}/sign.secret with mode 0600 if absent.
func EnsureSignSecret(stateDir string) ([]byte, error) {
	path := filepath.Join(stateDir, SignSecretFile)
	b, err := os.ReadFile(path)
	if err == nil {
		if len(b) < 32 {
			return nil, fmt.Errorf("store: %s is too short (%d bytes); refusing to use it as a signing secret", path, len(b))
		}
		if err := os.Chmod(path, 0o600); err != nil {
			return nil, fmt.Errorf("store: restrict %s: %w", path, err)
		}
		return b, nil
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("store: read %s: %w", path, err)
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("store: generate signing secret: %w", err)
	}
	// The file stores hex; the in-memory secret is the same hex string's bytes,
	// so a re-read returns an identical secret.
	secret := []byte(hex.EncodeToString(raw))
	// O_EXCL keeps a concurrent creator from racing us; mode 0600 from creation.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("store: create %s: %w", path, err)
	}
	if _, err := f.Write(secret); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("store: write %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("store: close %s: %w", path, err)
	}
	return secret, nil
}

// CheckSignSecretPerms verifies the signing secret file exists with owner-only
// permissions (doctor).
func CheckSignSecretPerms(stateDir string) error {
	path := filepath.Join(stateDir, SignSecretFile)
	fi, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("sign secret missing: %w", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		return fmt.Errorf("sign secret %s has mode %04o, want 0600", path, perm)
	}
	return nil
}
