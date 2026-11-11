package store

import (
	"context"
	"fmt"
	"time"
)

// AuditEntry is one recorded tool call.
type AuditEntry struct {
	ID        string
	UserID    string
	KeyID     string
	KeyLabel  string
	ToolName  string
	Arguments string
	Response  *string
	CreatedAt time.Time
}

// AppendAudit records one proxied tool call. response may be nil.
func (s *Store) AppendAudit(ctx context.Context, e *AuditEntry) error {
	var resp any
	if e.Response != nil {
		resp = *e.Response
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO audit_log (id, user_id, key_id, key_label, tool_name, arguments, response, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		e.ID, e.UserID, e.KeyID, e.KeyLabel, e.ToolName, e.Arguments, resp, FormatTime(e.CreatedAt))
	if err != nil {
		return fmt.Errorf("store: append audit: %w", err)
	}
	return nil
}

// ListAuditForUser returns the newest entries of one user, capped at limit.
func (s *Store) ListAuditForUser(ctx context.Context, userID string, limit int) ([]*AuditEntry, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT id, user_id, key_id, key_label, tool_name, arguments, response, created_at
FROM audit_log WHERE user_id = ? ORDER BY created_at DESC LIMIT ?`, userID, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []*AuditEntry
	for rows.Next() {
		var e AuditEntry
		var args, resp, created any
		if err := rows.Scan(&e.ID, &e.UserID, &e.KeyID, &e.KeyLabel, &e.ToolName, &args, &resp, &created); err != nil {
			return nil, err
		}
		if s2, ok := args.(string); ok {
			e.Arguments = s2
		}
		if s2, ok := resp.(string); ok {
			e.Response = &s2
		}
		t, perr := ParseTime(created.(string))
		if perr != nil {
			return nil, fmt.Errorf("store: decode audit created_at: %w", perr)
		}
		e.CreatedAt = t
		out = append(out, &e)
	}
	return out, rows.Err()
}

// DeleteAuditOlderThan garbage-collects entries older than cutoff.
func (s *Store) DeleteAuditOlderThan(ctx context.Context, cutoff time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM audit_log WHERE created_at < ?`, FormatTime(cutoff))
	if err != nil {
		return 0, fmt.Errorf("store: gc audit: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}
