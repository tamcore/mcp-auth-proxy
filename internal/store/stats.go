package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// ActivityStat aggregates one user's activity, or the whole instance's.
// Challenge times are creation times; a challenge resolves within its expiry.
type ActivityStat struct {
	ActiveKeys, RevokedKeys           int
	ToolCalls                         int // audit rows, bounded by audit retention
	Granted, Denied, Expired, Pending int
	LastActive, LastToolCall          *time.Time
	LastGranted, LastDenied           *time.Time
}

// Activity is per-user stats keyed by user ID, plus the instance total
// (which also counts keys without an owner).
type Activity struct {
	Users map[string]*ActivityStat
	Total ActivityStat
}

func (a *Activity) of(userID string) *ActivityStat {
	s, ok := a.Users[userID]
	if !ok {
		s = &ActivityStat{}
		a.Users[userID] = s
	}
	return s
}

// latest keeps the later of *dst and t.
func latest(dst **time.Time, t *time.Time) {
	if t != nil && (*dst == nil || t.After(**dst)) {
		*dst = t
	}
}

// ActivityStats aggregates keys, challenges and the audit log at now. Maxima
// are taken in Go: the stored RFC 3339 text does not sort as time.
// ponytail: scans every challenge row; add a rollup if the table grows past
// what a personal instance produces.
func (s *Store) ActivityStats(ctx context.Context, now time.Time) (*Activity, error) {
	a := &Activity{Users: map[string]*ActivityStat{}}
	for _, step := range []func(context.Context, *Activity, time.Time) error{
		s.keyActivity, s.challengeActivity, s.auditActivity,
	} {
		if err := step(ctx, a, now); err != nil {
			return nil, err
		}
	}
	return a, nil
}

func (s *Store) keyActivity(ctx context.Context, a *Activity, _ time.Time) error {
	return s.scanRows(ctx,
		`SELECT COALESCE(user_id, ''), revoked_at IS NOT NULL, last_used_at, last_success_at FROM keys`,
		func(rows *sql.Rows) error {
			var user string
			var revoked bool
			var used, success any
			if err := rows.Scan(&user, &revoked, &used, &success); err != nil {
				return err
			}
			u, err := optionalTime(used)
			if err != nil {
				return err
			}
			ok, err := optionalTime(success)
			if err != nil {
				return err
			}
			for _, st := range []*ActivityStat{a.of(user), &a.Total} {
				if revoked {
					st.RevokedKeys++
				} else {
					st.ActiveKeys++
				}
				latest(&st.LastActive, u)
				latest(&st.LastToolCall, ok)
			}
			return nil
		})
}

func (s *Store) challengeActivity(ctx context.Context, a *Activity, now time.Time) error {
	return s.scanRows(ctx, `
SELECT COALESCE(k.user_id, ''), c.status, c.created_at, c.expires_at
FROM challenges c JOIN keys k ON k.id = c.key_id`,
		func(rows *sql.Rows) error {
			var user, status, created, expires string
			if err := rows.Scan(&user, &status, &created, &expires); err != nil {
				return err
			}
			at, err := ParseTime(created)
			if err != nil {
				return fmt.Errorf("store: decode challenge time: %w", err)
			}
			exp, err := ParseTime(expires)
			if err != nil {
				return fmt.Errorf("store: decode challenge time: %w", err)
			}
			for _, st := range []*ActivityStat{a.of(user), &a.Total} {
				switch {
				case status == ChallengeApproved:
					st.Granted++
					latest(&st.LastGranted, &at)
				case status == ChallengeDenied:
					st.Denied++
					latest(&st.LastDenied, &at)
				case status == ChallengePending && now.Before(exp):
					st.Pending++
				default:
					st.Expired++
				}
			}
			return nil
		})
}

func (s *Store) auditActivity(ctx context.Context, a *Activity, _ time.Time) error {
	return s.scanRows(ctx, `SELECT user_id, COUNT(*) FROM audit_log GROUP BY user_id`,
		func(rows *sql.Rows) error {
			var user string
			var n int
			if err := rows.Scan(&user, &n); err != nil {
				return err
			}
			a.of(user).ToolCalls += n
			a.Total.ToolCalls += n
			return nil
		})
}

func (s *Store) scanRows(ctx context.Context, query string, each func(*sql.Rows) error) error {
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return fmt.Errorf("store: activity stats: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		if err := each(rows); err != nil {
			return err
		}
	}
	return rows.Err()
}
