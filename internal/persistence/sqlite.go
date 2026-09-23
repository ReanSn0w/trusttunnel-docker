package persistence

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"

	"github.com/reansnow/trusttunnel-controller/internal/domain"
)

const schemaVersion = 1

var migrations = []string{`
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    username TEXT NOT NULL UNIQUE,
    password_hash BLOB NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS vpn_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    credential TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active','disabled','revoked')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS vpn_users_status_idx ON vpn_users(status);
CREATE TABLE IF NOT EXISTS settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    hostname TEXT NOT NULL DEFAULT '',
    listen_address TEXT NOT NULL DEFAULT '0.0.0.0:8443',
    active_revision TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS apply_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    revision TEXT NOT NULL,
    kind TEXT NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('restart','sighup','none')),
    result TEXT NOT NULL CHECK (result IN ('pending','success','failure','rollback')),
    error TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS apply_events_created_idx ON apply_events(created_at DESC);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash BLOB PRIMARY KEY,
    admin_id INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_expiry_idx ON sessions(expires_at);
`}

type Store struct{ db *sql.DB }

func Open(ctx context.Context, path string) (*Store, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("database path must be absolute")
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL", "PRAGMA foreign_keys=ON", "PRAGMA busy_timeout=5000",
	} {
		if _, err = db.ExecContext(ctx, pragma); err != nil {
			db.Close()
			return nil, fmt.Errorf("sqlite setup: %w", err)
		}
	}
	s := &Store{db: db}
	if err = s.migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}
	if err = s.bootstrap(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate(ctx context.Context) error {
	for i, migration := range migrations {
		version := i + 1
		var exists int
		err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='schema_migrations'").Scan(&exists)
		if err != nil {
			return err
		}
		if exists != 0 {
			var applied int
			if err = s.db.QueryRowContext(ctx, "SELECT count(*) FROM schema_migrations WHERE version=?", version).Scan(&applied); err != nil || applied != 0 {
				if err != nil {
					return err
				}
				continue
			}
		}
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, migration); err == nil {
			_, err = tx.ExecContext(ctx, "INSERT INTO schema_migrations(version, applied_at) VALUES(?, ?)", version, time.Now().UTC().Format(time.RFC3339Nano))
		}
		if err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("migration %d: %w", version, err)
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) bootstrap(ctx context.Context) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(ctx, `INSERT INTO settings(id, updated_at) VALUES(1, ?)
        ON CONFLICT(id) DO NOTHING`, now)
	return err
}

func (s *Store) Snapshot(ctx context.Context) (domain.Snapshot, error) {
	var snap domain.Snapshot
	if err := s.db.QueryRowContext(ctx, `SELECT active_revision, hostname, listen_address FROM settings WHERE id=1`).
		Scan(&snap.Revision, &snap.Hostname, &snap.ListenAddress); err != nil {
		return snap, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, username, credential, status, created_at, updated_at FROM vpn_users ORDER BY username`)
	if err != nil {
		return snap, err
	}
	defer rows.Close()
	for rows.Next() {
		var u domain.VPNUser
		var created, updated string
		if err = rows.Scan(&u.ID, &u.Username, &u.Credential, &u.Status, &created, &updated); err != nil {
			return snap, err
		}
		u.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		u.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
		snap.Users = append(snap.Users, u)
	}
	return snap, rows.Err()
}

func (s *Store) UpsertUser(ctx context.Context, u domain.VPNUser) error {
	if u.Status != domain.UserActive && u.Status != domain.UserDisabled && u.Status != domain.UserRevoked {
		return fmt.Errorf("invalid user status %q", u.Status)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(ctx, `INSERT INTO vpn_users(username, credential, status, created_at, updated_at)
        VALUES(?,?,?,?,?) ON CONFLICT(username) DO UPDATE SET credential=excluded.credential,
        status=excluded.status, updated_at=excluded.updated_at`, u.Username, u.Credential, u.Status, now, now)
	return err
}

func (s *Store) RecordEvent(ctx context.Context, e domain.ApplyEvent) error {
	if len(e.Error) > 2048 {
		e.Error = e.Error[:2048]
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO apply_events(revision,kind,action,result,error,created_at)
        VALUES(?,?,?,?,?,?)`, e.Revision, e.Kind, e.Action, e.Result, e.Error, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

func (s *Store) SchemaVersion(ctx context.Context) (int, error) {
	var version int
	err := s.db.QueryRowContext(ctx, "SELECT coalesce(max(version), 0) FROM schema_migrations").Scan(&version)
	return version, err
}
