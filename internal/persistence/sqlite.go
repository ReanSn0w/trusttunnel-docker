package persistence

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/reansnow/trusttunnel-controller/internal/auth"
	"github.com/reansnow/trusttunnel-controller/internal/certificate"
	"github.com/reansnow/trusttunnel-controller/internal/domain"
)

const schemaVersion = 4

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
`, `
CREATE TABLE IF NOT EXISTS acme_account (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    directory_url TEXT NOT NULL,
    email TEXT NOT NULL,
    registration_uri TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'new',
    last_error TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tls_certificate (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    state TEXT NOT NULL CHECK (state IN ('unconfigured','issuing','active','renewing','degraded','manual')),
    mode TEXT NOT NULL CHECK (mode IN ('production','staging','manual')),
    hostname TEXT NOT NULL,
    email TEXT NOT NULL DEFAULT '',
    directory_url TEXT NOT NULL DEFAULT '',
    registration_uri TEXT NOT NULL DEFAULT '',
    serial TEXT NOT NULL DEFAULT '',
    issuer TEXT NOT NULL DEFAULT '',
    sans TEXT NOT NULL DEFAULT '',
    not_before TEXT NOT NULL DEFAULT '',
    not_after TEXT NOT NULL DEFAULT '',
    fingerprint TEXT NOT NULL DEFAULT '',
    active_revision TEXT NOT NULL DEFAULT '',
    previous_revision TEXT NOT NULL DEFAULT '',
    last_error TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS tls_certificate_expiry_idx ON tls_certificate(not_after);
`, `
ALTER TABLE tls_certificate ADD COLUMN certificate_path TEXT NOT NULL DEFAULT '';
ALTER TABLE tls_certificate ADD COLUMN private_key_path TEXT NOT NULL DEFAULT '';
CREATE TABLE IF NOT EXISTS rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    action TEXT NOT NULL CHECK (action IN ('allow','deny')),
    network TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
`, `
CREATE TABLE client_profile (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    settings_json TEXT NOT NULL
);
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
	if err := s.db.QueryRowContext(ctx, `SELECT s.active_revision,s.hostname,s.listen_address,coalesce(t.certificate_path,''),coalesce(t.private_key_path,'') FROM settings s LEFT JOIN tls_certificate t ON t.id=1 WHERE s.id=1`).
		Scan(&snap.Revision, &snap.Hostname, &snap.ListenAddress, &snap.TLSCertificatePath, &snap.TLSPrivateKeyPath); err != nil {
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
	if err = rows.Err(); err != nil {
		return snap, err
	}
	ruleRows, err := s.db.QueryContext(ctx, "SELECT name,action,network FROM rules ORDER BY name")
	if err != nil {
		return snap, err
	}
	defer ruleRows.Close()
	for ruleRows.Next() {
		var rule domain.Rule
		if err = ruleRows.Scan(&rule.Name, &rule.Action, &rule.Network); err != nil {
			return snap, err
		}
		snap.Rules = append(snap.Rules, rule)
	}
	return snap, ruleRows.Err()
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

func (s *Store) ListUsers(ctx context.Context) ([]domain.VPNUser, error) {
	snap, err := s.Snapshot(ctx)
	return snap.Users, err
}
func (s *Store) UserByID(ctx context.Context, id int64) (domain.VPNUser, error) {
	var u domain.VPNUser
	var created, updated string
	err := s.db.QueryRowContext(ctx, "SELECT id,username,credential,status,created_at,updated_at FROM vpn_users WHERE id=?", id).Scan(&u.ID, &u.Username, &u.Credential, &u.Status, &created, &updated)
	u.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	u.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
	return u, err
}
func (s *Store) InsertUser(ctx context.Context, u domain.VPNUser) (int64, error) {
	if u.Status != domain.UserActive {
		return 0, errors.New("new user must be active")
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := s.db.ExecContext(ctx, "INSERT INTO vpn_users(username,credential,status,created_at,updated_at) VALUES(?,?,?,?,?)", u.Username, u.Credential, u.Status, now, now)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}
func (s *Store) UpdateUser(ctx context.Context, u domain.VPNUser) error {
	if u.Status != domain.UserActive && u.Status != domain.UserDisabled && u.Status != domain.UserRevoked {
		return errors.New("invalid user status")
	}
	res, err := s.db.ExecContext(ctx, "UPDATE vpn_users SET username=?,credential=?,status=?,updated_at=? WHERE id=?", u.Username, u.Credential, u.Status, time.Now().UTC().Format(time.RFC3339Nano), u.ID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err == nil && n != 1 {
		return sql.ErrNoRows
	}
	return err
}
func (s *Store) DeleteUser(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM vpn_users WHERE id=?", id)
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

func (s *Store) ListApplyEvents(ctx context.Context, before int64, limit int) ([]domain.ApplyEvent, error) {
	if limit < 1 || limit > 100 {
		return nil, errors.New("event limit must be between 1 and 100")
	}
	query := "SELECT id,revision,kind,action,result,error,created_at FROM apply_events"
	args := []any{}
	if before > 0 {
		query += " WHERE id<?"
		args = append(args, before)
	}
	query += " ORDER BY id DESC LIMIT ?"
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	events := make([]domain.ApplyEvent, 0, limit)
	for rows.Next() {
		var e domain.ApplyEvent
		var at string
		if err = rows.Scan(&e.ID, &e.Revision, &e.Kind, &e.Action, &e.Result, &e.Error, &at); err != nil {
			return nil, err
		}
		e.At = parseTime(at)
		events = append(events, e)
	}
	return events, rows.Err()
}

func (s *Store) ActiveRevision(ctx context.Context) (string, error) {
	var revision string
	err := s.db.QueryRowContext(ctx, "SELECT active_revision FROM settings WHERE id=1").Scan(&revision)
	return revision, err
}

func (s *Store) SetActiveRevision(ctx context.Context, revision string) error {
	_, err := s.db.ExecContext(ctx, "UPDATE settings SET active_revision=?, updated_at=? WHERE id=1", revision, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

func (s *Store) SetHostname(ctx context.Context, hostname string) error {
	_, err := s.db.ExecContext(ctx, "UPDATE settings SET hostname=?,updated_at=? WHERE id=1", hostname, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

func (s *Store) SetListenAddress(ctx context.Context, address string) error {
	_, err := s.db.ExecContext(ctx, "UPDATE settings SET listen_address=?,updated_at=? WHERE id=1", address, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}
func (s *Store) UpsertRule(ctx context.Context, r domain.Rule) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO rules(name,action,network,updated_at) VALUES(?,?,?,?) ON CONFLICT(name) DO UPDATE SET action=excluded.action,network=excluded.network,updated_at=excluded.updated_at`, r.Name, r.Action, r.Network, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

func (s *Store) SchemaVersion(ctx context.Context) (int, error) {
	var version int
	err := s.db.QueryRowContext(ctx, "SELECT coalesce(max(version), 0) FROM schema_migrations").Scan(&version)
	return version, err
}

func (s *Store) HasAdmin(ctx context.Context) (bool, error) {
	var count int
	err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM admins").Scan(&count)
	return count > 0, err
}

func (s *Store) CreateFirstAdmin(ctx context.Context, username, passwordHash string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var count int
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM admins").Scan(&count); err != nil {
		return err
	}
	if count != 0 {
		return auth.ErrAlreadyBootstrapped
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err = tx.ExecContext(ctx, "INSERT INTO admins(id,username,password_hash,created_at,updated_at) VALUES(1,?,?,?,?)", username, passwordHash, now, now); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) AdminByUsername(ctx context.Context, username string) (auth.Admin, error) {
	var a auth.Admin
	err := s.db.QueryRowContext(ctx, "SELECT id,username,password_hash FROM admins WHERE username=?", username).Scan(&a.ID, &a.Username, &a.PasswordHash)
	return a, err
}
func (s *Store) AdminByID(ctx context.Context, id int64) (auth.Admin, error) {
	var a auth.Admin
	err := s.db.QueryRowContext(ctx, "SELECT id,username,password_hash FROM admins WHERE id=?", id).Scan(&a.ID, &a.Username, &a.PasswordHash)
	return a, err
}
func (s *Store) CreateSession(ctx context.Context, hash []byte, adminID int64, expires time.Time) error {
	_, err := s.db.ExecContext(ctx, "INSERT INTO sessions(token_hash,admin_id,expires_at,created_at) VALUES(?,?,?,?)", hash, adminID, expires.UTC().Format(time.RFC3339Nano), time.Now().UTC().Format(time.RFC3339Nano))
	return err
}
func (s *Store) SessionAdmin(ctx context.Context, hash []byte, now time.Time) (auth.Admin, error) {
	_, _ = s.db.ExecContext(ctx, "DELETE FROM sessions WHERE expires_at<=?", now.UTC().Format(time.RFC3339Nano))
	var a auth.Admin
	err := s.db.QueryRowContext(ctx, `SELECT a.id,a.username,a.password_hash FROM sessions s JOIN admins a ON a.id=s.admin_id WHERE s.token_hash=? AND s.expires_at>?`, hash, now.UTC().Format(time.RFC3339Nano)).Scan(&a.ID, &a.Username, &a.PasswordHash)
	return a, err
}
func (s *Store) DeleteSession(ctx context.Context, hash []byte) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM sessions WHERE token_hash=?", hash)
	return err
}
func (s *Store) UpdateAdminPassword(ctx context.Context, adminID int64, passwordHash string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "UPDATE admins SET password_hash=?,updated_at=? WHERE id=?", passwordHash, time.Now().UTC().Format(time.RFC3339Nano), adminID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM sessions WHERE admin_id=?", adminID); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) DeleteAdmin(ctx context.Context, adminID int64) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM admins WHERE id=?", adminID)
	return err
}

func (s *Store) SaveACMEAccount(ctx context.Context, directoryURL, email, registrationURI, status, lastError string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(ctx, `INSERT INTO acme_account(id,directory_url,email,registration_uri,status,last_error,created_at,updated_at)
        VALUES(1,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET directory_url=excluded.directory_url,email=excluded.email,
        registration_uri=excluded.registration_uri,status=excluded.status,last_error=excluded.last_error,updated_at=excluded.updated_at`, directoryURL, email, registrationURI, status, lastError, now, now)
	return err
}

func (s *Store) SaveTLSMetadata(ctx context.Context, m certificate.Metadata) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO tls_certificate(id,state,mode,hostname,email,directory_url,registration_uri,serial,issuer,sans,not_before,not_after,fingerprint,active_revision,previous_revision,last_error,updated_at,certificate_path,private_key_path)
        VALUES(1,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET state=excluded.state,mode=excluded.mode,hostname=excluded.hostname,email=excluded.email,directory_url=excluded.directory_url,registration_uri=excluded.registration_uri,serial=excluded.serial,issuer=excluded.issuer,sans=excluded.sans,not_before=excluded.not_before,not_after=excluded.not_after,fingerprint=excluded.fingerprint,active_revision=excluded.active_revision,previous_revision=excluded.previous_revision,last_error=excluded.last_error,updated_at=excluded.updated_at,certificate_path=excluded.certificate_path,private_key_path=excluded.private_key_path`, m.State, m.Mode, m.Hostname, m.Email, m.DirectoryURL, m.RegistrationURI, m.Serial, m.Issuer, strings.Join(m.SANs, "\n"), formatTime(m.NotBefore), formatTime(m.NotAfter), m.Fingerprint, m.ActiveRevision, m.PreviousRevision, m.LastError, time.Now().UTC().Format(time.RFC3339Nano), m.CertificatePath, m.PrivateKeyPath)
	return err
}

func (s *Store) LoadTLSMetadata(ctx context.Context) (certificate.Metadata, error) {
	var m certificate.Metadata
	var sans, notBefore, notAfter, updated string
	err := s.db.QueryRowContext(ctx, `SELECT state,mode,hostname,email,directory_url,registration_uri,serial,issuer,sans,not_before,not_after,fingerprint,active_revision,previous_revision,last_error,updated_at,certificate_path,private_key_path FROM tls_certificate WHERE id=1`).Scan(&m.State, &m.Mode, &m.Hostname, &m.Email, &m.DirectoryURL, &m.RegistrationURI, &m.Serial, &m.Issuer, &sans, &notBefore, &notAfter, &m.Fingerprint, &m.ActiveRevision, &m.PreviousRevision, &m.LastError, &updated, &m.CertificatePath, &m.PrivateKeyPath)
	if err != nil {
		return m, err
	}
	if sans != "" {
		m.SANs = strings.Split(sans, "\n")
	}
	m.NotBefore, m.NotAfter, m.UpdatedAt = parseTime(notBefore), parseTime(notAfter), parseTime(updated)
	return m, nil
}

func formatTime(v time.Time) string {
	if v.IsZero() {
		return ""
	}
	return v.UTC().Format(time.RFC3339Nano)
}
func parseTime(v string) time.Time { t, _ := time.Parse(time.RFC3339Nano, v); return t }
