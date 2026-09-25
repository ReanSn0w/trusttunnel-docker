package persistence

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/reansnow/trusttunnel-controller/internal/clientprofile"
)

func (s *Store) LoadClientProfile(ctx context.Context) (clientprofile.Settings, error) {
	p := clientprofile.Default()
	var data string
	err := s.db.QueryRowContext(ctx, "SELECT settings_json FROM client_profile WHERE id=1").Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return p, nil
	}
	if err != nil {
		return p, err
	}
	if err = json.Unmarshal([]byte(data), &p); err != nil {
		return p, err
	}
	return p, p.Validate()
}

func (s *Store) SaveClientProfile(ctx context.Context, p clientprofile.Settings) error {
	if err := p.Validate(); err != nil {
		return err
	}
	data, err := json.Marshal(p)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, "INSERT INTO client_profile(id,settings_json) VALUES(1,?) ON CONFLICT(id) DO UPDATE SET settings_json=excluded.settings_json", string(data))
	return err
}
