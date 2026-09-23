package domain

import "time"

type UserStatus string

const (
	UserActive   UserStatus = "active"
	UserDisabled UserStatus = "disabled"
	UserRevoked  UserStatus = "revoked"
)

type VPNUser struct {
	ID                   int64
	Username, Credential string
	Status               UserStatus
	CreatedAt, UpdatedAt time.Time
}

type EndpointStatus struct {
	State, Revision, Version string
	PID                      int
	StartedAt                time.Time
	LastError                string
}

type EndpointMetrics struct{ ActiveConnections, TotalConnections float64 }
type ClientConfig struct{ DeepLink, TOML string }
type ApplyEvent struct {
	Revision, Kind, Action, Result, Error string
	At                                    time.Time
}
type Event struct {
	Level, Message string
	At             time.Time
}

type Snapshot struct {
	Revision                              string
	Hostname, ListenAddress               string
	Users                                 []VPNUser
	Rules                                 []Rule
	TLSCertificatePath, TLSPrivateKeyPath string
}

type Rule struct {
	Name, Action, Network string
}

type Change struct {
	Kind     string
	Snapshot Snapshot
}
type Revision struct {
	ID        string
	CreatedAt time.Time
}
