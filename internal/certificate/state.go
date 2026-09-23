package certificate

import (
	"fmt"
	"time"
)

type State string

const (
	Unconfigured State = "unconfigured"
	Issuing      State = "issuing"
	Active       State = "active"
	Renewing     State = "renewing"
	Degraded     State = "degraded"
	Manual       State = "manual"
)

type Mode string

const (
	Production Mode = "production"
	Staging    Mode = "staging"
	ManualMode Mode = "manual"
)

type Metadata struct {
	State                                          State
	Mode                                           Mode
	Hostname, Email, DirectoryURL, RegistrationURI string
	Serial, Issuer                                 string
	SANs                                           []string
	NotBefore, NotAfter                            time.Time
	Fingerprint, ActiveRevision, PreviousRevision  string
	CertificatePath, PrivateKeyPath                string
	LastError                                      string
	UpdatedAt                                      time.Time
}

func CanTransition(from, to State) bool {
	allowed := map[State]map[State]bool{
		Unconfigured: {Issuing: true, Manual: true},
		Issuing:      {Active: true, Degraded: true},
		Active:       {Renewing: true, Manual: true},
		Renewing:     {Active: true, Degraded: true},
		Degraded:     {Renewing: true, Active: true, Manual: true},
		Manual:       {Issuing: true, Manual: true},
	}
	return from == to || allowed[from][to]
}

func (m Metadata) Transition(to State) (Metadata, error) {
	if !CanTransition(m.State, to) {
		return m, fmt.Errorf("invalid TLS transition %s -> %s", m.State, to)
	}
	m.State, m.UpdatedAt = to, time.Now().UTC()
	return m, nil
}
