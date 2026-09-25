package certificate

import "testing"

func TestValidateSourceSettings(t *testing.T) {
	tests := []struct {
		name, hostname, email, cert, key string
		source                           Source
		valid                            bool
	}{
		{"letsencrypt", "vpn.example.com", "admin@example.com", "", "", LetsEncrypt, true},
		{"self-signed", "vpn.example.test", "", "", "", SelfSigned, true},
		{"provided", "vpn.example.com", "", "/run/tls/cert.pem", "/run/tls/key.pem", Provided, true},
		{"missing ACME email", "vpn.example.com", "", "", "", LetsEncrypt, false},
		{"self-signed ACME conflict", "vpn.example.com", "admin@example.com", "", "", SelfSigned, false},
		{"provided incomplete pair", "vpn.example.com", "", "/run/tls/cert.pem", "", Provided, false},
		{"provided relative path", "vpn.example.com", "", "cert.pem", "/run/tls/key.pem", Provided, false},
		{"ACME PEM conflict", "vpn.example.com", "admin@example.com", "/run/tls/cert.pem", "/run/tls/key.pem", LetsEncrypt, false},
		{"IP hostname", "127.0.0.1", "", "", "", SelfSigned, false},
		{"unknown source", "vpn.example.com", "", "", "", "other", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateSourceSettings(tc.source, tc.hostname, tc.email, tc.cert, tc.key)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v err=%v", tc.valid, err)
			}
		})
	}
}
