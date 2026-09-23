package service

import (
	"context"
	"errors"
	"testing"

	"github.com/reansnow/trusttunnel-controller/internal/certificate"
)

type authStub struct{ err error }

func (a authStub) AuthorizeCertificateManagement(context.Context, Actor) error { return a.err }

type importerStub struct{ called bool }

func (i *importerStub) ImportManual(context.Context, string, []byte, []byte) (certificate.Metadata, error) {
	i.called = true
	return certificate.Metadata{State: certificate.Manual}, nil
}
func TestCertificateServiceRequiresAuthorization(t *testing.T) {
	importer := &importerStub{}
	svc := NewCertificateService(authStub{err: errors.New("denied")}, importer)
	if _, err := svc.ImportManual(context.Background(), Actor{}, "vpn.example.net", nil, nil); err == nil {
		t.Fatal("expected denial")
	}
	if importer.called {
		t.Fatal("import called after denial")
	}
}
func TestCertificateServiceCallsAuthorizedImporter(t *testing.T) {
	importer := &importerStub{}
	svc := NewCertificateService(authStub{}, importer)
	got, err := svc.ImportManual(context.Background(), Actor{AdminID: 1}, "vpn.example.net", []byte("chain"), []byte("key"))
	if err != nil || !importer.called || got.State != certificate.Manual {
		t.Fatalf("got=%#v called=%v err=%v", got, importer.called, err)
	}
}
