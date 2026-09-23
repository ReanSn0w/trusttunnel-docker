package endpointcli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/reansnow/trusttunnel-controller/internal/domain"
)

func TestEndpointHelper(t *testing.T) {
	if os.Getenv("TT_CLI_HELPER") != "1" {
		return
	}
	args := os.Args
	format := args[len(args)-1]
	if format == "deeplink" {
		fmt.Print("tt://?safe-test")
	} else {
		fmt.Print("hostname = \"vpn.example.com\"")
	}
}

func TestExportBothOfficialFormats(t *testing.T) {
	t.Setenv("TT_CLI_HELPER", "1")
	c, err := New(os.Args[0], "vpn.toml", "hosts.toml", time.Second, 1024, 1)
	if err != nil {
		t.Fatal(err)
	}
	// Make the test binary execute only its helper test while preserving official CLI args.
	c.vpnConfig = "-test.run=TestEndpointHelper"
	got, err := c.Export(context.Background(), domain.VPNUser{Username: "alice", Status: domain.UserActive}, "vpn.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got.DeepLink, "tt://?") || !strings.Contains(got.TOML, "hostname") {
		t.Fatalf("unexpected export: %#v", got)
	}
}

func TestExportRejectsInactiveUser(t *testing.T) {
	c, _ := New("binary", "vpn", "hosts", time.Second, 1024, 1)
	if _, err := c.Export(context.Background(), domain.VPNUser{Username: "alice", Status: domain.UserDisabled}, "vpn.example.com"); err == nil {
		t.Fatal("expected inactive rejection")
	}
}
