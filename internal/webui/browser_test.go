//go:build browser

package webui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/reansnow/trusttunnel-controller/internal/clientprofile"
	"github.com/reansnow/trusttunnel-controller/internal/domain"
)

func TestBrowserOfflineAssets(t *testing.T) {
	chrome := os.Getenv("CHROME")
	if chrome == "" {
		chrome = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
	}
	if _, err := os.Stat(chrome); err != nil {
		t.Skip("Chrome is not installed")
	}
	mux := http.NewServeMux()
	mux.Handle("/assets/v1/", http.StripPrefix("/assets/v1/", AssetHandler()))
	mux.HandleFunc("/", NewUsersHandler(userWebStub{users: []domain.VPNUser{{ID: 1, Username: "browser-user", Status: domain.UserActive}}}).List)
	server := httptest.NewServer(mux)
	defer server.Close()
	dir := t.TempDir()
	netlog := filepath.Join(dir, "netlog.json")
	domPath := filepath.Join(dir, "dom.txt")
	domFile, err := os.Create(domPath)
	if err != nil {
		t.Fatal(err)
	}
	browserCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(browserCtx, chrome, "--headless", "--disable-gpu", "--no-sandbox", "--disable-background-networking", "--disable-component-update", "--no-first-run", "--user-data-dir="+filepath.Join(dir, "profile"), "--log-net-log="+netlog, "--dump-dom", server.URL)
	cmd.Stdout, cmd.Stderr = domFile, domFile
	err = cmd.Run()
	_ = domFile.Close()
	out, _ := os.ReadFile(domPath)
	if err != nil && len(out) == 0 {
		t.Fatalf("chrome: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "VPN users") || !strings.Contains(string(out), "browser-user") {
		t.Fatalf("user workflow not rendered: %s", out)
	}
	logData, _ := os.ReadFile(netlog)
	for _, host := range []string{"cdn.jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com", "bootstrapcdn.com"} {
		if strings.Contains(string(logData), host) {
			t.Fatalf("external CDN request: %s", host)
		}
	}
}

func TestBrowserConnectionPresets(t *testing.T) {
	chrome := os.Getenv("CHROME")
	if chrome == "" {
		chrome = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
	}
	if _, err := os.Stat(chrome); err != nil {
		t.Skip("Chrome is not installed")
	}
	mux := http.NewServeMux()
	mux.Handle("/assets/v1/", http.StripPrefix("/assets/v1/", AssetHandler()))
	mux.HandleFunc("/check.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/javascript")
		_, _ = w.Write([]byte(`const f=document.getElementById('connection-settings'),p=document.getElementById('connection-preset');let ok=true;for(const [name,protocol,anti,pq] of [['dpi','http2',true,true],['compact','http2',false,false],['quic','http3',false,true]]){p.value=name;p.dispatchEvent(new Event('change',{bubbles:true}));ok=ok&&f.elements.protocol.value===protocol&&f.elements.anti_dpi.checked===anti&&f.elements.post_quantum.checked===pq;}document.body.setAttribute('data-presets',ok?'passed':'failed');`))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		out := httptest.NewRecorder()
		NewConnectionHandler(&profileWebStub{settings: clientprofile.Default()}).ServeHTTP(out, r)
		_, _ = w.Write([]byte(strings.Replace(out.Body.String(), "</body>", `<script defer src="/check.js"></script></body>`, 1)))
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, chrome, "--headless", "--disable-gpu", "--no-sandbox", "--disable-background-networking", "--no-first-run", "--user-data-dir="+filepath.Join(t.TempDir(), "profile"), "--dump-dom", server.URL)
	cmd.WaitDelay = time.Second
	out, err := cmd.CombinedOutput()
	if !strings.Contains(string(out), `data-presets="passed"`) {
		t.Fatalf("browser presets: %v\n%s", err, out)
	}
	// macOS Chrome can remain alive after --dump-dom has completed. The DOM
	// assertion above proves all three event-driven preset checks actually ran.
	if err != nil {
		t.Logf("Chrome rendered and passed assertions but required timeout cleanup: %v", err)
	}
}
