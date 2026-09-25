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

	"github.com/reansnow/trusttunnel-controller/internal/auth"
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

type browserSessionService struct{ webSessionStub }

func (*browserSessionService) Authenticate(_ context.Context, token string) (auth.Admin, error) {
	if token == "random-session" {
		return auth.Admin{ID: 1, Username: "admin"}, nil
	}
	return auth.Admin{}, auth.ErrInvalidCredentials
}

func TestBrowserHTTPSBootstrapLogin(t *testing.T) {
	chrome := os.Getenv("CHROME")
	if chrome == "" {
		chrome = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
	}
	if _, err := os.Stat(chrome); err != nil {
		t.Skip("Chrome is not installed")
	}
	bootstrap := &bootstrapServiceStub{required: true}
	authHandler := NewAuthHandler(&browserSessionService{}, nil)
	panel := http.NewServeMux()
	panel.HandleFunc("GET /login", authHandler.Login)
	panel.HandleFunc("POST /login", authHandler.Login)
	panel.Handle("GET /session", authHandler.Require(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("authenticated")) })))
	panel.HandleFunc("GET /{$}", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("home")) })
	panelHandler := SecurityMiddleware(nil, 1<<20, NewCSRF(true).Wrap(BootstrapGate(bootstrap, panel)))
	root := http.NewServeMux()
	root.Handle("/", panelHandler)
	root.HandleFunc("GET /browser-flow", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<body data-flow="pending"><script>
(async()=>{try{
const form=async(path)=>{const r=await fetch(path);if(!r.ok)throw Error(path+': '+r.status);return new DOMParser().parseFromString(await r.text(),'text/html').querySelector('input[name="_csrf"]').value};
let token=await form('/bootstrap');let r=await fetch('/bootstrap',{method:'POST',body:new URLSearchParams({_csrf:token,username:'admin',password:'Correct-Horse-9!'})});if(!r.ok)throw Error('bootstrap: '+r.status);
token=await form('/login');r=await fetch('/login',{method:'POST',body:new URLSearchParams({_csrf:token,username:'admin',password:'Correct-Horse-9!'})});if(!r.ok)throw Error('login: '+r.status);
r=await fetch('/session');if(!r.ok||await r.text()!=='authenticated')throw Error('session: '+r.status);
document.body.dataset.flow='passed';
}catch(e){document.body.dataset.flow='failed';document.body.textContent=String(e)}})();
</script></body>`))
	})
	server := httptest.NewTLSServer(root)
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, chrome, "--headless", "--disable-gpu", "--no-sandbox", "--no-proxy-server", "--ignore-certificate-errors", "--disable-background-networking", "--no-first-run", "--virtual-time-budget=5000", "--user-data-dir="+filepath.Join(t.TempDir(), "profile"), "--dump-dom", server.URL+"/browser-flow")
	out, err := cmd.CombinedOutput()
	if !strings.Contains(string(out), `data-flow="passed"`) {
		t.Fatalf("HTTPS browser bootstrap/login: %v\n%s", err, out)
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
	mux.HandleFunc("GET /assets/v1/app.js", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/javascript")
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		_, _ = w.Write([]byte("/* previously cached app.js without connection controls */"))
	})
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

func TestBrowserDirectDeepLinkAnchor(t *testing.T) {
	chrome := os.Getenv("CHROME")
	if chrome == "" {
		chrome = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
	}
	if _, err := os.Stat(chrome); err != nil {
		t.Skip("Chrome is not installed")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		r := httptest.NewRequest(http.MethodPost, "/users/1/client/deeplink", nil)
		r.SetPathValue("id", "1")
		NewClientConfigHandler(profileExportStub{link: "tt://?AAEB"}).DeepLink(w, r)
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, chrome, "--headless", "--disable-gpu", "--no-sandbox", "--no-proxy-server", "--disable-background-networking", "--no-first-run", "--user-data-dir="+filepath.Join(t.TempDir(), "profile"), "--dump-dom", server.URL)
	out, err := cmd.CombinedOutput()
	if !strings.Contains(string(out), `href="tt://?AAEB"`) || strings.Contains(string(out), "<img") {
		t.Fatalf("browser deeplink DOM: %v\n%s", err, out)
	}
}
