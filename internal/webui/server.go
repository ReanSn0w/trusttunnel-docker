package webui

import "net/http"

type RouterDependencies struct {
	Bootstrap   BootstrapService
	Auth        *AuthHandler
	Dashboard   *DashboardHandler
	Users       *UsersHandler
	Clients     *ClientConfigHandler
	TLS         *TLSHandler
	Events      *EventsHandler
	Connection  *ConnectionHandler
	CSRF        *CSRF
	Logger      RequestLogger
	ExternalTLS bool
}

func NewRouter(d RouterDependencies) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /assets/v1/", http.StripPrefix("/assets/v1/", AssetHandler()))
	mux.HandleFunc("GET /login", d.Auth.Login)
	mux.HandleFunc("POST /login", d.Auth.Login)
	protected := func(pattern string, handler http.Handler) { mux.Handle(pattern, d.Auth.Require(handler)) }
	protected("GET /{$}", d.Dashboard)
	protected("GET /fragments/status", d.Dashboard)
	protected("POST /logout", http.HandlerFunc(d.Auth.Logout))
	protected("GET /account", http.HandlerFunc(d.Auth.Account))
	protected("POST /account/password", http.HandlerFunc(d.Auth.ChangePassword))
	protected("GET /users", http.HandlerFunc(d.Users.List))
	protected("POST /users", http.HandlerFunc(d.Users.Create))
	protected("POST /users/{id}/enable", http.HandlerFunc(d.Users.Enable))
	protected("POST /users/{id}/disable", http.HandlerFunc(d.Users.Disable))
	protected("POST /users/{id}/rotate", http.HandlerFunc(d.Users.Rotate))
	protected("POST /users/{id}/revoke", http.HandlerFunc(d.Users.Revoke))
	protected("POST /users/{id}/client/deeplink", http.HandlerFunc(d.Clients.DeepLink))
	protected("POST /users/{id}/client/toml", http.HandlerFunc(d.Clients.TOML))
	protected("POST /users/{id}/client/qr", http.HandlerFunc(d.Clients.QR))
	protected("POST /users/{id}/client/cli", http.HandlerFunc(d.Clients.CLI))
	if d.Connection != nil {
		protected("GET /connection", d.Connection)
		protected("POST /connection", d.Connection)
	}
	protected("GET /tls", http.HandlerFunc(d.TLS.View))
	protected("GET /tls/certificate", http.HandlerFunc(d.TLS.PublicCertificate))
	protected("POST /tls", http.HandlerFunc(d.TLS.Save))
	protected("POST /tls/issue", http.HandlerFunc(d.TLS.Issue))
	protected("POST /tls/renew", http.HandlerFunc(d.TLS.Renew))
	protected("GET /events", d.Events)
	var handler http.Handler = mux
	handler = BootstrapGate(d.Bootstrap, handler)
	handler = d.CSRF.Wrap(handler)
	return SecurityMiddleware(d.Logger, d.ExternalTLS, 1<<20, handler)
}
