// Package server wires the HTTP mux: /mcp and /mcp/{token} for MCP (bearer or
// path auth), the /oauth endpoints of the client-facing AS, the signed
// /approve/{id} and /deny/{id} button routes. /metrics, /healthz and /readyz
// live on the separate ops listener.
package server

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tamcore/mcp-auth-proxy/internal/config"
	"github.com/tamcore/mcp-auth-proxy/internal/gate"
	"github.com/tamcore/mcp-auth-proxy/internal/identity"
	"github.com/tamcore/mcp-auth-proxy/internal/mcpserver"
	"github.com/tamcore/mcp-auth-proxy/internal/metrics"
	"github.com/tamcore/mcp-auth-proxy/internal/oauthserver"
	"github.com/tamcore/mcp-auth-proxy/internal/store"
	"github.com/tamcore/mcp-auth-proxy/internal/ui"
	"github.com/tamcore/mcp-auth-proxy/internal/version"
	"github.com/tamcore/mcp-auth-proxy/internal/webui"
)

// contextKey carries the resolved key through the mux to the MCP handler.
type ctxKey struct{}

// Server is the root HTTP handler.
type Server struct {
	cfg      *config.Config
	resolver *identity.Resolver
	proxy    *mcpserver.Proxy
	as       *oauthserver.Server
	gate     *gate.Gate
	store    *store.Store
	metrics  *metrics.Metrics
	webui    *webui.WebUI
	pages    *ui.Renderer
	logger   *slog.Logger
}

// New builds the root handler's dependencies.
func New(ctx context.Context, cfg *config.Config, st *store.Store, g *gate.Gate,
	proxy *mcpserver.Proxy, m *metrics.Metrics, signSecret []byte, logger *slog.Logger) (*Server, error) {
	if logger == nil {
		logger = slog.Default()
	}
	pages := ui.New(logger)
	as, err := oauthserver.New(ctx, st, cfg, pages, logger)
	if err != nil {
		return nil, err
	}
	web := webui.New(st, cfg, signSecret, pages, g, logger)
	as.CurrentUser = func(r *http.Request) *store.User {
		u, _ := web.Sessions().User(r, st)
		return u
	}
	return &Server{
		cfg:      cfg,
		resolver: identity.New(st, nil),
		proxy:    proxy,
		as:       as,
		gate:     g,
		store:    st,
		metrics:  m,
		webui:    web,
		pages:    pages,
		logger:   logger,
	}, nil
}

// Handler returns the root mux.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mcpHandler := mcp.NewStreamableHTTPHandler(s.mcpGetServer, &mcp.StreamableHTTPOptions{Stateless: true})
	mux.Handle("/mcp", s.authMiddleware(mcpHandler))
	mux.Handle("/mcp/", s.authMiddleware(mcpHandler))
	s.webui.Register(mux)
	mux.Handle("GET /static/", s.pages.Static())
	mux.HandleFunc("GET /oauth/authorize", s.requireLogin(s.as.HandleAuthorize))
	mux.HandleFunc("POST /oauth/consent", s.requireLogin(s.as.HandleConsent))
	mux.HandleFunc("POST /oauth/token", s.as.HandleToken)
	mux.HandleFunc("/approve/{id}", allowCrossOrigin(s.handleApprove))
	mux.HandleFunc("/deny/{id}", allowCrossOrigin(s.handleDeny))
	return accessLog(s.logger, strictTransport(s.cfg.BaseURL, securityHeaders(crossOriginProtection().Handler(mux))))
}

// crossOriginProtection rejects cross-site browser POSTs (CSRF) everywhere
// except the endpoints that clients and the ntfy web app call cross-origin.
func crossOriginProtection() *http.CrossOriginProtection {
	cop := http.NewCrossOriginProtection()
	for _, p := range []string{"/mcp", "/mcp/", "/oauth/token", "/approve/{id}", "/deny/{id}"} {
		cop.AddInsecureBypassPattern(p)
	}
	return cop
}

// securityHeaders keeps pages out of frames (clickjacking on Approve) and
// limits them to same-origin content.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

// strictTransport sends HSTS when the public origin is https, so browsers
// stop using plain http (passkeys need a secure context).
func strictTransport(baseURL string, next http.Handler) http.Handler {
	if !strings.HasPrefix(baseURL, "https://") {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		next.ServeHTTP(w, r)
	})
}

// OpsHandler serves the ops endpoints: /metrics, /healthz (process up) and
// /readyz (database reachable).
func (s *Server) OpsHandler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", s.metrics.Handler())
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if err := s.store.DB().PingContext(r.Context()); err != nil {
			s.logger.Warn("readyz: database unreachable", "error", err)
			http.Error(w, "database unreachable", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ok\n"))
	})
	return mux
}

// authMiddleware resolves the credential (Bearer header for /mcp, path token
// for /mcp/{token}) and rejects unauthenticated requests with 401.
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := bearerToken(r)
		if token == "" {
			token = pathToken(r)
		}
		if token == "" {
			unauthorized(w)
			return
		}
		key, err := s.resolver.Resolve(r.Context(), token)
		if err != nil {
			if !errors.Is(err, identity.ErrUnauthorized) {
				s.logger.Error("resolve credential", "error", err)
			}
			unauthorized(w)
			return
		}
		// ponytail: one write per request; batch if request volume ever matters.
		if err := s.store.MarkKeyUsed(r.Context(), key.ID, time.Now().UTC()); err != nil {
			s.logger.Warn("mark key used", "key", key.ID, "error", err)
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, key)))
	})
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
}

func pathToken(r *http.Request) string {
	if !strings.HasPrefix(r.URL.Path, "/mcp/") {
		return ""
	}
	return strings.TrimPrefix(r.URL.Path, "/mcp/")
}

// mcpGetServer is the SDK handler's server factory: the per-key server is chosen
// from the resolved key in the request context, never from headers alone.
func (s *Server) mcpGetServer(r *http.Request) *mcp.Server {
	key, _ := r.Context().Value(ctxKey{}).(*store.Key)
	if key == nil {
		return mcp.NewServer(version.Implementation(), nil)
	}
	srv, err := s.proxy.ServerFor(r.Context(), key)
	if err != nil {
		s.logger.Error("build per-key MCP server", "key", key.ID, "error", err)
		return mcp.NewServer(version.Implementation(), nil)
	}
	return srv
}

func (s *Server) handleApprove(w http.ResponseWriter, r *http.Request) {
	s.handleSignButton(w, r, true)
}

func (s *Server) handleDeny(w http.ResponseWriter, r *http.Request) {
	s.handleSignButton(w, r, false)
}

func (s *Server) handleSignButton(w http.ResponseWriter, r *http.Request, approve bool) {
	if r.Method == http.MethodGet {
		s.pages.Render(w, http.StatusOK, "result", ui.Page{Title: "Confirm", Data: confirmPage(approve)})
		return
	}
	id := r.PathValue("id")
	sig := r.URL.Query().Get("sig")
	var err error
	if approve {
		err = s.gate.Approve(r.Context(), id, sig)
	} else {
		err = s.gate.Deny(r.Context(), id, sig)
	}
	status, res := signResult(approve, err)
	res.Back = "/"
	s.pages.Render(w, status, "result", ui.Page{Title: res.Heading, Data: res})
}

// confirmPage answers a GET (opened link, link preview): only the POST acts.
func confirmPage(approve bool) ui.ResultData {
	if approve {
		return ui.ResultData{Tone: ui.ToneAsk, Heading: "Approve this request?",
			Message: "The key gets a session and the waiting tool call can run.", Confirm: "Approve"}
	}
	return ui.ResultData{Tone: ui.ToneAsk, Heading: "Deny this request?",
		Message: "The waiting tool call stays blocked.", Confirm: "Deny"}
}

func signResult(approve bool, err error) (int, ui.ResultData) {
	switch {
	case err == nil && approve:
		return http.StatusOK, ui.ResultData{Tone: ui.ToneOK, Heading: "Approved",
			Message: "The session is authorized; the AI client can retry its tool call."}
	case err == nil:
		return http.StatusOK, ui.ResultData{Tone: ui.ToneDeny, Heading: "Denied",
			Message: "The tool call stays blocked."}
	case errors.Is(err, gate.ErrBadSignature):
		return http.StatusForbidden, ui.ResultData{Tone: ui.ToneError, Heading: "Forbidden",
			Message: "This link has an invalid signature."}
	default:
		return http.StatusNotFound, ui.ResultData{Tone: ui.ToneError, Heading: "Not found",
			Message: "This request is unknown or has expired."}
	}
}

// allowCrossOrigin lets the ntfy web app POST the Approve/Deny actions. The
// links carry no cookies; the HMAC signature is the authorization.
func allowCrossOrigin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next(w, r)
	}
}

// requireLogin redirects browser requests without a web session to /login.
func (s *Server) requireLogin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := s.webui.Sessions().User(r, s.webuiStore()); !ok {
			http.Redirect(w, r, "/login?next="+r.URL.Path+"?"+r.URL.RawQuery, http.StatusFound)
			return
		}
		next(w, r)
	}
}

func (s *Server) webuiStore() *store.Store { return s.webui.Store() }

func unauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="mcp-auth-proxy"`)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}
