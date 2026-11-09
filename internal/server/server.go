// Package server wires the HTTP mux: /mcp and /mcp/{token} for MCP (bearer or
// path auth), the /oauth endpoints of the client-facing AS, the signed
// /approve/{id} and /deny/{id} button routes, and /metrics.
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tamcore/mcp-auth-proxy/internal/config"
	"github.com/tamcore/mcp-auth-proxy/internal/gate"
	"github.com/tamcore/mcp-auth-proxy/internal/identity"
	"github.com/tamcore/mcp-auth-proxy/internal/mcpserver"
	"github.com/tamcore/mcp-auth-proxy/internal/metrics"
	"github.com/tamcore/mcp-auth-proxy/internal/oauthserver"
	"github.com/tamcore/mcp-auth-proxy/internal/store"
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
	metrics  *metrics.Metrics
	logger   *slog.Logger
}

// New builds the root handler's dependencies.
func New(ctx context.Context, cfg *config.Config, st *store.Store, g *gate.Gate,
	proxy *mcpserver.Proxy, m *metrics.Metrics, logger *slog.Logger) (*Server, error) {
	as, err := oauthserver.New(ctx, st, cfg, logger)
	if err != nil {
		return nil, err
	}
	return &Server{
		cfg:      cfg,
		resolver: identity.New(st, nil),
		proxy:    proxy,
		as:       as,
		gate:     g,
		metrics:  m,
		logger:   logger,
	}, nil
}

// Handler returns the root mux.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mcpHandler := mcp.NewStreamableHTTPHandler(s.mcpGetServer, &mcp.StreamableHTTPOptions{Stateless: true})
	mux.Handle("/mcp", s.authMiddleware(mcpHandler))
	mux.Handle("/mcp/", s.authMiddleware(mcpHandler))
	mux.HandleFunc("GET /oauth/authorize", s.as.HandleAuthorize)
	mux.HandleFunc("POST /oauth/consent", s.as.HandleConsent)
	mux.HandleFunc("POST /oauth/token", s.as.HandleToken)
	mux.HandleFunc("/approve/{id}", s.handleApprove)
	mux.HandleFunc("/deny/{id}", s.handleDeny)
	mux.Handle("/metrics", s.metrics.Handler())
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
		return mcp.NewServer(&mcp.Implementation{Name: "mcp-auth-proxy", Version: "dev"}, nil)
	}
	srv, err := s.proxy.ServerFor(r.Context(), key)
	if err != nil {
		s.logger.Error("build per-key MCP server", "key", key.ID, "error", err)
		return mcp.NewServer(&mcp.Implementation{Name: "mcp-auth-proxy", Version: "dev"}, nil)
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
	id := r.PathValue("id")
	sig := r.URL.Query().Get("sig")
	var err error
	if approve {
		err = s.gate.Approve(r.Context(), id, sig)
	} else {
		err = s.gate.Deny(r.Context(), id, sig)
	}
	switch {
	case err == nil:
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if approve {
			_, _ = fmt.Fprintln(w, "Approved. The session is authorized; the AI client can retry its tool call.")
		} else {
			_, _ = fmt.Fprintln(w, "Denied. The tool call stays blocked.")
		}
	case errors.Is(err, gate.ErrBadSignature):
		http.Error(w, "forbidden", http.StatusForbidden)
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

func unauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="mcp-auth-proxy"`)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}
