package upstream

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/tamcore/mcp-auth-proxy/internal/ui"
)

// callbackResult is the payload delivered by the loopback callback handler.
type callbackResult struct {
	code  string
	state string
	err   error
}

// startLoopback starts a loopback-only HTTP server on a random port for the
// OAuth linking callback. It returns the server, its port, and the channel the
// callback result is delivered on.
func startLoopback(ctx context.Context) (*http.Server, int, <-chan callbackResult, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, 0, nil, fmt.Errorf("upstream: loopback listen: %w", err)
	}
	resCh := make(chan callbackResult, 1)
	pages := ui.New(nil)
	mux := http.NewServeMux()
	mux.Handle("GET /static/", pages.Static())
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if e := q.Get("error"); e != "" {
			resCh <- callbackResult{err: fmt.Errorf("upstream: authorize error: %s", e)}
			pages.Render(w, http.StatusBadRequest, "result", ui.Page{Title: "Authorization failed", Data: ui.ResultData{
				Tone: ui.ToneError, Heading: "Authorization failed", Message: "You can close this tab.",
			}})
			return
		}
		resCh <- callbackResult{code: q.Get("code"), state: q.Get("state")}
		pages.Render(w, http.StatusOK, "result", ui.Page{Title: "Authorization received", Data: ui.ResultData{
			Tone: ui.ToneOK, Heading: "Authorization received", Message: "You can close this tab.",
		}})
	})
	srv := &http.Server{Handler: mux}
	go func() {
		_ = srv.Serve(ln)
	}()
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	return srv, ln.Addr().(*net.TCPAddr).Port, resCh, nil
}

// waitForCode blocks until the callback arrives or the context ends, and
// verifies the state parameter.
func waitForCode(ctx context.Context, resCh <-chan callbackResult, wantState string) (string, error) {
	select {
	case res := <-resCh:
		if res.err != nil {
			return "", res.err
		}
		if res.code == "" {
			return "", errors.New("upstream: callback missing code")
		}
		if res.state != wantState {
			return "", errors.New("upstream: state mismatch")
		}
		return res.code, nil
	case <-ctx.Done():
		return "", ctx.Err()
	case <-time.After(5 * time.Minute):
		return "", errors.New("upstream: timed out waiting for browser callback")
	}
}
