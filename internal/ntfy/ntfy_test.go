package ntfy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tamcore/mcp-auth-proxy/internal/store"
)

func TestHTTPPublisherPayloadShape(t *testing.T) {
	var got Message
	srv := httptest.NewServer(captureHandler(t, &got))
	defer srv.Close()
	pub := NewHTTPPublisher(srv.URL, "", srv.Client(), nil)
	ch := &store.Challenge{ID: "c1", KeyID: "k1", ToolName: "echo__echo", PendingOTP: "12345",
		ExpiresAt: time.Date(2025, 1, 1, 12, 3, 0, 0, time.UTC)}
	n := NewNotifier(pub, "mytopic",
		func(id string) string { return "http://p/approve/" + id + "?sig=aa" },
		func(id string) string { return "http://p/deny/" + id + "?sig=bb" })
	if err := n.Notify(context.Background(), ch, "laptop"); err != nil {
		t.Fatal(err)
	}
	assertPayload(t, &got)
}

func captureHandler(t *testing.T, got *Message) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("content-type %q", ct)
		}
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, got); err != nil {
			t.Errorf("decode: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}
}

func assertPayload(t *testing.T, got *Message) {
	t.Helper()
	if got.Topic != "mytopic" {
		t.Fatalf("topic %q", got.Topic)
	}
	if got.Message == "" || !strings.Contains(got.Message, "12345") || !strings.Contains(got.Message, "laptop") {
		t.Fatalf("message %q", got.Message)
	}
	if len(got.Actions) != 2 {
		t.Fatalf("actions %+v", got.Actions)
	}
	ap, dn := got.Actions[0], got.Actions[1]
	if ap.Action != "http" || ap.Label != "Approve" || ap.Method != "POST" || !ap.Clear || ap.URL == "" {
		t.Fatalf("approve action %+v", ap)
	}
	if dn.Label != "Deny" || dn.URL == "" {
		t.Fatalf("deny action %+v", dn)
	}
}

func TestHTTPPublisherError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	pub := NewHTTPPublisher(srv.URL, "", srv.Client(), nil)
	if err := pub.Publish(context.Background(), Message{Topic: "t"}); err == nil {
		t.Fatal("want error on 500")
	}
}

func TestLogPublisherFallback(t *testing.T) {
	pub := NewLogPublisher(slog.New(slog.NewTextHandler(io.Discard, nil)))
	ch := &store.Challenge{ID: "c1", ToolName: "t", PendingOTP: "12345", ExpiresAt: time.Now()}
	n := NewNotifier(pub, "topic",
		func(id string) string { return "http://p/approve/" + id },
		func(id string) string { return "http://p/deny/" + id })
	if err := n.Notify(context.Background(), ch, "laptop"); err != nil {
		t.Fatal(err)
	}
}

func TestHTTPPublisherAuth(t *testing.T) {
	var auth []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = append(auth, r.Header.Get("Authorization"))
	}))
	defer srv.Close()
	for _, token := range []string{"tk_secret", ""} {
		if err := NewHTTPPublisher(srv.URL, token, srv.Client(), nil).Publish(context.Background(), Message{}); err != nil {
			t.Fatal(err)
		}
	}
	if auth[0] != "Bearer tk_secret" || auth[1] != "" {
		t.Fatalf("authorization headers: %q", auth)
	}
}

func TestHTTPPublisherWarnsOnRejectedToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	err := NewHTTPPublisher(srv.URL, "tk_bad", srv.Client(), logger).Publish(context.Background(), Message{Topic: "t"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("want 403 error, got %v", err)
	}
	if !strings.Contains(buf.String(), `"level":"WARN"`) || !strings.Contains(buf.String(), `"status":403`) {
		t.Fatalf("want WARN log with status, got %s", buf.String())
	}
	if strings.Contains(buf.String(), "tk_bad") {
		t.Fatal("token must never be logged")
	}
}
