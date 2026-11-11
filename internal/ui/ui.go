// Package ui renders every HTML page of the proxy from embedded templates and
// serves the same-origin stylesheet and script under /static/.
package ui

//go:generate tailwindcss -i src/input.css -o assets/app.css --minify

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"mime"
	"net/http"
	"path"
	"slices"
	"strings"
	"time"
)

//go:embed assets/app.css assets/app.js templates/*.tmpl
var files embed.FS

// User is the logged-in user shown in the top bar.
type User struct {
	Name  string
	Admin bool
}

// Page is the data every template receives. Data is page specific.
type Page struct {
	Title string
	User  *User
	Data  any
}

type asset struct {
	body  []byte
	ctype string
}

// Renderer holds the parsed page templates and the static assets.
type Renderer struct {
	pages  map[string]*template.Template
	assets map[string]asset
	logger *slog.Logger
}

// New parses the embedded templates. It panics on a broken template, which is
// a build defect, not a runtime condition.
func New(logger *slog.Logger) *Renderer {
	if logger == nil {
		logger = slog.Default()
	}
	r := &Renderer{pages: map[string]*template.Template{}, assets: map[string]asset{}, logger: logger}
	versions := map[string]string{}
	for _, name := range []string{"app.css", "app.js"} {
		body, err := files.ReadFile("assets/" + name)
		if err != nil {
			panic(err)
		}
		sum := sha256.Sum256(body)
		versions[name] = hex.EncodeToString(sum[:4])
		r.assets[name] = asset{body: body, ctype: mime.TypeByExtension(path.Ext(name))}
	}
	funcs := template.FuncMap{
		"asset":  func(name string) string { return "/static/" + name + "?v=" + versions[name] },
		"themes": func() []string { return []string{"auto", "light", "dark"} },
		"has":    slices.Contains[[]string],
		"list":   func(v ...string) []string { return v },
		"ptr":    func(t time.Time) *time.Time { return &t },
		"when": func(t *time.Time) string {
			if t == nil {
				return "never"
			}
			return t.UTC().Format("2006-01-02 15:04 UTC")
		},
	}
	layout := template.Must(template.New("layout").Funcs(funcs).ParseFS(files, "templates/layout.tmpl"))
	pages, err := fs.Glob(files, "templates/*.tmpl")
	if err != nil {
		panic(err)
	}
	for _, p := range pages {
		name := strings.TrimSuffix(path.Base(p), ".tmpl")
		if name == "layout" {
			continue
		}
		r.pages[name] = template.Must(template.Must(layout.Clone()).ParseFS(files, p))
	}
	return r
}

// Render writes page name with the given HTTP status.
func (r *Renderer) Render(w http.ResponseWriter, status int, name string, p Page) {
	t, ok := r.pages[name]
	if !ok {
		r.fail(w, fmt.Errorf("unknown page %q", name))
		return
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "layout", p); err != nil {
		r.fail(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

func (r *Renderer) fail(w http.ResponseWriter, err error) {
	r.logger.Error("render page", "error", err)
	http.Error(w, "could not render page", http.StatusInternalServerError)
}

// Static serves /static/{name}. URLs carry a content hash, so responses are
// cacheable forever.
func (r *Renderer) Static() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		a, ok := r.assets[strings.TrimPrefix(req.URL.Path, "/static/")]
		if !ok {
			http.NotFound(w, req)
			return
		}
		w.Header().Set("Content-Type", a.ctype)
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		http.ServeContent(w, req, "", time.Time{}, bytes.NewReader(a.body))
	})
}
