// Package handlers contains all HTTP handler implementations for the platform.
//
// Handler design:
//   - All handlers are methods on *Handler, which aggregates all dependencies
//     (store, config, templateFS). This avoids package-level globals and makes
//     dependencies explicit and testable.
//   - Handlers do not perform FHIR API calls directly; they delegate to the
//     fhir package. This keeps HTTP concerns separate from FHIR protocol logic.
//   - Templates are parsed per-render as a (base.html + page.html) pair.
//     This is the correct Go html/template pattern for layout inheritance:
//     a single global template.Set with multiple files all defining "content"
//     blocks will have the last-parsed definition win, causing incorrect renders.
//     Per-render parsing is cheap (microseconds) and completely correct.
//   - Each handler file handles one logical concern:
//     handler.go   — shared Handler type and constructor
//     launch.go    — SMART EHR launch initiation
//     auth.go      — OAuth2 callback, token exchange, user upsert, session creation
//     logout.go    — session invalidation
package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"time"

	"github.com/AmanTahiliani/FHIR-Sandbox/app/config"
	"github.com/AmanTahiliani/FHIR-Sandbox/app/db"
	"github.com/AmanTahiliani/FHIR-Sandbox/app/models"
)

const (
	// SessionCookieName is the name of the HttpOnly session cookie.
	SessionCookieName = "session_id"

	// SessionTTL is how long a session remains valid after SMART launch.
	SessionTTL = 8 * 60 * 60 // 8 hours in seconds
)

// Handler is the central handler struct. All HTTP handlers are methods on it.
// It holds all dependencies so they can be injected in tests.
type Handler struct {
	store      *db.Store
	cfg        *config.AppConfig
	templateFS fs.FS
	funcMap    template.FuncMap
}

// New creates a Handler with all dependencies wired in.
// templateFS must be an fs.FS rooted so that "base.html", "dashboard.html",
// etc. are directly accessible (i.e. pass an fs.Sub of the embed.FS).
func New(store *db.Store, cfg *config.AppConfig, templateFS fs.FS, funcMap template.FuncMap) *Handler {
	return &Handler{
		store:      store,
		cfg:        cfg,
		templateFS: templateFS,
		funcMap:    funcMap,
	}
}

// render parses base.html + the named page file and executes the combined
// template set, using the page filename as the entry point.
//
// Go's html/template block/define system works correctly when each page
// is parsed together with base.html in a fresh template.Template — the
// page's {{define "content"}} overrides the {{block "content"}} in base.html
// without conflicting with other pages' definitions.
func (h *Handler) render(w http.ResponseWriter, page string, data interface{}) {
	tmpl, err := template.New("").Funcs(h.funcMap).ParseFS(h.templateFS, "base.html", page)
	if err != nil {
		log.Printf("handlers: parse template %q: %v", page, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.ExecuteTemplate(w, "base.html", data); err != nil {
		log.Printf("handlers: execute template %q: %v", page, err)
	}
}

// renderError writes a clean HTML error page.
func (h *Handler) renderError(w http.ResponseWriter, code int, message string) {
	data := struct {
		Code    int
		Message string
	}{code, message}
	tmpl, err := template.New("").Funcs(h.funcMap).ParseFS(h.templateFS, "base.html", "error.html")
	if err != nil {
		log.Printf("handlers: parse error template: %v", err)
		http.Error(w, message, code)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	if err := tmpl.ExecuteTemplate(w, "base.html", data); err != nil {
		log.Printf("handlers: execute error template: %v", err)
		http.Error(w, message, code)
	}
}

// generateState creates a cryptographically secure random state token.
// This replaces the naive iss+launchID concatenation in the original code.
func generateState() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// templateFuncs returns the custom template function map.
// Defined here so it is available to both main.go (for wiring) and
// handler tests.
func TemplateFuncs() template.FuncMap {
	return template.FuncMap{
		"formatDate": func(s string) string {
			if s == "" {
				return "—"
			}
			t, err := time.Parse("2006-01-02", s)
			if err != nil {
				return s
			}
			return t.Format("January 2, 2006")
		},
		"formatDateTime": func(t time.Time) string {
			if t.IsZero() {
				return "—"
			}
			return t.UTC().Format("Jan 2, 2006 15:04 UTC")
		},
		"derefFloat64": func(p *float64) float64 {
			if p == nil {
				return 0
			}
			return *p
		},
		"titleCase": func(s string) string {
			if s == "" {
				return "—"
			}
			if len(s) == 1 {
				return string(s[0] - 32)
			}
			return string(s[0]-32) + s[1:]
		},
		"orDash": func(s string) string {
			if s == "" {
				return "—"
			}
			return s
		},
		"groupByCategory": func(obs []models.Observation) map[string][]models.Observation {
			m := make(map[string][]models.Observation)
			for _, o := range obs {
				cat := o.Category
				if cat == "" {
					cat = "other"
				}
				m[cat] = append(m[cat], o)
			}
			return m
		},
		"hasCriticalAllergies": func(allergies []models.AllergyIntolerance) bool {
			for _, a := range allergies {
				if a.Criticality == "high" {
					return true
				}
			}
			return false
		},
	}
}
