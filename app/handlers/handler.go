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
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/AmanTahiliani/FHIR-Sandbox/app/config"
	"github.com/AmanTahiliani/FHIR-Sandbox/app/db"
	"github.com/AmanTahiliani/FHIR-Sandbox/app/fhir"
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

// ---------------------------------------------------------------------------
// Private helpers used by both template funcs and buildClinicalSummary.
// ---------------------------------------------------------------------------

// filterObsByCategory returns observations whose category matches cat
// using a normalised (lowercase, spaces→hyphens) comparison.
func filterObsByCategory(obs []models.Observation, cat string) []models.Observation {
	want := strings.ToLower(strings.ReplaceAll(cat, " ", "-"))
	var out []models.Observation
	for _, o := range obs {
		got := strings.ToLower(strings.ReplaceAll(o.Category, " ", "-"))
		if got == want {
			out = append(out, o)
		}
	}
	return out
}

// latestObsPerCode returns the most-recent observation per LOINC code (or code
// text when code is absent), sorted by code text for stable display.
func latestObsPerCode(obs []models.Observation) []models.Observation {
	latest := make(map[string]models.Observation)
	for _, o := range obs {
		key := o.CodeCode
		if key == "" {
			key = o.CodeText
		}
		if existing, ok := latest[key]; !ok || o.EffectiveDate > existing.EffectiveDate {
			latest[key] = o
		}
	}
	out := make([]models.Observation, 0, len(latest))
	for _, o := range latest {
		out = append(out, o)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CodeText < out[j].CodeText })
	return out
}

// isAbnormalInterp returns true for interpretation codes that indicate an
// out-of-range or critical result.
func isAbnormalInterp(interp string) bool {
	switch strings.ToUpper(strings.TrimSpace(interp)) {
	case "H", "HH", "L", "LL", "A", "AA", "HIGH", "LOW", "ABNORMAL", "CRITICAL":
		return true
	}
	return false
}

// ---------------------------------------------------------------------------
// TemplateFuncs returns the custom template function map.
// Defined here so it is available to both main.go (for wiring) and
// handler tests.
// ---------------------------------------------------------------------------
func TemplateFuncs() template.FuncMap {
	return template.FuncMap{
		"formatDate": func(s string) string {
			if s == "" {
				return "—"
			}
			// Try full datetime first (FHIR dateTime), then plain date.
			for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05Z0700", "2006-01-02"} {
				t, err := time.Parse(layout, s)
				if err == nil {
					return t.Format("Jan 2, 2006")
				}
			}
			return s
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
		// groupByCategory is kept for backward compatibility.
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
		// --- T1.2 Vitals/Labs ---
		"filterObsByCategory": func(obs []models.Observation, cat string) []models.Observation {
			return filterObsByCategory(obs, cat)
		},
		"latestObPerCode": func(obs []models.Observation) []models.Observation {
			return latestObsPerCode(obs)
		},
		"isAbnormal": func(interp string) bool {
			return isAbnormalInterp(interp)
		},
		// --- T1.3 Medication history ---
		"filterMedsByStatus": func(meds []models.MedicationRequest, status string) []models.MedicationRequest {
			if status == "" || status == "all" {
				return meds
			}
			var out []models.MedicationRequest
			for _, m := range meds {
				if strings.EqualFold(m.Status, status) {
					out = append(out, m)
				}
			}
			return out
		},
		// --- T1.1 Demographics ---
		"calculateAge": func(dob string) string {
			if dob == "" {
				return ""
			}
			t, err := time.Parse("2006-01-02", dob)
			if err != nil {
				return ""
			}
			now := time.Now()
			years := now.Year() - t.Year()
			if now.Month() < t.Month() || (now.Month() == t.Month() && now.Day() < t.Day()) {
				years--
			}
			return fmt.Sprintf("%d", years)
		},
		"primaryPhone": func(p *fhir.Patient) string {
			if p == nil {
				return ""
			}
			for _, tc := range p.Telecom {
				if tc.System == "phone" && tc.Value != "" {
					return tc.Value
				}
			}
			return ""
		},
		"primaryAddress": func(p *fhir.Patient) string {
			if p == nil || len(p.Address) == 0 {
				return ""
			}
			addr := p.Address[0]
			var parts []string
			if len(addr.Line) > 0 {
				parts = append(parts, addr.Line[0])
			}
			if addr.City != "" {
				parts = append(parts, addr.City)
			}
			if addr.State != "" {
				parts = append(parts, addr.State)
			}
			if addr.PostalCode != "" {
				parts = append(parts, addr.PostalCode)
			}
			return strings.Join(parts, ", ")
		},
		"usRace": func(p *fhir.Patient) string {
			if p == nil {
				return ""
			}
			return fhir.ExtractUSCoreRaceText(p)
		},
		"usEthnicity": func(p *fhir.Patient) string {
			if p == nil {
				return ""
			}
			return fhir.ExtractUSCoreEthnicityText(p)
		},
		// --- T2.3 Encounters ---
		"encounterClassBadge": func(class string) string {
			switch strings.ToUpper(class) {
			case "AMB":
				return "badge-info"
			case "EMER":
				return "badge-danger"
			case "IMP", "INPATIENT":
				return "badge-warning"
			default:
				return "badge-neutral"
			}
		},
		"encounterClassLabel": func(class string) string {
			switch strings.ToUpper(class) {
			case "AMB":
				return "Ambulatory"
			case "EMER":
				return "Emergency"
			case "IMP":
				return "Inpatient"
			case "VR":
				return "Virtual"
			default:
				if class == "" {
					return "Visit"
				}
				return class
			}
		},
		"split": func(s, sep string) []string {
			if s == "" {
				return nil
			}
			return strings.Split(s, sep)
		},
		"min": func(a, b int) int {
			if a < b {
				return a
			}
			return b
		},
	}
}
