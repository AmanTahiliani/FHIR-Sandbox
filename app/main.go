// main.go is the application entry point. Its only job is to:
//  1. Load configuration.
//  2. Initialize the database store.
//  3. Expose the embedded template FS to the handlers package.
//  4. Wire all dependencies into handlers and middleware.
//  5. Register routes and start the HTTP server.
//
// No business logic lives here. All behaviour is delegated to the
// handlers, db, fhir, config, and middleware packages.
package main

import (
	"embed"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"time"

	"github.com/AmanTahiliani/FHIR-Sandbox/app/config"
	"github.com/AmanTahiliani/FHIR-Sandbox/app/db"
	"github.com/AmanTahiliani/FHIR-Sandbox/app/handlers"
	"github.com/AmanTahiliani/FHIR-Sandbox/app/middleware"
)

//go:embed templates/*.html
var embeddedTemplates embed.FS

func main() {
	// -------------------------------------------------------------------------
	// Configuration
	// -------------------------------------------------------------------------
	cfg := &config.AppConfig{
		DBPath: "fhir_sandbox.db",
		Server: config.ServerConfig{
			Port: 8080,
		},
		SMART: config.SMARTConfig{
			RedirectURL: "http://localhost:8080/auth-redirect",
			Scopes:      []string{"openid", "profile", "launch", "patient/*.read", "user/*.read"},
		},
		EHRs: []config.EHRConfig{
			{
				Name:         "SmartHealthIT Sandbox (R4)",
				FHIRURL:      "https://launch.smarthealthit.org/v/r4/fhir",
				ClientID:     "abcdefghijklmnopqrst",
				ClientSecret: "ehr_a_client_secret",
			},
			// Add additional EHR configurations here as needed.
		},
	}

	// -------------------------------------------------------------------------
	// Database
	// -------------------------------------------------------------------------
	store, err := db.New(cfg.DBPath)
	if err != nil {
		log.Fatalf("main: database init failed: %v", err)
	}
	defer store.Close()
	log.Printf("main: database ready at %q", cfg.DBPath)

	// Purge expired sessions on startup so the table doesn't accumulate stale rows.
	if n, err := store.DeleteExpiredSessions(); err != nil {
		log.Printf("main: warning — could not purge expired sessions: %v", err)
	} else if n > 0 {
		log.Printf("main: purged %d expired session(s)", n)
	}

	// -------------------------------------------------------------------------
	// Templates
	// Sub the embed.FS to strip the "templates/" prefix so handlers can
	// reference files as "base.html", "dashboard.html", etc.
	// -------------------------------------------------------------------------
	templateFS, err := fs.Sub(embeddedTemplates, "templates")
	if err != nil {
		log.Fatalf("main: template FS sub failed: %v", err)
	}

	// -------------------------------------------------------------------------
	// Handlers & middleware
	// -------------------------------------------------------------------------
	h := handlers.New(store, cfg, templateFS, handlers.TemplateFuncs())
	sessionMW := middleware.NewSessionMiddleware(store)

	// -------------------------------------------------------------------------
	// Routes
	// -------------------------------------------------------------------------
	mux := http.NewServeMux()

	// Public routes
	mux.HandleFunc("/", h.HandleRoot)
	mux.HandleFunc("/launch", h.HandleLaunch)
	mux.HandleFunc("/auth-redirect", h.HandleAuthRedirect)
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("app/static"))))

	// Session-required routes — wrapped with the hard-gate middleware.
	mux.Handle("/dashboard", sessionMW.RequireSession(http.HandlerFunc(h.HandleDashboard)))
	mux.Handle("/dashboard/sync", sessionMW.RequireSession(http.HandlerFunc(h.HandleSync)))
	mux.Handle("/patients", sessionMW.RequireSession(http.HandlerFunc(h.HandlePatients)))
	mux.Handle("/logout", sessionMW.RequireSession(http.HandlerFunc(h.HandleLogout)))

	// Apply the soft session loader to every request so templates can always
	// read the current user from context.
	root := sessionMW.LoadSession(mux)

	// -------------------------------------------------------------------------
	// Server
	// -------------------------------------------------------------------------
	addr := fmt.Sprintf(":%d", cfg.Server.Port)
	srv := &http.Server{
		Addr:         addr,
		Handler:      root,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	log.Printf("main: starting FHIR platform on http://localhost%s", addr)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("main: server error: %v", err)
	}
}
