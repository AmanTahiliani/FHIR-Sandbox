// launch.go handles the SMART on FHIR EHR launch initiation sequence.
//
// Flow:
//  1. EHR calls GET /launch?iss=<fhir_base>&launch=<opaque_token>
//  2. This handler validates iss against the registered EHR list.
//  3. Fetches the SMART discovery document (.well-known/smart-configuration).
//  4. Generates a cryptographically secure state token.
//  5. Stores launch context (iss + launch token) in a short-lived in-memory
//     map keyed by state, so the callback can recover context without
//     encoding sensitive values in the state URL parameter.
//  6. Redirects the browser to the EHR's authorization_endpoint.
package handlers

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/AmanTahiliani/FHIR-Sandbox/app/fhir"
)

// launchState holds the OAuth2 launch context that must survive the
// browser redirect round-trip. It is keyed by a random state token.
type launchState struct {
	ISS      string
	LaunchID string
	StoredAt time.Time
	UsedAt   time.Time // Added to track when the state was first consumed.
}

// stateStore is a short-lived, in-memory map from state token → launchState.
// Entries are expired after 10 minutes to limit memory growth from abandoned
// launch flows. In a multi-instance deployment this should be replaced with
// a shared store (e.g., Redis).
type stateStore struct {
	mu      sync.Mutex
	entries map[string]launchState
}

var globalStateStore = &stateStore{
	entries: make(map[string]launchState),
}

// set stores a launch state entry.
func (ss *stateStore) set(token string, ls launchState) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	// Opportunistically evict stale entries on every write.
	ss.evict()
	ss.entries[token] = ls
}

// get retrieves a state entry. Returns false if not found or expired.
// Implements a 10-second grace period for duplicate requests (common in some
// browsers/environments) after the first consumption.
func (ss *stateStore) get(token string) (launchState, bool) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	ls, ok := ss.entries[token]
	if !ok {
		return launchState{}, false
	}

	// If already used more than 10 seconds ago, consider it fully consumed.
	if !ls.UsedAt.IsZero() && time.Since(ls.UsedAt) > 10*time.Second {
		delete(ss.entries, token)
		return launchState{}, false
	}

	if time.Since(ls.StoredAt) > 10*time.Minute {
		delete(ss.entries, token)
		return launchState{}, false
	}

	// Mark as used but don't delete yet to allow for race conditions/double-requests.
	if ls.UsedAt.IsZero() {
		ls.UsedAt = time.Now()
		ss.entries[token] = ls
	}

	return ls, true
}

// evict removes entries older than 10 minutes. Must be called with ss.mu held.
func (ss *stateStore) evict() {
	cutoff := time.Now().Add(-10 * time.Minute)
	for k, v := range ss.entries {
		if v.StoredAt.Before(cutoff) {
			delete(ss.entries, k)
		}
	}
}

// HandleRoot serves the application home page.
func (h *Handler) HandleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		h.renderError(w, http.StatusNotFound, "Page not found.")
		return
	}
	h.render(w, "index.html", nil)
}

// HandleLaunch processes the SMART EHR launch initiation.
// GET /launch?iss=<fhir_base_url>&launch=<opaque_launch_token>
func (h *Handler) HandleLaunch(w http.ResponseWriter, r *http.Request) {
	launchID := r.URL.Query().Get("launch")
	iss := r.URL.Query().Get("iss")

	log.Printf("handlers: launch request iss=%q launch=%q", iss, launchID)

	if launchID == "" || iss == "" {
		h.renderError(w, http.StatusBadRequest, "Missing required parameters: iss and launch.")
		return
	}

	// Validate iss is a well-formed URI before doing anything with it.
	if _, err := url.ParseRequestURI(iss); err != nil {
		h.renderError(w, http.StatusBadRequest, "Invalid FHIR server URL (iss).")
		return
	}

	// Confirm this EHR is registered.
	ehrConfig := h.cfg.EHRByURL(iss)
	if ehrConfig == nil {
		log.Printf("handlers: unregistered EHR iss=%q", iss)
		h.renderError(w, http.StatusBadRequest, "Unregistered FHIR server.")
		return
	}

	// Fetch SMART discovery document.
	smartCfg, err := fhir.GetSmartConfiguration(iss)
	if err != nil {
		log.Printf("handlers: SMART discovery failed for iss=%q: %v", iss, err)
		h.renderError(w, http.StatusBadGateway, "Unable to fetch SMART configuration from FHIR server.")
		return
	}

	if smartCfg.AuthorizationEndpoint == "" {
		h.renderError(w, http.StatusBadGateway, "SMART configuration missing authorization_endpoint.")
		return
	}

	// Generate a secure random state token.
	state, err := generateState()
	if err != nil {
		log.Printf("handlers: state generation failed: %v", err)
		h.renderError(w, http.StatusInternalServerError, "Internal error.")
		return
	}

	// Store the launch context server-side, keyed by state.
	globalStateStore.set(state, launchState{
		ISS:      strings.TrimRight(iss, "/"),
		LaunchID: launchID,
		StoredAt: time.Now(),
	})

	// Build the authorization URL.
	scopes := strings.Join(h.cfg.SMART.Scopes, " ")
	authURL := fmt.Sprintf(
		"%s?response_type=code&client_id=%s&redirect_uri=%s&launch=%s&scope=%s&state=%s&aud=%s",
		smartCfg.AuthorizationEndpoint,
		url.QueryEscape(ehrConfig.ClientID),
		url.QueryEscape(h.cfg.SMART.RedirectURL),
		url.QueryEscape(launchID),
		url.QueryEscape(scopes),
		url.QueryEscape(state),
		url.QueryEscape(iss),
	)

	log.Printf("handlers: redirecting to authorization endpoint for EHR %q", ehrConfig.Name)
	http.Redirect(w, r, authURL, http.StatusFound)
}
