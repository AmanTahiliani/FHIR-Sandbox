// auth.go handles the OAuth2 authorization callback, token exchange,
// FHIR resource fetching, user upsert, and session creation.
//
// Flow (continued from launch.go):
//  1. EHR calls GET /auth-redirect?code=<auth_code>&state=<state_token>
//  2. Recover launch context from the state store (validates state, prevents CSRF).
//  3. Fetch the EHR's token endpoint from SMART discovery.
//  4. Exchange the authorization code for an access token.
//  5. Fetch the Patient FHIR resource using the access token.
//  6. Resolve the practitioner from the token response. The SMART spec allows
//     the practitioner to appear in two places — we handle both:
//     a. tokenResp.Practitioner — a bare FHIR ID (some EHRs)
//     b. tokenResp.User         — a relative reference "Practitioner/<id>" (SmartHealthIT)
//  7. Upsert both users into the database.
//  8. Create a server-side session for the HCP and set the session cookie.
//  9. Render the patient dashboard.
package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/AmanTahiliani/FHIR-Sandbox/app/fhir"
	"github.com/AmanTahiliani/FHIR-Sandbox/app/models"
)

// HandleAuthRedirect processes the SMART on FHIR authorization callback.
// GET /auth-redirect?code=<authorization_code>&state=<state_token>
func (h *Handler) HandleAuthRedirect(w http.ResponseWriter, r *http.Request) {
	log.Printf("handlers: auth redirect query=%v", r.URL.Query())

	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	if code == "" || state == "" {
		h.renderError(w, http.StatusBadRequest, "Missing code or state parameter.")
		return
	}

	// Recover and validate the launch context from the server-side state store.
	// This is the CSRF protection — the state token is single-use and time-limited.
	lc, ok := globalStateStore.get(state)
	if !ok {
		h.renderError(w, http.StatusBadRequest, "Invalid or expired state parameter.")
		return
	}

	// Confirm the EHR is still registered (config could theoretically change).
	ehrConfig := h.cfg.EHRByURL(lc.ISS)
	if ehrConfig == nil {
		h.renderError(w, http.StatusBadRequest, "Unregistered FHIR server.")
		return
	}

	// Fetch the SMART discovery document to get the token endpoint.
	smartCfg, err := fhir.GetSmartConfiguration(lc.ISS)
	if err != nil {
		log.Printf("handlers: SMART discovery failed for iss=%q: %v", lc.ISS, err)
		h.renderError(w, http.StatusBadGateway, "Unable to fetch SMART configuration.")
		return
	}

	if smartCfg.TokenEndpoint == "" {
		h.renderError(w, http.StatusBadGateway, "SMART configuration missing token_endpoint.")
		return
	}

	// Exchange the authorization code for an access token.
	tokenResp, err := exchangeCode(
		smartCfg.TokenEndpoint,
		ehrConfig.ClientID,
		ehrConfig.ClientSecret,
		h.cfg.SMART.RedirectURL,
		code,
	)
	if err != nil {
		log.Printf("handlers: token exchange failed: %v", err)
		h.renderError(w, http.StatusBadGateway, "Failed to exchange authorization code for token.")
		return
	}

	if tokenResp.AccessToken == "" {
		h.renderError(w, http.StatusBadGateway, "Token response missing access_token.")
		return
	}
	if tokenResp.Patient == "" {
		h.renderError(w, http.StatusBadGateway, "Token response missing patient context.")
		return
	}

	log.Printf("handlers: token response patient=%q practitioner=%q user=%q",
		tokenResp.Patient, tokenResp.Practitioner, tokenResp.User)

	// Build a typed FHIR client for subsequent resource calls.
	fhirClient := fhir.NewClient(lc.ISS, tokenResp.AccessToken)

	// --- Fetch and upsert the Patient ---
	patient, err := fhirClient.GetPatient(tokenResp.Patient)
	if err != nil {
		log.Printf("handlers: fetch Patient/%s failed: %v", tokenResp.Patient, err)
		h.renderError(w, http.StatusBadGateway, "Failed to fetch patient details.")
		return
	}

	patientUser := fhir.ExtractUserFromPatient(patient, lc.ISS)
	patientInternalID, err := h.store.UpsertUser(patientUser)
	if err != nil {
		log.Printf("handlers: upsert patient failed: %v", err)
		h.renderError(w, http.StatusInternalServerError, "Failed to persist patient record.")
		return
	}
	log.Printf("handlers: upserted patient fhir_id=%s internal_id=%s", patient.ID, patientInternalID)

	// --- Resolve the practitioner FHIR ID ---
	// The SMART spec allows the practitioner to be communicated in several ways:
	//   1. tokenResp.Practitioner — a bare FHIR resource ID
	//   2. tokenResp.User         — a relative reference (e.g. "Practitioner/123")
	//   3. id_token.fhirUser      — a relative or absolute URL (OIDC standard)
	//
	// We check them in order of specificity.
	practitionerFHIRID := tokenResp.Practitioner
	if practitionerFHIRID == "" {
		// Try the legacy "user" field.
		practitionerFHIRID = parsePractitionerFromUserField(tokenResp.User)
	}
	if practitionerFHIRID == "" && tokenResp.IDToken != "" {
		// Try the OIDC fhirUser claim.
		fhirUserClaim := fhir.ParseFHIRUserFromIDToken(tokenResp.IDToken)
		log.Printf("handlers: inspecting id_token fhirUser=%q", fhirUserClaim)
		practitionerFHIRID = parsePractitionerFromUserField(fhirUserClaim)
	}

	// --- Resolve the Practitioner or fallback to Patient for the session ---
	var sessionUserID string
	var practitionerUser *models.User

	if practitionerFHIRID != "" {
		practitioner, err := fhirClient.GetPractitioner(practitionerFHIRID)
		if err != nil {
			// Non-fatal: log and continue.
			log.Printf("handlers: fetch Practitioner/%s failed (non-fatal): %v", practitionerFHIRID, err)
		} else {
			practitionerUser = fhir.ExtractUserFromPractitioner(practitioner, lc.ISS)
			practInternalID, err := h.store.UpsertUser(practitionerUser)
			if err != nil {
				log.Printf("handlers: upsert practitioner failed: %v", err)
				h.renderError(w, http.StatusInternalServerError, "Failed to persist practitioner record.")
				return
			}
			log.Printf("handlers: upserted practitioner fhir_id=%s internal_id=%s", practitioner.ID, practInternalID)
			sessionUserID = practInternalID
		}
	}

	// If no practitioner was resolved, fallback to the patient's identity to
	// establish a session (common in patient-facing or testing flows).
	if sessionUserID == "" {
		log.Printf("handlers: no practitioner identity found — falling back to patient identity for session")
		sessionUserID = patientInternalID
		practitionerUser = patientUser // For the UI to show who is "logged in"
	}

	// --- Create session ---
	if sessionUserID != "" {
		sess, err := h.store.CreateSession(sessionUserID, tokenResp.Patient, tokenResp.AccessToken, tokenResp.IDToken, tokenResp.Scope, lc.ISS, 8*time.Hour)
		if err != nil {
			log.Printf("handlers: create session failed: %v", err)
			h.renderError(w, http.StatusInternalServerError, "Failed to create session.")
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     SessionCookieName,
			Value:    sess.ID,
			Path:     "/",
			MaxAge:   SessionTTL,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})
		log.Printf("handlers: session created id=%s for practitioner user_id=%s", sess.ID, sessionUserID)
	}

	// --- Redirect to the stable dashboard ---
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

// parsePractitionerFromUserField extracts a bare Practitioner FHIR ID from a
// SMART "user" claim or fhirUser OIDC claim.
// The input may be:
//   - A bare ID (if the context implies it): "123"
//   - A relative reference: "Practitioner/123"
//   - An absolute FHIR URL: "https://ehr.com/fhir/Practitioner/123"
//
// Returns an empty string if the value is not a Practitioner reference.
func parsePractitionerFromUserField(user string) string {
	// If it's a URL, take the path part.
	if strings.HasPrefix(user, "http") {
		u, err := url.Parse(user)
		if err == nil {
			user = u.Path
		}
	}

	// Remove leading slashes if any.
	user = strings.TrimLeft(user, "/")

	const prefix = "Practitioner/"
	// We check for the prefix anywhere in the path to handle potential sub-paths.
	if idx := strings.Index(user, prefix); idx != -1 {
		return strings.TrimPrefix(user[idx:], prefix)
	}

	return ""
}

// exchangeCode performs the OAuth2 authorization_code token exchange.
// Returns an error on any network failure or non-200 HTTP status.
func exchangeCode(tokenEndpoint, clientID, clientSecret, redirectURI, code string) (*fhir.TokenResponse, error) {
	formData := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {redirectURI},
	}

	req, err := http.NewRequest(http.MethodPost, tokenEndpoint, strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, fmt.Errorf("build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, clientSecret)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read token response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp fhir.TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("decode token response: %w", err)
	}
	return &tokenResp, nil
}
