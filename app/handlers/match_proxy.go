// Package handlers — match_proxy.go implements the browser-facing
// "Find in Rimidi" proxy endpoint.
//
// POST /api/patient-match-proxy
//
// This endpoint is session-protected. It reads the current patient's
// demographics from the local database, calls the remote Rimidi patient
// match API, and returns the response to the browser.
package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/AmanTahiliani/FHIR-Sandbox/app/middleware"
)

// proxyTimeout is the HTTP client timeout for the outbound match call.
const proxyTimeout = 10 * time.Second

// matchProxyResponse wraps the remote response and adds the local patient's
// demographics so the UI can render a side-by-side diff.
type matchProxyResponse struct {
	SourceSystem string                 `json:"source_system"`
	Matches      []matchResult          `json:"matches"`
	LocalPatient map[string]string      `json:"local_patient"`
	Raw          map[string]interface{} `json:"-"` // internal only
}

// HandlePatientMatchProxy handles POST /api/patient-match-proxy.
// It requires a valid session and reads the patient from session context.
func (h *Handler) HandlePatientMatchProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	sess := middleware.SessionFromContext(r.Context())
	if sess == nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	// ── Resolve patient from the session or query param ─────────────
	patientFHIRID := sess.PatientFHIRID
	if override := r.URL.Query().Get("patient_id"); override != "" {
		patientFHIRID = override
	}

	if patientFHIRID == "" {
		http.Error(w, `{"error":"no patient in context"}`, http.StatusBadRequest)
		return
	}

	// Fetch patient demographics from the local database.
	patient, err := h.store.GetUserByFHIRID(patientFHIRID, sess.EHRURL)
	if err != nil {
		log.Printf("handlers: match-proxy GetUserByFHIRID(%s): %v", patientFHIRID, err)
		http.Error(w, `{"error":"patient not found in local database"}`, http.StatusNotFound)
		return
	}

	// ── Build outbound payload ──────────────────────────────────────
	payload := patientMatchRequest{
		FirstName: patient.FirstName,
		LastName:  patient.LastName,
		Email:     patient.Email,
		DOB:       patient.DOB,
		Sex:       patient.Gender,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		log.Printf("handlers: match-proxy marshal payload: %v", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	// ── Call remote Rimidi match API ─────────────────────────────────
	remoteURL := h.cfg.PatientMatchRemoteURL
	remoteKey := h.cfg.PatientMatchRemoteAPIKey

	if remoteURL == "" || remoteKey == "" {
		log.Printf("handlers: match-proxy remote URL/key not configured")
		http.Error(w, `{"error":"remote patient match not configured"}`, http.StatusServiceUnavailable)
		return
	}

	client := &http.Client{Timeout: proxyTimeout}
	req, err := http.NewRequest(http.MethodPost, remoteURL, bytes.NewReader(body))
	if err != nil {
		log.Printf("handlers: match-proxy new request: %v", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Api-Key", remoteKey)

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("handlers: match-proxy remote call failed: %v", err)
		http.Error(w, `{"error":"could not reach remote system"}`, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("handlers: match-proxy read response: %v", err)
		http.Error(w, `{"error":"failed to read remote response"}`, http.StatusBadGateway)
		return
	}

	if resp.StatusCode != http.StatusOK {
		log.Printf("handlers: match-proxy remote returned %d: %s", resp.StatusCode, string(respBody[:min(len(respBody), 500)]))
		http.Error(w, fmt.Sprintf(`{"error":"remote system returned HTTP %d"}`, resp.StatusCode), http.StatusBadGateway)
		return
	}

	// ── Parse remote response and augment with local demographics ───
	var remoteData map[string]interface{}
	if err := json.Unmarshal(respBody, &remoteData); err != nil {
		log.Printf("handlers: match-proxy unmarshal response: %v", err)
		http.Error(w, `{"error":"invalid response from remote system"}`, http.StatusBadGateway)
		return
	}

	// Attach local patient demographics for side-by-side diff rendering.
	remoteData["local_patient"] = map[string]string{
		"first_name": patient.FirstName,
		"last_name":  patient.LastName,
		"email":      patient.Email,
		"dob":        patient.DOB,
		"sex":        patient.Gender,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(remoteData)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
