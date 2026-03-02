// Package handlers — cgm.go implements the CGM preview proxy endpoint.
//
// GET /api/cgm-preview?patient_id=<fhir_id>
//
// This endpoint proxies requests to the Rimidi Provider CGM API to display
// CGM data for a patient that has been matched between HRS and Rimidi.
package handlers

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/AmanTahiliani/FHIR-Sandbox/app/middleware"
)

// proxyTimeout is the HTTP client timeout for the outbound CGM API call.
const cgmProxyTimeout = 15 * time.Second

// HandleCGMPreview handles GET /api/cgm-preview requests.
// It requires a valid session and looks up the confirmed match for the patient,
// then proxies the request to the Rimidi Provider CGM API.
func (h *Handler) HandleCGMPreview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	sess := middleware.SessionFromContext(r.Context())
	if sess == nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	// ── Resolve patient from query param or session ────────────────
	patientFHIRID := r.URL.Query().Get("patient_id")
	if patientFHIRID == "" {
		patientFHIRID = sess.PatientFHIRID
	}

	if patientFHIRID == "" {
		http.Error(w, `{"error":"no patient in context"}`, http.StatusBadRequest)
		return
	}

	// ── Look up confirmed match for this patient ───────────────────
	match, err := h.store.GetPatientMatchByFHIRID(patientFHIRID, sess.EHRURL)
	if err != nil {
		log.Printf("handlers: cgm-preview GetPatientMatchByFHIRID(%s, %s): %v", patientFHIRID, sess.EHRURL, err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "No confirmed patient match found. Please confirm a match first.",
		})
		return
	}

	// ── Build Rimidi CGM API URL ───────────────────────────────────
	rimidiURL := h.cfg.RimidiCGMAPIURL
	rimidiKey := h.cfg.RimidiInternalAPIKey

	if rimidiURL == "" || rimidiKey == "" {
		log.Printf("handlers: cgm-preview Rimidi CGM API not configured")
		http.Error(w, `{"error":"CGM API not configured"}`, http.StatusServiceUnavailable)
		return
	}

	// Construct the full URL: {base_url}/{patient_pk}/cgm-preview/
	cgmURL := rimidiURL + "/" + match.RimidiPatientPK + "/cgm-preview/"

	// ── Call Rimidi CGM API ────────────────────────────────────────
	client := &http.Client{Timeout: cgmProxyTimeout}
	req, err := http.NewRequest(http.MethodGet, cgmURL, nil)
	if err != nil {
		log.Printf("handlers: cgm-preview new request: %v", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	req.Header.Set("X-Api-Key", rimidiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("handlers: cgm-preview remote call failed: %v", err)
		http.Error(w, `{"error":"could not reach Rimidi CGM API"}`, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("handlers: cgm-preview read response: %v", err)
		http.Error(w, `{"error":"failed to read remote response"}`, http.StatusBadGateway)
		return
	}

	if resp.StatusCode != http.StatusOK {
		bodyLen := len(respBody)
		if bodyLen > 500 {
			bodyLen = 500
		}
		log.Printf("handlers: cgm-preview remote returned %d: %s", resp.StatusCode, string(respBody[:bodyLen]))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		w.Write(respBody)
		return
	}

	// ── Parse and forward the response ──────────────────────────────
	var cgmData map[string]interface{}
	if err := json.Unmarshal(respBody, &cgmData); err != nil {
		log.Printf("handlers: cgm-preview unmarshal response: %v", err)
		http.Error(w, `{"error":"invalid response from Rimidi CGM API"}`, http.StatusBadGateway)
		return
	}

	// Reports now come with presigned S3 URLs, no transformation needed

	// Forward the response as-is
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(cgmData)
}
