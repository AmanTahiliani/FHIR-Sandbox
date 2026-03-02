// Package handlers — match.go implements the patient match API endpoint.
//
// POST /api/patient-match
//
// This endpoint accepts demographic identifiers (first_name, last_name,
// email, dob, sex) and returns a list of patients in the FHIR Sandbox
// that match ≥ 2 fields exactly. Auth is via X-Api-Key header.
package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/AmanTahiliani/FHIR-Sandbox/app/middleware"
	"github.com/AmanTahiliani/FHIR-Sandbox/app/models"
	"github.com/google/uuid"
)

// patientMatchRequest is the inbound JSON shape for a match query.
type patientMatchRequest struct {
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Email     string `json:"email"`
	DOB       string `json:"dob"`
	Sex       string `json:"sex"`
}

// fieldResult describes whether a single field matched and what the
// remote system's value is.
type fieldResult struct {
	Value string `json:"value"`
	Match bool   `json:"match"`
}

// matchResult is one potential patient match in the response.
type matchResult struct {
	PatientRef string                 `json:"patient_ref"`
	Score      int                    `json:"score"`
	Fields     map[string]fieldResult `json:"fields"`
}

// patientMatchResponse is the top-level response shape.
type patientMatchResponse struct {
	SourceSystem string        `json:"source_system"`
	Matches      []matchResult `json:"matches"`
}

// Minimum number of exact field matches required to include a patient.
const minMatchScore = 2

// sexNormMap normalises FHIR/Provider gender codes → canonical M/F/O/U.
var sexNormMap = map[string]string{
	"m":       "M",
	"f":       "F",
	"o":       "O",
	"u":       "U",
	"male":    "M",
	"female":  "F",
	"other":   "O",
	"unknown": "U",
}

// normName lowercases and trims a name string.
func normName(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// normSex normalises a sex/gender value to M/F/O/U.
func normSex(s string) string {
	v, ok := sexNormMap[strings.ToLower(strings.TrimSpace(s))]
	if !ok {
		return ""
	}
	return v
}

// normDOB trims and returns the DOB string (expected YYYY-MM-DD).
func normDOB(s string) string { return strings.TrimSpace(s) }

// computeMatchScore compares normalised criteria against a candidate user.
// Returns the score (0–5) and per-field report.
func computeMatchScore(criteria, candidate map[string]string) (int, map[string]fieldResult) {
	fields := make(map[string]fieldResult, 5)
	score := 0

	for _, f := range []string{"first_name", "last_name", "email", "dob", "sex"} {
		cVal := criteria[f]
		pVal := candidate[f]

		isMatch := cVal != "" && pVal != "" && cVal == pVal
		if isMatch {
			score++
		}
		fields[f] = fieldResult{Value: pVal, Match: isMatch}
	}
	return score, fields
}

// normaliseUser converts a User model into a normalised string map.
func normaliseUser(u *models.User) map[string]string {
	return map[string]string{
		"first_name": normName(u.FirstName),
		"last_name":  normName(u.LastName),
		"email":      normName(u.Email),
		"dob":        normDOB(u.DOB),
		"sex":        normSex(u.Gender),
	}
}

// normaliseCriteria converts a match request into a normalised string map.
func normaliseCriteria(req *patientMatchRequest) map[string]string {
	return map[string]string{
		"first_name": normName(req.FirstName),
		"last_name":  normName(req.LastName),
		"email":      normName(req.Email),
		"dob":        normDOB(req.DOB),
		"sex":        normSex(req.Sex),
	}
}

// HandlePatientMatch processes POST /api/patient-match requests.
func (h *Handler) HandlePatientMatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	// ── Decode request body ─────────────────────────────────────────
	var req patientMatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid JSON body"}`, http.StatusBadRequest)
		return
	}

	// ── Validate required fields ────────────────────────────────────
	var missing []string
	if strings.TrimSpace(req.FirstName) == "" {
		missing = append(missing, "first_name")
	}
	if strings.TrimSpace(req.LastName) == "" {
		missing = append(missing, "last_name")
	}
	if strings.TrimSpace(req.DOB) == "" {
		missing = append(missing, "dob")
	}
	if strings.TrimSpace(req.Sex) == "" {
		missing = append(missing, "sex")
	}
	if len(missing) > 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Missing required fields: " + strings.Join(missing, ", "),
		})
		return
	}

	criteria := normaliseCriteria(&req)

	// ── Load all patients from the database ─────────────────────────
	patients, err := h.store.ListAllPatients()
	if err != nil {
		log.Printf("handlers: HandlePatientMatch ListAllPatients failed: %v", err)
		http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
		return
	}

	// ── Match loop ──────────────────────────────────────────────────
	var matches []matchResult
	for i := range patients {
		candidate := normaliseUser(&patients[i])
		score, fields := computeMatchScore(criteria, candidate)

		if score >= minMatchScore {
			matches = append(matches, matchResult{
				PatientRef: patients[i].ID, // internal UUID — opaque to caller
				Score:      score,
				Fields:     fields,
			})
		}
	}

	// Sort by score descending, then patient_ref for deterministic order.
	sort.Slice(matches, func(i, j int) bool {
		if matches[i].Score != matches[j].Score {
			return matches[i].Score > matches[j].Score
		}
		return matches[i].PatientRef < matches[j].PatientRef
	})

	log.Printf("handlers: patient-match candidates=%d matches=%d", len(patients), len(matches))

	// ── Write response ──────────────────────────────────────────────
	resp := patientMatchResponse{
		SourceSystem: "hrs",
		Matches:      matches,
	}
	// Ensure matches is never null in JSON
	if resp.Matches == nil {
		resp.Matches = []matchResult{}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

// confirmMatchRequest is the inbound JSON shape for a match confirmation.
type confirmMatchRequest struct {
	RimidiPatientRef string `json:"rimidi_patient_ref"`
	RimidiPatientPK  string `json:"rimidi_patient_pk"`
}

// confirmMatchResponse is the response shape for match confirmation.
type confirmMatchResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Match   *models.PatientMatch `json:"match,omitempty"`
}

// HandleConfirmMatch processes POST /api/patient-match/confirm requests.
// It requires a valid session and stores the confirmed match in the database.
func (h *Handler) HandleConfirmMatch(w http.ResponseWriter, r *http.Request) {
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

	// ── Decode request body ─────────────────────────────────────────
	var req confirmMatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid JSON body"}`, http.StatusBadRequest)
		return
	}

	// ── Validate required fields ────────────────────────────────────
	if strings.TrimSpace(req.RimidiPatientRef) == "" {
		http.Error(w, `{"error":"rimidi_patient_ref is required"}`, http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.RimidiPatientPK) == "" {
		http.Error(w, `{"error":"rimidi_patient_pk is required"}`, http.StatusBadRequest)
		return
	}

	// ── Get Rimidi app ID from config ──────────────────────────────
	rimidiAppID := h.cfg.RimidiAppID
	if rimidiAppID == "" {
		rimidiAppID = "demo-app" // Default for demo
	}

	// ── Create patient match record ─────────────────────────────────
	match := &models.PatientMatch{
		ID:               uuid.NewString(),
		HRSPatientFHIRID: patientFHIRID,
		HRSEHRURL:        sess.EHRURL,
		RimidiAppID:      rimidiAppID,
		RimidiPatientPK:  req.RimidiPatientPK,
		RimidiPatientRef: req.RimidiPatientRef,
		ConfirmedAt:      time.Now().UTC(),
		CreatedAt:        time.Now().UTC(),
		UpdatedAt:        time.Now().UTC(),
	}

	// ── Store match in database ────────────────────────────────────
	if err := h.store.UpsertPatientMatch(match); err != nil {
		log.Printf("handlers: confirm-match UpsertPatientMatch failed: %v", err)
		http.Error(w, `{"error":"failed to store match"}`, http.StatusInternalServerError)
		return
	}

	log.Printf("handlers: confirmed patient match: hrs_patient=%s rimidi_pk=%s", patientFHIRID, req.RimidiPatientPK)

	// ── Write success response ─────────────────────────────────────
	resp := confirmMatchResponse{
		Success: true,
		Message: "Patient match confirmed successfully",
		Match:   match,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

// HandleUnlinkMatch processes DELETE /api/patient-match/unlink requests.
// It requires a valid session and removes the confirmed match for the patient.
func (h *Handler) HandleUnlinkMatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete && r.Method != http.MethodPost {
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

	// ── Delete the match ──────────────────────────────────────────
	err := h.store.DeletePatientMatch(patientFHIRID, sess.EHRURL)
	if err != nil {
		log.Printf("handlers: unlink-match DeletePatientMatch(%s, %s): %v", patientFHIRID, sess.EHRURL, err)
		http.Error(w, `{"error":"failed to unlink patient"}`, http.StatusInternalServerError)
		return
	}

	log.Printf("handlers: unlinked patient match: hrs_patient=%s", patientFHIRID)

	// ── Write success response ─────────────────────────────────────
	resp := map[string]interface{}{
		"success": true,
		"message": "Patient unlinked successfully",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}
