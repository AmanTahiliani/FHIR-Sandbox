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

	"github.com/AmanTahiliani/FHIR-Sandbox/app/models"
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
