package handlers

import (
	"log"
	"net/http"

	"github.com/AmanTahiliani/FHIR-Sandbox/app/fhir"
	"github.com/AmanTahiliani/FHIR-Sandbox/app/middleware"
)

// HandleSync performs a live FHIR pull for Observations, Conditions, and
// DocumentReferences for the session's patient, upserts all results into the
// database, records a PatientSync event, then redirects back to GET /dashboard.
//
// POST /dashboard/sync
func (h *Handler) HandleSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	sess := middleware.SessionFromContext(r.Context())
	if sess == nil {
		h.handleUnauthorized(w, r)
		return
	}

	ehrURL := sess.EHRURL
	patientID := sess.PatientFHIRID
	client := fhir.NewClient(ehrURL, sess.AccessToken)

	// -----------------------------------------------------------------
	// Fetch Observations
	// -----------------------------------------------------------------
	rawObs, err := client.GetObservations(patientID)
	if err != nil {
		log.Printf("handlers: sync GetObservations for Patient/%s: %v", patientID, err)
		// Non-fatal; continue with whatever we got.
	}

	obsCount := 0
	for i := range rawObs {
		m := fhir.ExtractObservation(&rawObs[i], patientID, ehrURL)
		if _, err := h.store.UpsertObservation(m); err != nil {
			log.Printf("handlers: sync UpsertObservation fhir_id=%s: %v", m.FHIRID, err)
			continue
		}
		obsCount++
	}

	// -----------------------------------------------------------------
	// Fetch Conditions
	// -----------------------------------------------------------------
	rawConds, err := client.GetConditions(patientID)
	if err != nil {
		log.Printf("handlers: sync GetConditions for Patient/%s: %v", patientID, err)
	}

	condCount := 0
	for i := range rawConds {
		m := fhir.ExtractCondition(&rawConds[i], patientID, ehrURL)
		if _, err := h.store.UpsertCondition(m); err != nil {
			log.Printf("handlers: sync UpsertCondition fhir_id=%s: %v", m.FHIRID, err)
			continue
		}
		condCount++
	}

	// -----------------------------------------------------------------
	// Fetch DocumentReferences
	// -----------------------------------------------------------------
	rawDocs, err := client.GetDocumentReferences(patientID)
	if err != nil {
		log.Printf("handlers: sync GetDocumentReferences for Patient/%s: %v", patientID, err)
	}

	docCount := 0
	for i := range rawDocs {
		m := fhir.ExtractDocumentReference(&rawDocs[i], patientID, ehrURL)
		if _, err := h.store.UpsertDocumentReference(m); err != nil {
			log.Printf("handlers: sync UpsertDocumentReference fhir_id=%s: %v", m.FHIRID, err)
			continue
		}
		docCount++
	}

	// -----------------------------------------------------------------
	// Record the sync event
	// -----------------------------------------------------------------
	if _, err := h.store.RecordSync(patientID, ehrURL, obsCount, condCount, docCount); err != nil {
		log.Printf("handlers: sync RecordSync Patient/%s: %v", patientID, err)
	}

	log.Printf("handlers: sync complete for Patient/%s — obs=%d cond=%d docs=%d",
		patientID, obsCount, condCount, docCount)

	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}
