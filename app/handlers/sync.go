package handlers

import (
	"log"
	"net/http"
	"time"

	"github.com/AmanTahiliani/FHIR-Sandbox/app/fhir"
	"github.com/AmanTahiliani/FHIR-Sandbox/app/middleware"
)

// HandleSync performs a live FHIR pull for Observations, Conditions, DocumentReferences,
// MedicationRequests, and AllergyIntolerances for the session's patient, upserts all
// results into the database, records a PatientSync event, then redirects back to
// GET /dashboard?synced=true.
//
// Incremental sync: If a previous sync exists, only fetches resources updated since
// the last sync time (using FHIR _lastUpdated parameter).
//
// GET /dashboard/sync (auto-sync on first dashboard load)
// POST /dashboard/sync (manual sync from dashboard UI)
func (h *Handler) HandleSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
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

	// Allow overriding the patient context via a query parameter.
	if overrideID := r.URL.Query().Get("patient_id"); overrideID != "" {
		patientID = overrideID
	}

	// Determine if this is an incremental sync
	latestSync, err := h.store.LatestSync(patientID, ehrURL)
	if err != nil {
		log.Printf("handlers: sync LatestSync Patient/%s: %v", patientID, err)
	}

	var sinceTime string
	if latestSync != nil {
		sinceTime = latestSync.SyncedAt.Format(time.RFC3339)
	}

	client := fhir.NewClient(ehrURL, sess.AccessToken)

	// -----------------------------------------------------------------
	// Fetch Observations
	// -----------------------------------------------------------------
	rawObs, err := client.GetObservations(patientID, sinceTime)
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
	rawConds, err := client.GetConditions(patientID, sinceTime)
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
	rawDocs, err := client.GetDocumentReferences(patientID, sinceTime)
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
	// Fetch MedicationRequests
	// -----------------------------------------------------------------
	rawMeds, err := client.GetMedicationRequests(patientID, sinceTime)
	if err != nil {
		log.Printf("handlers: sync GetMedicationRequests for Patient/%s: %v", patientID, err)
	}

	medCount := 0
	for i := range rawMeds {
		m := fhir.ExtractMedicationRequest(&rawMeds[i], patientID, ehrURL)
		if _, err := h.store.UpsertMedicationRequest(m); err != nil {
			log.Printf("handlers: sync UpsertMedicationRequest fhir_id=%s: %v", m.FHIRID, err)
			continue
		}
		medCount++
	}

	// -----------------------------------------------------------------
	// Fetch AllergyIntolerances
	// -----------------------------------------------------------------
	rawAllergies, err := client.GetAllergyIntolerances(patientID, sinceTime)
	if err != nil {
		log.Printf("handlers: sync GetAllergyIntolerances for Patient/%s: %v", patientID, err)
	}

	allergyCount := 0
	for i := range rawAllergies {
		m := fhir.ExtractAllergyIntolerance(&rawAllergies[i], patientID, ehrURL)
		if _, err := h.store.UpsertAllergyIntolerance(m); err != nil {
			log.Printf("handlers: sync UpsertAllergyIntolerance fhir_id=%s: %v", m.FHIRID, err)
			continue
		}
		allergyCount++
	}

	// -----------------------------------------------------------------
	// Fetch Immunizations
	// -----------------------------------------------------------------
	rawImmunizations, err := client.GetImmunizations(patientID, sinceTime)
	if err != nil {
		log.Printf("handlers: sync GetImmunizations for Patient/%s: %v", patientID, err)
	}

	immunizationCount := 0
	for i := range rawImmunizations {
		m := fhir.ExtractImmunization(&rawImmunizations[i], patientID, ehrURL)
		if _, err := h.store.UpsertImmunization(m); err != nil {
			log.Printf("handlers: sync UpsertImmunization fhir_id=%s: %v", m.FHIRID, err)
			continue
		}
		immunizationCount++
	}

	// -----------------------------------------------------------------
	// Fetch Procedures
	// -----------------------------------------------------------------
	rawProcedures, err := client.GetProcedures(patientID, sinceTime)
	if err != nil {
		log.Printf("handlers: sync GetProcedures for Patient/%s: %v", patientID, err)
	}

	procedureCount := 0
	for i := range rawProcedures {
		m := fhir.ExtractProcedure(&rawProcedures[i], patientID, ehrURL)
		if _, err := h.store.UpsertProcedure(m); err != nil {
			log.Printf("handlers: sync UpsertProcedure fhir_id=%s: %v", m.FHIRID, err)
			continue
		}
		procedureCount++
	}

	// -----------------------------------------------------------------
	// Fetch Encounters
	// -----------------------------------------------------------------
	rawEncounters, err := client.GetEncounters(patientID, sinceTime)
	if err != nil {
		log.Printf("handlers: sync GetEncounters for Patient/%s: %v", patientID, err)
	}

	encounterCount := 0
	for i := range rawEncounters {
		m := fhir.ExtractEncounter(&rawEncounters[i], patientID, ehrURL)
		if _, err := h.store.UpsertEncounter(m); err != nil {
			log.Printf("handlers: sync UpsertEncounter fhir_id=%s: %v", m.FHIRID, err)
			continue
		}
		encounterCount++
	}

	// -----------------------------------------------------------------
	// Record the sync event
	// -----------------------------------------------------------------
	if _, err := h.store.RecordSync(patientID, ehrURL, obsCount, condCount, docCount); err != nil {
		log.Printf("handlers: sync RecordSync Patient/%s: %v", patientID, err)
	}

	log.Printf("handlers: sync complete for Patient/%s — obs=%d cond=%d docs=%d med=%d allergy=%d imm=%d proc=%d enc=%d",
		patientID, obsCount, condCount, docCount, medCount, allergyCount, immunizationCount, procedureCount, encounterCount)

	dashboardURL := "/dashboard?synced=true"
	if overrideID := r.URL.Query().Get("patient_id"); overrideID != "" {
		dashboardURL += "&patient_id=" + overrideID
	}
	http.Redirect(w, r, dashboardURL, http.StatusSeeOther)
}
