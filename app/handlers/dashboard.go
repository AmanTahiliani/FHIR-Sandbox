package handlers

import (
	"log"
	"net/http"
	"time"

	"github.com/AmanTahiliani/FHIR-Sandbox/app/fhir"
	"github.com/AmanTahiliani/FHIR-Sandbox/app/middleware"
	"github.com/AmanTahiliani/FHIR-Sandbox/app/models"
)

// ClinicalSummary holds pre-computed summary values for the Summary tab.
type ClinicalSummary struct {
	LatestVitals       []models.Observation
	ActiveCondCount    int
	ActiveMedCount     int
	AbnormalLabCount   int
	AbnormalLabsRecent []models.Observation
}

// buildClinicalSummary computes the clinical summary from existing in-memory data.
// No additional DB or FHIR calls are made.
func buildClinicalSummary(obs []models.Observation, conds []models.Condition, meds []models.MedicationRequest) ClinicalSummary {
	// Latest value per vital code.
	latestVitals := latestObsPerCode(filterObsByCategory(obs, "vital-signs"))

	activeConds := 0
	for _, c := range conds {
		if c.ClinicalStatus == "active" {
			activeConds++
		}
	}

	activeMeds := 0
	for _, m := range meds {
		if m.Status == "active" {
			activeMeds++
		}
	}

	// Abnormal labs within the last 30 days.
	cutoff := time.Now().AddDate(0, 0, -30).Format("2006-01-02")
	var abnormalLabs []models.Observation
	for _, o := range obs {
		if isAbnormalInterp(o.Interpretation) && o.EffectiveDate >= cutoff {
			abnormalLabs = append(abnormalLabs, o)
		}
	}

	return ClinicalSummary{
		LatestVitals:       latestVitals,
		ActiveCondCount:    activeConds,
		ActiveMedCount:     activeMeds,
		AbnormalLabCount:   len(abnormalLabs),
		AbnormalLabsRecent: abnormalLabs,
	}
}

// HandleDashboard renders the stable patient dashboard.
// On first load (no prior sync), automatically triggers a sync to populate data.
// All other clinical data is read from the local database; no live FHIR calls are
// made here. Use POST /dashboard/sync to refresh data from the EHR.
//
// GET /dashboard
func (h *Handler) HandleDashboard(w http.ResponseWriter, r *http.Request) {
	sess := middleware.SessionFromContext(r.Context())
	practitionerUser := middleware.UserFromContext(r.Context())

	if sess == nil || practitionerUser == nil {
		h.handleUnauthorized(w, r)
		return
	}

	ehrURL := sess.EHRURL
	patientID := sess.PatientFHIRID

	// Allow overriding the patient context via a query parameter.
	if overrideID := r.URL.Query().Get("patient_id"); overrideID != "" {
		patientID = overrideID
	}

	// Check if this is the first load and trigger auto-sync
	latestSync, err := h.store.LatestSync(patientID, ehrURL)
	if err != nil {
		log.Printf("handlers: dashboard LatestSync Patient/%s: %v", patientID, err)
	}

	if latestSync == nil {
		// First load — redirect to sync endpoint for auto-sync
		syncURL := "/dashboard/sync"
		if overrideID := r.URL.Query().Get("patient_id"); overrideID != "" {
			syncURL += "?patient_id=" + overrideID
		}
		http.Redirect(w, r, syncURL, http.StatusSeeOther)
		return
	}

	// Fetch patient demographics from the FHIR server. This is a cheap single
	// resource call and keeps the patient card always current.
	fhirClient := fhir.NewClient(ehrURL, sess.AccessToken)
	patient, err := fhirClient.GetPatient(patientID)
	if err != nil {
		log.Printf("handlers: dashboard fetch Patient/%s failed: %v", patientID, err)
		h.renderError(w, http.StatusBadGateway, "Failed to fetch patient details from the FHIR server.")
		return
	}
	patientUser := fhir.ExtractUserFromPatient(patient, ehrURL)

	// Read clinical data from the local database.
	observations, err := h.store.ListObservations(patientID, ehrURL)
	if err != nil {
		log.Printf("handlers: dashboard ListObservations Patient/%s: %v", patientID, err)
	}

	conditions, err := h.store.ListConditions(patientID, ehrURL)
	if err != nil {
		log.Printf("handlers: dashboard ListConditions Patient/%s: %v", patientID, err)
	}

	docRefs, err := h.store.ListDocumentReferences(patientID, ehrURL)
	if err != nil {
		log.Printf("handlers: dashboard ListDocumentReferences Patient/%s: %v", patientID, err)
	}

	medications, err := h.store.ListMedicationRequests(patientID, ehrURL)
	if err != nil {
		log.Printf("handlers: dashboard ListMedicationRequests Patient/%s: %v", patientID, err)
	}

	allergies, err := h.store.ListAllergyIntolerances(patientID, ehrURL)
	if err != nil {
		log.Printf("handlers: dashboard ListAllergyIntolerances Patient/%s: %v", patientID, err)
	}

	immunizations, err := h.store.ListImmunizations(patientID, ehrURL)
	if err != nil {
		log.Printf("handlers: dashboard ListImmunizations Patient/%s: %v", patientID, err)
	}

	procedures, err := h.store.ListProcedures(patientID, ehrURL)
	if err != nil {
		log.Printf("handlers: dashboard ListProcedures Patient/%s: %v", patientID, err)
	}

	encounters, err := h.store.ListEncounters(patientID, ehrURL)
	if err != nil {
		log.Printf("handlers: dashboard ListEncounters Patient/%s: %v", patientID, err)
	}

	summary := buildClinicalSummary(observations, conditions, medications)
	synced := r.URL.Query().Get("synced") == "true"

	h.render(w, "dashboard.html", dashboardData{
		Patient:            patientUser,
		Practitioner:       practitionerUser,
		RawPatient:         patient,
		Observations:       observations,
		Conditions:         conditions,
		DocumentReferences: docRefs,
		Medications:        medications,
		Allergies:          allergies,
		Immunizations:      immunizations,
		Procedures:         procedures,
		Encounters:         encounters,
		Summary:            summary,
		LatestSync:         latestSync,
		Session:            sess,
		Synced:             synced,
	})
}

// dashboardData is the view model passed to the dashboard template.
type dashboardData struct {
	Patient            *models.User
	Practitioner       *models.User
	RawPatient         *fhir.Patient
	Observations       []models.Observation
	Conditions         []models.Condition
	DocumentReferences []models.DocumentReference
	Medications        []models.MedicationRequest
	Allergies          []models.AllergyIntolerance
	Immunizations      []models.Immunization
	Procedures         []models.Procedure
	Encounters         []models.Encounter
	Summary            ClinicalSummary
	LatestSync         *models.PatientSync
	Session            *models.Session
	Synced             bool
}

// handleUnauthorized redirects to root for dashboard requests.
func (h *Handler) handleUnauthorized(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
