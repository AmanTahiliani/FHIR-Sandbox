package handlers

import (
	"log"
	"net/http"

	"github.com/AmanTahiliani/FHIR-Sandbox/app/fhir"
	"github.com/AmanTahiliani/FHIR-Sandbox/app/middleware"
	"github.com/AmanTahiliani/FHIR-Sandbox/app/models"
)

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
		// Non-fatal; render with empty slice.
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
	LatestSync         *models.PatientSync
	Session            *models.Session
	Synced             bool
}

// handleUnauthorized redirects to root for dashboard requests.
func (h *Handler) handleUnauthorized(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
