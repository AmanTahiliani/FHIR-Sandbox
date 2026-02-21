package handlers

import (
	"log"
	"net/http"

	"github.com/AmanTahiliani/FHIR-Sandbox/app/middleware"
	"github.com/AmanTahiliani/FHIR-Sandbox/app/models"
)

// HandlePatients renders the list of all synced patients for the current EHR.
// GET /patients
func (h *Handler) HandlePatients(w http.ResponseWriter, r *http.Request) {
	sess := middleware.SessionFromContext(r.Context())
	practitionerUser := middleware.UserFromContext(r.Context())

	if sess == nil || practitionerUser == nil {
		h.handleUnauthorized(w, r)
		return
	}

	patients, err := h.store.ListUsersByRole(models.RolePatient, sess.EHRURL)
	if err != nil {
		log.Printf("handlers: HandlePatients ListUsersByRole failed: %v", err)
		h.renderError(w, http.StatusInternalServerError, "Failed to retrieve patients from the database.")
		return
	}

	h.render(w, "patients.html", patientsData{
		Patients:     patients,
		Practitioner: practitionerUser,
		Session:      sess,
	})
}

type patientsData struct {
	Patients     []models.User
	Practitioner *models.User
	Session      *models.Session
}
