// Package models defines the core domain types used throughout the application.
// These structs map directly to database tables and serve as the canonical
// representation of platform entities. As the platform grows, new resource
// types (e.g., Observation, Condition, MedicationRequest) should be added here.
package models

import "time"

// Role represents the access tier of a platform user.
// New roles (e.g., RoleAdmin, RoleCaregiver) can be appended without
// breaking existing comparisons since the underlying type is a string.
type Role string

const (
	// RolePatient identifies a patient-context user created on SMART launch.
	RolePatient Role = "patient"

	// RolePractitioner identifies an HCP who initiated a SMART launch.
	RolePractitioner Role = "practitioner"
)

// User is the canonical platform user record, independent of any specific
// FHIR resource type. It maps to the `users` table.
//
// Design note: FHIRResourceType allows the same struct to represent both
// Patient and Practitioner FHIR resources without a separate table per type.
// Adding support for RelatedPerson or CareTeam members only requires updating
// the fhir package's extraction logic and inserting with the correct type.
type User struct {
	// ID is the internal UUID primary key. Never exposed in URLs.
	ID string `json:"id" db:"id"`

	// FHIRResourceType is the FHIR resource type string, e.g. "Patient" or "Practitioner".
	FHIRResourceType string `json:"fhir_resource_type" db:"fhir_resource_type"`

	// FHIRID is the resource id from the originating EHR FHIR server.
	// Combined with EHRURL this forms a globally unique identity.
	FHIRID string `json:"fhir_id" db:"fhir_id"`

	// EHRURL is the base FHIR server URL the user was sourced from.
	// Storing this prevents ID collisions across EHR tenants.
	EHRURL string `json:"ehr_url" db:"ehr_url"`

	// Role defines the user's access tier within this platform.
	Role Role `json:"role" db:"role"`

	// Demographics
	FirstName  string `json:"first_name" db:"first_name"`
	MiddleName string `json:"middle_name" db:"middle_name"`
	LastName   string `json:"last_name" db:"last_name"`
	DOB        string `json:"dob" db:"dob"`       // ISO 8601 date, e.g. "1990-04-22"
	Gender     string `json:"gender" db:"gender"` // FHIR value set: male|female|other|unknown

	// Email is optional — not all FHIR resources include contact telecom data.
	Email string `json:"email" db:"email"`

	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// Session represents an active authenticated session for a platform user.
// Sessions are created on SMART launch completion and destroyed on logout.
// Only HCP (RolePractitioner) users create sessions; patients are stored
// passively and do not log in directly via this flow.
type Session struct {
	// ID is the session token — a UUID stored as an HttpOnly cookie.
	ID string `json:"id" db:"id"`

	// UserID references the authenticated User.ID (internal UUID).
	UserID string `json:"user_id" db:"user_id"`

	// AccessToken holds the FHIR Bearer token for the duration of the session,
	// enabling subsequent FHIR API calls on behalf of the logged-in HCP.
	AccessToken string `json:"access_token" db:"access_token"`

	// IDToken holds the raw OIDC ID token if provided by the EHR.
	IDToken string `json:"id_token" db:"id_token"`

	// Scope holds the scopes granted by the EHR during this session.
	Scope string `json:"scope" db:"scope"`

	// EHRURL is the FHIR server base URL associated with this session.
	// Stored so any handler can construct FHIR API requests without
	// re-deriving the EHR context from state parameters.
	EHRURL string `json:"ehr_url" db:"ehr_url"`

	// PatientFHIRID is the FHIR ID of the patient in context for this session.
	// Stored so the dashboard can fetch patient-specific resources.
	PatientFHIRID string `json:"patient_fhir_id" db:"patient_fhir_id"`

	CreatedAt time.Time `json:"created_at" db:"created_at"`
	ExpiresAt time.Time `json:"expires_at" db:"expires_at"`
}

// SessionContextKey is the type used to store the resolved Session in a
// request context. Using a dedicated unexported type avoids key collisions.
type SessionContextKey struct{}

// UserContextKey is the type used to store the resolved User in a
// request context.
type UserContextKey struct{}

// ---------------------------------------------------------------------------
// Clinical resource models
// ---------------------------------------------------------------------------

// Observation is the persisted representation of a FHIR R4 Observation.
// The natural key is (fhir_id, ehr_url).
type Observation struct {
	ID                 string    `json:"id"                   db:"id"`
	FHIRID             string    `json:"fhir_id"              db:"fhir_id"`
	EHRURL             string    `json:"ehr_url"              db:"ehr_url"`
	PatientFHIRID      string    `json:"patient_fhir_id"      db:"patient_fhir_id"`
	Status             string    `json:"status"               db:"status"`
	Category           string    `json:"category"             db:"category"`
	CodeText           string    `json:"code_text"            db:"code_text"`
	CodeSystem         string    `json:"code_system"          db:"code_system"`
	CodeCode           string    `json:"code_code"            db:"code_code"`
	EffectiveDate      string    `json:"effective_date"       db:"effective_date"`
	ValueQuantity      *float64  `json:"value_quantity"       db:"value_quantity"`
	ValueUnit          string    `json:"value_unit"           db:"value_unit"`
	ValueString        string    `json:"value_string"         db:"value_string"`
	Interpretation     string    `json:"interpretation"       db:"interpretation"`
	ReferenceRangeLow  *float64  `json:"ref_range_low"        db:"ref_range_low"`
	ReferenceRangeHigh *float64  `json:"ref_range_high"       db:"ref_range_high"`
	SyncedAt           time.Time `json:"synced_at"            db:"synced_at"`
}

// Condition is the persisted representation of a FHIR R4 Condition.
type Condition struct {
	ID                 string    `json:"id"                   db:"id"`
	FHIRID             string    `json:"fhir_id"              db:"fhir_id"`
	EHRURL             string    `json:"ehr_url"              db:"ehr_url"`
	PatientFHIRID      string    `json:"patient_fhir_id"      db:"patient_fhir_id"`
	ClinicalStatus     string    `json:"clinical_status"      db:"clinical_status"`
	VerificationStatus string    `json:"verification_status"  db:"verification_status"`
	Category           string    `json:"category"             db:"category"`
	CodeText           string    `json:"code_text"            db:"code_text"`
	CodeSystem         string    `json:"code_system"          db:"code_system"`
	CodeCode           string    `json:"code_code"            db:"code_code"`
	OnsetDate          string    `json:"onset_date"           db:"onset_date"`
	RecordedDate       string    `json:"recorded_date"        db:"recorded_date"`
	SyncedAt           time.Time `json:"synced_at"            db:"synced_at"`
}

// DocumentReference is the persisted representation of a FHIR R4 DocumentReference.
type DocumentReference struct {
	ID            string    `json:"id"              db:"id"`
	FHIRID        string    `json:"fhir_id"         db:"fhir_id"`
	EHRURL        string    `json:"ehr_url"         db:"ehr_url"`
	PatientFHIRID string    `json:"patient_fhir_id" db:"patient_fhir_id"`
	Status        string    `json:"status"          db:"status"`
	DocStatus     string    `json:"doc_status"      db:"doc_status"`
	TypeText      string    `json:"type_text"       db:"type_text"`
	TypeSystem    string    `json:"type_system"     db:"type_system"`
	TypeCode      string    `json:"type_code"       db:"type_code"`
	Category      string    `json:"category"        db:"category"`
	Date          string    `json:"date"            db:"date"`
	Description   string    `json:"description"     db:"description"`
	ContentType   string    `json:"content_type"    db:"content_type"`
	ContentURL    string    `json:"content_url"     db:"content_url"`
	ContentData   string    `json:"content_data"    db:"content_data"`
	SyncedAt      time.Time `json:"synced_at"       db:"synced_at"`
}

// MedicationRequest is the persisted representation of a FHIR R4 MedicationRequest.
type MedicationRequest struct {
	ID               string    `json:"id"               db:"id"`
	FHIRID           string    `json:"fhir_id"          db:"fhir_id"`
	EHRURL           string    `json:"ehr_url"          db:"ehr_url"`
	PatientFHIRID    string    `json:"patient_fhir_id"  db:"patient_fhir_id"`
	Status           string    `json:"status"           db:"status"`
	Intent           string    `json:"intent"           db:"intent"`
	MedCodeText      string    `json:"med_code_text"    db:"med_code_text"`
	MedCodeSystem    string    `json:"med_code_system"  db:"med_code_system"`
	MedCodeCode      string    `json:"med_code_code"    db:"med_code_code"`
	AuthoredOn       string    `json:"authored_on"      db:"authored_on"`
	RequesterDisplay string    `json:"requester_display" db:"requester_display"`
	DosageText       string    `json:"dosage_text"      db:"dosage_text"`
	SyncedAt         time.Time `json:"synced_at"        db:"synced_at"`
}

// AllergyIntolerance is the persisted representation of a FHIR R4 AllergyIntolerance.
type AllergyIntolerance struct {
	ID                 string    `json:"id"                    db:"id"`
	FHIRID             string    `json:"fhir_id"               db:"fhir_id"`
	EHRURL             string    `json:"ehr_url"               db:"ehr_url"`
	PatientFHIRID      string    `json:"patient_fhir_id"       db:"patient_fhir_id"`
	ClinicalStatus     string    `json:"clinical_status"       db:"clinical_status"`
	VerificationStatus string    `json:"verification_status"   db:"verification_status"`
	Type               string    `json:"type"                  db:"type"`
	Category           string    `json:"category"              db:"category"`
	Criticality        string    `json:"criticality"           db:"criticality"`
	CodeText           string    `json:"code_text"             db:"code_text"`
	CodeSystem         string    `json:"code_system"           db:"code_system"`
	CodeCode           string    `json:"code_code"             db:"code_code"`
	RecordedDate       string    `json:"recorded_date"         db:"recorded_date"`
	SyncedAt           time.Time `json:"synced_at"             db:"synced_at"`
}

// PatientSync records a completed FHIR sync event for a patient.
type PatientSync struct {
	ID            string    `json:"id"              db:"id"`
	PatientFHIRID string    `json:"patient_fhir_id" db:"patient_fhir_id"`
	EHRURL        string    `json:"ehr_url"         db:"ehr_url"`
	SyncedAt      time.Time `json:"synced_at"       db:"synced_at"`
	ObsCount      int       `json:"obs_count"       db:"obs_count"`
	CondCount     int       `json:"cond_count"      db:"cond_count"`
	DocCount      int       `json:"doc_count"       db:"doc_count"`
}
