package fhir_test

import (
	"testing"

	"github.com/AmanTahiliani/FHIR-Sandbox/app/fhir"
	"github.com/AmanTahiliani/FHIR-Sandbox/app/models"
)

// ---------------------------------------------------------------------------
// ExtractUserFromPatient tests
// ---------------------------------------------------------------------------

func TestExtractUserFromPatient_FullRecord(t *testing.T) {
	p := &fhir.Patient{
		ResourceTypeField: "Patient",
		ID:                "patient-001",
		Gender:            "female",
		BirthDate:         "1990-04-22",
		Name: []fhir.HumanName{
			{Use: "official", Family: "Smith", Given: []string{"Alice", "Marie"}},
		},
		Telecom: []fhir.ContactPoint{
			{System: "phone", Value: "+15555550100"},
			{System: "email", Value: "alice@example.com"},
		},
	}

	u := fhir.ExtractUserFromPatient(p, "https://ehr.example.com/fhir")

	assertEqual(t, "FHIRID", "patient-001", u.FHIRID)
	assertEqual(t, "Role", string(models.RolePatient), string(u.Role))
	assertEqual(t, "FHIRResourceType", "Patient", u.FHIRResourceType)
	assertEqual(t, "FirstName", "Alice", u.FirstName)
	assertEqual(t, "MiddleName", "Marie", u.MiddleName)
	assertEqual(t, "LastName", "Smith", u.LastName)
	assertEqual(t, "DOB", "1990-04-22", u.DOB)
	assertEqual(t, "Gender", "female", u.Gender)
	assertEqual(t, "Email", "alice@example.com", u.Email)
	assertEqual(t, "EHRURL", "https://ehr.example.com/fhir", u.EHRURL)
}

func TestExtractUserFromPatient_NoMiddleName(t *testing.T) {
	p := &fhir.Patient{
		ID:     "patient-002",
		Gender: "male",
		Name:   []fhir.HumanName{{Use: "official", Family: "Jones", Given: []string{"Bob"}}},
	}

	u := fhir.ExtractUserFromPatient(p, "https://ehr.example.com/fhir")

	assertEqual(t, "FirstName", "Bob", u.FirstName)
	assertEqual(t, "MiddleName", "", u.MiddleName)
	assertEqual(t, "LastName", "Jones", u.LastName)
}

func TestExtractUserFromPatient_NoEmail(t *testing.T) {
	p := &fhir.Patient{
		ID:      "patient-003",
		Telecom: []fhir.ContactPoint{{System: "phone", Value: "+15555559999"}},
	}

	u := fhir.ExtractUserFromPatient(p, "https://ehr.example.com/fhir")

	if u.Email != "" {
		t.Errorf("Email: got %q, want empty string", u.Email)
	}
}

func TestExtractUserFromPatient_OfficialNamePreferred(t *testing.T) {
	// When both "usual" and "official" names are present, "official" must win.
	p := &fhir.Patient{
		ID: "patient-004",
		Name: []fhir.HumanName{
			{Use: "usual", Family: "Nickname", Given: []string{"Nick"}},
			{Use: "official", Family: "Registered", Given: []string{"Nicholas", "James"}},
		},
	}

	u := fhir.ExtractUserFromPatient(p, "https://ehr.example.com/fhir")

	assertEqual(t, "LastName", "Registered", u.LastName)
	assertEqual(t, "FirstName", "Nicholas", u.FirstName)
}

func TestExtractUserFromPatient_EHRURLTrailingSlashNormalised(t *testing.T) {
	p := &fhir.Patient{ID: "patient-005"}
	u := fhir.ExtractUserFromPatient(p, "https://ehr.example.com/fhir/")

	if u.EHRURL == "https://ehr.example.com/fhir/" {
		t.Error("trailing slash should be stripped from EHRURL")
	}
	assertEqual(t, "EHRURL", "https://ehr.example.com/fhir", u.EHRURL)
}

// ---------------------------------------------------------------------------
// ExtractUserFromPractitioner tests
// ---------------------------------------------------------------------------

func TestExtractUserFromPractitioner_FullRecord(t *testing.T) {
	p := &fhir.Practitioner{
		ResourceTypeField: "Practitioner",
		ID:                "pract-001",
		Gender:            "female",
		BirthDate:         "1975-09-15",
		Name:              []fhir.HumanName{{Use: "official", Family: "Chen", Given: []string{"Emily"}}},
		Telecom: []fhir.ContactPoint{
			{System: "email", Value: "dr.chen@hospital.org"},
		},
	}

	u := fhir.ExtractUserFromPractitioner(p, "https://ehr.example.com/fhir")

	assertEqual(t, "Role", string(models.RolePractitioner), string(u.Role))
	assertEqual(t, "FHIRResourceType", "Practitioner", u.FHIRResourceType)
	assertEqual(t, "FHIRID", "pract-001", u.FHIRID)
	assertEqual(t, "FirstName", "Emily", u.FirstName)
	assertEqual(t, "LastName", "Chen", u.LastName)
	assertEqual(t, "Email", "dr.chen@hospital.org", u.Email)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func assertEqual(t *testing.T, field, want, got string) {
	t.Helper()
	if got != want {
		t.Errorf("%s: got %q, want %q", field, got, want)
	}
}
