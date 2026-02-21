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
// ExtractAllergyIntolerance tests
// ---------------------------------------------------------------------------

func TestExtractAllergyIntolerance_WithReaction(t *testing.T) {
	a := &fhir.AllergyIntolerance{
		ID: "allergy-001",
		Code: fhir.CodeableConcept{
			Text:   "Penicillin",
			Coding: []fhir.Coding{{System: "http://rxnorm", Code: "7980"}},
		},
		ClinicalStatus:     fhir.CodeableConcept{Coding: []fhir.Coding{{Code: "active"}}},
		VerificationStatus: fhir.CodeableConcept{Coding: []fhir.Coding{{Code: "confirmed"}}},
		Criticality:        "high",
		RecordedDate:       "2018-05-01",
		Reaction: []fhir.AllergyReaction{
			{
				Severity: "severe",
				Manifestation: []fhir.CodeableConcept{
					{Text: "Anaphylaxis"},
				},
			},
		},
	}

	m := fhir.ExtractAllergyIntolerance(a, "patient-001", "https://ehr.example.com/fhir")

	assertEqual(t, "ReactionSeverity", "severe", m.ReactionSeverity)
	assertEqual(t, "ReactionManifestation", "Anaphylaxis", m.ReactionManifestation)
	assertEqual(t, "ClinicalStatus", "active", m.ClinicalStatus)
	assertEqual(t, "Criticality", "high", m.Criticality)
}

func TestExtractAllergyIntolerance_NoReaction(t *testing.T) {
	a := &fhir.AllergyIntolerance{
		ID:   "allergy-002",
		Code: fhir.CodeableConcept{Text: "Latex"},
	}

	m := fhir.ExtractAllergyIntolerance(a, "patient-001", "https://ehr.example.com/fhir")

	if m.ReactionSeverity != "" {
		t.Errorf("ReactionSeverity: expected empty, got %q", m.ReactionSeverity)
	}
	if m.ReactionManifestation != "" {
		t.Errorf("ReactionManifestation: expected empty, got %q", m.ReactionManifestation)
	}
}

// ---------------------------------------------------------------------------
// ExtractImmunization tests
// ---------------------------------------------------------------------------

func TestExtractImmunization_Full(t *testing.T) {
	imm := &fhir.Immunization{
		ID:     "imm-001",
		Status: "completed",
		VaccineCode: fhir.CodeableConcept{
			Text:   "Influenza, seasonal",
			Coding: []fhir.Coding{{System: "http://hl7.org/fhir/sid/cvx", Code: "141"}},
		},
		OccurrenceDateTime: "2023-10-01",
		PrimarySource:      true,
		LotNumber:          "LOT123",
	}

	m := fhir.ExtractImmunization(imm, "patient-001", "https://ehr.example.com/fhir")

	assertEqual(t, "FHIRID", "imm-001", m.FHIRID)
	assertEqual(t, "Status", "completed", m.Status)
	assertEqual(t, "VaccineText", "Influenza, seasonal", m.VaccineText)
	assertEqual(t, "VaccineCode", "141", m.VaccineCode)
	assertEqual(t, "OccurrenceDate", "2023-10-01", m.OccurrenceDate)
	assertEqual(t, "LotNumber", "LOT123", m.LotNumber)
	if !m.PrimarySource {
		t.Error("PrimarySource should be true")
	}
}

// ---------------------------------------------------------------------------
// ExtractProcedure tests
// ---------------------------------------------------------------------------

func TestExtractProcedure_WithDatetime(t *testing.T) {
	p := &fhir.Procedure{
		ID:     "proc-001",
		Status: "completed",
		Code: fhir.CodeableConcept{
			Text:   "Appendectomy",
			Coding: []fhir.Coding{{System: "http://snomed.info/sct", Code: "80146002"}},
		},
		PerformedDateTime: "2019-06-15",
		ReasonCode: []fhir.CodeableConcept{
			{Text: "Acute appendicitis"},
		},
		Outcome: fhir.CodeableConcept{Text: "Successful"},
	}

	m := fhir.ExtractProcedure(p, "patient-001", "https://ehr.example.com/fhir")

	assertEqual(t, "FHIRID", "proc-001", m.FHIRID)
	assertEqual(t, "Status", "completed", m.Status)
	assertEqual(t, "CodeText", "Appendectomy", m.CodeText)
	assertEqual(t, "PerformedDate", "2019-06-15", m.PerformedDate)
	assertEqual(t, "ReasonText", "Acute appendicitis", m.ReasonText)
	assertEqual(t, "Outcome", "Successful", m.Outcome)
}

func TestExtractProcedure_FallsBackToPeriodStart(t *testing.T) {
	p := &fhir.Procedure{
		ID:     "proc-002",
		Status: "completed",
		Code:   fhir.CodeableConcept{Text: "Colonoscopy"},
		PerformedPeriod: &fhir.Period{
			Start: "2022-03-01",
			End:   "2022-03-01",
		},
	}

	m := fhir.ExtractProcedure(p, "patient-001", "https://ehr.example.com/fhir")
	assertEqual(t, "PerformedDate (from period)", "2022-03-01", m.PerformedDate)
}

// ---------------------------------------------------------------------------
// ExtractEncounter tests
// ---------------------------------------------------------------------------

func TestExtractEncounter_Full(t *testing.T) {
	e := &fhir.Encounter{
		ID:     "enc-001",
		Status: "finished",
		Class:  fhir.EncounterClass{Code: "AMB"},
		Type: []fhir.CodeableConcept{
			{Text: "Office visit"},
		},
		Period: &fhir.Period{Start: "2024-03-10", End: "2024-03-10"},
		ReasonCode: []fhir.CodeableConcept{
			{Text: "Annual physical"},
		},
	}

	m := fhir.ExtractEncounter(e, "patient-001", "https://ehr.example.com/fhir")

	assertEqual(t, "FHIRID", "enc-001", m.FHIRID)
	assertEqual(t, "Status", "finished", m.Status)
	assertEqual(t, "Class", "AMB", m.Class)
	assertEqual(t, "TypeText", "Office visit", m.TypeText)
	assertEqual(t, "PeriodStart", "2024-03-10", m.PeriodStart)
	assertEqual(t, "PeriodEnd", "2024-03-10", m.PeriodEnd)
	assertEqual(t, "ReasonText", "Annual physical", m.ReasonText)
}

// ---------------------------------------------------------------------------
// ExtractCondition category code tests
// ---------------------------------------------------------------------------

func TestExtractCondition_UsesCategoryCode(t *testing.T) {
	c := &fhir.Condition{
		ID: "cond-001",
		Code: fhir.CodeableConcept{
			Text:   "Hypertension",
			Coding: []fhir.Coding{{System: "http://snomed.info/sct", Code: "38341003"}},
		},
		ClinicalStatus:     fhir.CodeableConcept{Coding: []fhir.Coding{{Code: "active"}}},
		VerificationStatus: fhir.CodeableConcept{Coding: []fhir.Coding{{Code: "confirmed"}}},
		Category: []fhir.CodeableConcept{
			{
				Coding: []fhir.Coding{{System: "http://terminology.hl7.org/CodeSystem/condition-category", Code: "problem-list-item", Display: "Problem List Item"}},
				Text:   "Problem List Item",
			},
		},
	}

	m := fhir.ExtractCondition(c, "patient-001", "https://ehr.example.com/fhir")

	// Must store the code ("problem-list-item"), not the display text ("Problem List Item").
	assertEqual(t, "Category code", "problem-list-item", m.Category)
}

// ---------------------------------------------------------------------------
// ExtractUSCoreRace/Ethnicity tests
// ---------------------------------------------------------------------------

func TestExtractUSCoreRaceText(t *testing.T) {
	p := &fhir.Patient{
		ID: "patient-race",
		Extension: []fhir.Extension{
			{
				URL: "http://hl7.org/fhir/us/core/StructureDefinition/us-core-race",
				Extension: []fhir.Extension{
					{URL: "text", ValueString: "White"},
					{URL: "ombCategory", ValueCoding: &fhir.Coding{Code: "2106-3", Display: "White"}},
				},
			},
		},
	}

	got := fhir.ExtractUSCoreRaceText(p)
	if got != "White" {
		t.Errorf("ExtractUSCoreRaceText: got %q, want White", got)
	}
}

func TestExtractUSCoreEthnicityText(t *testing.T) {
	p := &fhir.Patient{
		ID: "patient-eth",
		Extension: []fhir.Extension{
			{
				URL: "http://hl7.org/fhir/us/core/StructureDefinition/us-core-ethnicity",
				Extension: []fhir.Extension{
					{URL: "text", ValueString: "Not Hispanic or Latino"},
				},
			},
		},
	}

	got := fhir.ExtractUSCoreEthnicityText(p)
	if got != "Not Hispanic or Latino" {
		t.Errorf("ExtractUSCoreEthnicityText: got %q, want Not Hispanic or Latino", got)
	}
}

func TestExtractUSCoreRaceText_Missing(t *testing.T) {
	p := &fhir.Patient{ID: "patient-no-race"}
	if got := fhir.ExtractUSCoreRaceText(p); got != "" {
		t.Errorf("expected empty string for patient without race extension, got %q", got)
	}
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
