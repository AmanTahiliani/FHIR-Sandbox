package db_test

// clinical_test.go — tests for clinical resource persistence (Observation,
// Condition, DocumentReference, PatientSync).

import (
	"testing"

	"github.com/AmanTahiliani/FHIR-Sandbox/app/models"
)

const (
	testEHRURL    = "https://ehr.example.com/fhir"
	testPatientID = "patient-clinical-001"
)

// ---------------------------------------------------------------------------
// Observation tests
// ---------------------------------------------------------------------------

func TestUpsertObservation_NewAndUpdate(t *testing.T) {
	store := newTestStore(t)

	qty := 98.6
	obs := &models.Observation{
		FHIRID:        "obs-001",
		EHRURL:        testEHRURL,
		PatientFHIRID: testPatientID,
		Status:        "final",
		Category:      "vital-signs",
		CodeText:      "Body Temperature",
		CodeSystem:    "http://loinc.org",
		CodeCode:      "8310-5",
		EffectiveDate: "2024-01-15",
		ValueQuantity: &qty,
		ValueUnit:     "°F",
	}

	id1, err := store.UpsertObservation(obs)
	if err != nil {
		t.Fatalf("initial UpsertObservation: %v", err)
	}
	if id1 == "" {
		t.Fatal("expected non-empty ID")
	}

	// Update: change value and status.
	newQty := 99.1
	obs.ValueQuantity = &newQty
	obs.Status = "amended"
	id2, err := store.UpsertObservation(obs)
	if err != nil {
		t.Fatalf("update UpsertObservation: %v", err)
	}

	// ID must be stable across upserts.
	if id1 != id2 {
		t.Errorf("ID changed on upsert: was %q, got %q", id1, id2)
	}

	// Read back and confirm updated fields.
	rows, err := store.ListObservations(testPatientID, testEHRURL)
	if err != nil {
		t.Fatalf("ListObservations: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(rows))
	}
	got := rows[0]
	if got.Status != "amended" {
		t.Errorf("Status: got %q, want %q", got.Status, "amended")
	}
	if got.ValueQuantity == nil || *got.ValueQuantity != 99.1 {
		t.Errorf("ValueQuantity: got %v, want 99.1", got.ValueQuantity)
	}
}

func TestUpsertObservation_TenantIsolation(t *testing.T) {
	store := newTestStore(t)

	makeObs := func(ehrURL string) *models.Observation {
		return &models.Observation{
			FHIRID:        "obs-shared",
			EHRURL:        ehrURL,
			PatientFHIRID: testPatientID,
			Status:        "final",
		}
	}

	id1, err := store.UpsertObservation(makeObs("https://ehr-a.example.com/fhir"))
	if err != nil {
		t.Fatalf("upsert A: %v", err)
	}
	id2, err := store.UpsertObservation(makeObs("https://ehr-b.example.com/fhir"))
	if err != nil {
		t.Fatalf("upsert B: %v", err)
	}
	if id1 == id2 {
		t.Error("expected different IDs for same fhir_id at different ehr_urls")
	}
}

func TestListObservations_Empty(t *testing.T) {
	store := newTestStore(t)
	rows, err := store.ListObservations("no-such-patient", testEHRURL)
	if err != nil {
		t.Fatalf("ListObservations: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("expected 0 rows, got %d", len(rows))
	}
}

func TestListObservations_OrderedNewestFirst(t *testing.T) {
	store := newTestStore(t)

	for _, item := range []struct {
		id   string
		date string
	}{
		{"obs-a", "2024-01-01"},
		{"obs-b", "2024-06-15"},
		{"obs-c", "2023-12-31"},
	} {
		_, err := store.UpsertObservation(&models.Observation{
			FHIRID:        item.id,
			EHRURL:        testEHRURL,
			PatientFHIRID: testPatientID,
			Status:        "final",
			EffectiveDate: item.date,
		})
		if err != nil {
			t.Fatalf("UpsertObservation %s: %v", item.id, err)
		}
	}

	rows, err := store.ListObservations(testPatientID, testEHRURL)
	if err != nil {
		t.Fatalf("ListObservations: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("expected 3 rows, got %d", len(rows))
	}
	// Newest first: obs-b (Jun) > obs-a (Jan) > obs-c (Dec 2023)
	if rows[0].FHIRID != "obs-b" {
		t.Errorf("first row: got %q, want obs-b", rows[0].FHIRID)
	}
	if rows[2].FHIRID != "obs-c" {
		t.Errorf("last row: got %q, want obs-c", rows[2].FHIRID)
	}
}

// ---------------------------------------------------------------------------
// Condition tests
// ---------------------------------------------------------------------------

func TestUpsertCondition_NewAndUpdate(t *testing.T) {
	store := newTestStore(t)

	cond := &models.Condition{
		FHIRID:             "cond-001",
		EHRURL:             testEHRURL,
		PatientFHIRID:      testPatientID,
		ClinicalStatus:     "active",
		VerificationStatus: "confirmed",
		Category:           "problem-list-item",
		CodeText:           "Hypertension",
		CodeSystem:         "http://snomed.info/sct",
		CodeCode:           "38341003",
		OnsetDate:          "2020-03-01",
		RecordedDate:       "2020-03-05",
	}

	id1, err := store.UpsertCondition(cond)
	if err != nil {
		t.Fatalf("initial UpsertCondition: %v", err)
	}

	// Update clinical status to resolved.
	cond.ClinicalStatus = "resolved"
	id2, err := store.UpsertCondition(cond)
	if err != nil {
		t.Fatalf("update UpsertCondition: %v", err)
	}

	if id1 != id2 {
		t.Errorf("ID changed on upsert: was %q, got %q", id1, id2)
	}

	rows, err := store.ListConditions(testPatientID, testEHRURL)
	if err != nil {
		t.Fatalf("ListConditions: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(rows))
	}
	if rows[0].ClinicalStatus != "resolved" {
		t.Errorf("ClinicalStatus: got %q, want resolved", rows[0].ClinicalStatus)
	}
}

func TestListConditions_Empty(t *testing.T) {
	store := newTestStore(t)
	rows, err := store.ListConditions("no-such-patient", testEHRURL)
	if err != nil {
		t.Fatalf("ListConditions: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("expected 0, got %d", len(rows))
	}
}

// ---------------------------------------------------------------------------
// DocumentReference tests
// ---------------------------------------------------------------------------

func TestUpsertDocumentReference_NewAndUpdate(t *testing.T) {
	store := newTestStore(t)

	doc := &models.DocumentReference{
		FHIRID:        "doc-001",
		EHRURL:        testEHRURL,
		PatientFHIRID: testPatientID,
		Status:        "current",
		DocStatus:     "final",
		TypeText:      "Discharge Summary",
		TypeSystem:    "http://loinc.org",
		TypeCode:      "18842-5",
		Date:          "2024-02-10",
		Description:   "Hospital discharge summary",
		ContentType:   "text/plain",
		ContentURL:    "https://ehr.example.com/fhir/Binary/bin-001",
	}

	id1, err := store.UpsertDocumentReference(doc)
	if err != nil {
		t.Fatalf("UpsertDocumentReference: %v", err)
	}

	// Supersede the document.
	doc.Status = "superseded"
	id2, err := store.UpsertDocumentReference(doc)
	if err != nil {
		t.Fatalf("update UpsertDocumentReference: %v", err)
	}

	if id1 != id2 {
		t.Errorf("ID changed on upsert: was %q, got %q", id1, id2)
	}

	rows, err := store.ListDocumentReferences(testPatientID, testEHRURL)
	if err != nil {
		t.Fatalf("ListDocumentReferences: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 doc, got %d", len(rows))
	}
	if rows[0].Status != "superseded" {
		t.Errorf("Status: got %q, want superseded", rows[0].Status)
	}
}

func TestListDocumentReferences_Empty(t *testing.T) {
	store := newTestStore(t)
	rows, err := store.ListDocumentReferences("no-such-patient", testEHRURL)
	if err != nil {
		t.Fatalf("ListDocumentReferences: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("expected 0, got %d", len(rows))
	}
}

// ---------------------------------------------------------------------------
// MedicationRequest tests
// ---------------------------------------------------------------------------

func TestUpsertMedicationRequest_NewAndUpdate(t *testing.T) {
	store := newTestStore(t)

	med := &models.MedicationRequest{
		FHIRID:           "med-001",
		EHRURL:           testEHRURL,
		PatientFHIRID:    testPatientID,
		Status:           "active",
		Intent:           "order",
		MedCodeText:      "Metformin 500mg",
		MedCodeSystem:    "http://www.nlm.nih.gov/research/umls/rxnorm",
		MedCodeCode:      "860975",
		AuthoredOn:       "2024-01-10",
		RequesterDisplay: "Dr. Smith",
		DosageText:       "1 tablet twice daily",
	}

	id1, err := store.UpsertMedicationRequest(med)
	if err != nil {
		t.Fatalf("initial UpsertMedicationRequest: %v", err)
	}
	if id1 == "" {
		t.Fatal("expected non-empty ID")
	}

	med.Status = "stopped"
	id2, err := store.UpsertMedicationRequest(med)
	if err != nil {
		t.Fatalf("update UpsertMedicationRequest: %v", err)
	}
	if id1 != id2 {
		t.Errorf("ID changed on upsert: was %q, got %q", id1, id2)
	}

	rows, err := store.ListMedicationRequests(testPatientID, testEHRURL)
	if err != nil {
		t.Fatalf("ListMedicationRequests: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 med, got %d", len(rows))
	}
	if rows[0].Status != "stopped" {
		t.Errorf("Status: got %q, want stopped", rows[0].Status)
	}
}

func TestListMedicationRequests_Empty(t *testing.T) {
	store := newTestStore(t)
	rows, err := store.ListMedicationRequests("no-such-patient", testEHRURL)
	if err != nil {
		t.Fatalf("ListMedicationRequests: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("expected 0, got %d", len(rows))
	}
}

// ---------------------------------------------------------------------------
// AllergyIntolerance tests (including reaction fields)
// ---------------------------------------------------------------------------

func TestUpsertAllergyIntolerance_WithReaction(t *testing.T) {
	store := newTestStore(t)

	allergy := &models.AllergyIntolerance{
		FHIRID:                "allergy-001",
		EHRURL:                testEHRURL,
		PatientFHIRID:         testPatientID,
		ClinicalStatus:        "active",
		VerificationStatus:    "confirmed",
		Type:                  "allergy",
		Category:              "medication",
		Criticality:           "high",
		CodeText:              "Penicillin",
		CodeSystem:            "http://www.nlm.nih.gov/research/umls/rxnorm",
		CodeCode:              "7980",
		RecordedDate:          "2018-05-01",
		ReactionSeverity:      "severe",
		ReactionManifestation: "Anaphylaxis",
	}

	id1, err := store.UpsertAllergyIntolerance(allergy)
	if err != nil {
		t.Fatalf("initial UpsertAllergyIntolerance: %v", err)
	}
	if id1 == "" {
		t.Fatal("expected non-empty ID")
	}

	// Update reaction.
	allergy.ReactionSeverity = "moderate"
	allergy.ReactionManifestation = "Rash"
	id2, err := store.UpsertAllergyIntolerance(allergy)
	if err != nil {
		t.Fatalf("update UpsertAllergyIntolerance: %v", err)
	}
	if id1 != id2 {
		t.Errorf("ID changed on upsert: was %q, got %q", id1, id2)
	}

	rows, err := store.ListAllergyIntolerances(testPatientID, testEHRURL)
	if err != nil {
		t.Fatalf("ListAllergyIntolerances: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 allergy, got %d", len(rows))
	}
	got := rows[0]
	if got.ReactionSeverity != "moderate" {
		t.Errorf("ReactionSeverity: got %q, want moderate", got.ReactionSeverity)
	}
	if got.ReactionManifestation != "Rash" {
		t.Errorf("ReactionManifestation: got %q, want Rash", got.ReactionManifestation)
	}
}

func TestUpsertAllergyIntolerance_NoReaction(t *testing.T) {
	store := newTestStore(t)

	allergy := &models.AllergyIntolerance{
		FHIRID:         "allergy-no-rxn",
		EHRURL:         testEHRURL,
		PatientFHIRID:  testPatientID,
		ClinicalStatus: "active",
		CodeText:       "Latex",
	}
	_, err := store.UpsertAllergyIntolerance(allergy)
	if err != nil {
		t.Fatalf("UpsertAllergyIntolerance (no reaction): %v", err)
	}

	rows, err := store.ListAllergyIntolerances(testPatientID, testEHRURL)
	if err != nil {
		t.Fatalf("ListAllergyIntolerances: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1, got %d", len(rows))
	}
	if rows[0].ReactionSeverity != "" {
		t.Errorf("expected empty ReactionSeverity, got %q", rows[0].ReactionSeverity)
	}
}

// ---------------------------------------------------------------------------
// Immunization tests
// ---------------------------------------------------------------------------

func TestUpsertImmunization_NewAndUpdate(t *testing.T) {
	store := newTestStore(t)

	imm := &models.Immunization{
		FHIRID:         "imm-001",
		EHRURL:         testEHRURL,
		PatientFHIRID:  testPatientID,
		Status:         "completed",
		VaccineText:    "Influenza, seasonal",
		VaccineSystem:  "http://hl7.org/fhir/sid/cvx",
		VaccineCode:    "141",
		OccurrenceDate: "2023-10-01",
		PrimarySource:  true,
		LotNumber:      "LOT123",
	}

	id1, err := store.UpsertImmunization(imm)
	if err != nil {
		t.Fatalf("initial UpsertImmunization: %v", err)
	}
	if id1 == "" {
		t.Fatal("expected non-empty ID")
	}

	imm.LotNumber = "LOT456"
	id2, err := store.UpsertImmunization(imm)
	if err != nil {
		t.Fatalf("update UpsertImmunization: %v", err)
	}
	if id1 != id2 {
		t.Errorf("ID changed on upsert: was %q, got %q", id1, id2)
	}

	rows, err := store.ListImmunizations(testPatientID, testEHRURL)
	if err != nil {
		t.Fatalf("ListImmunizations: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 immunization, got %d", len(rows))
	}
	if rows[0].LotNumber != "LOT456" {
		t.Errorf("LotNumber: got %q, want LOT456", rows[0].LotNumber)
	}
	if !rows[0].PrimarySource {
		t.Error("PrimarySource should be true")
	}
}

func TestListImmunizations_Empty(t *testing.T) {
	store := newTestStore(t)
	rows, err := store.ListImmunizations("no-such-patient", testEHRURL)
	if err != nil {
		t.Fatalf("ListImmunizations: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("expected 0, got %d", len(rows))
	}
}

func TestListImmunizations_OrderedNewestFirst(t *testing.T) {
	store := newTestStore(t)

	for _, item := range []struct {
		id   string
		date string
	}{
		{"imm-a", "2022-09-01"},
		{"imm-b", "2023-10-15"},
		{"imm-c", "2021-03-01"},
	} {
		_, err := store.UpsertImmunization(&models.Immunization{
			FHIRID:         item.id,
			EHRURL:         testEHRURL,
			PatientFHIRID:  testPatientID,
			Status:         "completed",
			OccurrenceDate: item.date,
		})
		if err != nil {
			t.Fatalf("UpsertImmunization %s: %v", item.id, err)
		}
	}

	rows, err := store.ListImmunizations(testPatientID, testEHRURL)
	if err != nil {
		t.Fatalf("ListImmunizations: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("expected 3, got %d", len(rows))
	}
	if rows[0].FHIRID != "imm-b" {
		t.Errorf("first: got %q, want imm-b", rows[0].FHIRID)
	}
	if rows[2].FHIRID != "imm-c" {
		t.Errorf("last: got %q, want imm-c", rows[2].FHIRID)
	}
}

// ---------------------------------------------------------------------------
// Procedure tests
// ---------------------------------------------------------------------------

func TestUpsertProcedure_NewAndUpdate(t *testing.T) {
	store := newTestStore(t)

	proc := &models.Procedure{
		FHIRID:        "proc-001",
		EHRURL:        testEHRURL,
		PatientFHIRID: testPatientID,
		Status:        "completed",
		CodeText:      "Appendectomy",
		CodeSystem:    "http://snomed.info/sct",
		CodeCode:      "80146002",
		PerformedDate: "2019-06-15",
		ReasonText:    "Acute appendicitis",
		Outcome:       "Successful procedure",
	}

	id1, err := store.UpsertProcedure(proc)
	if err != nil {
		t.Fatalf("initial UpsertProcedure: %v", err)
	}
	if id1 == "" {
		t.Fatal("expected non-empty ID")
	}

	proc.Outcome = "Procedure completed without complications"
	id2, err := store.UpsertProcedure(proc)
	if err != nil {
		t.Fatalf("update UpsertProcedure: %v", err)
	}
	if id1 != id2 {
		t.Errorf("ID changed on upsert: was %q, got %q", id1, id2)
	}

	rows, err := store.ListProcedures(testPatientID, testEHRURL)
	if err != nil {
		t.Fatalf("ListProcedures: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 procedure, got %d", len(rows))
	}
	if rows[0].Outcome != "Procedure completed without complications" {
		t.Errorf("Outcome: got %q", rows[0].Outcome)
	}
}

func TestListProcedures_Empty(t *testing.T) {
	store := newTestStore(t)
	rows, err := store.ListProcedures("no-such-patient", testEHRURL)
	if err != nil {
		t.Fatalf("ListProcedures: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("expected 0, got %d", len(rows))
	}
}

// ---------------------------------------------------------------------------
// Encounter tests
// ---------------------------------------------------------------------------

func TestUpsertEncounter_NewAndUpdate(t *testing.T) {
	store := newTestStore(t)

	enc := &models.Encounter{
		FHIRID:        "enc-001",
		EHRURL:        testEHRURL,
		PatientFHIRID: testPatientID,
		Status:        "finished",
		Class:         "AMB",
		TypeText:      "Office visit",
		PeriodStart:   "2024-03-10",
		PeriodEnd:     "2024-03-10",
		ReasonText:    "Annual physical",
	}

	id1, err := store.UpsertEncounter(enc)
	if err != nil {
		t.Fatalf("initial UpsertEncounter: %v", err)
	}
	if id1 == "" {
		t.Fatal("expected non-empty ID")
	}

	enc.Status = "cancelled"
	id2, err := store.UpsertEncounter(enc)
	if err != nil {
		t.Fatalf("update UpsertEncounter: %v", err)
	}
	if id1 != id2 {
		t.Errorf("ID changed on upsert: was %q, got %q", id1, id2)
	}

	rows, err := store.ListEncounters(testPatientID, testEHRURL)
	if err != nil {
		t.Fatalf("ListEncounters: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 encounter, got %d", len(rows))
	}
	if rows[0].Status != "cancelled" {
		t.Errorf("Status: got %q, want cancelled", rows[0].Status)
	}
	if rows[0].Class != "AMB" {
		t.Errorf("Class: got %q, want AMB", rows[0].Class)
	}
}

func TestListEncounters_Empty(t *testing.T) {
	store := newTestStore(t)
	rows, err := store.ListEncounters("no-such-patient", testEHRURL)
	if err != nil {
		t.Fatalf("ListEncounters: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("expected 0, got %d", len(rows))
	}
}

func TestListEncounters_OrderedNewestFirst(t *testing.T) {
	store := newTestStore(t)

	for _, item := range []struct {
		id    string
		start string
	}{
		{"enc-a", "2023-01-01"},
		{"enc-b", "2024-06-01"},
		{"enc-c", "2022-12-01"},
	} {
		_, err := store.UpsertEncounter(&models.Encounter{
			FHIRID:        item.id,
			EHRURL:        testEHRURL,
			PatientFHIRID: testPatientID,
			Status:        "finished",
			PeriodStart:   item.start,
		})
		if err != nil {
			t.Fatalf("UpsertEncounter %s: %v", item.id, err)
		}
	}

	rows, err := store.ListEncounters(testPatientID, testEHRURL)
	if err != nil {
		t.Fatalf("ListEncounters: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("expected 3, got %d", len(rows))
	}
	if rows[0].FHIRID != "enc-b" {
		t.Errorf("first: got %q, want enc-b", rows[0].FHIRID)
	}
	if rows[2].FHIRID != "enc-c" {
		t.Errorf("last: got %q, want enc-c", rows[2].FHIRID)
	}
}

// ---------------------------------------------------------------------------
// PatientSync tests
// ---------------------------------------------------------------------------

func TestRecordAndLatestSync(t *testing.T) {
	store := newTestStore(t)

	// No sync yet.
	ps, err := store.LatestSync(testPatientID, testEHRURL)
	if err != nil {
		t.Fatalf("LatestSync (empty): %v", err)
	}
	if ps != nil {
		t.Errorf("expected nil before any sync, got %+v", ps)
	}

	// Record first sync.
	recorded, err := store.RecordSync(testPatientID, testEHRURL, 10, 3, 1)
	if err != nil {
		t.Fatalf("RecordSync: %v", err)
	}
	if recorded.ID == "" {
		t.Fatal("expected non-empty ID")
	}
	if recorded.ObsCount != 10 || recorded.CondCount != 3 || recorded.DocCount != 1 {
		t.Errorf("counts wrong: %+v", recorded)
	}

	// LatestSync should now return that record.
	latest, err := store.LatestSync(testPatientID, testEHRURL)
	if err != nil {
		t.Fatalf("LatestSync: %v", err)
	}
	if latest == nil {
		t.Fatal("expected non-nil latest sync")
	}
	if latest.ID != recorded.ID {
		t.Errorf("ID mismatch: got %q, want %q", latest.ID, recorded.ID)
	}

	// Record a second sync with higher counts; LatestSync must return the newer one.
	_, err = store.RecordSync(testPatientID, testEHRURL, 20, 5, 2)
	if err != nil {
		t.Fatalf("RecordSync second: %v", err)
	}

	latest2, err := store.LatestSync(testPatientID, testEHRURL)
	if err != nil {
		t.Fatalf("LatestSync second: %v", err)
	}
	if latest2.ObsCount != 20 {
		t.Errorf("expected ObsCount 20 from latest, got %d", latest2.ObsCount)
	}
}

func TestLatestSync_TenantIsolation(t *testing.T) {
	store := newTestStore(t)

	_, err := store.RecordSync(testPatientID, "https://ehr-a.example.com/fhir", 5, 1, 0)
	if err != nil {
		t.Fatalf("RecordSync EHR-A: %v", err)
	}

	// Querying for a different EHR URL should return nil.
	ps, err := store.LatestSync(testPatientID, "https://ehr-b.example.com/fhir")
	if err != nil {
		t.Fatalf("LatestSync EHR-B: %v", err)
	}
	if ps != nil {
		t.Errorf("expected nil for different EHR URL, got %+v", ps)
	}
}
