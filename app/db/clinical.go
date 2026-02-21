// clinical.go provides persistence operations for FHIR clinical resources:
// Observation, Condition, DocumentReference, and PatientSync.
//
// All upsert methods use (fhir_id, ehr_url) as the natural deduplication key,
// matching the same pattern used for users. On conflict the stored row is
// overwritten with the latest data from the EHR and synced_at is updated.
package db

import (
	"fmt"
	"time"

	"github.com/AmanTahiliani/FHIR-Sandbox/app/models"
	"github.com/google/uuid"
)

// ---------------------------------------------------------------------------
// Observation
// ---------------------------------------------------------------------------

// UpsertObservation inserts or replaces an Observation record keyed on
// (fhir_id, ehr_url). Returns the internal UUID.
func (s *Store) UpsertObservation(o *models.Observation) (string, error) {
	now := time.Now().UTC()

	var existingID string
	err := s.db.QueryRow(
		`SELECT id FROM observations WHERE fhir_id = ? AND ehr_url = ?`,
		o.FHIRID, o.EHRURL,
	).Scan(&existingID)

	if err == nil {
		_, err = s.db.Exec(`
			UPDATE observations SET
				patient_fhir_id    = ?,
				status             = ?,
				category           = ?,
				code_text          = ?,
				code_system        = ?,
				code_code          = ?,
				effective_date     = ?,
				value_quantity     = ?,
				value_unit         = ?,
				value_string       = ?,
				interpretation     = ?,
				ref_range_low      = ?,
				ref_range_high     = ?,
				synced_at          = ?
			WHERE id = ?`,
			o.PatientFHIRID, o.Status, o.Category,
			o.CodeText, o.CodeSystem, o.CodeCode,
			o.EffectiveDate, o.ValueQuantity, o.ValueUnit, o.ValueString,
			o.Interpretation, o.ReferenceRangeLow, o.ReferenceRangeHigh,
			now, existingID,
		)
		if err != nil {
			return "", fmt.Errorf("db: update observation %s: %w", existingID, err)
		}
		return existingID, nil
	}

	id := uuid.NewString()
	_, err = s.db.Exec(`
		INSERT INTO observations (
			id, fhir_id, ehr_url, patient_fhir_id, status, category,
			code_text, code_system, code_code, effective_date,
			value_quantity, value_unit, value_string, interpretation,
			ref_range_low, ref_range_high, synced_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, o.FHIRID, o.EHRURL, o.PatientFHIRID, o.Status, o.Category,
		o.CodeText, o.CodeSystem, o.CodeCode, o.EffectiveDate,
		o.ValueQuantity, o.ValueUnit, o.ValueString, o.Interpretation,
		o.ReferenceRangeLow, o.ReferenceRangeHigh, now,
	)
	if err != nil {
		return "", fmt.Errorf("db: insert observation fhir_id=%s: %w", o.FHIRID, err)
	}
	return id, nil
}

// ListObservations returns all Observations for the given patient, newest first.
func (s *Store) ListObservations(patientFHIRID, ehrURL string) ([]models.Observation, error) {
	rows, err := s.db.Query(`
		SELECT id, fhir_id, ehr_url, patient_fhir_id, status, category,
		       code_text, code_system, code_code, effective_date,
		       value_quantity, value_unit, value_string, interpretation,
		       ref_range_low, ref_range_high, synced_at
		FROM observations
		WHERE patient_fhir_id = ? AND ehr_url = ?
		ORDER BY effective_date DESC`,
		patientFHIRID, ehrURL,
	)
	if err != nil {
		return nil, fmt.Errorf("db: list observations: %w", err)
	}
	defer rows.Close()

	var out []models.Observation
	for rows.Next() {
		var o models.Observation
		if err := rows.Scan(
			&o.ID, &o.FHIRID, &o.EHRURL, &o.PatientFHIRID, &o.Status, &o.Category,
			&o.CodeText, &o.CodeSystem, &o.CodeCode, &o.EffectiveDate,
			&o.ValueQuantity, &o.ValueUnit, &o.ValueString, &o.Interpretation,
			&o.ReferenceRangeLow, &o.ReferenceRangeHigh, &o.SyncedAt,
		); err != nil {
			return nil, fmt.Errorf("db: scan observation: %w", err)
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// Condition
// ---------------------------------------------------------------------------

// UpsertCondition inserts or updates a Condition record keyed on (fhir_id, ehr_url).
func (s *Store) UpsertCondition(c *models.Condition) (string, error) {
	now := time.Now().UTC()

	var existingID string
	err := s.db.QueryRow(
		`SELECT id FROM conditions WHERE fhir_id = ? AND ehr_url = ?`,
		c.FHIRID, c.EHRURL,
	).Scan(&existingID)

	if err == nil {
		_, err = s.db.Exec(`
			UPDATE conditions SET
				patient_fhir_id     = ?,
				clinical_status     = ?,
				verification_status = ?,
				category            = ?,
				code_text           = ?,
				code_system         = ?,
				code_code           = ?,
				onset_date          = ?,
				recorded_date       = ?,
				synced_at           = ?
			WHERE id = ?`,
			c.PatientFHIRID, c.ClinicalStatus, c.VerificationStatus,
			c.Category, c.CodeText, c.CodeSystem, c.CodeCode,
			c.OnsetDate, c.RecordedDate, now, existingID,
		)
		if err != nil {
			return "", fmt.Errorf("db: update condition %s: %w", existingID, err)
		}
		return existingID, nil
	}

	id := uuid.NewString()
	_, err = s.db.Exec(`
		INSERT INTO conditions (
			id, fhir_id, ehr_url, patient_fhir_id,
			clinical_status, verification_status, category,
			code_text, code_system, code_code,
			onset_date, recorded_date, synced_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, c.FHIRID, c.EHRURL, c.PatientFHIRID,
		c.ClinicalStatus, c.VerificationStatus, c.Category,
		c.CodeText, c.CodeSystem, c.CodeCode,
		c.OnsetDate, c.RecordedDate, now,
	)
	if err != nil {
		return "", fmt.Errorf("db: insert condition fhir_id=%s: %w", c.FHIRID, err)
	}
	return id, nil
}

// ListConditions returns all Conditions for the given patient, newest first.
func (s *Store) ListConditions(patientFHIRID, ehrURL string) ([]models.Condition, error) {
	rows, err := s.db.Query(`
		SELECT id, fhir_id, ehr_url, patient_fhir_id,
		       clinical_status, verification_status, category,
		       code_text, code_system, code_code,
		       onset_date, recorded_date, synced_at
		FROM conditions
		WHERE patient_fhir_id = ? AND ehr_url = ?
		ORDER BY recorded_date DESC`,
		patientFHIRID, ehrURL,
	)
	if err != nil {
		return nil, fmt.Errorf("db: list conditions: %w", err)
	}
	defer rows.Close()

	var out []models.Condition
	for rows.Next() {
		var c models.Condition
		if err := rows.Scan(
			&c.ID, &c.FHIRID, &c.EHRURL, &c.PatientFHIRID,
			&c.ClinicalStatus, &c.VerificationStatus, &c.Category,
			&c.CodeText, &c.CodeSystem, &c.CodeCode,
			&c.OnsetDate, &c.RecordedDate, &c.SyncedAt,
		); err != nil {
			return nil, fmt.Errorf("db: scan condition: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// DocumentReference
// ---------------------------------------------------------------------------

// UpsertDocumentReference inserts or updates a DocumentReference record.
func (s *Store) UpsertDocumentReference(d *models.DocumentReference) (string, error) {
	now := time.Now().UTC()

	var existingID string
	err := s.db.QueryRow(
		`SELECT id FROM document_references WHERE fhir_id = ? AND ehr_url = ?`,
		d.FHIRID, d.EHRURL,
	).Scan(&existingID)

	if err == nil {
		_, err = s.db.Exec(`
			UPDATE document_references SET
				patient_fhir_id = ?,
				status          = ?,
				doc_status      = ?,
				type_text       = ?,
				type_system     = ?,
				type_code       = ?,
				category        = ?,
				date            = ?,
				description     = ?,
				content_type    = ?,
				content_url     = ?,
				content_data    = ?,
				synced_at       = ?
			WHERE id = ?`,
			d.PatientFHIRID, d.Status, d.DocStatus,
			d.TypeText, d.TypeSystem, d.TypeCode,
			d.Category, d.Date, d.Description,
			d.ContentType, d.ContentURL, d.ContentData,
			now, existingID,
		)
		if err != nil {
			return "", fmt.Errorf("db: update document_reference %s: %w", existingID, err)
		}
		return existingID, nil
	}

	id := uuid.NewString()
	_, err = s.db.Exec(`
		INSERT INTO document_references (
			id, fhir_id, ehr_url, patient_fhir_id,
			status, doc_status, type_text, type_system, type_code,
			category, date, description,
			content_type, content_url, content_data, synced_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, d.FHIRID, d.EHRURL, d.PatientFHIRID,
		d.Status, d.DocStatus, d.TypeText, d.TypeSystem, d.TypeCode,
		d.Category, d.Date, d.Description,
		d.ContentType, d.ContentURL, d.ContentData, now,
	)
	if err != nil {
		return "", fmt.Errorf("db: insert document_reference fhir_id=%s: %w", d.FHIRID, err)
	}
	return id, nil
}

// ListDocumentReferences returns all DocumentReferences for the given patient,
// newest first.
func (s *Store) ListDocumentReferences(patientFHIRID, ehrURL string) ([]models.DocumentReference, error) {
	rows, err := s.db.Query(`
		SELECT id, fhir_id, ehr_url, patient_fhir_id,
		       status, doc_status, type_text, type_system, type_code,
		       category, date, description,
		       content_type, content_url, content_data, synced_at
		FROM document_references
		WHERE patient_fhir_id = ? AND ehr_url = ?
		ORDER BY date DESC`,
		patientFHIRID, ehrURL,
	)
	if err != nil {
		return nil, fmt.Errorf("db: list document_references: %w", err)
	}
	defer rows.Close()

	var out []models.DocumentReference
	for rows.Next() {
		var d models.DocumentReference
		if err := rows.Scan(
			&d.ID, &d.FHIRID, &d.EHRURL, &d.PatientFHIRID,
			&d.Status, &d.DocStatus, &d.TypeText, &d.TypeSystem, &d.TypeCode,
			&d.Category, &d.Date, &d.Description,
			&d.ContentType, &d.ContentURL, &d.ContentData, &d.SyncedAt,
		); err != nil {
			return nil, fmt.Errorf("db: scan document_reference: %w", err)
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// MedicationRequest
// ---------------------------------------------------------------------------

// UpsertMedicationRequest inserts or updates a MedicationRequest record keyed on (fhir_id, ehr_url).
func (s *Store) UpsertMedicationRequest(m *models.MedicationRequest) (string, error) {
	now := time.Now().UTC()

	var existingID string
	err := s.db.QueryRow(
		`SELECT id FROM medication_requests WHERE fhir_id = ? AND ehr_url = ?`,
		m.FHIRID, m.EHRURL,
	).Scan(&existingID)

	if err == nil {
		_, err = s.db.Exec(`
			UPDATE medication_requests SET
				patient_fhir_id  = ?,
				status           = ?,
				intent           = ?,
				med_code_text    = ?,
				med_code_system  = ?,
				med_code_code    = ?,
				authored_on      = ?,
				requester_display = ?,
				dosage_text      = ?,
				synced_at        = ?
			WHERE id = ?`,
			m.PatientFHIRID, m.Status, m.Intent,
			m.MedCodeText, m.MedCodeSystem, m.MedCodeCode,
			m.AuthoredOn, m.RequesterDisplay, m.DosageText,
			now, existingID,
		)
		if err != nil {
			return "", fmt.Errorf("db: update medication_request %s: %w", existingID, err)
		}
		return existingID, nil
	}

	id := uuid.NewString()
	_, err = s.db.Exec(`
		INSERT INTO medication_requests (
			id, fhir_id, ehr_url, patient_fhir_id,
			status, intent, med_code_text, med_code_system, med_code_code,
			authored_on, requester_display, dosage_text, synced_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, m.FHIRID, m.EHRURL, m.PatientFHIRID,
		m.Status, m.Intent, m.MedCodeText, m.MedCodeSystem, m.MedCodeCode,
		m.AuthoredOn, m.RequesterDisplay, m.DosageText, now,
	)
	if err != nil {
		return "", fmt.Errorf("db: insert medication_request fhir_id=%s: %w", m.FHIRID, err)
	}
	return id, nil
}

// ListMedicationRequests returns all MedicationRequests for the given patient, newest first.
func (s *Store) ListMedicationRequests(patientFHIRID, ehrURL string) ([]models.MedicationRequest, error) {
	rows, err := s.db.Query(`
		SELECT id, fhir_id, ehr_url, patient_fhir_id,
		       status, intent, med_code_text, med_code_system, med_code_code,
		       authored_on, requester_display, dosage_text, synced_at
		FROM medication_requests
		WHERE patient_fhir_id = ? AND ehr_url = ?
		ORDER BY authored_on DESC`,
		patientFHIRID, ehrURL,
	)
	if err != nil {
		return nil, fmt.Errorf("db: list medication_requests: %w", err)
	}
	defer rows.Close()

	var out []models.MedicationRequest
	for rows.Next() {
		var m models.MedicationRequest
		if err := rows.Scan(
			&m.ID, &m.FHIRID, &m.EHRURL, &m.PatientFHIRID,
			&m.Status, &m.Intent, &m.MedCodeText, &m.MedCodeSystem, &m.MedCodeCode,
			&m.AuthoredOn, &m.RequesterDisplay, &m.DosageText, &m.SyncedAt,
		); err != nil {
			return nil, fmt.Errorf("db: scan medication_request: %w", err)
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// AllergyIntolerance
// ---------------------------------------------------------------------------

// UpsertAllergyIntolerance inserts or updates an AllergyIntolerance record keyed on (fhir_id, ehr_url).
func (s *Store) UpsertAllergyIntolerance(a *models.AllergyIntolerance) (string, error) {
	now := time.Now().UTC()

	var existingID string
	err := s.db.QueryRow(
		`SELECT id FROM allergy_intolerances WHERE fhir_id = ? AND ehr_url = ?`,
		a.FHIRID, a.EHRURL,
	).Scan(&existingID)

	if err == nil {
		_, err = s.db.Exec(`
			UPDATE allergy_intolerances SET
				patient_fhir_id        = ?,
				clinical_status        = ?,
				verification_status    = ?,
				type                   = ?,
				category               = ?,
				criticality            = ?,
				code_text              = ?,
				code_system            = ?,
				code_code              = ?,
				recorded_date          = ?,
				reaction_severity      = ?,
				reaction_manifestation = ?,
				synced_at              = ?
			WHERE id = ?`,
			a.PatientFHIRID, a.ClinicalStatus, a.VerificationStatus,
			a.Type, a.Category, a.Criticality,
			a.CodeText, a.CodeSystem, a.CodeCode,
			a.RecordedDate, a.ReactionSeverity, a.ReactionManifestation,
			now, existingID,
		)
		if err != nil {
			return "", fmt.Errorf("db: update allergy_intolerance %s: %w", existingID, err)
		}
		return existingID, nil
	}

	id := uuid.NewString()
	_, err = s.db.Exec(`
		INSERT INTO allergy_intolerances (
			id, fhir_id, ehr_url, patient_fhir_id,
			clinical_status, verification_status, type, category, criticality,
			code_text, code_system, code_code, recorded_date,
			reaction_severity, reaction_manifestation, synced_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, a.FHIRID, a.EHRURL, a.PatientFHIRID,
		a.ClinicalStatus, a.VerificationStatus, a.Type, a.Category, a.Criticality,
		a.CodeText, a.CodeSystem, a.CodeCode, a.RecordedDate,
		a.ReactionSeverity, a.ReactionManifestation, now,
	)
	if err != nil {
		return "", fmt.Errorf("db: insert allergy_intolerance fhir_id=%s: %w", a.FHIRID, err)
	}
	return id, nil
}

// ListAllergyIntolerances returns all AllergyIntolerances for the given patient, newest first.
func (s *Store) ListAllergyIntolerances(patientFHIRID, ehrURL string) ([]models.AllergyIntolerance, error) {
	rows, err := s.db.Query(`
		SELECT id, fhir_id, ehr_url, patient_fhir_id,
		       clinical_status, verification_status, type, category, criticality,
		       code_text, code_system, code_code, recorded_date,
		       reaction_severity, reaction_manifestation, synced_at
		FROM allergy_intolerances
		WHERE patient_fhir_id = ? AND ehr_url = ?
		ORDER BY recorded_date DESC`,
		patientFHIRID, ehrURL,
	)
	if err != nil {
		return nil, fmt.Errorf("db: list allergy_intolerances: %w", err)
	}
	defer rows.Close()

	var out []models.AllergyIntolerance
	for rows.Next() {
		var a models.AllergyIntolerance
		if err := rows.Scan(
			&a.ID, &a.FHIRID, &a.EHRURL, &a.PatientFHIRID,
			&a.ClinicalStatus, &a.VerificationStatus, &a.Type, &a.Category, &a.Criticality,
			&a.CodeText, &a.CodeSystem, &a.CodeCode, &a.RecordedDate,
			&a.ReactionSeverity, &a.ReactionManifestation, &a.SyncedAt,
		); err != nil {
			return nil, fmt.Errorf("db: scan allergy_intolerance: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// Immunization
// ---------------------------------------------------------------------------

// UpsertImmunization inserts or updates an Immunization record keyed on (fhir_id, ehr_url).
func (s *Store) UpsertImmunization(imm *models.Immunization) (string, error) {
	now := time.Now().UTC()

	var existingID string
	err := s.db.QueryRow(
		`SELECT id FROM immunizations WHERE fhir_id = ? AND ehr_url = ?`,
		imm.FHIRID, imm.EHRURL,
	).Scan(&existingID)

	if err == nil {
		_, err = s.db.Exec(`
			UPDATE immunizations SET
				patient_fhir_id = ?,
				status          = ?,
				vaccine_text    = ?,
				vaccine_system  = ?,
				vaccine_code    = ?,
				occurrence_date = ?,
				primary_source  = ?,
				lot_number      = ?,
				synced_at       = ?
			WHERE id = ?`,
			imm.PatientFHIRID, imm.Status,
			imm.VaccineText, imm.VaccineSystem, imm.VaccineCode,
			imm.OccurrenceDate, imm.PrimarySource, imm.LotNumber,
			now, existingID,
		)
		if err != nil {
			return "", fmt.Errorf("db: update immunization %s: %w", existingID, err)
		}
		return existingID, nil
	}

	id := uuid.NewString()
	_, err = s.db.Exec(`
		INSERT INTO immunizations (
			id, fhir_id, ehr_url, patient_fhir_id,
			status, vaccine_text, vaccine_system, vaccine_code,
			occurrence_date, primary_source, lot_number, synced_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, imm.FHIRID, imm.EHRURL, imm.PatientFHIRID,
		imm.Status, imm.VaccineText, imm.VaccineSystem, imm.VaccineCode,
		imm.OccurrenceDate, imm.PrimarySource, imm.LotNumber, now,
	)
	if err != nil {
		return "", fmt.Errorf("db: insert immunization fhir_id=%s: %w", imm.FHIRID, err)
	}
	return id, nil
}

// ListImmunizations returns all Immunizations for the given patient, newest first.
func (s *Store) ListImmunizations(patientFHIRID, ehrURL string) ([]models.Immunization, error) {
	rows, err := s.db.Query(`
		SELECT id, fhir_id, ehr_url, patient_fhir_id,
		       status, vaccine_text, vaccine_system, vaccine_code,
		       occurrence_date, primary_source, lot_number, synced_at
		FROM immunizations
		WHERE patient_fhir_id = ? AND ehr_url = ?
		ORDER BY occurrence_date DESC`,
		patientFHIRID, ehrURL,
	)
	if err != nil {
		return nil, fmt.Errorf("db: list immunizations: %w", err)
	}
	defer rows.Close()

	var out []models.Immunization
	for rows.Next() {
		var imm models.Immunization
		if err := rows.Scan(
			&imm.ID, &imm.FHIRID, &imm.EHRURL, &imm.PatientFHIRID,
			&imm.Status, &imm.VaccineText, &imm.VaccineSystem, &imm.VaccineCode,
			&imm.OccurrenceDate, &imm.PrimarySource, &imm.LotNumber, &imm.SyncedAt,
		); err != nil {
			return nil, fmt.Errorf("db: scan immunization: %w", err)
		}
		out = append(out, imm)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// Procedure
// ---------------------------------------------------------------------------

// UpsertProcedure inserts or updates a Procedure record keyed on (fhir_id, ehr_url).
func (s *Store) UpsertProcedure(p *models.Procedure) (string, error) {
	now := time.Now().UTC()

	var existingID string
	err := s.db.QueryRow(
		`SELECT id FROM procedures WHERE fhir_id = ? AND ehr_url = ?`,
		p.FHIRID, p.EHRURL,
	).Scan(&existingID)

	if err == nil {
		_, err = s.db.Exec(`
			UPDATE procedures SET
				patient_fhir_id = ?,
				status          = ?,
				code_text       = ?,
				code_system     = ?,
				code_code       = ?,
				performed_date  = ?,
				reason_text     = ?,
				outcome         = ?,
				synced_at       = ?
			WHERE id = ?`,
			p.PatientFHIRID, p.Status,
			p.CodeText, p.CodeSystem, p.CodeCode,
			p.PerformedDate, p.ReasonText, p.Outcome,
			now, existingID,
		)
		if err != nil {
			return "", fmt.Errorf("db: update procedure %s: %w", existingID, err)
		}
		return existingID, nil
	}

	id := uuid.NewString()
	_, err = s.db.Exec(`
		INSERT INTO procedures (
			id, fhir_id, ehr_url, patient_fhir_id,
			status, code_text, code_system, code_code,
			performed_date, reason_text, outcome, synced_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, p.FHIRID, p.EHRURL, p.PatientFHIRID,
		p.Status, p.CodeText, p.CodeSystem, p.CodeCode,
		p.PerformedDate, p.ReasonText, p.Outcome, now,
	)
	if err != nil {
		return "", fmt.Errorf("db: insert procedure fhir_id=%s: %w", p.FHIRID, err)
	}
	return id, nil
}

// ListProcedures returns all Procedures for the given patient, newest first.
func (s *Store) ListProcedures(patientFHIRID, ehrURL string) ([]models.Procedure, error) {
	rows, err := s.db.Query(`
		SELECT id, fhir_id, ehr_url, patient_fhir_id,
		       status, code_text, code_system, code_code,
		       performed_date, reason_text, outcome, synced_at
		FROM procedures
		WHERE patient_fhir_id = ? AND ehr_url = ?
		ORDER BY performed_date DESC`,
		patientFHIRID, ehrURL,
	)
	if err != nil {
		return nil, fmt.Errorf("db: list procedures: %w", err)
	}
	defer rows.Close()

	var out []models.Procedure
	for rows.Next() {
		var p models.Procedure
		if err := rows.Scan(
			&p.ID, &p.FHIRID, &p.EHRURL, &p.PatientFHIRID,
			&p.Status, &p.CodeText, &p.CodeSystem, &p.CodeCode,
			&p.PerformedDate, &p.ReasonText, &p.Outcome, &p.SyncedAt,
		); err != nil {
			return nil, fmt.Errorf("db: scan procedure: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// Encounter
// ---------------------------------------------------------------------------

// UpsertEncounter inserts or updates an Encounter record keyed on (fhir_id, ehr_url).
func (s *Store) UpsertEncounter(e *models.Encounter) (string, error) {
	now := time.Now().UTC()

	var existingID string
	err := s.db.QueryRow(
		`SELECT id FROM encounters WHERE fhir_id = ? AND ehr_url = ?`,
		e.FHIRID, e.EHRURL,
	).Scan(&existingID)

	if err == nil {
		_, err = s.db.Exec(`
			UPDATE encounters SET
				patient_fhir_id = ?,
				status          = ?,
				class           = ?,
				type_text       = ?,
				period_start    = ?,
				period_end      = ?,
				reason_text     = ?,
				synced_at       = ?
			WHERE id = ?`,
			e.PatientFHIRID, e.Status, e.Class, e.TypeText,
			e.PeriodStart, e.PeriodEnd, e.ReasonText,
			now, existingID,
		)
		if err != nil {
			return "", fmt.Errorf("db: update encounter %s: %w", existingID, err)
		}
		return existingID, nil
	}

	id := uuid.NewString()
	_, err = s.db.Exec(`
		INSERT INTO encounters (
			id, fhir_id, ehr_url, patient_fhir_id,
			status, class, type_text,
			period_start, period_end, reason_text, synced_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, e.FHIRID, e.EHRURL, e.PatientFHIRID,
		e.Status, e.Class, e.TypeText,
		e.PeriodStart, e.PeriodEnd, e.ReasonText, now,
	)
	if err != nil {
		return "", fmt.Errorf("db: insert encounter fhir_id=%s: %w", e.FHIRID, err)
	}
	return id, nil
}

// ListEncounters returns all Encounters for the given patient, newest first.
func (s *Store) ListEncounters(patientFHIRID, ehrURL string) ([]models.Encounter, error) {
	rows, err := s.db.Query(`
		SELECT id, fhir_id, ehr_url, patient_fhir_id,
		       status, class, type_text,
		       period_start, period_end, reason_text, synced_at
		FROM encounters
		WHERE patient_fhir_id = ? AND ehr_url = ?
		ORDER BY period_start DESC`,
		patientFHIRID, ehrURL,
	)
	if err != nil {
		return nil, fmt.Errorf("db: list encounters: %w", err)
	}
	defer rows.Close()

	var out []models.Encounter
	for rows.Next() {
		var e models.Encounter
		if err := rows.Scan(
			&e.ID, &e.FHIRID, &e.EHRURL, &e.PatientFHIRID,
			&e.Status, &e.Class, &e.TypeText,
			&e.PeriodStart, &e.PeriodEnd, &e.ReasonText, &e.SyncedAt,
		); err != nil {
			return nil, fmt.Errorf("db: scan encounter: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// PatientSync
// ---------------------------------------------------------------------------

// RecordSync inserts a new sync event for a patient.
func (s *Store) RecordSync(patientFHIRID, ehrURL string, obsCount, condCount, docCount int) (*models.PatientSync, error) {
	ps := &models.PatientSync{
		ID:            uuid.NewString(),
		PatientFHIRID: patientFHIRID,
		EHRURL:        ehrURL,
		SyncedAt:      time.Now().UTC(),
		ObsCount:      obsCount,
		CondCount:     condCount,
		DocCount:      docCount,
	}
	_, err := s.db.Exec(`
		INSERT INTO patient_syncs (id, patient_fhir_id, ehr_url, synced_at, obs_count, cond_count, doc_count)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		ps.ID, ps.PatientFHIRID, ps.EHRURL, ps.SyncedAt, ps.ObsCount, ps.CondCount, ps.DocCount,
	)
	if err != nil {
		return nil, fmt.Errorf("db: record sync for patient %s: %w", patientFHIRID, err)
	}
	return ps, nil
}

// LatestSync retrieves the most recent sync event for a patient.
// Returns nil, nil when no sync has ever been performed.
func (s *Store) LatestSync(patientFHIRID, ehrURL string) (*models.PatientSync, error) {
	ps := &models.PatientSync{}
	err := s.db.QueryRow(`
		SELECT id, patient_fhir_id, ehr_url, synced_at, obs_count, cond_count, doc_count
		FROM patient_syncs
		WHERE patient_fhir_id = ? AND ehr_url = ?
		ORDER BY synced_at DESC
		LIMIT 1`,
		patientFHIRID, ehrURL,
	).Scan(
		&ps.ID, &ps.PatientFHIRID, &ps.EHRURL, &ps.SyncedAt,
		&ps.ObsCount, &ps.CondCount, &ps.DocCount,
	)
	if err != nil {
		if err.Error() == "sql: no rows in result set" {
			return nil, nil
		}
		return nil, fmt.Errorf("db: latest sync for patient %s: %w", patientFHIRID, err)
	}
	return ps, nil
}
