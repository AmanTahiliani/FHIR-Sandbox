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
				patient_fhir_id = ?,
				status          = ?,
				category        = ?,
				code_text       = ?,
				code_system     = ?,
				code_code       = ?,
				effective_date  = ?,
				value_quantity  = ?,
				value_unit      = ?,
				value_string    = ?,
				synced_at       = ?
			WHERE id = ?`,
			o.PatientFHIRID, o.Status, o.Category,
			o.CodeText, o.CodeSystem, o.CodeCode,
			o.EffectiveDate, o.ValueQuantity, o.ValueUnit, o.ValueString,
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
			value_quantity, value_unit, value_string, synced_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, o.FHIRID, o.EHRURL, o.PatientFHIRID, o.Status, o.Category,
		o.CodeText, o.CodeSystem, o.CodeCode, o.EffectiveDate,
		o.ValueQuantity, o.ValueUnit, o.ValueString, now,
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
		       value_quantity, value_unit, value_string, synced_at
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
			&o.ValueQuantity, &o.ValueUnit, &o.ValueString, &o.SyncedAt,
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
