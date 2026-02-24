// Package db provides the SQLite-backed persistence layer for the platform.
//
// Architecture notes:
//   - Uses the standard database/sql interface with a pure-Go SQLite driver
//     (modernc.org/sqlite), requiring no CGO.
//   - Schema versioning is handled via the schema_migrations table, enabling
//     forward-only incremental migrations as the platform grows.
//   - All public functions accept a *Store receiver, keeping the DB handle
//     encapsulated and allowing easy substitution (e.g., for testing with
//     an in-memory SQLite instance).
//   - Upsert semantics for users use (fhir_id, ehr_url) as the natural key,
//     preventing duplicates across EHR tenants while allowing the same FHIR
//     ID to exist at different servers.
package db

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	"github.com/AmanTahiliani/FHIR-Sandbox/app/models"
	"github.com/google/uuid"
	_ "modernc.org/sqlite" // Register the sqlite driver under the name "sqlite".
)

// Store wraps a database/sql.DB and exposes all persistence operations
// for the platform. It is the single point of DB access — no raw *sql.DB
// handles should escape this package.
type Store struct {
	db *sql.DB
}

// New opens (or creates) the SQLite database at the given path, applies
// all pending migrations, and returns a ready-to-use Store.
//
// Use path ":memory:" in tests to get a disposable in-memory database.
func New(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("db: open: %w", err)
	}

	// SQLite is file-based; a small pool is sufficient.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("db: migrate: %w", err)
	}
	return s, nil
}

// Close releases the underlying database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

// ---------------------------------------------------------------------------
// Schema migrations
// ---------------------------------------------------------------------------

// migration represents a single, versioned, forward-only DDL statement.
// New tables and columns must be added as new migrations — never alter
// existing ones, to preserve upgrade safety.
type migration struct {
	version int
	sql     string
}

var migrations = []migration{
	{
		version: 1,
		sql: `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version    INTEGER PRIMARY KEY,
			applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		);

		CREATE TABLE IF NOT EXISTS users (
			id                 TEXT PRIMARY KEY,
			fhir_resource_type TEXT NOT NULL,
			fhir_id            TEXT NOT NULL,
			ehr_url            TEXT NOT NULL,
			role               TEXT NOT NULL,
			first_name         TEXT NOT NULL DEFAULT '',
			middle_name        TEXT NOT NULL DEFAULT '',
			last_name          TEXT NOT NULL DEFAULT '',
			dob                TEXT NOT NULL DEFAULT '',
			gender             TEXT NOT NULL DEFAULT '',
			email              TEXT NOT NULL DEFAULT '',
			created_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(fhir_id, ehr_url)
		);

		CREATE TABLE IF NOT EXISTS sessions (
			id           TEXT PRIMARY KEY,
			user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			access_token TEXT NOT NULL DEFAULT '',
			ehr_url      TEXT NOT NULL DEFAULT '',
			created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			expires_at   DATETIME NOT NULL
		);

		CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
		CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
		CREATE INDEX IF NOT EXISTS idx_users_fhir ON users(fhir_id, ehr_url);
		`,
	},
	{
		version: 2,
		sql: `
		ALTER TABLE sessions ADD COLUMN patient_fhir_id TEXT NOT NULL DEFAULT '';
		ALTER TABLE sessions ADD COLUMN id_token TEXT NOT NULL DEFAULT '';
		ALTER TABLE sessions ADD COLUMN scope TEXT NOT NULL DEFAULT '';
		`,
	},
	{
		version: 3,
		sql: `
		CREATE TABLE IF NOT EXISTS observations (
			id              TEXT PRIMARY KEY,
			fhir_id         TEXT NOT NULL,
			ehr_url         TEXT NOT NULL,
			patient_fhir_id TEXT NOT NULL,
			status          TEXT NOT NULL DEFAULT '',
			category        TEXT NOT NULL DEFAULT '',
			code_text       TEXT NOT NULL DEFAULT '',
			code_system     TEXT NOT NULL DEFAULT '',
			code_code       TEXT NOT NULL DEFAULT '',
			effective_date  TEXT NOT NULL DEFAULT '',
			value_quantity  REAL,
			value_unit      TEXT NOT NULL DEFAULT '',
			value_string    TEXT NOT NULL DEFAULT '',
			synced_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(fhir_id, ehr_url)
		);

		CREATE TABLE IF NOT EXISTS conditions (
			id                   TEXT PRIMARY KEY,
			fhir_id              TEXT NOT NULL,
			ehr_url              TEXT NOT NULL,
			patient_fhir_id      TEXT NOT NULL,
			clinical_status      TEXT NOT NULL DEFAULT '',
			verification_status  TEXT NOT NULL DEFAULT '',
			category             TEXT NOT NULL DEFAULT '',
			code_text            TEXT NOT NULL DEFAULT '',
			code_system          TEXT NOT NULL DEFAULT '',
			code_code            TEXT NOT NULL DEFAULT '',
			onset_date           TEXT NOT NULL DEFAULT '',
			recorded_date        TEXT NOT NULL DEFAULT '',
			synced_at            DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(fhir_id, ehr_url)
		);

		CREATE TABLE IF NOT EXISTS document_references (
			id              TEXT PRIMARY KEY,
			fhir_id         TEXT NOT NULL,
			ehr_url         TEXT NOT NULL,
			patient_fhir_id TEXT NOT NULL,
			status          TEXT NOT NULL DEFAULT '',
			doc_status      TEXT NOT NULL DEFAULT '',
			type_text       TEXT NOT NULL DEFAULT '',
			type_system     TEXT NOT NULL DEFAULT '',
			type_code       TEXT NOT NULL DEFAULT '',
			category        TEXT NOT NULL DEFAULT '',
			date            TEXT NOT NULL DEFAULT '',
			description     TEXT NOT NULL DEFAULT '',
			content_type    TEXT NOT NULL DEFAULT '',
			content_url     TEXT NOT NULL DEFAULT '',
			content_data    TEXT NOT NULL DEFAULT '',
			synced_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(fhir_id, ehr_url)
		);

		CREATE TABLE IF NOT EXISTS patient_syncs (
			id              TEXT PRIMARY KEY,
			patient_fhir_id TEXT NOT NULL,
			ehr_url         TEXT NOT NULL,
			synced_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			obs_count       INTEGER NOT NULL DEFAULT 0,
			cond_count      INTEGER NOT NULL DEFAULT 0,
			doc_count       INTEGER NOT NULL DEFAULT 0
		);

		CREATE INDEX IF NOT EXISTS idx_observations_patient  ON observations(patient_fhir_id, ehr_url);
		CREATE INDEX IF NOT EXISTS idx_conditions_patient    ON conditions(patient_fhir_id, ehr_url);
		CREATE INDEX IF NOT EXISTS idx_docrefs_patient       ON document_references(patient_fhir_id, ehr_url);
		CREATE INDEX IF NOT EXISTS idx_patient_syncs_patient ON patient_syncs(patient_fhir_id, ehr_url);
		`,
	},
	{
		version: 4,
		sql: `
		ALTER TABLE observations ADD COLUMN interpretation TEXT NOT NULL DEFAULT '';
		ALTER TABLE observations ADD COLUMN ref_range_low REAL;
		ALTER TABLE observations ADD COLUMN ref_range_high REAL;

		CREATE TABLE IF NOT EXISTS medication_requests (
			id              TEXT PRIMARY KEY,
			fhir_id         TEXT NOT NULL,
			ehr_url         TEXT NOT NULL,
			patient_fhir_id TEXT NOT NULL,
			status          TEXT NOT NULL DEFAULT '',
			intent          TEXT NOT NULL DEFAULT '',
			med_code_text   TEXT NOT NULL DEFAULT '',
			med_code_system TEXT NOT NULL DEFAULT '',
			med_code_code   TEXT NOT NULL DEFAULT '',
			authored_on     TEXT NOT NULL DEFAULT '',
			requester_display TEXT NOT NULL DEFAULT '',
			dosage_text     TEXT NOT NULL DEFAULT '',
			synced_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(fhir_id, ehr_url)
		);

		CREATE TABLE IF NOT EXISTS allergy_intolerances (
			id                  TEXT PRIMARY KEY,
			fhir_id             TEXT NOT NULL,
			ehr_url             TEXT NOT NULL,
			patient_fhir_id     TEXT NOT NULL,
			clinical_status     TEXT NOT NULL DEFAULT '',
			verification_status TEXT NOT NULL DEFAULT '',
			type                TEXT NOT NULL DEFAULT '',
			category            TEXT NOT NULL DEFAULT '',
			criticality         TEXT NOT NULL DEFAULT '',
			code_text           TEXT NOT NULL DEFAULT '',
			code_system         TEXT NOT NULL DEFAULT '',
			code_code           TEXT NOT NULL DEFAULT '',
			recorded_date       TEXT NOT NULL DEFAULT '',
			synced_at           DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(fhir_id, ehr_url)
		);

		CREATE INDEX IF NOT EXISTS idx_medication_requests_patient ON medication_requests(patient_fhir_id, ehr_url);
		CREATE INDEX IF NOT EXISTS idx_allergy_intolerances_patient ON allergy_intolerances(patient_fhir_id, ehr_url);
		`,
	},
	{
		version: 5,
		sql: `
		ALTER TABLE allergy_intolerances ADD COLUMN reaction_severity TEXT NOT NULL DEFAULT '';
		ALTER TABLE allergy_intolerances ADD COLUMN reaction_manifestation TEXT NOT NULL DEFAULT '';
		`,
	},
	{
		version: 6,
		sql: `
		CREATE TABLE IF NOT EXISTS immunizations (
			id              TEXT PRIMARY KEY,
			fhir_id         TEXT NOT NULL,
			ehr_url         TEXT NOT NULL,
			patient_fhir_id TEXT NOT NULL,
			status          TEXT NOT NULL DEFAULT '',
			vaccine_text    TEXT NOT NULL DEFAULT '',
			vaccine_system  TEXT NOT NULL DEFAULT '',
			vaccine_code    TEXT NOT NULL DEFAULT '',
			occurrence_date TEXT NOT NULL DEFAULT '',
			primary_source  INTEGER NOT NULL DEFAULT 0,
			lot_number      TEXT NOT NULL DEFAULT '',
			synced_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(fhir_id, ehr_url)
		);
		CREATE INDEX IF NOT EXISTS idx_immunizations_patient ON immunizations(patient_fhir_id, ehr_url);
		`,
	},
	{
		version: 7,
		sql: `
		CREATE TABLE IF NOT EXISTS procedures (
			id              TEXT PRIMARY KEY,
			fhir_id         TEXT NOT NULL,
			ehr_url         TEXT NOT NULL,
			patient_fhir_id TEXT NOT NULL,
			status          TEXT NOT NULL DEFAULT '',
			code_text       TEXT NOT NULL DEFAULT '',
			code_system     TEXT NOT NULL DEFAULT '',
			code_code       TEXT NOT NULL DEFAULT '',
			performed_date  TEXT NOT NULL DEFAULT '',
			reason_text     TEXT NOT NULL DEFAULT '',
			outcome         TEXT NOT NULL DEFAULT '',
			synced_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(fhir_id, ehr_url)
		);
		CREATE INDEX IF NOT EXISTS idx_procedures_patient ON procedures(patient_fhir_id, ehr_url);
		`,
	},
	{
		version: 8,
		sql: `
		CREATE TABLE IF NOT EXISTS encounters (
			id              TEXT PRIMARY KEY,
			fhir_id         TEXT NOT NULL,
			ehr_url         TEXT NOT NULL,
			patient_fhir_id TEXT NOT NULL,
			status          TEXT NOT NULL DEFAULT '',
			class           TEXT NOT NULL DEFAULT '',
			type_text       TEXT NOT NULL DEFAULT '',
			period_start    TEXT NOT NULL DEFAULT '',
			period_end      TEXT NOT NULL DEFAULT '',
			reason_text     TEXT NOT NULL DEFAULT '',
			synced_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(fhir_id, ehr_url)
		);
		CREATE INDEX IF NOT EXISTS idx_encounters_patient ON encounters(patient_fhir_id, ehr_url);
		`,
	},
	{
		version: 9,
		sql: `
		ALTER TABLE users ADD COLUMN mrn TEXT NOT NULL DEFAULT '';
		`,
	},
}

// migrate applies any migrations that have not yet been run, in order.
func (s *Store) migrate() error {
	// Enable WAL mode for better concurrent read performance.
	if _, err := s.db.Exec(`PRAGMA journal_mode=WAL;`); err != nil {
		return fmt.Errorf("set WAL mode: %w", err)
	}
	// Enable foreign key enforcement (off by default in SQLite).
	if _, err := s.db.Exec(`PRAGMA foreign_keys=ON;`); err != nil {
		return fmt.Errorf("enable foreign keys: %w", err)
	}

	// Bootstrap the migrations table if it doesn't exist yet.
	if _, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version    INTEGER PRIMARY KEY,
			applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		);`); err != nil {
		return fmt.Errorf("bootstrap schema_migrations: %w", err)
	}

	for _, m := range migrations {
		var count int
		row := s.db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version = ?`, m.version)
		if err := row.Scan(&count); err != nil {
			return fmt.Errorf("check migration v%d: %w", m.version, err)
		}
		if count > 0 {
			continue // Already applied.
		}

		if _, err := s.db.Exec(m.sql); err != nil {
			return fmt.Errorf("apply migration v%d: %w", m.version, err)
		}
		if _, err := s.db.Exec(`INSERT INTO schema_migrations(version) VALUES(?)`, m.version); err != nil {
			return fmt.Errorf("record migration v%d: %w", m.version, err)
		}
		log.Printf("db: applied migration v%d", m.version)
	}
	return nil
}

// ---------------------------------------------------------------------------
// User operations
// ---------------------------------------------------------------------------

// UpsertUser inserts a new user or updates the demographics of an existing one,
// matched on the (fhir_id, ehr_url) natural key.
//
// Returns the user's internal UUID (which may be the existing one if the user
// already existed).
func (s *Store) UpsertUser(u *models.User) (string, error) {
	now := time.Now().UTC()

	// Check if the user already exists to preserve the original created_at
	// and internal ID.
	var existingID string
	err := s.db.QueryRow(
		`SELECT id FROM users WHERE fhir_id = ? AND ehr_url = ?`,
		u.FHIRID, u.EHRURL,
	).Scan(&existingID)

	if err == nil {
		// User exists — update demographics but preserve ID and created_at.
		_, err = s.db.Exec(`
			UPDATE users SET
				first_name         = ?,
				middle_name        = ?,
				last_name          = ?,
				mrn                = ?,
				dob                = ?,
				gender             = ?,
				email              = ?,
				fhir_resource_type = ?,
				role               = ?,
				updated_at         = ?
			WHERE id = ?`,
			u.FirstName, u.MiddleName, u.LastName, u.MRN,
			u.DOB, u.Gender, u.Email,
			u.FHIRResourceType, string(u.Role),
			now, existingID,
		)
		if err != nil {
			return "", fmt.Errorf("db: update user %s: %w", existingID, err)
		}
		return existingID, nil
	}

	if err != sql.ErrNoRows {
		return "", fmt.Errorf("db: lookup user (%s, %s): %w", u.FHIRID, u.EHRURL, err)
	}

	// New user — generate a fresh internal UUID.
	id := uuid.NewString()
	_, err = s.db.Exec(`
		INSERT INTO users (
			id, fhir_resource_type, fhir_id, ehr_url, role,
			first_name, middle_name, last_name, mrn, dob, gender, email,
			created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, u.FHIRResourceType, u.FHIRID, u.EHRURL, string(u.Role),
		u.FirstName, u.MiddleName, u.LastName, u.MRN, u.DOB, u.Gender, u.Email,
		now, now,
	)
	if err != nil {
		return "", fmt.Errorf("db: insert user (fhir_id=%s): %w", u.FHIRID, err)
	}
	return id, nil
}

// GetUserByFHIRID retrieves a user by their FHIR ID and originating EHR URL.
// Returns sql.ErrNoRows if no matching user is found.
func (s *Store) GetUserByFHIRID(fhirID, ehrURL string) (*models.User, error) {
	u := &models.User{}
	err := s.db.QueryRow(`
		SELECT id, fhir_resource_type, fhir_id, ehr_url, role,
		       first_name, middle_name, last_name, mrn, dob, gender, email,
		       created_at, updated_at
		FROM users WHERE fhir_id = ? AND ehr_url = ?`,
		fhirID, ehrURL,
	).Scan(
		&u.ID, &u.FHIRResourceType, &u.FHIRID, &u.EHRURL, &u.Role,
		&u.FirstName, &u.MiddleName, &u.LastName, &u.MRN, &u.DOB, &u.Gender, &u.Email,
		&u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return u, nil
}

// GetUserByID retrieves a user by their internal UUID primary key.
func (s *Store) GetUserByID(id string) (*models.User, error) {
	u := &models.User{}
	err := s.db.QueryRow(`
		SELECT id, fhir_resource_type, fhir_id, ehr_url, role,
		       first_name, middle_name, last_name, mrn, dob, gender, email,
		       created_at, updated_at
		FROM users WHERE id = ?`, id,
	).Scan(
		&u.ID, &u.FHIRResourceType, &u.FHIRID, &u.EHRURL, &u.Role,
		&u.FirstName, &u.MiddleName, &u.LastName, &u.MRN, &u.DOB, &u.Gender, &u.Email,
		&u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return u, nil
}

// ListUsersByRole retrieves all users with the given role and originating EHR URL.
func (s *Store) ListUsersByRole(role models.Role, ehrURL string) ([]models.User, error) {
	rows, err := s.db.Query(`
		SELECT id, fhir_resource_type, fhir_id, ehr_url, role,
		       first_name, middle_name, last_name, mrn, dob, gender, email,
		       created_at, updated_at
		FROM users WHERE role = ? AND ehr_url = ?
		ORDER BY last_name ASC, first_name ASC`,
		string(role), ehrURL,
	)
	if err != nil {
		return nil, fmt.Errorf("db: list users by role: %w", err)
	}
	defer rows.Close()

	var users []models.User
	for rows.Next() {
		var u models.User
		if err := rows.Scan(
			&u.ID, &u.FHIRResourceType, &u.FHIRID, &u.EHRURL, &u.Role,
			&u.FirstName, &u.MiddleName, &u.LastName, &u.MRN, &u.DOB, &u.Gender, &u.Email,
			&u.CreatedAt, &u.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("db: scan user: %w", err)
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

// ListAllPatients returns every user with role='patient' across all EHR
// tenants. Used by the patient-match API which needs to compare against
// the full patient population.
func (s *Store) ListAllPatients() ([]models.User, error) {
	rows, err := s.db.Query(`
		SELECT id, fhir_resource_type, fhir_id, ehr_url, role,
		       first_name, middle_name, last_name, mrn, dob, gender, email,
		       created_at, updated_at
		FROM users WHERE role = ?
		ORDER BY last_name ASC, first_name ASC`,
		string(models.RolePatient),
	)
	if err != nil {
		return nil, fmt.Errorf("db: list all patients: %w", err)
	}
	defer rows.Close()

	var users []models.User
	for rows.Next() {
		var u models.User
		if err := rows.Scan(
			&u.ID, &u.FHIRResourceType, &u.FHIRID, &u.EHRURL, &u.Role,
			&u.FirstName, &u.MiddleName, &u.LastName, &u.MRN, &u.DOB, &u.Gender, &u.Email,
			&u.CreatedAt, &u.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("db: scan patient: %w", err)
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

// ---------------------------------------------------------------------------
// Session operations
// ---------------------------------------------------------------------------

// CreateSession creates a new authenticated session for the given user,
// storing the FHIR access token and EHR context. Sessions expire after
// the provided duration from now.
func (s *Store) CreateSession(userID, patientFHIRID, accessToken, idToken, scope, ehrURL string, ttl time.Duration) (*models.Session, error) {
	now := time.Now().UTC()
	sess := &models.Session{
		ID:            uuid.NewString(),
		UserID:        userID,
		PatientFHIRID: patientFHIRID,
		AccessToken:   accessToken,
		IDToken:       idToken,
		Scope:         scope,
		EHRURL:        ehrURL,
		CreatedAt:     now,
		ExpiresAt:     now.Add(ttl),
	}

	_, err := s.db.Exec(`
		INSERT INTO sessions (id, user_id, patient_fhir_id, access_token, id_token, scope, ehr_url, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		sess.ID, sess.UserID, sess.PatientFHIRID, sess.AccessToken, sess.IDToken, sess.Scope, sess.EHRURL,
		sess.CreatedAt, sess.ExpiresAt,
	)
	if err != nil {
		return nil, fmt.Errorf("db: create session for user %s: %w", userID, err)
	}
	return sess, nil
}

// GetSession retrieves a session by its token ID.
// Returns sql.ErrNoRows if the session does not exist.
func (s *Store) GetSession(id string) (*models.Session, error) {
	sess := &models.Session{}
	err := s.db.QueryRow(`
		SELECT id, user_id, patient_fhir_id, access_token, id_token, scope, ehr_url, created_at, expires_at
		FROM sessions WHERE id = ?`, id,
	).Scan(
		&sess.ID, &sess.UserID, &sess.PatientFHIRID, &sess.AccessToken, &sess.IDToken, &sess.Scope, &sess.EHRURL,
		&sess.CreatedAt, &sess.ExpiresAt,
	)
	if err != nil {
		return nil, err
	}
	return sess, nil
}

// DeleteSession removes a session by its token ID. Used during logout.
func (s *Store) DeleteSession(id string) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("db: delete session %s: %w", id, err)
	}
	return nil
}

// DeleteExpiredSessions removes all sessions whose expiry time has passed.
// This should be called periodically (e.g., on startup or via a background
// goroutine) to keep the sessions table lean.
func (s *Store) DeleteExpiredSessions() (int64, error) {
	res, err := s.db.Exec(`DELETE FROM sessions WHERE expires_at < ?`, time.Now().UTC())
	if err != nil {
		return 0, fmt.Errorf("db: purge expired sessions: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}
