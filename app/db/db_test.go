package db_test

import (
	"database/sql"
	"testing"
	"time"

	"github.com/AmanTahiliani/FHIR-Sandbox/app/db"
	"github.com/AmanTahiliani/FHIR-Sandbox/app/models"
)

// newTestStore creates a disposable in-memory SQLite store for testing.
func newTestStore(t *testing.T) *db.Store {
	t.Helper()
	store, err := db.New(":memory:")
	if err != nil {
		t.Fatalf("newTestStore: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

// ---------------------------------------------------------------------------
// User tests
// ---------------------------------------------------------------------------

func TestUpsertUser_NewUser(t *testing.T) {
	store := newTestStore(t)

	u := &models.User{
		FHIRResourceType: "Patient",
		FHIRID:           "patient-abc",
		EHRURL:           "https://ehr.example.com/fhir",
		Role:             models.RolePatient,
		FirstName:        "Alice",
		MiddleName:       "Marie",
		LastName:         "Smith",
		DOB:              "1990-04-22",
		Gender:           "female",
		Email:            "alice@example.com",
	}

	id, err := store.UpsertUser(u)
	if err != nil {
		t.Fatalf("UpsertUser: %v", err)
	}
	if id == "" {
		t.Fatal("expected non-empty ID for new user")
	}

	// Fetch back and verify.
	got, err := store.GetUserByFHIRID(u.FHIRID, u.EHRURL)
	if err != nil {
		t.Fatalf("GetUserByFHIRID: %v", err)
	}
	if got.FirstName != "Alice" {
		t.Errorf("FirstName: got %q, want %q", got.FirstName, "Alice")
	}
	if got.Role != models.RolePatient {
		t.Errorf("Role: got %q, want %q", got.Role, models.RolePatient)
	}
	if got.Email != "alice@example.com" {
		t.Errorf("Email: got %q, want %q", got.Email, "alice@example.com")
	}
}

func TestUpsertUser_UpdateExisting(t *testing.T) {
	store := newTestStore(t)

	u := &models.User{
		FHIRResourceType: "Patient",
		FHIRID:           "patient-xyz",
		EHRURL:           "https://ehr.example.com/fhir",
		Role:             models.RolePatient,
		FirstName:        "Bob",
		LastName:         "Jones",
		DOB:              "1985-01-01",
		Gender:           "male",
	}

	id1, err := store.UpsertUser(u)
	if err != nil {
		t.Fatalf("initial UpsertUser: %v", err)
	}

	// Update demographics.
	u.Email = "bob.updated@example.com"
	u.FirstName = "Robert"
	id2, err := store.UpsertUser(u)
	if err != nil {
		t.Fatalf("update UpsertUser: %v", err)
	}

	// Internal ID must remain stable across upserts.
	if id1 != id2 {
		t.Errorf("ID changed on upsert: got %q, was %q", id2, id1)
	}

	got, err := store.GetUserByFHIRID(u.FHIRID, u.EHRURL)
	if err != nil {
		t.Fatalf("GetUserByFHIRID after update: %v", err)
	}
	if got.FirstName != "Robert" {
		t.Errorf("updated FirstName: got %q, want %q", got.FirstName, "Robert")
	}
	if got.Email != "bob.updated@example.com" {
		t.Errorf("updated Email: got %q, want %q", got.Email, "bob.updated@example.com")
	}
}

func TestGetUserByFHIRID_NotFound(t *testing.T) {
	store := newTestStore(t)
	_, err := store.GetUserByFHIRID("nonexistent", "https://ehr.example.com/fhir")
	if err != sql.ErrNoRows {
		t.Errorf("expected sql.ErrNoRows, got %v", err)
	}
}

func TestUpsertUser_TenantIsolation(t *testing.T) {
	// The same FHIR ID at two different EHR URLs must produce two separate records.
	store := newTestStore(t)

	makeUser := func(ehrURL string) *models.User {
		return &models.User{
			FHIRResourceType: "Patient",
			FHIRID:           "shared-fhir-id",
			EHRURL:           ehrURL,
			Role:             models.RolePatient,
			FirstName:        "Carol",
			LastName:         "Tenant",
		}
	}

	id1, err := store.UpsertUser(makeUser("https://ehr-a.example.com/fhir"))
	if err != nil {
		t.Fatalf("upsert EHR-A: %v", err)
	}
	id2, err := store.UpsertUser(makeUser("https://ehr-b.example.com/fhir"))
	if err != nil {
		t.Fatalf("upsert EHR-B: %v", err)
	}

	if id1 == id2 {
		t.Error("expected separate internal IDs for same FHIR ID at different EHR URLs")
	}
}

// ---------------------------------------------------------------------------
// Session tests
// ---------------------------------------------------------------------------

func TestCreateAndGetSession(t *testing.T) {
	store := newTestStore(t)

	// Create a practitioner user first.
	practUser := &models.User{
		FHIRResourceType: "Practitioner",
		FHIRID:           "pract-001",
		EHRURL:           "https://ehr.example.com/fhir",
		Role:             models.RolePractitioner,
		FirstName:        "Dr. Emily",
		LastName:         "Chen",
	}
	userID, err := store.UpsertUser(practUser)
	if err != nil {
		t.Fatalf("UpsertUser practitioner: %v", err)
	}

	// Create a session.
	sess, err := store.CreateSession(userID, "patient-001", "access-token-xyz", "id-token-abc", "openid profile", "https://ehr.example.com/fhir", 8*time.Hour)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if sess.ID == "" {
		t.Fatal("expected non-empty session ID")
	}

	// Retrieve the session.
	got, err := store.GetSession(sess.ID)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if got.UserID != userID {
		t.Errorf("UserID: got %q, want %q", got.UserID, userID)
	}
	if got.AccessToken != "access-token-xyz" {
		t.Errorf("AccessToken: got %q, want %q", got.AccessToken, "access-token-xyz")
	}
	if got.ExpiresAt.Before(time.Now()) {
		t.Error("session should not be expired immediately after creation")
	}
}

func TestDeleteSession(t *testing.T) {
	store := newTestStore(t)

	userID, err := store.UpsertUser(&models.User{
		FHIRResourceType: "Practitioner",
		FHIRID:           "pract-delete",
		EHRURL:           "https://ehr.example.com/fhir",
		Role:             models.RolePractitioner,
		FirstName:        "Test",
		LastName:         "Delete",
	})
	if err != nil {
		t.Fatalf("UpsertUser: %v", err)
	}

	sess, err := store.CreateSession(userID, "pat", "tok", "id", "scope", "https://ehr.example.com/fhir", time.Hour)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	if err := store.DeleteSession(sess.ID); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}

	_, err = store.GetSession(sess.ID)
	if err != sql.ErrNoRows {
		t.Errorf("expected sql.ErrNoRows after deletion, got %v", err)
	}
}

func TestDeleteExpiredSessions(t *testing.T) {
	store := newTestStore(t)

	userID, err := store.UpsertUser(&models.User{
		FHIRResourceType: "Practitioner",
		FHIRID:           "pract-expire",
		EHRURL:           "https://ehr.example.com/fhir",
		Role:             models.RolePractitioner,
		FirstName:        "Expire",
		LastName:         "Test",
	})
	if err != nil {
		t.Fatalf("UpsertUser: %v", err)
	}

	// Create one valid and one already-expired session.
	_, err = store.CreateSession(userID, "pat", "valid-tok", "id", "scope", "https://ehr.example.com/fhir", time.Hour)
	if err != nil {
		t.Fatalf("CreateSession (valid): %v", err)
	}
	_, err = store.CreateSession(userID, "pat", "expired-tok", "id", "scope", "https://ehr.example.com/fhir", -1*time.Second) // already past
	if err != nil {
		t.Fatalf("CreateSession (expired): %v", err)
	}

	n, err := store.DeleteExpiredSessions()
	if err != nil {
		t.Fatalf("DeleteExpiredSessions: %v", err)
	}
	if n != 1 {
		t.Errorf("deleted %d expired sessions, want 1", n)
	}
}
