# FHIR-Sandbox: SMART on FHIR Healthcare Platform

A production-quality Go-based platform for integrating with Electronic Health Record (EHR) systems using the SMART on FHIR protocol. This sandbox demonstrates authentication, persistence, and dashboarding for patient and practitioner data, serving as a robust starting point for healthcare applications.

## Features

- **SMART on FHIR Launch:** Supports the full SMART App Launch flow (EHR launch and standalone) with OAuth2 code exchange.
- **Identity Resolution:** Correctly handles practitioner identification from both `practitioner` and `user` (Practitioner/ID) fields in OAuth2 token responses.
- **Comprehensive FHIR Sync:** Automatically synchronizes and persists key clinical data:
  - Patient Demographics
  - Observations (Vitals, Labs)
  - Conditions (Problems)
  - DocumentReferences
  - MedicationRequests
  - AllergyIntolerances
- **SQLite Persistence:** Persists all synced data using a pure-Go SQLite driver (`modernc.org/sqlite`), requiring no CGO or external database server.
- **Secure Session Management:** Server-side sessions stored in SQLite with secure, HttpOnly cookies.
- **Responsive Dashboard:** A modern UI built with Go `html/template` that displays patient demographics, clinical data, and practitioner details.
- **Extensible Architecture:** Modular design with clean separation of concerns (`handlers`, `db`, `fhir`, `models`, `middleware`, `config`).

## Architecture

The project is structured into modular packages under `/app`:

- `/config`: Configuration structures and URL normalization.
- `/db`: Database schema, versioned migrations, and CRUD operations using `modernc.org/sqlite`.
- `/fhir`: FHIR R4 resource definitions, SMART discovery, and FHIR client logic.
- `/handlers`: HTTP request handlers (launch, auth, dashboard, sync) and template rendering.
- `/middleware`: Session management middleware (loading and hard-gate protection).
- `/models`: Core domain models and context keys.
- `/templates`: Embedded HTML templates with layout inheritance.

## Prerequisites

- **Go 1.24+**
- **No external database required** (uses embedded SQLite)

## Getting Started

1. **Clone the repository:**
   ```bash
   git clone https://github.com/AmanTahiliani/FHIR-Sandbox.git
   cd FHIR-Sandbox
   ```

2. **Run the application:**
   ```bash
   go run app/main.go
   ```
   The server starts on `http://localhost:8080`.

3. **Test with a Sandbox:**
   Use the [SMART Health IT Sandbox](https://launch.smarthealthit.org/):
   - **App Launch URL:** `http://localhost:8080/launch`
   - **Redirect URL:** `http://localhost:8080/auth-redirect`
   
   The default configuration in `main.go` is pre-set to work with the SmartHealthIT sandbox.

## Configuration

Configuration is currently managed in `app/main.go` via the `config.AppConfig` struct. You can define multiple EHRs, set your redirect URI, and required scopes directly in the code.

```go
// Example configuration in app/main.go
cfg := &config.AppConfig{
    DBPath: "fhir_sandbox.db",
    Server: config.ServerConfig{
        Port: 8080,
    },
    SMART: config.SMARTConfig{
        RedirectURL: "http://localhost:8080/auth-redirect",
        Scopes:      []string{"openid", "profile", "launch", "patient/*.read", "user/*.read"},
    },
    EHRs: []config.EHRConfig{
        {
            Name:         "SmartHealthIT Sandbox (R4)",
            FHIRURL:      "https://launch.smarthealthit.org/v/r4/fhir",
            ClientID:     "your-client-id",
            ClientSecret: "your-client-secret", // Optional, depending on EHR
        },
    },
}
```

## Testing

The project includes comprehensive unit tests for database logic, FHIR parsing, and clinical data handling.

- **Run all tests:**
  ```bash
  go test ./...
  ```

- **Run tests with coverage:**
  ```bash
  go test -cover ./...
  ```

## Future Improvements

- [ ] **Configuration Loading:** Implement a robust configuration loader (e.g., `spf13/viper`) to load settings from files or environment variables.
- [ ] **Structured Logging:** Migrate to Go 1.21's `log/slog` for structured, leveled logging.
- [ ] **Refresh Tokens:** Implement OAuth2 refresh token logic to maintain long-lived sessions.
- [ ] **Additional Resources:** Add support for Encounters, Procedures, Immunizations, etc.
- [ ] **Frontend Enhancement:** Evolve the UI with HTMX or a modern JS framework for better interactivity.
- [ ] **FHIR Type Safety:** Adopt a comprehensive FHIR library (e.g., `google/fhir/go`) for stricter type safety.
