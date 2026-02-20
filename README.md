# FHIR-Sandbox: SMART on FHIR Healthcare Platform

A production-quality Go-based platform for integrating with Electronic Health Record (EHR) systems using the SMART on FHIR protocol. This sandbox demonstrates authentication, persistence, and dashboarding for patient and practitioner data.

## Features

- **SMART on FHIR Launch:** Supports the full SMART App Launch flow (EHR launch and standalone).
- **Identity Resolution:** Correctly handles practitioner identification from both `practitioner` and `user` (Practitioner/ID) fields in OAuth2 token responses.
- **SQLite Persistence:** Persists patient and practitioner data upon successful launch using a pure-Go SQLite driver (no CGO required).
- **Session Management:** Server-side sessions stored in SQLite with secure, HttpOnly cookies.
- **Responsive Dashboard:** A modern UI built with Go `html/template` that displays patient demographics and practitioner details.
- **Extensible Architecture:** Clean package separation (`handlers`, `db`, `fhir`, `models`, `middleware`, `config`) designed for growth.

## Architecture

The project is structured into modular packages under `/app`:
- `/db`: Database schema, migrations, and CRUD operations using `modernc.org/sqlite`.
- `/fhir`: FHIR R4 resource definitions and SMART discovery/client logic.
- `/handlers`: HTTP request handlers and template rendering.
- `/middleware`: Session loading and authentication guards.
- `/models`: Shared data structures.
- `/templates`: HTML templates with layout inheritance.

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
   - The default configuration in `main.go` is pre-set to work with the SmartHealthIT sandbox.

## Configuration

Configuration is currently managed in `app/main.go` via `config.AppConfig`. You can define multiple EHRs, set your redirect URI, and required scopes.

```go
cfg := &config.AppConfig{
    DBPath: "fhir_sandbox.db",
    SMART: config.SMARTConfig{
        RedirectURL: "http://localhost:8080/auth-redirect",
        Scopes:      []string{"openid", "profile", "launch", "patient/*.read", "user/*.read"},
    },
    EHRs: []config.EHRConfig{
        {
            Name:     "SmartHealthIT Sandbox (R4)",
            FHIRURL:  "https://launch.smarthealthit.org/v/r4/fhir",
            ClientID: "your-client-id",
        },
    },
}
```

## Testing

The project includes unit tests for database logic and FHIR parsing.

```bash
go test ./...
```

## Future Improvements

- [ ] Support for Observations, Conditions, and Encounters.
- [ ] Move configuration to a YAML/TOML file.
- [ ] Add structured logging (slog).
- [ ] Implement Refresh Token handling.
