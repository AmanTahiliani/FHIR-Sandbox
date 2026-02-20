# AI Agent Developer Guide (AGENTS.md)

This document provides essential information for AI coding agents (like yourself) to work efficiently in the **FHIR-Sandbox** repository. It covers build/test commands, code style guidelines, and the project's architecture.

---

## 1. Build, Lint, and Test Commands

### Build & Run
- **Build the binary:**
  ```bash
  go build -o fhir-sandbox app/main.go
  ```
- **Run the application:**
  ```bash
  go run app/main.go
  ```
  The server starts on `http://localhost:8080` by default.

### Testing
- **Run all tests:**
  ```bash
  go test ./...
  ```
- **Run a single test (by name):**
  ```bash
  go test -v -run TestName ./app/db
  ```
- **Run tests with coverage:**
  ```bash
  go test -cover ./...
  ```
  *Note: New features MUST include `_test.go` files. We have 100% coverage on core DB and FHIR logic.*

### Linting & Formatting
- **Standard Go formatting:**
  ```bash
  go fmt ./...
  ```
- **Import management (using goimports if available):**
  ```bash
  goimports -w .
  ```
- **Static analysis (vet):**
  ```bash
  go vet ./...
  ```

---

## 2. Code Style Guidelines

### General Principles
- **Simplicity:** Prefer standard library packages (e.g., `net/http`, `encoding/json`) over complex frameworks unless strictly necessary.
- **Explicit over Implicit:** Do not use magic values. Use constants or configuration fields.
- **Idiomatic Go:** Follow the patterns described in [Effective Go](https://golang.org/doc/effective_go).

### Imports
Group imports into three blocks, separated by a blank line:
1. Standard library imports (alphabetical).
2. Third-party library imports (alphabetical).
3. Local project imports (alphabetical).

```go
import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/google/uuid"

	"github.com/AmanTahiliani/FHIR-Sandbox/app/models"
)
```

### Naming Conventions
- **Exported items:** `PascalCase`.
- **Unexported items:** `camelCase`.
- **Receiver names:** Use 1-3 letter abbreviations (e.g., `func (app *Application) ...`).
- **Interfaces:** Usually end in `-er` (e.g., `FHIRClient`).
- **Variables:** Use short names for short-lived variables (`err`, `w`, `r`) and descriptive names for long-lived ones.

### Formatting
- Use **tabs** for indentation (Go standard).
- Limit line length to **120 characters** where possible for readability.
- Braces: Standard Go placement (opening brace on the same line).

### Types & Data Structures
- **Structs for Configuration:** Group related settings into nested structs (e.g., `ApplicationConfig`, `SMARTAppConfig`).
- **JSON Tags:** Always include JSON tags for structs that will be serialized or deserialized from JSON.
  ```go
  type LaunchContext struct {
  	LaunchID string `json:"launch"`
  	Patient  string `json:"patient"`
  }
  ```

### Error Handling
- **Never ignore errors:** Always check `if err != nil`.
- **Wrap errors:** Use `fmt.Errorf("context: %w", err)` to provide additional context for debugging.
- **HTTP Error responses:** Use `http.Error(w, message, code)` for standard error reporting to the client.
- **Logging errors:** Log significant errors using `log.Printf` or a structured logger if introduced.

### Logging
- Currently uses the standard `log` package.
- Always include context in logs (e.g., "Failed to fetch well-known URL: %v").
- Do not log sensitive information like `client_secret` or `access_token` in production-like environments.

---

## 3. SMART on FHIR Implementation Guidelines

### Launch Flow
The application implements the SMART on FHIR launch flow. When modifying the launch logic:
- **`iss` parameter:** This is the FHIR server base URL. It must be validated.
- **`launch` parameter:** The opaque launch ID provided by the EHR.
- **Discovery:** Always use the `.well-known/smart-configuration` endpoint to find `authorization_endpoint` and `token_endpoint`.

### Security
- **State Parameter:** Use the `state` parameter to maintain context and prevent CSRF attacks. The current implementation uses cryptographically secure random values via `crypto/rand` and stores launch context server-side in a short-lived in-memory map (expires after 10 minutes).
- **Basic Auth:** Use `req.SetBasicAuth(clientID, clientSecret)` for the token exchange when required by the EHR.
- **Bearer Tokens:** Always include the `Authorization: Bearer <token>` header when fetching FHIR resources.

### FHIR Resources
- When fetching patient details, expect JSON and decode it into `map[string]interface{}` for flexibility, or define specific FHIR resource structs for better type safety.

### Handler Implementation Notes
- **Template Rendering:** Templates are parsed on every request (base.html + page.html) to avoid global template state conflicts. This is correct Go best practice.
- **Handler HTTP Methods:** All handler methods check the request method explicitly. For example, `/dashboard/sync` accepts both GET (auto-sync on first load) and POST (manual sync from UI).
- **State Store:** The in-memory state store in `launch.go` expires entries after 10 minutes and implements a 10-second grace period for duplicate requests.
- **Middleware Chain:** The session middleware provides both hard-gate (`RequireSession`) and soft-load (`LoadSession`) middleware. Hard-gate routes redirect unauthenticated users to `/`, while soft-load routes allow unauthenticated access but attach session context if present.

---

## 4. Project Structure

The project is organised into modular packages under `/app`:
- `/app/config`: Configuration structures and URL normalisation.
- `/app/db`: SQLite storage, versioned migrations, and CRUD operations.
- `/app/fhir`: FHIR R4 type definitions, SMART discovery, and FHIR client.
- `/app/handlers`: HTTP handlers (launch.go, auth.go, dashboard.go, sync.go, logout.go, patients.go) and per-render template logic.
- `/app/middleware`: Session management middleware (session loading, hard-gate protection).
- `/app/models`: Core domain models and context keys.
- `/app/templates`: Embedded HTML templates (base.html, index.html, dashboard.html, patients.html, error.html).

- `app/main.go`: Application entry point and dependency wiring.
- `go.mod`: Go module definition (v1.24.0).

---

## 5. Current Implementation Status
The application has the following features implemented:
- Full SMART on FHIR launch flow with OAuth2 code exchange
- Session management with server-side state validation
- FHIR resource sync for: Observations, Conditions, DocumentReferences, MedicationRequests, and AllergyIntolerances
- SQLite storage with CRUD operations for all synced resources
- Patient dashboard with clinical data display
- Patient list view for browsing all synced patients

## 6. Future Improvements for Agents
When working in this repo, consider the following high-priority improvements:
1. **Configuration Loading:** Implement a robust configuration loader for `app/main.go` (e.g., using `spf13/viper` or environment variables).
2. **Structured Logging:** Move from the standard `log` package to Go 1.21's `log/slog` for better performance and structured logging.
3. **Refresh Tokens:** Implement OAuth2 refresh token logic to maintain long-lived sessions without requiring re-authentication.
4. **Additional FHIR Resources:** Add support for more resources like Encounters, Procedures, Immunizations, etc.
5. **Frontend Enhancement:** Evolve the current templates into a more dynamic UI with better interactivity (e.g., using HTMX, htmx+ forms, or a modern JS framework if appropriate).
6. **FHIR Type Safety:** Consider using a comprehensive FHIR library (e.g., `google/fhir/go`) for type-safe resource handling as the scope grows.
7. **Testing:** Add comprehensive handler and integration tests to complement the existing db and fhir package tests.

---
*Created by AI Agent. Updated Feb 2026.*
