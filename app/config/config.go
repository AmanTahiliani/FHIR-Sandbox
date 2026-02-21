// Package config defines the application configuration types.
//
// The AppConfig struct is the single source of truth for all runtime
// settings. Currently values are populated programmatically in main.go,
// but the structure is designed so that a future loader (e.g., from a
// TOML/YAML file or environment variables) can populate it without
// changing how the rest of the codebase consumes configuration.
package config

// AppConfig is the root configuration for the platform.
type AppConfig struct {
	// Server holds HTTP server settings.
	Server ServerConfig

	// SMART holds the platform's own OAuth2 identity.
	SMART SMARTConfig

	// EHRs is the list of registered EHR FHIR server configurations.
	EHRs []EHRConfig

	// DBPath is the file path for the SQLite database.
	// Use ":memory:" for in-process testing.
	DBPath string
}

// ServerConfig holds HTTP server settings.
type ServerConfig struct {
	// Port is the port the HTTP server listens on.
	Port int
}

// SMARTConfig holds the platform's own SMART on FHIR OAuth2 identity.
type SMARTConfig struct {
	// RedirectURL is the full URL for the OAuth2 callback endpoint,
	// e.g. "http://localhost:8080/auth-redirect".
	RedirectURL string

	// Scopes is the list of OAuth2 scopes requested during authorization.
	// Standard SMART scopes: launch, openid, profile, patient/*.read, etc.
	Scopes []string
}

// EHRConfig describes a registered EHR FHIR server.
type EHRConfig struct {
	// Name is a human-readable label for this EHR (e.g., "SmartHealthIT Sandbox").
	Name string

	// FHIRURL is the FHIR server base URL used as the `iss` parameter.
	// This is the canonical identifier for matching incoming launch requests.
	FHIRURL string

	// ClientID is the OAuth2 client_id registered with this EHR.
	ClientID string

	// ClientSecret is the OAuth2 client_secret registered with this EHR.
	// In production this should be loaded from a secrets manager, not
	// hardcoded in source.
	ClientSecret string
}

// EHRByURL returns the EHRConfig whose FHIRURL matches the given URL,
// normalising trailing slashes for comparison.
// Returns nil if no match is found.
func (c *AppConfig) EHRByURL(url string) *EHRConfig {
	// Trim trailing slash for comparison robustness.
	url = trimTrailingSlash(url)
	for i := range c.EHRs {
		if trimTrailingSlash(c.EHRs[i].FHIRURL) == url {
			return &c.EHRs[i]
		}
	}
	return nil
}

func trimTrailingSlash(s string) string {
	if len(s) > 0 && s[len(s)-1] == '/' {
		return s[:len(s)-1]
	}
	return s
}
