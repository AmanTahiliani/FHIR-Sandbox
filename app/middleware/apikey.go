// Package middleware — apikey.go provides API key authentication for
// machine-to-machine endpoints (e.g., /api/patient-match).
//
// The middleware reads the X-Api-Key header and compares it against
// a configured expected value. It is applied only to /api/* routes
// via the route registration in main.go.
package middleware

import (
	"net/http"
)

// APIKeyMiddleware validates the X-Api-Key header on incoming requests.
type APIKeyMiddleware struct {
	expectedKey string
}

// NewAPIKeyMiddleware creates a middleware that gates requests behind
// the given API key.
func NewAPIKeyMiddleware(expectedKey string) *APIKeyMiddleware {
	return &APIKeyMiddleware{expectedKey: expectedKey}
}

// Wrap returns an http.Handler that checks for a valid API key before
// delegating to the wrapped handler. Returns 401 if the key is missing
// and 403 if the key is incorrect.
func (m *APIKeyMiddleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("X-Api-Key")
		if key == "" {
			http.Error(w, `{"error":"missing API key"}`, http.StatusUnauthorized)
			return
		}
		if key != m.expectedKey {
			http.Error(w, `{"error":"invalid API key"}`, http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
