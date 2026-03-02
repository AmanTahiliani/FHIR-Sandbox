package handlers

import (
	"io"
	"log"
	"net/http"
	"time"
)

const cgmReportProxyTimeout = 30 * time.Second

// HandleCGMReportProxy proxies CGM report requests (PDFs and images) from Rimidi Provider.
// This allows the browser to access reports without needing to handle API keys directly.
func (h *Handler) HandleCGMReportProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get the target URL from query parameter
	targetURL := r.URL.Query().Get("url")
	if targetURL == "" {
		http.Error(w, "Missing 'url' query parameter", http.StatusBadRequest)
		return
	}

	// Validate that the URL is from the configured Rimidi CGM API
	rimidiBaseURL := h.cfg.RimidiCGMAPIURL
	if rimidiBaseURL == "" {
		http.Error(w, "CGM API not configured", http.StatusServiceUnavailable)
		return
	}

	// Extract base URL (remove /{patient_pk}/cgm-preview/)
	baseURL := rimidiBaseURL
	if len(baseURL) > 20 {
		// Remove trailing path components to get base URL
		lastSlash := -1
		for i := len(baseURL) - 1; i >= 0; i-- {
			if baseURL[i] == '/' {
				lastSlash = i
				if i > 0 && baseURL[i-1] != '/' {
					break
				}
			}
		}
		if lastSlash > 0 {
			baseURL = baseURL[:lastSlash]
		}
	}
	// Remove /privateadmin/patients if present
	if len(baseURL) > 20 && baseURL[len(baseURL)-20:] == "/privateadmin/patients" {
		baseURL = baseURL[:len(baseURL)-20]
	}
	// Add /cshub if not present
	if len(baseURL) < 7 || baseURL[len(baseURL)-7:] != "/cshub" {
		baseURL = baseURL + "/cshub"
	}

	// Check if target URL starts with the expected base
	expectedPrefix := baseURL + "/api/cgm-report-proxy/"
	if len(targetURL) < len(expectedPrefix) || targetURL[:len(expectedPrefix)] != expectedPrefix {
		log.Printf("handlers: cgm-report-proxy invalid URL prefix: %s (expected: %s)", targetURL, expectedPrefix)
		http.Error(w, "Invalid URL", http.StatusBadRequest)
		return
	}

	// Call Rimidi Provider API with internal API key
	client := &http.Client{Timeout: cgmReportProxyTimeout}
	req, err := http.NewRequest(http.MethodGet, targetURL, nil)
	if err != nil {
		log.Printf("handlers: cgm-report-proxy new request: %v", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	req.Header.Set("X-Api-Key", h.cfg.RimidiInternalAPIKey)

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("handlers: cgm-report-proxy remote call failed: %v", err)
		http.Error(w, "Could not fetch report", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy response headers
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	// Set status code
	w.WriteHeader(resp.StatusCode)

	// Copy response body
	if _, err := io.Copy(w, resp.Body); err != nil {
		log.Printf("handlers: cgm-report-proxy copy response: %v", err)
		return
	}
}
