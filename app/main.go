package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
)

type Application struct {
	config *ApplicationConfig
}

type ApplicationConfig struct {
	smart *SMARTAppConfig
	eHRs  []EHRClientsConfig // List of EHR clients configuration
}

type SMARTAppConfig struct {
	oAuth1       bool   // Enable OAuth1 for certain EHRs
	oAuth2       bool   // Enable OAuth2 for others
	redirectPath string // Where to redirect after auth
	clientID     string // OAuth client ID (if applicable)
	clientSecret string // OAuth client secret
	scopes       []string
}

type EHRClientsConfig struct {
	name         string // Name of the EHR, e.g., "EHR_A"
	url          string // FHIR endpoint URL
	authType     string // auth-1 or auth-2 for OAuth type
	clientID     string // OAuth client ID (for Azure AD)
	clientSecret string // OAuth secret (for Azure AD)
	patientAPI   bool   // Whether to enable patient API endpoints
}

type LaunchContext struct {
	LaunchID string `json:"launch"`
	Patient  string `json:"patient"`
}

func main() {
	log.Printf("Starting EHR integration application...")

	appConfig := &ApplicationConfig{
		smart: &SMARTAppConfig{
			redirectPath: "http://localhost:8080/auth-redirect",
			clientID:     "my-smart-client-id",
			clientSecret: "my-smart-client-secret",
			scopes:       []string{"launch", "patient/*.read"},
			oAuth1:       true,
			oAuth2:       false,
		},
		eHRs: []EHRClientsConfig{ // Sample EHR clients configuration
			{
				name:         "EHR_A",
				url:          "https://launch.smarthealthit.org/v/r4/fhir",
				authType:     "auth-2",
				clientID:     "abcdefghijklmnopqrst",
				clientSecret: "ehr_a_client_secret",
				patientAPI:   true,
			},
			{
				name:         "EHR_B",
				url:          "https://ehr-b.healthcare-provider.com/fhir/v2",
				authType:     "auth-2",
				clientID:     "ehr_b_client_id", // OAuth 2.0 client ID
				clientSecret: "ehr_b_client_secret",
				patientAPI:   true,
			},
		},
	}

	app := &Application{
		config: appConfig,
	}

	log.Printf("Listening on port %d...", 8080)

	// Start HTTP server and handle routes
	http.HandleFunc("/", app.handleRoot)
	http.HandleFunc("/launch", app.handleLaunch)
	http.HandleFunc("/auth-redirect", app.handleAuthRedirect)

	log.Fatal(http.ListenAndServe(":8080", nil))
}

// handleRoot is a method of Application that handles the root endpoint.
func (app *Application) handleRoot(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("Welcome to the EHR integration application!"))
}

func getWellKnownUrl(iss string) (string, error) {
	wellKnownUrl := fmt.Sprintf("%s/.well-known/smart-configuration", iss)
	resp, err := http.Get(wellKnownUrl)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to fetch well-known URL")
	}

	var bodyBytes []byte
	bodyBytes, err = io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(bodyBytes), nil

}

// handleLaunch processes the SMART on FHIR launch request.
func (app *Application) handleLaunch(w http.ResponseWriter, r *http.Request) {
	launchID := r.URL.Query().Get("launch")
	iss := r.URL.Query().Get("iss")
	// Log the query parameters and body data for debugging
	log.Printf("Query parameters: %v", r.URL.Query())
	if launchID == "" || iss == "" {
		http.Error(w, "Missing launch or iss parameter", http.StatusBadRequest)
		return
	}

	// Validate the FHIR server base URL (iss)
	_, err := url.ParseRequestURI(iss)
	if err != nil {
		http.Error(w, "Invalid FHIR server base URL (iss)", http.StatusBadRequest)
		return
	}

	//Make sure the FHIR server base URL (iss) is registered in the application's configuration
	var ehrConfig *EHRClientsConfig
	for _, ehr := range app.config.eHRs {
		if ehr.url == iss {
			ehrConfig = &ehr
			break
		}
	}

	if ehrConfig == nil {
		http.Error(w, "Unsupported FHIR server base URL (iss)", http.StatusBadRequest)
		return
	}

	var clientID string
	var clientSecret string
	clientID = ehrConfig.clientID
	clientSecret = ehrConfig.clientSecret

	if clientID == "" || clientSecret == "" {
		http.Error(w, "Missing client ID or client secret", http.StatusBadRequest)
		return
	}

	wellKnownBody, err := getWellKnownUrl(iss)
	if err != nil {
		http.Error(w, "Failed to fetch SMART configuration from FHIR server", http.StatusInternalServerError)
		return
	}
	// Get the authorization endpoint from the wellKnownBody and use it to construct the authorization URL
	var discoveryDoc map[string]interface{}
	if err := json.NewDecoder(strings.NewReader(wellKnownBody)).Decode(&discoveryDoc); err != nil {
		http.Error(w, "Invalid SMART configuration response", http.StatusInternalServerError)
		return
	}

	authEndpoint, ok := discoveryDoc["authorization_endpoint"].(string)
	if !ok || authEndpoint == "" {
		http.Error(w, "Authorization endpoint not found in SMART configuration", http.StatusInternalServerError)
		return
	}

	// Generate a state value that can be used to identify the EHR client and can be used to prevent CSRF attacks.
	state := iss + "state_hash" + launchID

	// Construct the authorization URL
	authURL := fmt.Sprintf("%s?response_type=code&client_id=%s&redirect_uri=%s&launch=%s&scope=openid+profile+launch+patient/*.read&state=%s&aud=%s",
		authEndpoint, clientID, url.QueryEscape(app.config.smart.redirectPath), launchID, state, iss)

	http.Redirect(w, r, authURL, http.StatusFound)
}

// handleAuthRedirect processes the authorization redirect and retrieves patient details.
func (app *Application) handleAuthRedirect(w http.ResponseWriter, r *http.Request) {
	// Log the query parameters and body data for debugging
	log.Printf("Query parameters: %v", r.URL.Query())

	bodyData := make(map[string]interface{})
	if err := json.NewDecoder(r.Body).Decode(&bodyData); err != nil {
		log.Printf("Failed to decode body data: %v", err)
	} else {
		log.Printf("Body data: %v", bodyData)
	}
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	if code == "" || state == "" {
		http.Error(w, "Missing code or state parameter", http.StatusBadRequest)
		return
	}
	// Extract the EHR client ID from the state parameter
	stateParts := strings.Split(state, "state_hash")
	if len(stateParts) != 2 {
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}
	ehr_iss := stateParts[0]
	// Fetch the EHR client configuration based on the EHR client ID
	var ehrConfig *EHRClientsConfig
	for _, ehr := range app.config.eHRs {
		if ehr.url == ehr_iss {
			ehrConfig = &ehr
			break
		}
	}
	if ehrConfig == nil {
		http.Error(w, "Unsupported EHR client", http.StatusBadRequest)
		return
	}
	wellKnownBody, err := getWellKnownUrl(ehr_iss)
	if err != nil {
		http.Error(w, "Failed to fetch SMART configuration from FHIR server", http.StatusInternalServerError)
		return
	}
	// Construct the token request URL from the well-knownBody
	var discoveryDoc map[string]interface{}
	if err := json.NewDecoder(strings.NewReader(wellKnownBody)).Decode(&discoveryDoc); err != nil {
		http.Error(w, "Invalid SMART configuration response", http.StatusInternalServerError)
		return
	}
	tokenEndpoint, ok := discoveryDoc["token_endpoint"].(string)
	if !ok || tokenEndpoint == "" {
		http.Error(w, "Token endpoint not found in SMART configuration", http.StatusInternalServerError)
		return
	}

	// Construct the token request URL from the well-knownBody
	// Prepare form data for token request
	formData := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {app.config.smart.redirectPath},
	}

	// Create request with Basic authentication
	req, err := http.NewRequest("POST", tokenEndpoint, strings.NewReader(formData.Encode()))
	if err != nil {
		http.Error(w, "Failed to exchange authorization code for token", http.StatusInternalServerError)
		return
	}

	// Add required headers
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(ehrConfig.clientID, ehrConfig.clientSecret)

	// Make the token request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("Failed to make token request: %v", err)
		http.Error(w, "Failed to exchange authorization code for token: ", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Printf("Failed to exchange authorization code for token: %v", resp.Status)

		// Decode and log the response body
		var responseBody map[string]interface{}
		bodyBytes, _ := io.ReadAll(resp.Body)
		if err := json.Unmarshal(bodyBytes, &responseBody); err != nil {
			log.Printf("Failed to decode token response body: %v", err)
		} else {
			log.Printf("Token response: %v", responseBody)
		}
		// Reset the response body for later use
		resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		http.Error(w, "Failed to exchange authorization code for token", http.StatusInternalServerError)
		return
	}
	// Parse the token response
	var tokenResponse map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		http.Error(w, "Invalid token response", http.StatusInternalServerError)
		return
	}
	//log the token response
	log.Printf("Token response: %v", tokenResponse)
	// Extract the access token and patient ID from the token response
	accessToken, ok := tokenResponse["access_token"].(string)
	if !ok || accessToken == "" {
		http.Error(w, "Access token not found in token response", http.StatusInternalServerError)
		return
	}
	patientID, ok := tokenResponse["patient"].(string)
	if !ok || patientID == "" {
		http.Error(w, "Patient ID not found in token response", http.StatusInternalServerError)
		return
	}
	// Fetch patient details from the EHR using the access token
	patientURL := fmt.Sprintf("%s/Patient/%s", ehrConfig.url, patientID)

	req, err = http.NewRequest("GET", patientURL, nil)
	if err != nil {
		http.Error(w, "Failed to create patient details request", http.StatusInternalServerError)
		return
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		http.Error(w, "Failed to fetch patient details", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		http.Error(w, "Failed to fetch patient details", http.StatusInternalServerError)
		return
	}
	// Parse the patient details response
	var patientDetails map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&patientDetails); err != nil {
		http.Error(w, "Invalid patient details response", http.StatusInternalServerError)
		return
	}
	// Log the patient details for debugging purposes
	log.Printf("Patient details: %v", patientDetails)
	// Render the patient details in the response
	w.Header().Set("Content-Type", "text/html")
	// Create HTML table header
	html := "<html><head><style>table,th,td {border: 1px solid black; border-collapse: collapse; padding: 5px;}</style></head><body>"
	html += "<h2>Patient Details</h2><table>"

	// Recursively build table rows from JSON
	var buildTableRows func(data map[string]interface{}, indent string) string
	buildTableRows = func(data map[string]interface{}, indent string) string {
		var rows string
		for key, value := range data {
			rows += "<tr>"
			rows += fmt.Sprintf("<td><strong>%s%s</strong></td>", indent, key)

			switch v := value.(type) {
			case map[string]interface{}:
				rows += "<td>" + buildTableRows(v, indent+"&nbsp;&nbsp;") + "</td>"
			case []interface{}:
				rows += "<td><table>"
				for _, item := range v {
					if m, ok := item.(map[string]interface{}); ok {
						rows += buildTableRows(m, indent+"&nbsp;&nbsp;")
					} else {
						rows += fmt.Sprintf("<tr><td>%v</td></tr>", item)
					}
				}
				rows += "</table></td>"
			default:
				rows += fmt.Sprintf("<td>%v</td>", v)
			}
			rows += "</tr>"
		}
		return rows
	}

	html += buildTableRows(patientDetails, "")
	html += "</table></body></html>"

	w.Write([]byte(html))
}
