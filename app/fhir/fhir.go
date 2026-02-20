// Package fhir provides typed representations of FHIR R4 resources and
// utilities for extracting platform-domain data from raw FHIR JSON payloads.
//
// Architecture notes:
//   - FHIR resources are received from EHR servers as JSON and decoded into
//     typed Go structs defined here. This gives us compile-time safety and
//     makes it straightforward to add support for new resource types.
//   - The Resource interface is the root of all FHIR types in this package.
//     Any new resource (Observation, Condition, Encounter, etc.) should
//     implement it so it can be handled generically by shared code.
//   - Extraction helpers (ExtractUserFromPatient, ExtractUserFromPractitioner)
//     translate FHIR types into the platform's models.User, decoupling the
//     FHIR representation from the persistence layer.
//   - The Client type wraps http.Client and provides typed FHIR API methods.
//     Extend it with new methods (GetObservations, GetConditions, etc.) as
//     the platform grows.
package fhir

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/AmanTahiliani/FHIR-Sandbox/app/models"
)

// ---------------------------------------------------------------------------
// Core FHIR R4 types
// ---------------------------------------------------------------------------

// Resource is the base interface for all FHIR R4 resources in this package.
// Every concrete FHIR type must implement ResourceType() returning its
// FHIR resource type string (e.g., "Patient", "Practitioner").
type Resource interface {
	ResourceType() string
}

// HumanName represents the FHIR HumanName data type (R4).
// https://www.hl7.org/fhir/datatypes.html#HumanName
type HumanName struct {
	Use    string   `json:"use"`
	Family string   `json:"family"`
	Given  []string `json:"given"`
	Prefix []string `json:"prefix"`
	Suffix []string `json:"suffix"`
	Text   string   `json:"text"`
}

// ContactPoint represents the FHIR ContactPoint data type (R4).
// https://www.hl7.org/fhir/datatypes.html#ContactPoint
type ContactPoint struct {
	System string `json:"system"` // phone | fax | email | pager | url | sms | other
	Value  string `json:"value"`
	Use    string `json:"use"` // home | work | temp | old | mobile
	Rank   int    `json:"rank"`
}

// Address represents the FHIR Address data type (R4).
// https://www.hl7.org/fhir/datatypes.html#Address
type Address struct {
	Use        string   `json:"use"`
	Type       string   `json:"type"`
	Text       string   `json:"text"`
	Line       []string `json:"line"`
	City       string   `json:"city"`
	District   string   `json:"district"`
	State      string   `json:"state"`
	PostalCode string   `json:"postalCode"`
	Country    string   `json:"country"`
}

// Coding represents the FHIR Coding data type (R4).
type Coding struct {
	System  string `json:"system"`
	Code    string `json:"code"`
	Display string `json:"display"`
}

// CodeableConcept represents the FHIR CodeableConcept data type (R4).
type CodeableConcept struct {
	Coding []Coding `json:"coding"`
	Text   string   `json:"text"`
}

// Reference represents the FHIR Reference data type (R4).
type Reference struct {
	Reference string `json:"reference"`
	Display   string `json:"display"`
	Type      string `json:"type"`
}

// Identifier represents the FHIR Identifier data type (R4).
type Identifier struct {
	Use    string          `json:"use"`
	Type   CodeableConcept `json:"type"`
	System string          `json:"system"`
	Value  string          `json:"value"`
}

// Meta represents the FHIR Meta data type (R4).
type Meta struct {
	VersionID   string    `json:"versionId"`
	LastUpdated time.Time `json:"lastUpdated"`
	Source      string    `json:"source"`
	Profile     []string  `json:"profile"`
}

// ---------------------------------------------------------------------------
// Patient resource (R4)
// https://www.hl7.org/fhir/patient.html
// ---------------------------------------------------------------------------

// Patient represents a FHIR R4 Patient resource.
// Fields are a curated subset of the full specification — add new fields
// here as the platform needs them, without breaking existing code.
type Patient struct {
	ResourceTypeField string          `json:"resourceType"`
	ID                string          `json:"id"`
	Meta              Meta            `json:"meta"`
	Identifier        []Identifier    `json:"identifier"`
	Active            bool            `json:"active"`
	Name              []HumanName     `json:"name"`
	Telecom           []ContactPoint  `json:"telecom"`
	Gender            string          `json:"gender"`
	BirthDate         string          `json:"birthDate"`
	Address           []Address       `json:"address"`
	MaritalStatus     CodeableConcept `json:"maritalStatus"`
}

// ResourceType implements the Resource interface.
func (p *Patient) ResourceType() string { return "Patient" }

// ---------------------------------------------------------------------------
// Practitioner resource (R4)
// https://www.hl7.org/fhir/practitioner.html
// ---------------------------------------------------------------------------

// Practitioner represents a FHIR R4 Practitioner resource.
type Practitioner struct {
	ResourceTypeField string         `json:"resourceType"`
	ID                string         `json:"id"`
	Meta              Meta           `json:"meta"`
	Identifier        []Identifier   `json:"identifier"`
	Active            bool           `json:"active"`
	Name              []HumanName    `json:"name"`
	Telecom           []ContactPoint `json:"telecom"`
	Gender            string         `json:"gender"`
	BirthDate         string         `json:"birthDate"`
	Address           []Address      `json:"address"`
}

// ResourceType implements the Resource interface.
func (p *Practitioner) ResourceType() string { return "Practitioner" }

// ---------------------------------------------------------------------------
// Clinical resources (R4)
// ---------------------------------------------------------------------------

// ObservationComponent represents a component of an Observation (used for
// compound observations like blood pressure with systolic/diastolic values).
type ObservationComponent struct {
	Code          CodeableConcept `json:"code"`
	ValueQuantity *Quantity       `json:"valueQuantity,omitempty"`
	ValueString   string          `json:"valueString,omitempty"`
}

// ObservationReferenceRange represents a reference range for an Observation.
type ObservationReferenceRange struct {
	Low  *Quantity       `json:"low,omitempty"`
	High *Quantity       `json:"high,omitempty"`
	Text string          `json:"text,omitempty"`
	Type CodeableConcept `json:"type,omitempty"`
}

// Observation represents a FHIR R4 Observation resource.
// https://www.hl7.org/fhir/observation.html
type Observation struct {
	ResourceTypeField string                      `json:"resourceType"`
	ID                string                      `json:"id"`
	Status            string                      `json:"status"`
	Category          []CodeableConcept           `json:"category"`
	Code              CodeableConcept             `json:"code"`
	Subject           Reference                   `json:"subject"`
	EffectiveDateTime string                      `json:"effectiveDateTime"`
	ValueQuantity     *Quantity                   `json:"valueQuantity,omitempty"`
	ValueString       string                      `json:"valueString,omitempty"`
	Interpretation    []CodeableConcept           `json:"interpretation,omitempty"`
	ReferenceRange    []ObservationReferenceRange `json:"referenceRange,omitempty"`
	Component         []ObservationComponent      `json:"component,omitempty"`
}

func (o *Observation) ResourceType() string { return "Observation" }

// Condition represents a FHIR R4 Condition resource.
// https://www.hl7.org/fhir/condition.html
type Condition struct {
	ResourceTypeField  string            `json:"resourceType"`
	ID                 string            `json:"id"`
	ClinicalStatus     CodeableConcept   `json:"clinicalStatus"`
	VerificationStatus CodeableConcept   `json:"verificationStatus"`
	Category           []CodeableConcept `json:"category"`
	Code               CodeableConcept   `json:"code"`
	Subject            Reference         `json:"subject"`
	OnsetDateTime      string            `json:"onsetDateTime"`
	RecordedDate       string            `json:"recordedDate"`
}

func (c *Condition) ResourceType() string { return "Condition" }

// Attachment represents the FHIR Attachment data type.
type Attachment struct {
	ContentType string `json:"contentType"`
	Language    string `json:"language"`
	Data        string `json:"data"` // base64-encoded
	URL         string `json:"url"`
	Title       string `json:"title"`
	Creation    string `json:"creation"`
}

// DocumentReferenceContent holds a single content item in a DocumentReference.
type DocumentReferenceContent struct {
	Attachment Attachment      `json:"attachment"`
	Format     CodeableConcept `json:"format"`
}

// DocumentReference represents a FHIR R4 DocumentReference resource.
// https://www.hl7.org/fhir/documentreference.html
type DocumentReference struct {
	ResourceTypeField string                     `json:"resourceType"`
	ID                string                     `json:"id"`
	Status            string                     `json:"status"`
	DocStatus         string                     `json:"docStatus"`
	Type              CodeableConcept            `json:"type"`
	Category          []CodeableConcept          `json:"category"`
	Subject           Reference                  `json:"subject"`
	Date              string                     `json:"date"`
	Description       string                     `json:"description"`
	Content           []DocumentReferenceContent `json:"content"`
}

func (d *DocumentReference) ResourceType() string { return "DocumentReference" }

// Dosage represents the FHIR Dosage data type (simplified).
type Dosage struct {
	Text   string          `json:"text"`
	Timing interface{}     `json:"timing,omitempty"`
	Route  CodeableConcept `json:"route,omitempty"`
}

// DoseAndRate represents a dose and rate in a Dosage.
type DoseAndRate struct {
	DoseQuantity *Quantity   `json:"doseQuantity,omitempty"`
	DoseRange    interface{} `json:"doseRange,omitempty"`
	RateQuantity *Quantity   `json:"rateQuantity,omitempty"`
	RateRange    interface{} `json:"rateRange,omitempty"`
}

// MedicationRequest represents a FHIR R4 MedicationRequest resource.
// https://www.hl7.org/fhir/medicationrequest.html
type MedicationRequest struct {
	ResourceTypeField         string          `json:"resourceType"`
	ID                        string          `json:"id"`
	Status                    string          `json:"status"`
	Intent                    string          `json:"intent"`
	MedicationCodeableConcept CodeableConcept `json:"medicationCodeableConcept"`
	Subject                   Reference       `json:"subject"`
	AuthoredOn                string          `json:"authoredOn"`
	Requester                 Reference       `json:"requester"`
	DosageInstruction         []Dosage        `json:"dosageInstruction"`
}

func (m *MedicationRequest) ResourceType() string { return "MedicationRequest" }

// AllergyIntolerance represents a FHIR R4 AllergyIntolerance resource.
// https://www.hl7.org/fhir/allergyintolerance.html
type AllergyIntolerance struct {
	ResourceTypeField  string          `json:"resourceType"`
	ID                 string          `json:"id"`
	ClinicalStatus     CodeableConcept `json:"clinicalStatus"`
	VerificationStatus CodeableConcept `json:"verificationStatus"`
	Type               string          `json:"type"`
	Category           []string        `json:"category"`
	Criticality        string          `json:"criticality"`
	Code               CodeableConcept `json:"code"`
	Patient            Reference       `json:"patient"`
	RecordedDate       string          `json:"recordedDate"`
}

func (a *AllergyIntolerance) ResourceType() string { return "AllergyIntolerance" }

// Quantity represents the FHIR Quantity data type.
type Quantity struct {
	Value  float64 `json:"value"`
	Unit   string  `json:"unit"`
	System string  `json:"system"`
	Code   string  `json:"code"`
}

// BundleLink represents a link element in a Bundle (used for pagination).
type BundleLink struct {
	Relation string `json:"relation"`
	URL      string `json:"url"`
}

// Bundle represents a FHIR R4 Bundle resource, used for search results.
type Bundle struct {
	ResourceType string       `json:"resourceType"`
	Type         string       `json:"type"`
	Total        int          `json:"total"`
	Link         []BundleLink `json:"link"`
	Entry        []struct {
		FullUrl  string          `json:"fullUrl"`
		Resource json.RawMessage `json:"resource"`
	} `json:"entry"`
}

// ---------------------------------------------------------------------------
// SMART discovery types
// ---------------------------------------------------------------------------

// SmartConfiguration represents the payload returned by the FHIR server's
// .well-known/smart-configuration endpoint.
// https://build.fhir.org/ig/HL7/smart-app-launch/conformance.html
type SmartConfiguration struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	RegistrationEndpoint              string   `json:"registration_endpoint"`
	ScopesSupported                   []string `json:"scopes_supported"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	Capabilities                      []string `json:"capabilities"`
}

// TokenResponse is the OAuth2 token endpoint response, extended with
// SMART-specific fields.
// https://build.fhir.org/ig/HL7/smart-app-launch/
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`

	// SMART launch context extensions
	Patient   string `json:"patient"`
	Encounter string `json:"encounter"`
	// Practitioner holds a bare Practitioner FHIR ID when provided by the EHR.
	Practitioner string `json:"practitioner"`
	// User holds a relative FHIR reference to the authenticated user,
	// e.g. "Practitioner/52919099-..." as returned by SmartHealthIT and
	// defined in the SMART App Launch specification.
	User              string `json:"user"`
	NeedPatientBanner bool   `json:"need_patient_banner"`
	SmartStyleURL     string `json:"smart_style_url"`
}

// ---------------------------------------------------------------------------
// FHIR API Client
// ---------------------------------------------------------------------------

// Client is a thin, typed FHIR R4 REST client. It holds an access token
// and the FHIR server base URL so callers don't have to manage headers
// on every request.
//
// To support new resource types: add a method like GetObservations,
// GetConditions, etc., following the pattern of GetPatient / GetPractitioner.
type Client struct {
	httpClient  *http.Client
	baseURL     string
	accessToken string
}

// NewClient creates a FHIR API client for the given base URL and Bearer token.
func NewClient(baseURL, accessToken string) *Client {
	return &Client{
		httpClient:  &http.Client{Timeout: 30 * time.Second},
		baseURL:     strings.TrimRight(baseURL, "/"),
		accessToken: accessToken,
	}
}

// get performs an authenticated GET request to the FHIR server and decodes
// the JSON response into dest.
func (c *Client) get(path string, dest interface{}) error {
	url := fmt.Sprintf("%s/%s", c.baseURL, strings.TrimLeft(path, "/"))
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("fhir: build request for %s: %w", url, err)
	}
	req.Header.Set("Authorization", "Bearer "+c.accessToken)
	req.Header.Set("Accept", "application/fhir+json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("fhir: GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("fhir: GET %s returned %d: %s", url, resp.StatusCode, string(body))
	}

	if err := json.NewDecoder(resp.Body).Decode(dest); err != nil {
		return fmt.Errorf("fhir: decode response from %s: %w", url, err)
	}
	return nil
}

// fetchAllBundlePages follows pagination links in a Bundle and accumulates all entries.
// It fetches the initial bundle and then follows 'next' links up to maxPages times.
// Returns a slice of raw JSON entries and any error encountered.
func (c *Client) fetchAllBundlePages(initialBundle *Bundle, maxPages int) ([]json.RawMessage, error) {
	if maxPages < 1 {
		maxPages = 1
	}

	var allEntries []json.RawMessage
	for _, entry := range initialBundle.Entry {
		allEntries = append(allEntries, entry.Resource)
	}

	currentBundle := initialBundle
	pageCount := 1

	for pageCount < maxPages {
		nextURL := ""
		for _, link := range currentBundle.Link {
			if link.Relation == "next" {
				nextURL = link.URL
				break
			}
		}

		if nextURL == "" {
			break
		}

		// Extract path from absolute URL
		var nextBundle Bundle
		if err := c.get(strings.TrimPrefix(nextURL, c.baseURL+"/"), &nextBundle); err != nil {
			// Don't fail on pagination error; return what we have so far
			break
		}

		for _, entry := range nextBundle.Entry {
			allEntries = append(allEntries, entry.Resource)
		}

		currentBundle = &nextBundle
		pageCount++
	}

	return allEntries, nil
}

// GetPatient fetches a Patient resource by FHIR ID.
func (c *Client) GetPatient(id string) (*Patient, error) {
	var p Patient
	if err := c.get(fmt.Sprintf("Patient/%s", id), &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// GetPractitioner fetches a Practitioner resource by FHIR ID.
func (c *Client) GetPractitioner(id string) (*Practitioner, error) {
	var p Practitioner
	if err := c.get(fmt.Sprintf("Practitioner/%s", id), &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// GetObservations fetches Observation resources for a specific patient.
// If since is non-empty, only fetches observations modified after that timestamp (RFC3339).
func (c *Client) GetObservations(patientID, since string) ([]Observation, error) {
	var bundle Bundle
	path := fmt.Sprintf("Observation?patient=%s&_sort=-date", patientID)
	if since != "" {
		path += fmt.Sprintf("&_lastUpdated=ge%s", since)
	}
	if err := c.get(path, &bundle); err != nil {
		return nil, err
	}

	entries, err := c.fetchAllBundlePages(&bundle, 10)
	if err != nil {
		return nil, err
	}

	var observations []Observation
	for _, entry := range entries {
		var o Observation
		if err := json.Unmarshal(entry, &o); err == nil {
			observations = append(observations, o)
		}
	}
	return observations, nil
}

// GetConditions fetches Condition resources for a specific patient.
// If since is non-empty, only fetches conditions modified after that timestamp (RFC3339).
func (c *Client) GetConditions(patientID, since string) ([]Condition, error) {
	var bundle Bundle
	path := fmt.Sprintf("Condition?patient=%s", patientID)
	if since != "" {
		path += fmt.Sprintf("&_lastUpdated=ge%s", since)
	}
	if err := c.get(path, &bundle); err != nil {
		return nil, err
	}

	entries, err := c.fetchAllBundlePages(&bundle, 10)
	if err != nil {
		return nil, err
	}

	var conditions []Condition
	for _, entry := range entries {
		var cond Condition
		if err := json.Unmarshal(entry, &cond); err == nil {
			conditions = append(conditions, cond)
		}
	}
	return conditions, nil
}

// GetDocumentReferences fetches DocumentReference resources for a specific patient.
// Results are sorted newest-first by date.
// If since is non-empty, only fetches documents modified after that timestamp (RFC3339).
func (c *Client) GetDocumentReferences(patientID, since string) ([]DocumentReference, error) {
	var bundle Bundle
	path := fmt.Sprintf("DocumentReference?patient=%s&_sort=-date", patientID)
	if since != "" {
		path += fmt.Sprintf("&_lastUpdated=ge%s", since)
	}
	if err := c.get(path, &bundle); err != nil {
		return nil, err
	}

	entries, err := c.fetchAllBundlePages(&bundle, 10)
	if err != nil {
		return nil, err
	}

	var docs []DocumentReference
	for _, entry := range entries {
		var d DocumentReference
		if err := json.Unmarshal(entry, &d); err == nil {
			docs = append(docs, d)
		}
	}
	return docs, nil
}

// GetMedicationRequests fetches MedicationRequest resources for a specific patient.
// If since is non-empty, only fetches requests modified after that timestamp (RFC3339).
func (c *Client) GetMedicationRequests(patientID, since string) ([]MedicationRequest, error) {
	var bundle Bundle
	path := fmt.Sprintf("MedicationRequest?patient=%s&status=active&_sort=-date", patientID)
	if since != "" {
		path += fmt.Sprintf("&_lastUpdated=ge%s", since)
	}
	if err := c.get(path, &bundle); err != nil {
		return nil, err
	}

	entries, err := c.fetchAllBundlePages(&bundle, 10)
	if err != nil {
		return nil, err
	}

	var requests []MedicationRequest
	for _, entry := range entries {
		var m MedicationRequest
		if err := json.Unmarshal(entry, &m); err == nil {
			requests = append(requests, m)
		}
	}
	return requests, nil
}

// GetAllergyIntolerances fetches AllergyIntolerance resources for a specific patient.
// If since is non-empty, only fetches allergies modified after that timestamp (RFC3339).
func (c *Client) GetAllergyIntolerances(patientID, since string) ([]AllergyIntolerance, error) {
	var bundle Bundle
	path := fmt.Sprintf("AllergyIntolerance?patient=%s&_sort=-date", patientID)
	if since != "" {
		path += fmt.Sprintf("&_lastUpdated=ge%s", since)
	}
	if err := c.get(path, &bundle); err != nil {
		return nil, err
	}

	entries, err := c.fetchAllBundlePages(&bundle, 10)
	if err != nil {
		return nil, err
	}

	var allergies []AllergyIntolerance
	for _, entry := range entries {
		var a AllergyIntolerance
		if err := json.Unmarshal(entry, &a); err == nil {
			allergies = append(allergies, a)
		}
	}
	return allergies, nil
}

// GetSmartConfiguration fetches and parses the SMART discovery document
// for this FHIR server.
func GetSmartConfiguration(issURL string) (*SmartConfiguration, error) {
	url := fmt.Sprintf("%s/.well-known/smart-configuration", strings.TrimRight(issURL, "/"))
	resp, err := http.Get(url) //nolint:noctx // discovery calls do not need request context
	if err != nil {
		return nil, fmt.Errorf("fhir: GET smart-configuration from %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("fhir: smart-configuration %s returned %d: %s", url, resp.StatusCode, string(body))
	}

	var cfg SmartConfiguration
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		return nil, fmt.Errorf("fhir: decode smart-configuration: %w", err)
	}
	return &cfg, nil
}

// ---------------------------------------------------------------------------
// Domain extraction helpers
// ---------------------------------------------------------------------------

// primaryName returns the first HumanName with use=="official", falling back
// to the first name in the slice, or an empty HumanName if none exist.
func primaryName(names []HumanName) HumanName {
	for _, n := range names {
		if n.Use == "official" {
			return n
		}
	}
	if len(names) > 0 {
		return names[0]
	}
	return HumanName{}
}

// primaryEmail returns the first email address from a ContactPoint slice.
func primaryEmail(telecom []ContactPoint) string {
	for _, t := range telecom {
		if t.System == "email" && t.Value != "" {
			return t.Value
		}
	}
	return ""
}

// ExtractUserFromPatient converts a FHIR Patient resource into a platform
// models.User with Role=RolePatient. The ehrURL is the originating FHIR
// server base URL.
func ExtractUserFromPatient(p *Patient, ehrURL string) *models.User {
	name := primaryName(p.Name)
	first, middle := "", ""
	if len(name.Given) > 0 {
		first = name.Given[0]
	}
	if len(name.Given) > 1 {
		middle = name.Given[1]
	}
	return &models.User{
		FHIRResourceType: "Patient",
		FHIRID:           p.ID,
		EHRURL:           strings.TrimRight(ehrURL, "/"),
		Role:             models.RolePatient,
		FirstName:        first,
		MiddleName:       middle,
		LastName:         name.Family,
		DOB:              p.BirthDate,
		Gender:           p.Gender,
		Email:            primaryEmail(p.Telecom),
	}
}

// ExtractUserFromPractitioner converts a FHIR Practitioner resource into a
// platform models.User with Role=RolePractitioner.
func ExtractUserFromPractitioner(p *Practitioner, ehrURL string) *models.User {
	name := primaryName(p.Name)
	first, middle := "", ""
	if len(name.Given) > 0 {
		first = name.Given[0]
	}
	if len(name.Given) > 1 {
		middle = name.Given[1]
	}
	return &models.User{
		FHIRResourceType: "Practitioner",
		FHIRID:           p.ID,
		EHRURL:           strings.TrimRight(ehrURL, "/"),
		Role:             models.RolePractitioner,
		FirstName:        first,
		MiddleName:       middle,
		LastName:         name.Family,
		DOB:              p.BirthDate,
		Gender:           p.Gender,
		Email:            primaryEmail(p.Telecom),
	}
}

// ---------------------------------------------------------------------------
// FHIR → domain model extraction helpers
// ---------------------------------------------------------------------------

// firstCoding returns the first Coding from a CodeableConcept, or zero value.
func firstCoding(cc CodeableConcept) Coding {
	if len(cc.Coding) > 0 {
		return cc.Coding[0]
	}
	return Coding{}
}

// firstCategoryText returns the text (or first coding display) of the first
// element in a []CodeableConcept, e.g. as used for Observation.category.
func firstCategoryText(cats []CodeableConcept) string {
	if len(cats) == 0 {
		return ""
	}
	c := cats[0]
	if c.Text != "" {
		return c.Text
	}
	if len(c.Coding) > 0 {
		if c.Coding[0].Display != "" {
			return c.Coding[0].Display
		}
		return c.Coding[0].Code
	}
	return ""
}

// ExtractObservation maps a FHIR Observation to a models.Observation ready
// for upsert. patientFHIRID and ehrURL are injected by the caller because
// they are session-level context, not encoded inside the FHIR resource.
func ExtractObservation(o *Observation, patientFHIRID, ehrURL string) *models.Observation {
	coding := firstCoding(o.Code)
	var qty *float64
	var unit string
	var valueStr string

	if o.ValueQuantity != nil {
		v := o.ValueQuantity.Value
		qty = &v
		unit = o.ValueQuantity.Unit
		valueStr = o.ValueString
	} else if len(o.Component) > 0 && o.ValueQuantity == nil {
		// Handle compound observations like blood pressure (systolic/diastolic)
		// Format: "value1/value2 unit" (e.g., "120/80 mmHg")
		var values []string
		var compUnit string
		for _, comp := range o.Component {
			if comp.ValueQuantity != nil {
				values = append(values, fmt.Sprintf("%.0f", comp.ValueQuantity.Value))
				if compUnit == "" {
					compUnit = comp.ValueQuantity.Unit
				}
			}
		}
		if len(values) > 0 {
			valueStr = strings.Join(values, "/")
			if compUnit != "" {
				valueStr += " " + compUnit
			}
			unit = compUnit
		}
	} else {
		valueStr = o.ValueString
	}

	// Extract interpretation (first coding display or code)
	var interpretation string
	if len(o.Interpretation) > 0 {
		interp := firstCoding(o.Interpretation[0])
		if interp.Display != "" {
			interpretation = interp.Display
		} else {
			interpretation = interp.Code
		}
	}

	// Extract reference range (low and high from first range entry)
	var refRangeLow, refRangeHigh *float64
	if len(o.ReferenceRange) > 0 {
		refRange := o.ReferenceRange[0]
		if refRange.Low != nil {
			v := refRange.Low.Value
			refRangeLow = &v
		}
		if refRange.High != nil {
			v := refRange.High.Value
			refRangeHigh = &v
		}
	}

	return &models.Observation{
		FHIRID:             o.ID,
		EHRURL:             strings.TrimRight(ehrURL, "/"),
		PatientFHIRID:      patientFHIRID,
		Status:             o.Status,
		Category:           firstCategoryText(o.Category),
		CodeText:           o.Code.Text,
		CodeSystem:         coding.System,
		CodeCode:           coding.Code,
		EffectiveDate:      o.EffectiveDateTime,
		ValueQuantity:      qty,
		ValueUnit:          unit,
		ValueString:        valueStr,
		Interpretation:     interpretation,
		ReferenceRangeLow:  refRangeLow,
		ReferenceRangeHigh: refRangeHigh,
	}
}

// ExtractCondition maps a FHIR Condition to a models.Condition ready for upsert.
func ExtractCondition(c *Condition, patientFHIRID, ehrURL string) *models.Condition {
	coding := firstCoding(c.Code)
	clinicalStatus := firstCoding(c.ClinicalStatus)
	verificationStatus := firstCoding(c.VerificationStatus)
	return &models.Condition{
		FHIRID:             c.ID,
		EHRURL:             strings.TrimRight(ehrURL, "/"),
		PatientFHIRID:      patientFHIRID,
		ClinicalStatus:     clinicalStatus.Code,
		VerificationStatus: verificationStatus.Code,
		Category:           firstCategoryText(c.Category),
		CodeText:           c.Code.Text,
		CodeSystem:         coding.System,
		CodeCode:           coding.Code,
		OnsetDate:          c.OnsetDateTime,
		RecordedDate:       c.RecordedDate,
	}
}

// ExtractDocumentReference maps a FHIR DocumentReference to a
// models.DocumentReference ready for upsert. Only the first content item is
// persisted; additional content attachments are not common in practice.
func ExtractDocumentReference(d *DocumentReference, patientFHIRID, ehrURL string) *models.DocumentReference {
	coding := firstCoding(d.Type)
	category := firstCategoryText(d.Category)

	var contentType, contentURL, contentData string
	if len(d.Content) > 0 {
		att := d.Content[0].Attachment
		contentType = att.ContentType
		contentURL = att.URL
		contentData = att.Data
	}

	return &models.DocumentReference{
		FHIRID:        d.ID,
		EHRURL:        strings.TrimRight(ehrURL, "/"),
		PatientFHIRID: patientFHIRID,
		Status:        d.Status,
		DocStatus:     d.DocStatus,
		TypeText:      d.Type.Text,
		TypeSystem:    coding.System,
		TypeCode:      coding.Code,
		Category:      category,
		Date:          d.Date,
		Description:   d.Description,
		ContentType:   contentType,
		ContentURL:    contentURL,
		ContentData:   contentData,
	}
}

// ExtractMedicationRequest maps a FHIR MedicationRequest to a models.MedicationRequest ready for upsert.
func ExtractMedicationRequest(m *MedicationRequest, patientFHIRID, ehrURL string) *models.MedicationRequest {
	medCoding := firstCoding(m.MedicationCodeableConcept)
	var dosageText string
	if len(m.DosageInstruction) > 0 {
		dosageText = m.DosageInstruction[0].Text
	}
	return &models.MedicationRequest{
		FHIRID:           m.ID,
		EHRURL:           strings.TrimRight(ehrURL, "/"),
		PatientFHIRID:    patientFHIRID,
		Status:           m.Status,
		Intent:           m.Intent,
		MedCodeText:      m.MedicationCodeableConcept.Text,
		MedCodeSystem:    medCoding.System,
		MedCodeCode:      medCoding.Code,
		AuthoredOn:       m.AuthoredOn,
		RequesterDisplay: m.Requester.Display,
		DosageText:       dosageText,
	}
}

// ExtractAllergyIntolerance maps a FHIR AllergyIntolerance to a models.AllergyIntolerance ready for upsert.
func ExtractAllergyIntolerance(a *AllergyIntolerance, patientFHIRID, ehrURL string) *models.AllergyIntolerance {
	codeCoding := firstCoding(a.Code)
	clinicalStatus := firstCoding(a.ClinicalStatus)
	verificationStatus := firstCoding(a.VerificationStatus)
	var category string
	if len(a.Category) > 0 {
		category = a.Category[0]
	}
	return &models.AllergyIntolerance{
		FHIRID:             a.ID,
		EHRURL:             strings.TrimRight(ehrURL, "/"),
		PatientFHIRID:      patientFHIRID,
		ClinicalStatus:     clinicalStatus.Code,
		VerificationStatus: verificationStatus.Code,
		Type:               a.Type,
		Category:           category,
		Criticality:        a.Criticality,
		CodeText:           a.Code.Text,
		CodeSystem:         codeCoding.System,
		CodeCode:           codeCoding.Code,
		RecordedDate:       a.RecordedDate,
	}
}

// ParseFHIRUserFromIDToken attempts to extract a FHIR resource reference
// (e.g. "Practitioner/123" or "Patient/abc") from the id_token's fhirUser claim.
// Returns an empty string if the claim is missing or invalid.
func ParseFHIRUserFromIDToken(idToken string) string {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return ""
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}

	var claims struct {
		FHIRUser string `json:"fhirUser"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}

	return claims.FHIRUser
}
