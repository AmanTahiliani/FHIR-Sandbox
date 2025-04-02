# FHIR-Sandbox: SMART on FHIR Integration Application

A Go-based application that demonstrates integration with Electronic Health Record (EHR) systems using the SMART on FHIR protocol.

## Overview

This application implements a SMART on FHIR client that can:
- Launch from an EHR context
- Authenticate using OAuth 2.0
- Retrieve patient information from FHIR servers
- Display patient details in a structured format

## Prerequisites

- Go 1.16 or higher
- Access to a SMART on FHIR-compatible EHR system
- Client credentials (client ID and secret) from your EHR system

## Configuration

The application uses a configuration structure defined in `main.go`. You'll need to configure:

1. SMART App settings:
   ```go
   SMARTAppConfig {
       redirectPath: "http://localhost:8080/auth-redirect",
       clientID:     "your-client-id",
       clientSecret: "your-client-secret",
       scopes:       []string{"launch", "patient/*.read"},
   }
2. EHR Client settings:
   ```go
    EHRClientsConfig {
        name:         "EHR_NAME",
        url:          "https://your-ehr-fhir-endpoint.com",
        authType:     "auth-2",
        clientID:     "your-ehr-client-id",
        clientSecret: "your-ehr-client-secret",
        patientAPI:   true,
    }
    ```
## Installation

1. Clone the repository:
```bash
git clone github.com/AmanTahiliani/fhir-sandbox.git
cd fhir-sandbox
```
2. Install dependencies:
```bash
go mod tidy
```

## Running the Application

1. Start the application:
```bash
go run main.go
```
2. The application will start and listen on `http://localhost:8080`.

## Endpoints
- `/` - Root endpoint, displays welcome message
- `/launch` - SMART launch endpoint
- `/auth-redirect` - OAuth2 redirect endpoint

## SMART on FHIR Launch Flow

- EHR system initiates launch with parameters:
    - `launch` - Launch ID
    - `iss` - FHIR server URL
- Application authenticates with the EHR:
    - Retrieves SMART configuration
    - Initiates OAuth2 flow
    - Exchanges code for access token
- Application retrieves and displays patient information

## Testing

You can test the application using a FHIR server that supports SMART on FHIR. Ensure you have the necessary credentials and configuration.
A good EHR Launcher to test with is: o test with is: [SMART Health IT Sandbox](https://launch.smarthealthit.org/). Some of the steps you would need to take are:
- Create a new EHR client in the sandbox
- Add the redirect URL
- Add the client ID and secret
- Add the scopes
- Set the same client ID and secret in the application
