# Bidirectional Patient-Matching API — Rimidi ↔ HRS (FHIR Sandbox)

## Overview

Rimidi was acquired by HRS, another healthcare company. Both platforms need to
discover overlapping patients so clinical staff in either system can see which
patients also exist in the other. This document defines the shared API contract,
matching algorithm, auth model, and phased rollout plan.

For the **demo** the FHIR Sandbox plays the role of HRS.

---

## Shared JSON Contract

Both systems expose `POST /api/patient-match/` behind API-key auth.

### Request

```json
{
  "first_name": "Jane",
  "last_name":  "Smith",
  "email":      "jane.smith@email.com",
  "dob":        "1990-04-22",
  "sex":        "F"
}
```

| Field        | Type   | Required | Notes                                  |
|--------------|--------|----------|----------------------------------------|
| `first_name` | string | yes      | Will be lowercased & trimmed           |
| `last_name`  | string | yes      | Will be lowercased & trimmed           |
| `email`      | string | no       | Will be lowercased & trimmed           |
| `dob`        | string | yes      | ISO 8601 `YYYY-MM-DD`                 |
| `sex`        | string | yes      | Normalized: `M`/`F`/`O`/`U`           |

### Response

```json
{
  "source_system": "rimidi",
  "matches": [
    {
      "patient_ref": "opaque-signed-token",
      "score": 4,
      "fields": {
        "first_name": { "value": "Jane",                "match": true  },
        "last_name":  { "value": "Smith",               "match": true  },
        "email":      { "value": "jane.smith@email.com", "match": true },
        "dob":        { "value": "1990-04-22",           "match": true },
        "sex":        { "value": "F",                    "match": false }
      }
    }
  ]
}
```

| Field                      | Notes                                           |
|----------------------------|-------------------------------------------------|
| `source_system`            | `"rimidi"` or `"hrs"` — identifies the responder |
| `matches[].patient_ref`    | Opaque token — never exposes raw DB PK           |
| `matches[].score`          | Count of exactly matching fields (2–5)           |
| `matches[].fields.*.value` | The **remote** system's value for this field      |
| `matches[].fields.*.match` | Whether the field matched exactly                |

### Rules

- Only patients with **≥ 2 exact field matches** are returned.
- Comparisons are **case-insensitive, whitespace-stripped**.
- Sex is normalized before comparison:
  - Provider: `"M"` / `"F"` → canonical `"M"` / `"F"` / `"O"` / `"U"`
  - Sandbox: `"male"` / `"female"` / `"other"` / `"unknown"` → `"M"` / `"F"` / `"O"` / `"U"`
- DOB is always ISO 8601 `"YYYY-MM-DD"`.
- Results are sorted by `score` descending.
- `patient_ref` is an HMAC-signed / Django-signed token of the internal PK.

---

## Auth Strategy

Both systems validate a **pre-shared API key** in the `X-Api-Key` header.

- **Provider** adds `PATIENT_MATCH_API_KEY` to Django settings.
- **FHIR Sandbox** adds a `PatientMatchAPIKey` config field and an API-key
  middleware that applies to `/api/*` routes only.
- Keys are **directional** — each system holds the key for the *other* system.

---

## Field Mapping

| Provider (`RimidiUser`)    | FHIR Sandbox (`User`)  | Normalization          |
|----------------------------|------------------------|------------------------|
| `first_name` (encrypted)  | `first_name`           | lowercase + trim       |
| `last_name` (encrypted)   | `last_name`            | lowercase + trim       |
| `email` (encrypted)       | `email`                | lowercase + trim       |
| `birth_date` (encrypted)  | `dob` (string)         | both → `YYYY-MM-DD`   |
| `sex` (`"M"` / `"F"`)     | `gender` (FHIR codes)  | both → `M/F/O/U`      |

---

## Critical Constraint: Provider PII Encryption

All matchable demographic fields in Provider (`first_name`, `last_name`, `email`,
`birth_date`, `sex`) are **AES-encrypted** at the column level via
`django-encrypted-model-fields`. No SQL-level filtering is possible.

Matching must be done in **Python application memory**: load all patients for the
provider, decrypt them via Django ORM, and compare. This works for typical
provider panels (hundreds to low-thousands of patients).

---

## Phased Rollout

### Phase 1 — Contract, Auth & Field Normalization (2–3 days)

- Lock the shared JSON schema (this document).
- Add `PATIENT_MATCH_API_KEY` to Provider settings (cs_hub app).
- Add API-key middleware + stub handler in FHIR Sandbox.
- Build field normalization utilities in both systems (unit-testable).

### Phase 2 — Provider Patient Match API (3–4 days)

- Full `POST /cshub/api/patient-match/` endpoint in `cs_hub`.
- In-memory matching loop (decrypt all patients for the provider, compare).
- Opaque `patient_ref` via Django `TimestampSigner`.
- Unit tests for matching logic, normalization, and auth.

### Phase 3 — FHIR Sandbox Patient Match API (2–3 days)

- `POST /api/patient-match` endpoint in Sandbox.
- `ListAllPatients()` DB query for matching.
- API-key middleware.
- Unit tests.

### Phase 4 — Provider UI: "Find in HRS" (3–4 days)

- Proxy endpoint `POST /cshub/api/patient-match-proxy/` (session-auth, calls Sandbox).
- "Find in HRS" button on patient chart.
- Match diff modal showing per-field comparison.

### Phase 5 — Sandbox UI: "Find in Rimidi" (2–3 days)

- Proxy handler (session-required, calls Provider).
- "Find in Rimidi" button on dashboard.
- Diff panel with field-level comparison.

---

## Future Considerations

1. **Deterministic hash columns** for scale (SHA-256 of lowercased fields) to
   avoid full-table decrypt at Provider panels > 5k patients.
2. **Multi-instance Rimidi** — HRS fans out to multiple Rimidi deployments.
   `org_key` + per-instance API key handles this.
3. **Patient linking** — a future `PatientCrossReference` model to explicitly
   link records after a match is confirmed by a human.
