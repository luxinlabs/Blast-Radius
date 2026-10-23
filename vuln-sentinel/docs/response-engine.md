# Response engine (scan, reconcile, respond)

Decides whether an installed package version is a problem. Code: `service.py`, `backend.py`, Snowflake procedure `SERVING.RESPOND`.

**Input:** a client SBOM (`POST /v1/clients/{id}/sbom`): `{source, packages: [{ecosystem, name, version, locator, direct, dependencies[]}], graph_complete, warnings}`. Versions must be exact.

**Process:** `POST /v1/clients/{id}/reconcile` (agent) or `POST /v1/reconcile` (admin, whole fleet) calls `respond` for every unique version, adds the client's own dependency paths (`client_blast_radius`) and use-case impact (`client_impact`), and opens an incident (emergency) when the result is not `NONE`.

**Output of `respond`** (`POST /v1/respond {ecosystem, package, version}`):
`{package, incident_type, advisories[], recommended_version{same_major, latest_clean, lowest_clean_upgrade}, blast_radius[], secrets_at_risk, playbook[], priority, intel, requires_human_approval}`

- `incident_type`: `NONE`, `VULNERABILITY`, `MALICIOUS_RELEASE`, `UNAVAILABLE`, `TRUST_STORE`, or `UNKNOWN` (not in the catalog; never treated as safe, and makes `complete` false).
- `priority`: `P0` malicious or known-exploited, `P1` vulnerable with exploit score ≥ 0.7, `P2` vulnerable, `P3` otherwise.

**Reconcile output:** `{checked, emergency_ids[], unknown[], errors[], complete}`. Re-scans are idempotent; changed inventory or evidence supersedes old incidents and reviews.

Demo backend knows only the fixture in `src/vuln_sentinel/demo.json` (axios, chalk, debug, ansi-styles, next, litellm, requests, certifi). Try: `curl -X POST $SENTINEL_URL/v1/respond -H "Authorization: Bearer $SENTINEL_ADMIN_TOKEN" -H 'content-type: application/json' -d '{"ecosystem":"npm","package":"axios","version":"1.14.1"}'`.
