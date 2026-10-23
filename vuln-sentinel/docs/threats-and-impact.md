# Threats and impact

**Inject a threat (demo only)** — `POST /v1/demo/threats`, admin token:

```json
{"ecosystem": "npm", "package": "chalk", "versions": ["5.6.2"], "advisory_id": "DEMO-CHALK"}
```

Output: `{"injected": true, ...the event}`. Afterwards every `respond` for a listed version returns `MALICIOUS_RELEASE`, `synthetic: true`, the injected advisory first, and `recommended_version` without the listed versions. Run `POST /v1/reconcile` (or `sentinel inject`, which does both) to open incidents. There is no retract; reset by deleting `.sentinel/` (demo) or `DELETE FROM VULN_SENTINEL_DB.SERVING.THREAT_EVENTS` (Snowflake).

**Impact** — `GET /v1/clients/{id}/impacts` (any role scoped to that client):

```json
[{"package": "npm/chalk@5.6.2", "use_case": "web pages", "criticality": "medium",
  "status": "compromised",
  "functionalities_affected": [{"file": "src/web/pages.js", "symbol": "renderHome", "via": "next"}]},
 {"package": "npm/axios", "use_case": "pay checkout", "criticality": "high", "status": "safe",
  "functionalities_affected": []}]
```

`compromised` rows come from open incidents; `via` is the package the code actually calls (a dependent when the bad package is transitive). `safe` rows list use cases with no open incident. `safe` only means no open incident: a package missing from the catalog is reported as `unknown` by reconcile, not here.
