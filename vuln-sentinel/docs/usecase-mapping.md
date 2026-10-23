# Use-case mapping

Turns "this package is bad" into "this feature is broken". Code: `src/vuln_sentinel/usecases.py`.

**Input** (`POST /v1/clients/{id}/usecases`, agent or admin token for that client):

```json
{"usages": [{"ecosystem": "npm", "package": "axios", "file": "src/pay/checkout.js", "symbol": "chargeCard"}]}
```

`sentinel map` builds `usages` by scanning `.py` (AST) and `.js/.ts` (regex) files for imports of packages in the lockfile and the functions that reference them; `symbol` is `<module>` when no function uses the import. Skipped: `node_modules`, `.venv`, `dist`, `build`. Python import names must equal the package name (no alias table).

**Output** (stored per client, replaced on each upload):

```json
[{"name": "pay checkout", "criticality": "high", "usages": [ ...same usage objects... ]}]
```

Naming: on Snowflake, Claude (`AI_COMPLETE`) names each file's use case and rates `high|medium|low`; if its JSON is invalid it falls back to the heuristic. On the demo backend (and as fallback) the name is the last two path parts, `high` if it contains pay, checkout, billing, auth, login, secret, key, token or crypto.

Response: `{"client_id": "...", "use_cases": N}`. Try: `sentinel demo-orgs`, then `GET /v1/clients/acme-pay/impacts`.
