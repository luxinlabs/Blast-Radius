# Access monitor

Flags abnormal access to resources the client marked `secure`. Code: `src/vuln_sentinel/monitor.py`. Runs on the client; the server never sees secret values.

**Inputs**

- Access log, JSON lines, timezone-aware timestamps: `{"ts": "2026-10-23T05:30:00Z", "principal": "ci-runner-7", "resource": "OPENAI_API_KEY", "ip": "198.51.100.23"}`. A malformed line is an error (never skipped).
- Secure list, one per line: `NAME` (anyone may read, bursts still flagged) or `NAME: principal, principal` (only these may read). `#` starts a comment.

**Rules** (`--window` minutes, default 10; `--limit` default 5):

| `rule` | Fires when | Priority |
|---|---|---|
| `UNAUTHORIZED_PRINCIPAL` | Principal not on a resource's allow-list | P0 |
| `EXCESSIVE_ACCESS` | ≥ limit secure accesses inside the window | P1 |
| `NEW_SOURCE_IP` | Secure access from an IP the principal never used on non-secure resources | P1 |

**Output / upload** (`POST /v1/clients/{id}/access`): `{"findings": [{rule, principal, resources[], count, first_seen, last_seen, ips[]}]}` → `{accepted, findings}`. Each finding becomes one `ACCESS_ANOMALY` notification (identical findings are not duplicated).

Try: `sentinel monitor examples/orgs/llm-gateway/access.log examples/orgs/llm-gateway/secure.txt` → three findings for `ci-runner-7`. Not covered: Snowflake `ACCESS_HISTORY` (it lags by hours), and decrypt-vs-read distinction.
