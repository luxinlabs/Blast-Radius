# Client agent (`sentinel` CLI)

Runs on a client device. Talks to the API with a bearer token (`SENTINEL_TOKEN`, scoped to `SENTINEL_CLIENT_ID`) at `SENTINEL_URL`. HTTPS is required except on loopback.

| Command | Input | Output (stdout JSON) | Uploads |
|---|---|---|---|
| `scan <lockfile>` | `package-lock.json`, `poetry.lock` or exact-pinned `requirements.txt` | `{snapshot, scan: {checked, emergency_ids, unknown, errors, complete}, emergencies, warnings}`; exit 2 if `complete` is false | Package names, exact versions, dependency edges |
| `map <src> <lockfile>` | Source tree + the lockfile naming installed packages | `{client_id, use_cases}` | File paths and function names only |
| `hunt <log>...` | Log files | `{findings: [{indicator, kind, count, source}], summary}` | Indicator match counts and file basenames, never log lines |
| `monitor <log> <secure-file>` | JSON-lines access log + secure resource list | `{findings: [...]}` | Resource names, principals, IPs, counts |
| `fix <lockfile> --emergency ID --test "cmd"` | An open incident | `{branch, worktree, target_version, test_passed, rollback_plan, pr_body}` | Nothing unless `--open-pr` |
| `reconcile [--interval N]` | Admin token | `{checked, emergency_ids, unknown, errors, complete}` | Nothing |
| `inject <eco> <pkg> <versions...>` | Admin token | `{threat, reconcile}` | Demo only |
| `demo`, `demo-orgs`, `init-demo` | Local files | Seeds local demo state / writes `.env` | Nothing |

Try (with the server running): `sentinel demo` once to register the `demo-app` client, then `sentinel scan examples/package-lock.json`. Scanning an unregistered client returns 409.
