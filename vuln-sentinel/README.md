# Vuln Sentinel

Scan exact dependency versions, evaluate OSV advisories in Snowflake, hunt for indicators locally, prepare tested fix branches, and record human reviews. The system never merges or deploys a fix.

## Run locally

Python 3.11+ is required; npm, Poetry, and GitHub CLI are needed only for their corresponding fix workflows.

```bash
cd vuln-sentinel
python3 -m venv .venv
source .venv/bin/activate
pip install -c constraints.txt -e '.[dev,snowflake]'
sentinel init-demo
sentinel demo
sentinel serve
```

`init-demo` creates an ignored `.env` with unique admin, agent, and reviewer tokens, readable only by your user. Commands load this file automatically. `demo` seeds a persistent incident and synthetic log findings using an in-process API; it does not need a running HTTP server and does not create a pretend PR or pretend test results.

In another terminal, from `vuln-sentinel`:

```bash
source .venv/bin/activate
sentinel dashboard
```

Open **http://127.0.0.1:8501** and paste `SENTINEL_REVIEWER_TOKEN` from `.env` into the password field. The API is at **http://127.0.0.1:8000**; authenticated API documentation is at `/docs` (supply a bearer header using an API client or browser header configuration).

The demo is explicitly labeled and uses a small fixture based on the supplied architecture. Its versions and indicators are synthetic test evidence, not current security guidance. Unknown fixture packages produce `UNKNOWN`, never a clean bill of health. No malicious demo dependencies are installed.

### Scan, hunt, and propose

With the API running:

```bash
sentinel scan examples/package-lock.json
sentinel scan examples/poetry.lock
sentinel scan examples/requirements.txt
sentinel hunt examples/demo.log
```

These commands use the agent token. Register another client first with `POST /v1/clients` using an admin token, then give its agent a token scoped to that client. `scan` uploads only the normalized inventory and graph; `hunt` reads local files and sends matched indicator counts and basenames, without log contents. IOC matches need investigation; Tor or AI endpoint traffic alone is not evidence of compromise.

To prepare a real fix in a clean, committed client repository:

```bash
sentinel fix /path/to/requirements.txt --emergency EMERGENCY_ID \
  --test 'uv run --with-requirements requirements.txt pytest'
```

The test command is explicit, split into arguments, and executed without a shell. Choose a command that tests the updated dependencies in an isolated environment. Merely running tests against an old globally installed environment is insufficient. The command runs inside a new Git worktree; your original checkout stays on its existing branch.

Add `--open-pr` to push the fix branch and open a **draft** GitHub PR through `gh`, then submit its proposal to the server. Without this flag, the branch, commit, PR description, and rollback plan stay local. Failed tests prevent the commit and proposal; the worktree is retained for inspection. The client never executes commands supplied by advisory text or an AI brief.

Supported automated edits: direct npm pins, exact requirements pins, and unambiguous direct Poetry dependencies, including named groups. Transitive npm fixes, ambiguous Poetry groups, source overrides, and complex markers/extras require a reviewed parent/manifest change. The client stops with an explanation rather than silently changing their semantics. npm lock regeneration disables install scripts. Poetry regeneration updates the manifest and lockfile with `poetry add --lock`.

The dashboard shows the proposal, validation command, rollback plan, client paths, advisory evidence, intel provenance, and audit trail. A reviewer can approve or reject a current proposal. Approval is a recorded decision, with no merge or deployment action. A proposer cannot review their own proposal.

### Use cases, threats and the notification center

```bash
sentinel demo-orgs                      # acme-pay, llm-gateway, buildkit: inventory, inferred use cases, access monitoring
sentinel inject npm chalk 5.6.2         # demo: publish a compromised version and reconcile the fleet
sentinel map path/to/src path/to/package-lock.json   # infer use cases for a real client
sentinel monitor access.log secure.txt  # flag abnormal access to resources marked secure
```

`map` uploads only file paths and function names; Claude (through `AI_COMPLETE` on Snowflake, a path heuristic on the demo backend) labels each file's use case. When a package is compromised, each client's `client_impact` lists the use cases and functions that call it, directly or through a dependent. `GET /v1/clients/{id}/impacts` returns per-use-case `compromised`/`safe` status.

`monitor` reads a JSON-lines log (`ts`, `principal`, `resource`, `ip`) and a file of secure resources (`NAME` or `NAME: allowed, principals`). It flags unlisted principals, bursts of secure accesses (default 5 in 10 minutes), and secure access from an IP the principal never used elsewhere. Only resource names and principals are uploaded.

Every incident, IOC match and access anomaly lands in the notification center (`GET /v1/notifications`). The autonomous code agent answers with actions and code; see [docs/AUTONOMOUS_CODE.md](docs/AUTONOMOUS_CODE.md). `inject` is demo-only and needs the admin token.

## Components

| Component | Implementation |
|---|---|
| HTTP API | `src/vuln_sentinel/server.py`, FastAPI, bearer PAT authentication |
| MCP | Same server, Streamable HTTP at `/mcp/`, seven tools |
| Client agent | `sentinel scan`, `hunt`, `fix` |
| Human review | `sentinel dashboard`, Streamlit, API-enforced authorization |
| Persistence | SQLite/WAL locally; Snowflake tracking tables in live mode |
| Reconciliation | `sentinel reconcile`, or native Snowflake procedure/task |
| Marketplace adapter | `INTEL.SIGNAL_FEED`, enriched package-risk view, source/expiry-aware priority and local IOC hunting |
| Response engine | Existing `SERVING.RESPOND`, corrected by migration 11 |

MCP tools: `respond`, `get_package_risk`, `get_blast_radius`, `list_emergencies`, `register_sbom`, `report_scan`, and `submit_fix_proposal`. Approval is deliberately outside the agent tool surface. Point an HTTP-capable MCP client at `http://127.0.0.1:8000/mcp/` and configure `Authorization: Bearer <agent-token>`. Do not commit tokens into client configuration.

```json
{
  "mcpServers": {
    "vuln-sentinel": {
      "url": "http://127.0.0.1:8000/mcp/",
      "headers": {"Authorization": "Bearer REPLACE_WITH_AGENT_TOKEN"}
    }
  }
}
```

The exact enclosing configuration format depends on the MCP client. The endpoint uses the official [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk). PAT authentication is implemented; OAuth identity-provider integration is not included.

Tokens map to authenticated subjects and roles in `SENTINEL_TOKENS`. Roles are `admin` (fleet), `agent`, `reviewer`, and `reader` (each scoped to one `client_id`). Agent tools cannot change this mapping. All endpoints except `/health` require a token. Public deployments require HTTPS and a secret manager. Configure `SENTINEL_ALLOWED_HOSTS` and `SENTINEL_ALLOWED_ORIGINS` with the actual public MCP host/origin; DNS rebinding protection remains enabled. `/health` reports process liveness, not Snowflake readiness.

### Incident consistency

The SBOM revision hashes the normalized inventory. Emergency identity hashes the client, revision, and response evidence. Repeated scans are idempotent. New inventory or evidence supersedes old reviews; withdrawn matches are retired. Returning to an older inventory reopens its incident with a new review requirement. Proposal submission and human review re-evaluate the inventory and target version. Coverage gaps or backend failures block review rather than implying safety.

SQLite uses immediate transactions. Snowflake uses a single enforced hybrid-table lock row to serialize tracking transactions across API instances and the native task. Audit inserts and status changes commit together. Application roles can append audit events but cannot update or delete them. Client-supplied test results are reported evidence, not independently attested CI results; reviewers must inspect the PR and its CI.

## Deploy back to Snowflake through GitHub

The original populated Snowflake data layer stays intact. **Do not rerun `01_database_schemas_tables.sql`: it replaces the database.** For an existing installation, use only the additive upgrades below.

1. Run `sql/10_tracking_and_intel.sql`. This creates tracking tables, a hybrid lock, a neutral intel feed, the enriched risk view, and an application-code stage. Hybrid table support is required for tracking concurrency; the script deliberately fails rather than silently weakening locking.
2. Run `sql/11_response_safety.sql`. This replaces only `IS_AFFECTED` and `RESPOND`. Safe versions are checked directly against all advisory ranges, including packages outside the watchlist. Unknown comparisons fail closed. `lowest_clean_upgrade` is the lowest registered stable, non-yanked, non-deprecated clean upgrade, rather than the largest advisory boundary. All matching CVE IDs are retained for intel joins even when displayed advisories are capped at 25.
3. Run `python scripts/package_snowflake.py` after changes. Commit the deterministic `dist/vuln_sentinel.zip` archive alongside the source. CI checks that it matches.
4. Sync the GitHub repository to Snowflake. Copy `dist/vuln_sentinel.zip` from the Git repository stage into `SERVING.APP_CODE` using the `COPY FILES` example in `sql/12_native_matching_task.sql`, replacing the repository reference. Alternatively upload the archive through the stage UI.
5. Run `sql/12_native_matching_task.sql`, adjusting `DEFAULT_WH`. It creates `MATCH_CLIENT_ADVISORIES()` using the shared Python implementation and creates a suspended hourly task. Call the procedure once and inspect its result (`complete`, `unknown`, `errors`) before resuming the task. The existing ingestion tasks remain suspended until you explicitly resume them.
6. Run `sql/13_roles.sql`, adjusting the warehouse. Assign `VULN_SENTINEL_APP` to the server's service user and configure a named connector connection with that role. The native procedure/task should be owned by a dedicated deployment role with the required object access. Clients use API PATs; do not distribute the service user's Snowflake credentials.
7. Run `sql/14_notifications_and_usecases.sql` for the notification center, use-case maps and threat events, and grant `SNOWFLAKE.CORTEX_USER` to the app role (the script does both). `python scripts/deploy_snowflake.py 10 11 13 14` runs numbered files through the named connection; step 01 needs `--fresh`.
8. Set `SENTINEL_BACKEND=snowflake` and `SNOWFLAKE_CONNECTION_NAME=vuln_sentinel`. Configure the connection in Snowflake's supported [`connections.toml`](https://docs.snowflake.com/en/developer-guide/python-connector/python-connector-connect), then start the API and dashboard on your application compute. `snowflake/spcs.sql` and `snowflake/service.yaml` run both as one Snowpark Container Services service; they were written without a live account and are untested. The HTTP server is an ASGI process; uploading SQL or Python to a worksheet does not host it. The dashboard needs a reachable API URL.

The native task evaluates every unique exact version in each client's latest SBOM, calls `RESPOND`, enriches it with intel, computes client paths, and writes emergencies and audit events. It uses no outbound client connection. As an alternative to the native task, run `sentinel reconcile --interval 3600` with an admin API token. Use one scheduler; enabling both is unnecessary.

Marketplace subscriptions and listing terms are external prerequisites. This implementation does **not** accept terms, purchase data, or guess provider schemas. After access is approved, map the provider's actual columns into `INTEL.SIGNAL_FEED`:

| `kind` | `indicator` | `score` | Purpose |
|---|---|---|---|
| `kev` | CVE identifier | NULL | Known exploited; P0 priority |
| `exploit` | CVE identifier | Provider score normalized to 0–1 | Score ≥0.7 boosts vulnerability to P1 |
| `ip`, `tor` | Exact canonical IP | NULL | Local log matches |
| `domain`, `ai_endpoint` | Hostname, without scheme/path | NULL | Local log matches |

Every signal needs `source` and timezone-aware `observed_at`; use `expires_at` for expiring feeds. Expired records are ignored. A missing feed is not evidence of no exploitation. `sql/09_marketplace_intel.sql` preserves the supplied listing identifiers as optional operator steps. No live Marketplace data was used in local validation.

### Containers

After `sentinel init-demo`, `docker compose up --build` starts API, dashboard, and worker. These development services share the API network namespace so the dashboard and worker can use the loopback API URL. Ports bind to the host's loopback interface. Run `docker compose exec api sentinel demo` to seed its persistent SQLite volume. Containers require Docker and were not built in this environment.

## Validate

```bash
ruff check src tests scripts
ruff format --check src tests scripts
python scripts/test.py -q
python scripts/package_snowflake.py
```

The test launcher avoids an optional libreadline crash found in the local macOS Conda Python. Standard `pytest` works in normal Python installations.

The suite exercises actual API and MCP ASGI transports, authorization, proposal/review transitions, stale evidence and withdrawals, parser behavior, IOC privacy, version matching, real isolated Git commits and failure paths, Streamlit forms, and the native Snowpark adapter against a local SQL engine. GitHub push/PR creation and the Snowflake query boundary are mocked. Tests never install the malicious example dependencies, push a branch, accept listing terms, or call paid services.

Live Snowflake DDL compilation, provider mappings, account privileges, warehouse execution, Cortex briefs, and real GitHub PR creation still need deployment validation. Local tests do not certify the provided row counts or the current vulnerability status of package versions.

## Data and coverage limits

- npm package-lock v2/v3 preserves installed locators, duplicate versions, and reverse paths. v1 directness is inferred and labeled incomplete. Workspace links without exact versions produce warnings.
- Poetry includes conditional variants conservatively; version constraints and environment markers may make its graph incomplete. requirements files require exact pins and have no dependency graph. Includes, hashes, editable sources, URL requirements, and floating versions are rejected rather than silently skipped.
- Snowflake watchlist paths still use latest-release declarations; client paths are separate and labeled. Six-hop limits apply to the original watchlist view; client traversal uses visited locators to handle cycles.
- Catalog coverage is limited to loaded npm/PyPI packages. Missing catalog entries return unknown. Scan/reconcile commands exit with status 2 for incomplete coverage.
- AI briefs are optional, untrusted summaries. The incident decision and approvals use structured facts, not generated prose.
