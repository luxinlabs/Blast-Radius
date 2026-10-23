# Blast Radius: demo operator runbook

## What this rehearsal proves

A local inventory scan, a transitive dependency path, response-agent coordination, a human-reviewed containment policy, and a deployment gate that rejects an affected fixture and accepts a clean fixture. Fixtures are synthetic. No vulnerable package is installed, no real PR is pushed, and no infrastructure is isolated.

The default local backend is SQLite plus demo data. Snowflake procedures and an adapter exist separately. Claude is accessed through MCP when a compatible client is connected; the dashboard's three workflow cards do not themselves run three Claude model instances.

## Before the judges arrive

1. From `vuln-sentinel`, ensure `.env` exists. If it does not, run `.venv/bin/sentinel init-demo` once. Keep credentials off screen.
2. Stop any old `sentinel serve` process with Ctrl+C. Start the API in terminal A:

   ```bash
   .venv/bin/sentinel serve
   ```

3. Start the dashboard in terminal B:

   ```bash
   .venv/bin/sentinel dashboard
   ```

4. Use terminal C for setup and the visible demo commands:

   ```bash
   .venv/bin/sentinel demo
   .venv/bin/sentinel scan examples/package-lock.json
   ```

   The first command registers demo-app. The second replaces its current inventory with three npm fixture entries. Keep the original seed command outside the live presentation.

5. Open http://127.0.0.1:8501. Enter the reviewer token from `.env`, client `demo-app`, and select the **chalk 5.6.1** incident. Keep both API and dashboard processes running.
6. Verify the scanner shows `next` as a dependent and the candidate is `5.6.2`. This is a synthetic lockfile example, not a claim about Next's current real dependency tree.
7. Ensure the selected containment policy is pending or absent. If it is already active from rehearsal, revoke it in Human review with a reason. A rejected/revoked policy will not automatically return to pending on the same emergency; for a fresh approval sequence, use a fresh rehearsal database and seed it before presenting. Do not delete the existing audit database on stage.
8. Pre-open the evidence tab, Human review tab, and a terminal showing only the two gate commands below. Clear unrelated scrollback and hide secrets.
9. Run the relevant local validation before presenting:

   ```bash
   .venv/bin/python scripts/test.py -q
   ```

10. Rehearse the complete sequence with a timer. If switching to Claude or Snowsight takes more than ten seconds, use the local track and explain their architecture roles accurately.

## Fresh rehearsal without deleting existing data

Use a separate SQLite path for the rehearsal API. Stop the API first, then in terminal A:

```bash
SENTINEL_SQLITE_PATH=.sentinel/pitch-rehearsal-01.sqlite .venv/bin/sentinel serve
```

In terminal C, seed that same file explicitly, then scan through the running API:

```bash
SENTINEL_SQLITE_PATH=.sentinel/pitch-rehearsal-01.sqlite .venv/bin/sentinel demo
.venv/bin/sentinel scan examples/package-lock.json
```

The dashboard needs no change because it talks to the API. For a new clean rehearsal, choose another unused filename; do not overwrite previous evidence. Do not run this separate-database setup against the Snowflake backend.

## On-stage click sequence

| Time | Operator action | Visible proof |
|---|---|---|
| 0:00 | PHP opening slide; switch to the app at 0:30 | October 17 observed attempt / October 21 patch release, with source footer |
| 0:30 | Select chalk 5.6.1 | Exact version and the `next` reverse dependency path |
| 1:00 | Click Run response agents | Recheck completes; patch ready; containment awaiting approval |
| 1:30 | Show connected Claude tool call if rehearsed, otherwise Evidence | Tool response or structured source evidence |
| 2:00 | Human review → containment notes → APPROVED → Record containment review | Policy becomes active; audit event is recorded |
| 2:10 | Run affected gate command | `allowed: false`, blocked package reasons |
| 2:22 | Run clean gate command | `allowed: true` |
| 2:35 | Return to command center / closing slide | Result and next milestone |

### Terminal commands to show

```bash
.venv/bin/sentinel gate examples/package-lock.json
```

Expected: `allowed: false`; exit code **3** is an intentional denial, not a demo crash. Other affected packages in the inventory also cause denial. The gate checks current advisories independently of approved policies, so do not say the approval is the only reason this inventory fails.

```bash
.venv/bin/sentinel gate examples/safe/package-lock.json
```

Expected: `allowed: true`; exit code **0**. This second file is a prepared clean fixture. **Do not say the patch agent created it live.** The test suite separately exercises actual isolated Git changes, passing/failing test commands, and the mocked GitHub boundary.

The gate only protects a real deployment after CI calls it and requires exit 0. Do not announce “production contained” for the local fixture demonstration.

## Claude interaction

Use CLAUDE_PROMPTS.md. Rehearse with a connected MCP client before the event. The claude.ai artifact URLs are presentation/demo artifacts, not proof that a Claude MCP client can reach localhost.

Keep one short tool interaction. Show the tool's structured response. Do not spend the live slot on authentication or typing a long prompt. Agent credentials must be scoped to demo-app; the reviewer uses a distinct token in the dashboard. Approval endpoints are not exposed as MCP tools.

## Optional Snowflake evidence

If you have a working Snowsight session, pre-open this query:

```sql
CALL VULN_SENTINEL_DB.SERVING.RESPOND('npm', 'chalk', '5.6.1', FALSE);
```

Its current result may differ from the local fixture. Rehearse and narrate the result you actually see. To show the optional Claude Cortex brief, use TRUE and confirm Cortex access, model availability, and latency first. Keep the structured evidence visible alongside the generated summary.

If Snowflake is not connected, show the architecture for a few seconds and say the local demo uses fixtures. Do not substitute a saved JSON result and describe it as a live query.

## Slide changes for the existing presentation

Only four visual beats are needed within three minutes: problem, product/demo, a brief architecture cue, and result/next. Most of the time belongs to the application.

| Screenshot claim | Demo-accurate replacement |
|---|---|
| “One bad library. Three Claude agents. Contained.” | “One bad library. Three response workflows. Human-reviewed.” |
| “Claude Opus 5 in Snowflake Cortex” | “Snowflake response layer + optional Claude Cortex brief” |
| “watching 2,140 libraries” | Use a measured current count, or omit it |
| PHP / Packagist / Maven / Go coverage | Use PHP as the real-world opening, then explicitly switch to the implemented npm/PyPI prototype |
| “PHP 8.3.35 compromised” | “PHP 8.3.35 vulnerable to PHP2Shell”; the advisory does not establish a malicious PHP release or confirmed compromise |
| “tests: 412 pass” | Show actual client CI results; local suite last verified 56 passing tests |
| WAF / isolation / alerts marked complete | Mark as connector-required manual actions |
| Four-minute timer | Remove the timer unless it measures a real run |

The supplied row counts describe a snapshot of the user's Snowflake data. If mentioned, call them a snapshot; local tests have not independently verified them.

## Failure recovery

- **Connection refused:** keep the API running in terminal A; the dashboard is a separate process.
- **404 on `/agents`:** restart the API to load current routes, then refresh the dashboard.
- **401:** use the token from the same `.env` used by the running API. Do not paste credentials into a projected terminal.
- **403 on review:** use the reviewer token, not the agent token.
- **No pending policy:** a rehearsal already used this incident; use a prepared fresh rehearsal database before the slot.
- **Stale evidence:** refresh and rerun the agents. Do not bypass review checks.
- **Claude/Snowflake unavailable:** continue the local flow and state the connection limitation in one sentence.
- **Browser fails entirely:** use a short prerecorded run, identified as recorded. Show the measured test result as a fallback; do not claim that a video is live.

## Closing result to leave on screen

> Affected fixture rejected. Clean fixture accepted. Human decision recorded.

Next milestone: connect and validate the full Snowflake-backed client path, then measure the time to a correct exposure decision and tested fix against a manual baseline.

The revised opening and supporting primary sources are in [PHP_HOOK_RESEARCH.md](PHP_HOOK_RESEARCH.md). The factual hook is exploitation attempts preceding public patches, not a claim that this prototype detected or remediated PHP.
