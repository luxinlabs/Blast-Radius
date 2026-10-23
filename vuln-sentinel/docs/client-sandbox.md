# Multi-client agents and the visible sandbox

The local client fleet watches the notification center for each configured repository. It generates a patch or investigation recommendation, posts the agent response, and waits for a reviewer before any code executes. The dashboard and terminal show the workflow as it happens.

The default planner is an explicit **rule-based demo worker**. It does not pretend to invoke Claude. The existing MCP tools remain available for a connected Claude client.

## Start the demonstration

Run from `vuln-sentinel`. Use the same `.env` and SQLite path in all terminals.

Prepare Docker Desktop (or a local Docker Engine) and download the small runtime image once:

```bash
docker pull python:3.12-alpine
```

The runner never pulls images automatically, installs package dependencies, or uses a host-execution fallback.

Restart the API to load the new sandbox endpoints:

```bash
# Terminal A
.venv/bin/sentinel serve
```

```bash
# Terminal B
.venv/bin/sentinel dashboard
```

Register the example clients, then start all three workers and stream their logs:

```bash
# Terminal C
.venv/bin/sentinel demo-orgs
.venv/bin/sentinel client-agents --clients acme-pay buildkit llm-gateway --watch
```

`demo-orgs` already creates access anomaly notifications for llm-gateway. Those workers will immediately recommend an investigation and a proposed access-deny policy.

Inject a dependency incident from another terminal:

```bash
# Terminal D
.venv/bin/sentinel inject npm chalk 5.6.2 --advisory DEMO-CHALK-SANDBOX
.venv/bin/sentinel inject pypi litellm 1.106.2 --advisory DEMO-LITELLM-SANDBOX
```

The Chalk event affects acme-pay and buildkit. The LiteLLM event affects llm-gateway. These are synthetic events, not statements about current package security.

## What to show on screen

1. Open http://127.0.0.1:8501. Use `SENTINEL_ADMIN_TOKEN` privately and leave Client ID blank for the fleet view. A reviewer token scoped to one configured client can inspect/review only that client's jobs.
2. Expand **Client sandbox / live execution requests**. You can start the workers from here instead of the CLI.
3. The table shows each client's job, notification kind, and state. Select a run to inspect its log and proposed patch. Logs refresh every two seconds.
4. Observe `AWAITING_APPROVAL`: the worker has recommended a fix and requested execution; no command has run yet.
5. Review the displayed changes, choose APPROVED or REJECTED, add a reason, and submit the sandbox decision.
6. An approved job moves through QUEUED and RUNNING. The Docker output shows the baseline check, copied-file patch, and patched check result.
7. CHECKS_PASSED means the **policy and syntax smoke checks** passed on a copy. It does not mean a full customer test suite passed, production is contained, or a fix was deployed.

The notification center also reflects the stored agent response and number of proposed actions. Code artifacts remain proposals; the server never interprets notification artifact text as executable commands.

## Example log shape

```text
[buildkit] Client agent received THREAT notification
[ERROR] Detector reported: MALICIOUS_RELEASE
[INFO] No automatic direct pin; recommend a reversible pause of affected modules
[APPROVAL] Request: run checks on an isolated copy. No commands have executed.
[REVIEW] local-admin approved this exact plan
[OUTPUT] CHECK_SCOPE containment policy and syntax smoke checks
[OUTPUT] BASELINE_FAIL affected module has no approved disable guard
[OUTPUT] PATCH_APPLIED scripts/build.js
[OUTPUT] PATCHED_CHECKS_PASS approved copy satisfies policy and syntax checks
[OUTPUT] ORIGINAL_REPOSITORY_UNCHANGED
```

The baseline is a **security-policy probe**, not an invented crash from a malicious package. Suspect dependencies are never installed or imported by the sandbox harness.

## Recommendation behavior

- **Threat with a verified direct candidate:** propose a pin edit in a copied requirements file or npm lockfile. A lockfile edit is illustrative until a package manager regenerates integrity/resolution metadata and the real application tests pass. Do not deploy it directly.
- **Threat without a verified direct pin, or a transitive dependency:** recommend a reversible pause of the affected source modules. The sandbox copy removes dependency imports and replaces the module's functions with explicit disabled-feature errors. This can affect other functions in the module and requires owner review.
- **Access anomaly:** generate a simulated deny policy and issuer-side investigation/revocation runbook. The check validates only that proposed policy. No actual principal is revoked and no secret is rotated.
- **IOC match:** generate an investigation plan. A match is not confirmation of compromise.

Application test execution and arbitrary agent-written shell commands are intentionally outside this sandbox runner. The existing `sentinel fix --test ...` flow is the separate path for an explicitly supplied customer test command in an isolated Git worktree.

## Additional commands

```bash
# Plan current notifications once, without starting background polling
.venv/bin/sentinel client-agents --clients acme-pay buildkit llm-gateway --once

# Stop polling; already approved checks continue until completion or timeout
.venv/bin/sentinel client-agents --clients acme-pay buildkit llm-gateway --stop
```

Ctrl+C stops the terminal log stream; it does not stop the API's workers. Restarting the API stops its workers; start them again afterward. Interrupted jobs are never automatically rerun. Repeated notification polling is idempotent; reopened notification generations can create a new review request.

## Isolation and storage

Approved checks run in a Docker container with no network, a read-only root filesystem, dropped capabilities, no new privileges, a non-root UID, bounded CPU/memory/processes, and a 60-second deadline. Only a generated bundle and the fixed check harness are mounted read-only. The writable workspace is a bounded tmpfs. No host repository, Docker socket, or credentials are mounted into that container.

Docker's controls reduce exposure; this is a local demonstration runner, not a general-purpose hardened service for hostile customer code. See the [Docker run reference](https://docs.docker.com/reference/cli/docker/container/run) for the container options.

State lives beside the configured SQLite database:

- `client-jobs.sqlite`: job states, approval metadata, and log events.
- `sandbox-runs/<job-id>/`: the generated input bundle and fixed runner. Container workspace changes are ephemeral; approved patch artifacts remain in the stored job.

The feature is restricted to `SENTINEL_BACKEND=demo`. The Snowflake backend and native tasks do not launch Docker. Run this feature from the host application; the existing API container does not include or mount a Docker daemon.

Configure additional local repositories through server-side environment configuration, not API-supplied paths:

```bash
export SENTINEL_CLIENT_REPOS='{"acme-pay":"/absolute/path/to/acme-pay","buildkit":"/absolute/path/to/buildkit","llm-gateway":"/absolute/path/to/llm-gateway"}'
```

Paths are allowlisted, source sizes are capped, and traversal/hidden paths and symlinks are rejected. Only selected source/manifest files enter the generated bundle. The UI never submits a command to execute; it approves the hash of the displayed plan.

## If Docker is unavailable

Planning and log viewing still work. Approval returns an explicit blocked result, the job stays AWAITING_APPROVAL, and no code executes on the host. Start Docker and prepare the configured image, then retry the same approval. The default image can be overridden with `SENTINEL_SANDBOX_IMAGE`; choose a trusted image, preferably pinned by digest.

The development environment used for implementation denied access to the Docker daemon socket. Automated tests cover the API, real worker threads, approval UI, generated code, path protection, Docker command restrictions, and fixed harness using a local test engine. A real Docker container launch still needs to be verified on a host with Docker access.
