# Fix and human review

**Fix (client device):** `sentinel fix <lockfile> --emergency ID --test "cmd" [--open-pr]` creates a git worktree, pins the recommended safe version (direct npm pins, exact `requirements.txt` pins, unambiguous direct Poetry dependencies), runs the test command without a shell, and commits only if tests pass. It stops with an explanation for transitive npm deps, ambiguous Poetry groups, markers and extras. `--open-pr` pushes and opens a **draft** PR, then submits the proposal.

**Proposal** (`POST /v1/clients/{id}/proposals`, agent): `{emergency_id, target_version, pr_url, test_command[], test_passed, rollback_plan}`. The target must be in the incident's `recommended_version` and still clean when submitted. Incident status `OPEN`/`REJECTED` → `PROPOSED`.

**Review** (`POST /v1/emergencies/{id}/review`, reviewer or admin; never the proposer): `{decision: "APPROVED"|"REJECTED", reason, revision}` → `{status, merged: false, deployed: false}`. `revision` must match the current inventory snapshot. Approval is a recorded decision only.

**Dashboard:** `sentinel dashboard` (Streamlit, http://127.0.0.1:8501). Paste a token; blank client ID shows the whole fleet for an admin token. Shows the notification center, per-use-case impact, incidents, evidence and the review form. Set `SENTINEL_URL` to the API.

Audit trail: `GET /v1/clients/{id}/events`.
