# Blast Radius — Three-Minute Demo Plan

**Format:** one minute of prepared speech, with the remaining two minutes for live product actions and brief narration. The opening spends its first 20 seconds on who the project serves.

**Audience:** on-call engineers, application security teams, and engineering owners responding to a vulnerable or compromised dependency.

**Result to demonstrate:** an affected inventory is rejected, a prepared clean inventory passes, and a human containment decision is recorded.

## One-minute prepared script

These three sections total about one minute. Deliver the closing after the live demo, rather than immediately after the introduction.

### Opening — 20 seconds

> Blast Radius is for the on-call engineer and security team who suddenly need to answer: where are we exposed, what can we safely change, and how do we stop another affected deployment? When a vulnerable dependency is buried inside an application, those answers can be scattered across several tools and teams.

### Illustrations and transition — 20 seconds

**Point once to the workflow illustration: Snowflake, the three agent panels, and the human approval boundary.**

> This diagram shows how we connect those answers. Snowflake holds the advisory and response evidence. Three workflows scan exposure, prepare a fix, and propose containment. Claude can access those capabilities through scoped MCP tools. A human approves changes. Let’s follow one affected inventory through that response.

### Closing — 20 seconds, after the live demo

> You just saw the affected inventory fail, the clean inventory pass, and the reviewer’s decision recorded. That is our result: evidence translated into a decision a deployment pipeline can enforce. Next, we want to partner with Anthropic. When their researchers find a severe vulnerability, they can brief us under coordinated disclosure, so our clients have the fix staged and the gate ready before attackers ever see the advisory. Blast Radius makes the response explicit, reviewable, and enforceable.

## Complete three-minute run of show

| Time | Screen and action | What to say or establish |
|---|---|---|
| **0:00–0:20** | Title or problem illustration | Deliver the audience-focused opening. |
| **0:20–0:40** | Workflow illustration | Deliver the diagram explanation. Point to Snowflake, the agent panels, and the approval boundary. |
| **0:40–1:05** | Dashboard: select **Chalk 5.6.1** | Identify the exact installed version and its dependent path back to Next. |
| **1:05–1:25** | Click **Run response agents** | Show scanner results, the patch candidate, and the containment proposal. |
| **1:25–1:55** | Human review tab | Enter a short review reason and approve the containment proposal. |
| **1:55–2:15** | Terminal: affected inventory gate | Show `allowed: false`. Explain that the gate checks both advisory evidence and active policies. |
| **2:15–2:35** | Terminal: prepared clean inventory gate | Show `allowed: true`. State that this comparison inventory was prepared before the demo. |
| **2:35–2:40** | Dashboard activity or closing screen | Point to the recorded reviewer decision. |
| **2:40–3:00** | Closing screen | Deliver the prepared closing and stop. |

## Which live demo to choose

**Use the local npm inventory → reviewed containment → deployment gate sequence.** This is the recommended three-minute demo because it has a clear input, visible evidence, an interactive human decision, and opposite outcomes that judges can immediately understand.

Keep these four things visible:

1. **Exact exposure:** Chalk 5.6.1 and the client dependency path back to Next.
2. **Coordinated response:** scanner evidence, the candidate version, and a pending containment policy.
3. **Human authority:** a reviewer activates the policy; an agent cannot approve it.
4. **Observable result:** the affected fixture fails the gate; the prepared clean fixture passes.

This is a controlled local scenario. The dependency relationships and package states shown are fixtures, not claims about current registry data or Next’s real dependency tree.

### Why this sequence fits

- It avoids network-dependent package installation, test execution, and GitHub authentication during the live slot.
- It demonstrates the containment workflow through actual API-backed actions and persistent state.
- It finishes with a result, rather than an unfinished patch or a diagram.
- It uses one inventory throughout. The clean comparison does not replace the registered incident inventory.

### What to leave outside the three-minute slot

- Creating a real fix branch, installing dependencies, running application tests, or opening a GitHub PR. Show those in Q&A or a separate rehearsed recording.
- Detailed SQL schemas and ingestion procedures.
- Setting up a Claude MCP connection on stage.
- WAF updates, host isolation, and owner notifications without their infrastructure connectors.
- Multiple incident scenarios or an extended tour of every dashboard tab.

**Important patch limitation:** Chalk is transitive in this fixture. The scanner can identify it and suggest a candidate, but the current automatic npm fix path requires a direct dependency. A parent upgrade or override needs review. Describe the patch card as a proposed candidate, not a completed live fix.

## Brief live-demo narration

Use these short lines between clicks. Leave time for the audience to read the result.

**Selecting the incident:**

> This is our controlled local inventory. Chalk is affected, and the dependency path shows why this application pulls it in.

**Running the workflows:**

> The scanner rechecks the evidence. The patch card identifies a candidate. Containment proposes a version block for review.

**Reviewing:**

> I’m using a separate reviewer identity to activate that policy. The decision is tied to the evidence and recorded.

**Affected gate result:**

> This inventory is rejected. A pipeline that requires this gate would stop here.

**Clean gate result:**

> This prepared clean inventory passes. We have demonstrated both sides of the deployment decision.

## Exact commands

Run from `vuln-sentinel`. Keep the API and dashboard running in separate terminals.

### Before presenting

```bash
# Terminal A
.venv/bin/sentinel serve
```

```bash
# Terminal B
.venv/bin/sentinel dashboard
```

```bash
# Terminal C: setup, before the presentation
.venv/bin/sentinel demo
.venv/bin/sentinel scan examples/package-lock.json
```

Open **http://127.0.0.1:8501**, sign in with the reviewer token privately, select client `demo-app`, and choose **Chalk 5.6.1**.

If a previous rehearsal already approved the policy, use the fresh rehearsal database procedure in the [operator runbook](vuln-sentinel/presentation/DEMO_RUNBOOK.md). Do not reset state or troubleshoot credentials on stage.

### During the demo

After running the agents and reviewing the containment proposal:

```bash
.venv/bin/sentinel gate examples/package-lock.json
```

**Expected:** `allowed: false`, exit code **3**. This is an intentional denial.

```bash
.venv/bin/sentinel gate examples/safe/package-lock.json
```

**Expected:** `allowed: true`, exit code **0**.

The clean file is a prepared comparison fixture. Do not say the patch agent generated it live. An active policy does not isolate running services; CI must call the gate and require success to enforce the decision on a real deployment.

## Use the illustrations quickly

### Problem illustration

Show the responder surrounded by advisory feeds, dependency inventories, repositories, and deployment controls. Point to the responder when saying who the project is for. Keep this visual behind the first 20 seconds; do not separately explain every icon.

### Workflow illustration

Open [WORKFLOW.html](WORKFLOW.html). Point to three places only:

1. **Snowflake:** shared evidence and response logic.
2. **Three agent panels:** the response workflows.
3. **Human approval boundary:** who authorizes action.

Keep this to 20 seconds. Preselect the relevant view and avoid clicking through all 16 components during the pitch.

### Optional PHP context

Use one caption on the opening illustration rather than adding another spoken section:

> **PHP2Shell: AWS observed an exploitation attempt four days before the October 21, 2026 patches.**

Source: [AWS’s first-party report](https://aws.amazon.com/blogs/security/amazon-threat-intelligence-identifies-php2shell-exploitation-prior-to-public-disclosure-in-madpot/). This is motivation for the response problem; the implemented prototype covers npm/PyPI, not PHP runtimes. Do not describe attempted exploitation as a confirmed successful breach. Further context is in the [PHP research notes](vuln-sentinel/presentation/PHP_HOOK_RESEARCH.md).

## Claude and Snowflake: what to claim

**For the current local demo:**

> The Snowflake data and response layer is built. This screen uses local fixtures. Claude integration is exposed through MCP, and the optional Cortex brief uses returned response facts.

The local dashboard does not independently execute three Claude models. Mention a live Claude call only when a compatible MCP client is actually connected.

**If a live Claude MCP call has been rehearsed successfully:** replace part of the 1:05–1:25 workflow slot with one short `get_agent_status` call for the selected incident. Keep the tool response visible and do not add time to the schedule. Use the [prepared prompts](vuln-sentinel/presentation/CLAUDE_PROMPTS.md).

**If a live Snowflake-backed request has been validated:** describe the exact live path shown. Do not label fixture output as a Snowflake result. Save a detailed Snowsight walkthrough for Q&A.

## Confident final delivery

Return to a clean closing screen with these three statements:

**Affected fixture rejected.**  
**Clean fixture accepted.**  
**Human decision recorded.**

Deliver the closing script, pause, and stop. Avoid adding a last-minute feature list or an unsupported claim about production containment, response-time savings, or prevented breaches.

### Short closing if time is running out

> Affected inventory rejected. Clean inventory accepted. Human decision recorded. That is Blast Radius: a clear path from exposure evidence to a reviewed deployment decision.

## Rehearsal and fallback

- Rehearse to **2:45**, leaving 15 seconds for slow clicks.
- Have the reviewer already signed in; keep all tokens off the projected screen.
- Pre-open the terminal with both gate commands ready.
- Verify the containment proposal is fresh before the slot.
- If the API is offline, restart it before presenting. A 404 on `/agents` means the API may still be running older code.
- If a live connection fails during the slot, state the limitation once and show a clearly labeled recorded run or the prepared evidence.
- End on the demonstrated result. Do not spend the closing minute troubleshooting.

---

# One-Minute Submission Video

**Format:** a screen recording with voice-over, edited, not live. About 150 spoken words. Cut between shots instead of waiting for clicks.

**Story:** a poisoned library spreads in hours, Blast Radius answers in seconds, and a human stays in control.

| Time | On screen | Voice-over |
|---|---|---|
| **0:00–0:10** | Title card: "chalk: 2 hours live → 1 in 10 cloud environments." | "In 2025, a hijacked version of chalk was live on npm for about two hours. In that time it reached at least one in ten cloud environments." |
| **0:10–0:20** | Dependency chain animating: your app → `next` → `chalk 5.6.1`. | "Most teams never imported it themselves. It came in through another library, so it's invisible in their manifest." |
| **0:20–0:32** | Dashboard: select **Chalk 5.6.1**, then highlight the dependency path and the affected use case. | "Blast Radius checks exact installed versions against advisories in Snowflake. It shows the full chain, and Claude maps it to the business function at risk." |
| **0:32–0:42** | Click **Run response agents**, then cut to the scanner, patch and containment cards. | "Agents recheck the exposure, find a clean upgrade and propose a block. They can't approve their own actions." |
| **0:42–0:50** | Human review: approve. Then the terminal: affected gate `allowed: false`, clean gate `allowed: true`. | "A reviewer approves. The affected build is rejected and the clean one passes." |
| **0:50–1:00** | Closing card: "1,000 orgs · every exposed org found in 5.5 s · 0 false blocks." Then "Next: early warning with Anthropic" and the logo. | "We found every exposed org out of a thousand in under six seconds. Next, with early warning from Anthropic, our clients are ready before attackers are." |

**Recording tips**

- Record each shot separately with `sentinel demo` state already seeded, then edit them together. Don't record one take.
- Overlay the experiment numbers as text; don't show the script running. Add a caption: "timed on local backend, synthetic fleet".
- In the 0:20 shot, add a small caption "controlled demo fixture", because the Chalk scenario is synthetic.
- Keep the tokens and the `.env` file out of every frame.
