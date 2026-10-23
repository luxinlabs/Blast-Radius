# Blast Radius: judging and questions

## Positioning

**For:** on-call engineers, application security teams, and engineering owners responding to a compromised dependency.

**Problem:** the incident spans advisory feeds, exact installed versions, dependency paths, code changes, and deployment controls. A responder needs a decision they can act on and explain.

**Hypothesis:** a shared evidence layer and coordinated, human-reviewed workflows reduce the time from advisory detection to a correct exposure decision and tested remediation.

**What the current demonstration proves:** exact-version decisions on controlled fixtures; a transitive path from the client inventory; durable, reviewable containment; and opposite deployment-gate results for affected and clean inventories. It does not establish a measured production reduction in response time.

## Allocate the judges' attention

| Criterion | Points | What to make visible | Strong line to use |
|---|---:|---|---|
| Impact | 35 | Named responder, propagation risk, enforceable gate result, measurement plan | “The next affected build can spread exposure while the team is still triaging.” |
| Demo | 30 | A visible input, actual scan result, approval, rejected gate, accepted gate | “Here is the affected inventory failing, and the clean one passing.” |
| Creativity | 25 | One incident connects dependency evidence, a client fix workflow, and reviewed containment | “The same evidence informs the proposed fix and the deployment decision.” |
| Craft with Snowflake and Claude | 10 | Clear platform roles, exact tool inputs, auditability, truthful limits | “Snowflake evaluates the facts; Claude can explain and act through scoped tools; a human approves changes.” |

Use roughly 30 seconds for the problem, two minutes for visible product behavior, and 30 seconds for the outcome and next milestone. Impact should also come through the demo, not only the opening.

## Why these technologies belong

- **Snowflake:** a shared relational evidence layer for advisories, versions, client inventories, risk joins, response playbooks, and audit records. Stored procedures make exact-version decisions repeatable. Data stays useful to SQL, dashboards, and tool clients.
- **Claude:** optional fact-grounded Cortex briefs and an MCP client that can inspect evidence and prepare response actions. State explicitly whether a Claude tool call or Cortex brief is connected in the live presentation.
- **MCP:** a common tool interface for agent clients, with exact version arguments and tenant-scoped credentials. Approval routes stay outside the MCP surface.
- **Local client:** accesses the repository and private logs where they live. Only normalized inventory and indicator findings go back. A test failure stops the fix path before a proposal.
- **Human review:** separate reviewer permissions, immutable evidence identity, revalidation, and auditable decisions. A changed snapshot cannot silently inherit an older approval.

## Questions and concise answers

**How is this different from a dependency alert or an upgrade bot?**

“Our focus is the incident response path across exposure, a tested change, and a reviewed deployment decision. Existing scanners or upgrade tools can feed or complement it. We are demonstrating that connected path, rather than claiming no other product offers these features.”

**Are these three autonomous Claude agents?**

“The implemented system has scanner, patch, and containment workflow agents exposed through API/MCP. The local dashboard does not independently run three Claude models. Claude can use the tools when connected; the decisions remain tied to structured evidence.”

**What is live today?**

“Today we are showing the local API, dashboard, inventory matching, agent coordination, human approval, and gate. This run uses fixtures. The Snowflake data layer is built separately; the adapter, migrations, and native reconciliation task are prepared for live validation.”

If you actually switch to the validated Snowflake backend before presenting, replace the last sentence with the precise live state. Do not mix a local screen with an unqualified live-data claim.

**Did the patch agent just fix the clean lockfile on screen?**

“No. The clean comparison inventory was prepared before the demo. The separate client fix workflow can create an isolated branch and run an explicit test command. Our local suite tests those real Git operations. We only claim a real PR or client test result when that evidence exists.”

**Could a hallucination approve a harmful change?**

“The structured response drives the decision. An AI brief is supporting text. An agent token cannot approve, and these tools do not merge or deploy. A reviewer inspects the evidence and CI. None of that guarantees every recommendation is correct, which is why human review remains part of the workflow.”

**Does an active policy mean the running service has been isolated?**

“No. It means the package block policy is active in the gate. CI must enforce the gate. Host isolation and WAF updates still require infrastructure-specific connectors.”

**What happens if the backend has no evidence for a package?**

“It returns unknown coverage. The gate fails closed instead of calling the inventory safe.”

**What about transitive packages?**

“The npm lockfile graph keeps installed paths and duplicate versions. We can trace a matched version back to its dependents. The original global Snowflake paths use latest-release declarations, so client paths are labeled separately.”

**Can you automatically upgrade the transitive Chalk example?**

“The scanner can identify it, but the current automatic npm fix path requires a direct dependency. A transitive fix needs a reviewed parent upgrade or override. We do not silently edit that relationship.”

**What leaves the client machine?**

“The normalized dependency inventory and summarized indicator matches. The log-hunting client does not upload raw log lines. A customer should still review inventory sensitivity and the deployment's access controls.”

**What scale have you validated?**

“The provided Snowflake snapshot has 25 watched packages, about four million version records, and approximately 257,000 advisory records. Those are data-layer snapshot counts, not counts of critical exposures or proof of API throughput. We have not benchmarked production concurrency.”

**What is the measurable business value?**

“Our target is less responder time spent joining evidence and a shorter period during which affected builds can pass. We will measure time to a correct exposure decision, time to a tested fix proposal, and the rate of unsafe or unnecessary blocks. We do not yet have a production savings figure.”

**What comes next?**

“Validate the Snowflake-backed client path end to end, run a pilot against manual triage, integrate licensed threat intelligence, and add one production containment connector.”

## What to remove from the pitch

Long team introductions; a table-by-table architecture explanation; unsupported PHP/Maven/Go coverage; fabricated test counts; unmeasured time or cost savings; claimed WAF/isolation success without a connector; and a product roadmap that crowds out the demonstrated result.

## Delivery

One narrator controls the story; one operator can handle clicks. Pause for the gate output. Point to the specific version and dependency path. Use the same incident throughout. Keep a recorded fallback ready and label it as recorded if used. End on the result, not on a terminal error or an unfinished architecture slide.


## Revised opening: PHP2Shell

Open with the verified timing: PHP's emergency security release was October 21, 2026; AWS reported an exploitation attempt dated October 17. This establishes urgency without inventing financial losses or a successful breach. See [the sourced research notes](PHP_HOOK_RESEARCH.md).

**If asked whether we support PHP today:** “PHP is the motivating incident. Our implemented prototype covers npm and PyPI; we are demonstrating the response workflow on an exact-version package inventory. PHP runtime and container discovery are future extensions.”
