# Blast Radius: three-minute pitch

Delivery target: about three minutes including clicks. Use the timestamps below and rehearse aloud; the source and accuracy notes are not spoken. Start a visible three-minute rehearsal timer. The scenario and package states are demo fixtures, not current security guidance. Follow the exact local runbook in DEMO_RUNBOOK.md.

## 0:00–0:30 — The PHP attack hook

[Show: “Attack attempts began four days before the patches.” Timeline: October 17 / October 21.]

“On October 21, PHP released emergency security fixes. AWS had already observed an exploitation attempt four days earlier. These flaws could allow remote code execution without a login.

For the on-call engineer, that announcement starts a race: which services are exposed, who owns them, and what can we safely change before the next deployment?

Blast Radius connects that evidence to a reviewed response. Let me show you.”

Sources: [AWS report of the October 17 attempt](https://aws.amazon.com/blogs/security/amazon-threat-intelligence-identifies-php2shell-exploitation-prior-to-public-disclosure-in-madpot/) and [PHP October 21 security advisory](https://www.php.net/archive/2026.php). Attempts do not establish a successful compromise. Background and slide notes are in PHP_HOOK_RESEARCH.md.

## 0:30–1:00 — Show the scanner working

[Select chalk 5.6.1. Point to its dependent path.]

“Our current prototype covers npm and PyPI. This controlled Chalk scenario demonstrates the response workflow. We uploaded exact versions from a lockfile rather than checking only the latest releases.

Here, the scanner identifies an affected Chalk release and shows the dependency path back to Next. That tells the responder why this package matters to this application.

The response carries its advisory evidence, recommended version, and review history.”

## 1:00–1:30 — Show the response workflows

[Click Run response agents. Point across the three cards.]

“The three workflows share that evidence. The scanner rechecks exposure. The patch workflow selects a candidate. For direct dependencies, its client workflow prepares an isolated fix branch, runs explicit tests, and proposes a draft pull request. Transitive upgrades require a reviewed parent change.

Containment prepares a block policy. These controls are connected to persisted state and API actions. The dashboard does not claim that tests or patches have run before the client reports them.”

## 1:30–2:00 — Establish Claude and Snowflake's roles

[Show a prepared Claude tool interaction if connected. Otherwise keep the evidence tab visible.]

“Snowflake is the shared data and response layer: advisories, version matching, dependency paths, and response playbooks. Its optional Cortex brief uses Claude to summarize those facts.

The MCP server gives Claude access to the response tools. The local interface here uses fixture data, so we can demonstrate the workflow reliably without presenting it as a live Snowflake session.”

## 2:00–2:35 — Prove the outcome

[Human review → approve containment. Terminal → run the two gate commands.]

“I approve the proposed package block as the reviewer. The agent cannot approve its own action.

Now the deployment gate rejects the affected inventory. Against the clean demo inventory, the gate passes.

That is the result: an explainable decision that a pipeline can enforce, with a human-controlled response and an audit trail. Production deployments must require this gate in CI.”

## 2:35–3:00 — Land impact and next steps

[Return to the command center or one closing slide.]

“PHP showed why that response window matters. We help on-call and security teams move from an advisory to a specific, reviewed action. The next milestone is to measure time to an exposure decision and a tested fix against manual triage.

Next, we will validate the live Snowflake integration, connect licensed threat intelligence, and add infrastructure-specific containment.

Blast Radius: know the exposure, prepare the fix, and put a reviewed decision in the deployment path.”

## Optional live-connected replacement for 1:30–2:00

Use ONLY after successfully rehearsing both the Claude MCP connection and a Snowflake-backed request. Replace the local-fixture disclosure with an accurate description of the live setup; keep a fixture disclosure if any screen still uses demo data.

“Here is Claude calling our response tool with an exact package version. Snowflake evaluates the advisory match and returns structured evidence. Claude explains the result using those facts and prepares the response through MCP. The incident, proposal, and review remain auditable. Claude cannot merge or deploy through these tools.”

Do not claim a live Cortex call unless AI_BRIEF was enabled and the returned brief is visible.
