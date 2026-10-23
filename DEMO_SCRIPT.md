# Blast Radius — Three-Minute Demo Script

Lead with the responder’s problem, prove a deployment decision, then close on impact. Spend about two minutes inside the product.

## 0:00–0:30 — The PHP attack hook

**Action:** Show one opening slide: **“Attack attempts began four days before the patches.”** Underneath: **October 17: AWS observation / October 21: PHP security release**. Put source links in the slide footer; keep CVE identifiers in speaker notes.

> On October 21, PHP released emergency security fixes. AWS had already observed an exploitation attempt four days earlier. These flaws could allow remote code execution without a login.

> For the on-call engineer, that announcement starts a race: which services are exposed, who owns them, and what can we safely change before the next deployment?

> Blast Radius connects that evidence to a reviewed response. Let me show you.

**Sources for the factual opening:** [AWS threat-intelligence report](https://aws.amazon.com/blogs/security/amazon-threat-intelligence-identifies-php2shell-exploitation-prior-to-public-disclosure-in-madpot/) and [PHP's October 21 security advisory](https://www.php.net/archive/2026.php). AWS reports an observed exploitation attempt; do not call it a confirmed successful breach.

## 0:30–1:00 — Show it working

**Action:** Select Chalk 5.6.1. Point to the dependency path.

> Our current prototype covers npm and PyPI. This controlled Chalk scenario demonstrates the response workflow. We uploaded exact versions from a lockfile rather than checking only the latest release.
>
> The scanner identifies an affected Chalk version and traces it back to Next. Now the responder can see why this package matters to this application, alongside the advisory evidence and recommended candidate.

## 1:00–1:30 — Show the three workflows

**Action:** Click **Run response agents**.

> The scanner rechecks exposure. The patch workflow identifies a candidate. For direct dependencies, the client can prepare an isolated branch, run explicit tests, and propose a draft pull request. Transitive upgrades require a reviewed parent change.
>
> Containment prepares a package block policy. The dashboard reflects what actually happened: tests remain marked “Not run” until results are reported.

## 1:30–2:00 — Explain Claude and Snowflake

**Action:** Show a rehearsed Claude tool call, or keep structured evidence visible.

> Snowflake is our shared data and response layer: advisories, version matching, dependency paths, and playbooks.
>
> Claude can access these response tools through MCP, and an optional Cortex brief summarizes the returned facts.
>
> This screen uses local fixtures for a reliable demonstration. We distinguish that from a live Snowflake or Claude connection.

## 2:00–2:35 — Prove the result

**Action:** Approve containment as the reviewer. Run the two commands from `vuln-sentinel`:

```bash
.venv/bin/sentinel gate examples/package-lock.json
.venv/bin/sentinel gate examples/safe/package-lock.json
```

> I approve the proposed block using the reviewer identity.
>
> The affected inventory fails the gate. The prepared clean inventory passes.
>
> That is an explainable decision a pipeline can enforce, with human review and an audit trail. Production CI must require this gate before deployment.

## 2:35–3:00 — Impact and next

**Action:** Return to the command center or closing slide.

> PHP showed why that response window matters. We help responders move from an advisory to a specific, reviewed action.
>
> Our next milestone is to measure time to a correct exposure decision and tested fix against manual triage. Then we’ll validate the live Snowflake integration, connect licensed intelligence, and add infrastructure-specific containment.
>
> Blast Radius: know the exposure, prepare the fix, and put a reviewed decision in the deployment path.

## Judging priorities

| Criterion | Points | What to emphasize |
|---|---:|---|
| Impact | 35 | Name the responder and show the deployment decision. Describe response-time reduction as a hypothesis until measured. |
| Demo | 30 | Show the exact version, dependency path, human approval, rejected affected inventory, and accepted clean inventory. |
| Creativity | 25 | Explain how shared evidence connects exposure, a proposed fix, and containment. |
| Craft with Snowflake and Claude | 10 | Give each technology a precise role. Show scoped tools, grounded evidence, and human approval boundaries. |

## Demo accuracy notes

- The local demo sequence was verified through the API in an isolated temporary database.
- The clean inventory is prepared beforehand. Do not describe it as a patch created live.
- The gate independently checks advisories as well as approved policies. Approval is not the only reason the affected inventory fails.
- Gate exit code 3 means an intentional denial; exit code 0 means the inventory passes.
- A policy protects a deployment only after CI requires the gate to succeed.
- The local dashboard does not run three independent Claude models. Show a live Claude tool call only after rehearsing a connected MCP client.
- WAF updates, host isolation, and owner notifications still require infrastructure connectors.
- Both Claude artifact links were inaccessible during preparation. This script follows the supplied screenshot and implemented app.

## PHP hook accuracy

The opening references CVE-2026-109618 and CVE-2026-109619, disclosed with emergency releases on October 21, 2026. Describe vulnerable PHP deployments and observed exploitation attempts. Do not describe a poisoned PHP release, confirmed compromise of every deployment, or PHP coverage in this prototype. See [the sourced research notes](vuln-sentinel/presentation/PHP_HOOK_RESEARCH.md) for the mechanism and slide wording.

## Supporting preparation

- [Full operator runbook](vuln-sentinel/presentation/DEMO_RUNBOOK.md)
- [Claude demo prompts](vuln-sentinel/presentation/CLAUDE_PROMPTS.md)
- [Judging strategy and Q&A](vuln-sentinel/presentation/JUDGES_BRIEF.md)

## Reference links

- [Presentation](https://claude.ai/artifact/F1Li1JXWMYVVqnsFs8jsk8#slide-37f071351b80)
- [Demo artifact](https://claude.ai/artifact/JiMEEqyDW3mFNoL2R2GpJC)
