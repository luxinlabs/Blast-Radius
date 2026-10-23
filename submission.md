# Blast Radius — Hackathon Submission

## Project Description

**Attackers now move faster than the patch cycle, and most companies can't see the code they actually run.**

October 2026 showed how short the response window has become:

- **PHP2Shell:** AWS observed attempts to exploit an unauthenticated remote code execution flaw in PHP on October 17, four days before PHP shipped emergency fixes on October 21.
- **OpenCode Console:** on October 16, an intruder reached a legacy system behind OpenCode's hosted Console. That system held users' saved OpenAI, Anthropic and Google API keys, and some users reported unauthorized charges soon after.
- **npm in 2026:** attackers took over the axios maintainer's account and published versions carrying a remote access trojan. The Mini Shai-Hulud worm used stolen publishing tokens and CI credentials to republish hundreds of trusted packages: one compromised account pushed 637 malicious versions across 317 packages.

These incidents share a root cause: **too much privilege in one place.** One maintainer token, one CI identity or one store of saved keys becomes a path into every downstream customer.

**The part nobody sees is transitive.** Your engineers import a trusted library. That library imports another, which imports another, and one of those was republished with malware last night. It never appears in your `package.json` or `requirements.txt`, and no one on the team chose it, but it ships in every build. Most teams find out from a customer, an invoice or a breach notice.

Blast Radius gives security and engineering leaders a straight answer within minutes of an advisory: **are we exposed, which products and customers does it touch, and can we stop the next build from shipping it?**

- **Scan:** matches the exact installed versions in each lockfile, including deeply nested packages, against OSV advisory data in Snowflake. It shows the full chain that pulls the bad package in, for example Chalk 5.6.1 arriving through Next.
- **Business impact:** Claude, running in Snowflake through Cortex, maps code to use cases. An incident then reads "checkout and login call the compromised package", not just "package X is affected".
- **Patch:** finds the lowest clean upgrade, prepares a tested fix branch in an isolated worktree, and can open a draft pull request.
- **Contain:** proposes a version block. Only a separate human reviewer can activate it.
- **Gate:** a CI check that rejects any build containing an affected version or a package with unknown coverage. Unknown is never reported as safe.
- **Access monitoring:** flags unusual access to resources marked secure, such as unlisted principals, bursts of access or unfamiliar IPs. These are the signals that excess privilege is being abused.

Blast Radius follows the least-privilege principle it enforces. Agents get tokens scoped to one client and can propose actions but never approve, merge or deploy. Raw logs and source code stay on the customer's machines. Every decision is recorded in an audit trail.

**The business case:** for a software company, a compromised dependency is a customer-trust problem before it is an engineering one. Customers and auditors ask within hours whether they were affected. Blast Radius turns that question into an answer backed by evidence, a fix ready for review, and a deployment gate that keeps the exposure from spreading while the team responds.

*Sources: [AWS on PHP2Shell](https://aws.amazon.com/blogs/security/amazon-threat-intelligence-identifies-php2shell-exploitation-prior-to-public-disclosure-in-madpot/), [The Hacker News on OpenCode](https://thehackernews.com/2026/10/opencode-console-breach-may-have.html), [Trend Micro on axios](https://www.trendmicro.com/en_us/research/26/c/axios-npm-package-compromised.html), [SafeDep on Mini Shai-Hulud](https://safedep.io/mini-shai-hulud-strikes-again-314-npm-packages-compromised/).*

## Public GitHub Repository

https://github.com/luxinlabs/Blast-Radius

## 1-Minute Demo Video

`<add link>`

## The Value Case

**Metrics it moves:**

1. **Time to a correct exposure decision:** from the advisory arriving to knowing which services run the affected version and why.
2. **Time to a tested fix proposal:** from that decision to a tested change ready for review.
3. **Exposure window:** how long builds with the affected version can still pass CI after the advisory.
4. **Block quality:** how often the gate wrongly lets a build through or blocks a safe one. Missing data fails closed instead of being reported as clean.

**Baseline:** triage done by hand. An engineer reads the advisory, searches lockfiles across repositories, tracks down owners in chat, and edits CI by hand. That often involves several teams for hours or days, while new builds keep shipping the affected version. We haven't measured our improvement in production yet. The pilot will time Blast Radius against manual triage on the same incidents.

**How fast a compromised library spreads:**

| Incident | How long the bad version was live | How far it reached |
|---|---|---|
| chalk and debug, npm (Sept 8, 2025) | about 2 hours | The malicious code reached at least 1 in 10 cloud environments. 99% of cloud environments already used at least one of the targeted packages. |
| axios, npm (Mar 31, 2026) | about 3 hours (00:21–03:29 UTC) | axios has 100M+ weekly downloads. If those are spread evenly, about 600,000 installs an hour, or roughly 1.8M during the window (our estimate). |
| Mini Shai-Hulud worm, npm (May 19, 2026) | two automated waves | One stolen account published 637 malicious versions across 317 packages. |

So a poisoned library reaches a large share of the industry in hours, while triage by hand takes hours to days.

**How fast Blast Radius answers (our timed experiment):** we built synthetic fleets of client organizations. About 40% of them pull a compromised `chalk` in transitively through `next`, so it never appears in their own manifest. We then published the compromise and timed the response. This ran on the local SQLite backend on an Apple M1 Pro laptop. Reproduce it with `python scripts/spread_experiment.py 10 100 500 1000`.

| Client orgs | Actually exposed | Found | Wrongly blocked | Time to find every exposed org | Time to map business impact | Gate check per build |
|---:|---:|---:|---:|---:|---:|---:|
| 10 | 6 | 6 | 0 | 0.07 s | 0.05 s | 7.7 ms |
| 100 | 43 | 43 | 0 | 0.47 s | 0.34 s | 7.0 ms |
| 500 | 215 | 215 | 0 | 2.4 s | 1.9 s | 6.6 ms |
| 1,000 | 440 | 440 | 0 | 5.5 s | 3.9 s | 6.8 ms |

Once an advisory exists, Blast Radius finds every exposed organization in seconds, including ones that only have the package transitively. It tells each one which business function is hit ("the home page calls `next`, which pulls in the bad `chalk`") and blocks the next affected build in under 10 ms. The window shrinks from hours or days of triage to seconds.

*Caveats:* the inventories are synthetic and the dependency chain is two levels deep. The clock starts when the advisory is published, so Blast Radius doesn't catch a compromise before anyone reports it. These timings come from the local backend; the Snowflake-backed path adds query latency we haven't benchmarked yet.

*Sources: [Wiz on chalk/debug](https://www.wiz.io/blog/widespread-npm-supply-chain-attack-breaking-down-impact-scope-across-debug-chalk), [Tenable on axios](https://tenable.com/blog/faq-about-the-axios-npm-supply-chain-attack-by-north-korea-nexus-threat-actor-unc1069), [Keboola's axios timeline](https://changelog.keboola.com/keboola-security-notice-axios-npm-supply-chain-attack-march-31-2026/), [SafeDep on Mini Shai-Hulud](https://safedep.io/mini-shai-hulud-strikes-again-314-npm-packages-compromised/).*

**Who funds it:** the CISO or AppSec budget, with platform or DevOps engineering as co-owner, because the gate runs in their CI.

**Rough worth (illustrative estimate):** take a mid-size company with about 500 engineers handling 4–6 serious supply-chain incidents a year. If each incident pulls in about 30 engineers for half a day of triage, that's roughly 500–700 engineer-hours a year. Halving it saves about $40–60k a year at fully loaded cost. The larger value is closing the exposure window. One compromised dependency that reaches production can trigger breach response, customer notices and compliance reporting that cost far more than the tool.

## Architecture Summary

Snowflake holds the evidence and makes the decisions. The application layer talks to it through a scoped API and an MCP server.

- **Data layer:** OSV advisories plus npm and PyPI registry data are loaded into Snowflake through an external access integration and network rules. The snapshot holds about 257,000 advisory records and about 4 million version records for 25 watched packages. Scheduled **Tasks** refresh the advisories.
- **Response engine:** **Snowpark Python stored procedures** (`RESPOND`, `IS_AFFECTED`) decide exactly whether a version is affected and pick the lowest clean upgrade. When a version can't be compared, the result is "unknown", not "safe".
- **Native reconciliation:** a Snowpark procedure plus an hourly **Task** (`MATCH_CLIENT_ADVISORIES`) checks every client's latest inventory against the advisories and records incidents with an audit trail. Its code is packaged from **GitHub** into a Snowflake stage.
- **Concurrency and audit:** a **Hybrid Table** lock serializes tracking writes across API instances and the task. Roles let the app add audit events but not change or delete them.
- **Claude in Snowflake:** **Cortex `AI_COMPLETE` (claude-sonnet-4-5)** writes incident briefs from the structured response data and labels each client file's use case. That lets an incident report say which business functions call the compromised package. Briefs are marked as untrusted, and decisions use the structured data, not the generated text.
- **Threat intel:** an `INTEL.SIGNAL_FEED` adapter is designed to take **Snowflake Marketplace** listings (CISA KEV, Tor exits, AI-endpoint egress) and use them to raise incident priority.
- **App surfaces:** a FastAPI service with 10 **MCP tools** so Claude can inspect evidence and prepare responses. Approval is deliberately not one of those tools. A Streamlit review dashboard and a local client agent read lockfiles and logs where they live and upload only the normalized inventory and indicator counts. **Snowpark Container Services** specs are included to run the API and dashboard inside Snowflake.

**Live status:** everything above except Container Services and Marketplace intel runs on the hackathon Snowflake account. Migrations 10–15 are applied, and the app's tracking state (clients, inventories, incidents, notifications, use-case maps, audit events) is in Snowflake tables instead of local SQLite. Three example client organizations are registered. A call to the native `MATCH_CLIENT_ADVISORIES` procedure checked all 8 of their packages with no errors or unknowns and opened one incident. Cortex `AI_COMPLETE` with `claude-sonnet-4-5` answers from inside the account. The API and dashboard still run on a laptop and connect with the `SENTINEL_BACKEND=snowflake` setting.

## Why Snowflake

Supply-chain risk is a shared-data problem. Every organization checks its code against the same advisories and the same package registries. Our design follows from that.

- **One catalog, many organizations.** The 257,000 advisories and 4 million package versions are loaded once and serve every client. Adding an organization means adding a few rows of inventory, not a new deployment, database or pipeline. The more organizations use the catalog, the lower the cost of each one.
- **The database keeps growing without a rebuild.** Storage and compute are separate, so the catalog can grow to more ecosystems, more history and more client inventories without re-architecting. The warehouse is X-Small and suspends when idle. A full advisory refresh can borrow a larger warehouse for minutes and then release it.
- **Agents update it safely.** Client agents upload inventories, scheduled Tasks refresh advisories and re-check every client every hour, and Claude writes through MCP tools. All of them work on the same governed tables. A role-scoped app account can add audit events but never edit or delete them, and a Hybrid Table lock keeps concurrent agents from overwriting each other. Humans approve; agents never do.
- **The decision runs next to the data.** The affected-version logic (Snowpark), the hourly reconciliation (Tasks) and the incident briefs and use-case labels (Claude through Cortex) all run inside Snowflake. Inventory and advisories never travel to a separate LLM gateway, queue or server, so there's less to secure and less to run.
- **Security data is already there.** Many security and platform teams keep logs and asset inventories in Snowflake. Blast Radius adds supply-chain exposure to that same governed store, rather than asking a CISO to approve one more SaaS copy of their software inventory.
- **A path to distribution (next step, not built).** Snowflake Secure Data Sharing and the Marketplace let a security vendor or an industry information-sharing group publish the advisory catalog once. Each subscribing organization would query it live from its own account, so its inventory never leaves its own boundary. Threat-intel providers already publish feeds this way, and our `INTEL.SIGNAL_FEED` adapter is built to take them.

## Snowflake Account Identifier

`SFSEHOL-ANTHROPIC_SNOWFLAKE_HACKATHON_XCAYXS` (database `VULN_SENTINEL_DB`)

## A Short Build Story

We split the work into two tracks. One teammate built the Snowflake data layer first: schemas, OSV and registry ingestion, and the first version of the response procedure. We then used **Claude Code** as the main engineer for the application on top. It built the FastAPI and MCP server, the inventory parsers for npm, Poetry and requirements files, the fix workflow, the review dashboard, the additive SQL migrations, and a test suite that runs real Git operations and the native Snowpark adapter against a local SQL engine. We worked in small, reviewable commits. Claude also wrote the component docs, the demo runbook and a judges' brief, and we used it to fact-check our pitch: it removed claims we couldn't support, like measured time savings or a breach being confirmed when only an attempt was observed.

What didn't work or got cut:

- **Three autonomous Claude agents.** We first pictured separate scanner, patch and containment models. We replaced them with deterministic workflow agents that Claude calls through MCP, because an agent that can approve its own containment is not a security control.
- **Automatic transitive npm fixes.** Upgrading a nested package like Chalk silently changes what the parent package depends on. The fix workflow now stops and asks for a reviewed upgrade of the parent package or an override.
- **Re-running the base schema.** Our first deployment script dropped and rebuilt the database. We switched to additive migrations so the loaded data survives.
- **A safety fix that passed tests but failed live.** Our "lowest clean upgrade" query called a Python UDF inside a correlated `NOT EXISTS`. Local tests passed, but Snowflake rejected it ("Unsupported subquery type"). We rewrote it as an anti-join and redeployed. It still fails closed.
- **Live Marketplace intel.** Listings require accepting terms and use schemas that vary by provider, so we built a neutral adapter instead of guessing column names.
- **Snowpark Container Services hosting.** The specs are written, but we didn't validate them end to end in the time we had.

## Viability

The natural owner is a company's AppSec team. They own the advisory evidence and the reviewer role. Platform engineering co-owns it, because they make the gate a required CI check. The Snowflake data layer fits teams that already keep security and engineering data in Snowflake.

**Next step: an early-warning partnership with Anthropic.** Anthropic's security researchers and Claude find serious vulnerabilities in widely used open-source software. Today, everyone learns about a flaw on disclosure day, the same moment attackers do, and the race starts there. We want to be a trusted early recipient under coordinated disclosure. When Anthropic finds a severe issue, they brief us under embargo, and we prepare a response for every client before the advisory goes public:

- **Know who is exposed before disclosure.** We already hold each client's exact inventory, including packages pulled in transitively, so we can list affected organizations and the business functions at risk without telling anyone the details.
- **Have the fix ready.** Patch candidates and tested fix branches are staged in advance, so clients merge a reviewed change instead of starting from scratch.
- **Switch on the gate at disclosure.** Version blocks are pre-approved by each client's reviewer and go live the moment the advisory is published, so no affected build ships during the race.

The result: our clients are ready before attackers have the details, instead of hours behind. This would follow standard coordinated disclosure rules. Nothing goes to clients before the agreed date beyond a "prepare for an update" notice, and pre-staged changes stay inside each client's own review process.

Other next steps:

1. Move the API and dashboard into Snowpark Container Services and turn on the hourly matching task. The data layer, migrations 10–15 and the native procedure already run live.
2. Pilot it with one team: time exposure decisions and fix proposals against manual triage.
3. Connect a licensed Marketplace threat-intel feed.
4. Publish the advisory catalog as a Secure Share so a second organization can use it from its own account.
5. Add one production containment connector, such as a registry or proxy block.

## Which Partner Tools Did You Use?

- **Snowflake:** Snowpark Python procedures, Tasks, Hybrid Tables, Cortex `AI_COMPLETE`, external access integrations, Git-to-stage packaging, Marketplace intel adapter, Snowpark Container Services specs.
- **Anthropic:** Claude Code for the build; Claude Sonnet through Cortex; Model Context Protocol server for Claude clients.
- **Other:** OSV.dev advisory data, GitHub with the gh CLI for draft PRs, FastAPI, Streamlit.

## Feedback on Anthropic and Snowflake Products

- **Claude Code:** it was strongest at multi-file work across Python, SQL and tests. It was good at catching places where the code or the pitch claimed more than we could show, like calling an unknown result "safe" or saying a fix ran when it hadn't. The friction was keeping it from building ahead of what we had validated live. We needed explicit notes saying which features were fixtures and which were live.
- **Cortex `AI_COMPLETE`:** calling Claude from inside a stored procedure, next to the data, was the simplest way to ground summaries in query results. It would help to have clearer docs on which Claude models are available in each region and on cost per call.
- **Snowflake:** Snowpark procedures and Tasks made the decisions repeatable without extra infrastructure. Hybrid Tables gave us a real lock for concurrent writes. The setup-heavy features slowed us down: Marketplace terms, compute-pool privileges for Container Services, and external access integrations. An end-to-end hackathon template for "Git repo → stage → procedure → task" would save teams a lot of time. A clearer compile-time error for UDFs inside correlated subqueries would have saved us a debugging round, since the failure only shows up when the procedure runs.
- **MCP:** a good fit for scoped tools. Being able to leave approval out of the tool list was an easy, clear safety boundary. OAuth examples for remote MCP servers would help.
