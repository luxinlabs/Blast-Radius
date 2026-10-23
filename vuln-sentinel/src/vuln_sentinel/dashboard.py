"""Blast Radius incident command center. Authorization remains enforced by the API."""

import json
import os
from html import escape

import httpx
import streamlit as st

from vuln_sentinel.client import Client

st.set_page_config(page_title="Blast Radius", page_icon="◈", layout="wide", initial_sidebar_state="expanded")
st.markdown(
    """
<style>
:root {--bg:#0d141c;--panel:#151f2a;--line:#263543;--muted:#94a3b3;--white:#f2f1eb;--orange:#ffa344;--blue:#67b7ee;--green:#47c58f;--red:#ff737b;}
.stApp,[data-testid="stHeader"] {background:var(--bg);color:var(--white)}
[data-testid="stSidebar"]{background:#101923;border-right:1px solid var(--line)}
.block-container{max-width:1600px;padding-top:2rem;padding-bottom:3rem}
h1,h2,h3,p,label{color:var(--white)} h1{font-size:3.2rem!important;letter-spacing:-1.5px;line-height:1.12!important;font-weight:750!important}
h2{font-size:1.45rem!important}h3{font-size:1.12rem!important}
[data-testid="stCaptionContainer"]{color:var(--muted)}
[data-testid="stMetric"]{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px 20px}
[data-testid="stMetricLabel"]{color:var(--muted);font-size:.8rem} [data-testid="stMetricValue"]{font-size:1.9rem;color:var(--white)}
.stButton>button,.stFormSubmitButton>button{border:1px solid #3a4a59;background:#1b2935;color:var(--white);border-radius:8px;font-weight:600}
.stButton>button:hover,.stFormSubmitButton>button:hover{border-color:var(--orange);color:var(--orange)}
.stButton>button[kind="primary"],.stFormSubmitButton>button[kind="primary"]{background:var(--orange);color:#10161c;border-color:var(--orange)}
[data-baseweb="input"],[data-baseweb="select"]>div,[data-baseweb="textarea"]{background:#172330!important;color:var(--white)!important}
input,textarea{color:var(--white)!important} [data-testid="stExpander"]{border-color:var(--line);background:#111b25;border-radius:10px}
[data-testid="stCode"]{background:#111b25!important;border:1px solid #263543;border-radius:8px}
[data-baseweb="tab-list"]{gap:1.6rem;border-bottom:1px solid var(--line)} [data-baseweb="tab"]{color:var(--muted);background:transparent}
[data-baseweb="tab"][aria-selected="true"]{color:var(--orange)} [data-baseweb="tab-highlight"]{background:var(--orange)}
.brand{display:flex;align-items:center;gap:12px;margin-bottom:28px}.brand-icon{color:var(--orange);font-size:30px}.brand-name{font-weight:800;font-size:20px;letter-spacing:-.4px}.brand-tag{color:var(--muted);font:11px monospace;letter-spacing:1.5px;margin-left:auto}
.eyebrow{color:var(--orange);font:700 12px monospace;letter-spacing:2px;margin-bottom:12px}.subtitle{font-size:16px;color:var(--muted);margin:4px 0 26px}
.pill{display:inline-block;border:1px solid #455262;border-radius:5px;padding:4px 9px;font:11px monospace;letter-spacing:.5px;color:var(--muted)}
.pill-red{color:var(--red);border-color:#77313b;background:#301d25}.pill-green{color:var(--green);border-color:#285f4d;background:#152b25}.pill-orange{color:var(--orange);border-color:#745232;background:#30261e}
.core{border:1px solid #e14856;border-radius:11px;background:#281b21;padding:22px 24px;margin-bottom:10px}.core-title{font-size:21px;font-weight:750;margin-bottom:6px}.core-meta{color:var(--muted);font-size:13px}.core-alert{color:var(--red);font-size:17px;font-weight:650;margin-top:12px}.core-status{float:right}
.upstream{border:1px solid var(--line);border-radius:11px;background:var(--panel);padding:18px;min-height:550px}.upstream-title{font-size:16px;font-weight:700}.upstream-sub{font-size:12px;color:var(--muted);margin:5px 0 18px}.package-row{display:flex;align-items:center;justify-content:space-between;gap:6px;font-size:12px;padding:10px 0;border-bottom:1px solid #22303d}.package-row.selected{color:var(--red);background:#34232d;padding:10px 7px;border-radius:5px}.package-version{font:11px monospace;color:var(--muted)}
.branch{display:flex;justify-content:space-around;height:30px;position:relative}.branch:before{content:'';position:absolute;top:0;left:16.6%;right:16.6%;border-top:1px solid #364c5d}.branch span{height:30px;border-left:2px solid}.branch span:nth-child(1){border-color:var(--blue)}.branch span:nth-child(2){border-color:var(--orange)}.branch span:nth-child(3){border-color:var(--green)}
.st-key-scanner_agent,.st-key-patch_agent,.st-key-containment_agent{background:var(--panel);border:1px solid;border-radius:11px;padding:18px;min-height:375px}
.st-key-scanner_agent{border-color:var(--blue)}.st-key-patch_agent{border-color:var(--orange)}.st-key-containment_agent{border-color:var(--green)}
.agent-heading{font-size:18px;font-weight:750;margin-bottom:5px}.blue{color:var(--blue)}.orange{color:var(--orange)}.green{color:var(--green)}.agent-runtime{font-size:12px;color:var(--muted);margin-bottom:15px}.agent-terminal{font:12px/1.8 monospace;white-space:pre-wrap;color:var(--white);overflow-wrap:anywhere}
.section-label{font:11px monospace;color:var(--muted);letter-spacing:1px;margin:22px 0 12px}.audit-event{display:flex;gap:18px;border-bottom:1px solid var(--line);padding:12px 0}.audit-time{font:11px monospace;color:var(--muted);min-width:140px}.audit-kind{font:12px monospace;color:var(--orange)}
@media(max-width:800px){h1{font-size:2.2rem!important}.brand-tag{display:none}.upstream{min-height:0}.core-status{float:none;display:block;margin-bottom:10px}.block-container{padding-left:1rem;padding-right:1rem}}
</style>
""",
    unsafe_allow_html=True,
)


def html(content):
    st.markdown(content, unsafe_allow_html=True)


def pill(text, color="orange"):
    return f'<span class="pill pill-{color}">{escape(str(text))}</span>'


html(
    '<div class="brand"><span class="brand-icon">◈</span><span class="brand-name">Blast Radius</span><span class="brand-tag">DEPENDENCY RESPONSE / INCIDENT COMMAND</span></div>'
)
html('<div class="eyebrow">INCIDENT COMMAND CENTER</div>')
st.title("One bad library. A coordinated response.")
html('<div class="subtitle">Find the exposure. Prepare the patch. Contain the release.</div>')

with st.sidebar:
    st.markdown("### ◈ Blast Radius")
    st.caption("Your incident workspace")
    token = st.text_input("Access token", type="password", key="access_token")
    client_id = st.text_input("Client ID (blank for admin fleet view)", value="demo-app")
    st.button("Refresh", use_container_width=True)
    statuses = st.multiselect(
        "Status",
        ["OPEN", "PROPOSED", "APPROVED", "REJECTED", "SUPERSEDED"],
        default=["OPEN", "PROPOSED", "APPROVED", "REJECTED"],
    )
    search = st.text_input("Search packages", placeholder="axios, litellm, next…")
    st.divider()
    st.caption("A human approves changes. Agents never merge or deploy.")

if not token:
    st.info("Enter your reviewer token to view incidents.")
    st.caption("Keep the API running with `sentinel serve`, then open this dashboard in a separate terminal.")
    st.stop()

url = os.getenv("SENTINEL_URL", "http://127.0.0.1:8000")
try:
    client = Client(url, token, client_id)
    health = client.request("GET", "/health")
    suffix = f"?client_id={client_id}" if client_id else ""
    emergencies = client.request("GET", f"/v1/emergencies{suffix}")
except httpx.ConnectError:
    st.error(
        f"API offline at {url}. Keep `sentinel serve` running in a separate terminal, then click Refresh."
    )
    st.stop()
except (httpx.HTTPError, ValueError) as exc:
    st.error(f"Cannot load fleet: {exc}")
    st.stop()

if health.get("demo"):
    st.caption("DEMO MODE · synthetic advisory fixtures · no live Marketplace data · npm + PyPI coverage")
visible = [
    e
    for e in emergencies
    if e["status"] in statuses and search.lower() in e["payload"]["package"]["name"].lower()
]
cols = st.columns(4)
for col, title, count in zip(
    cols,
    ["Active incidents", "Urgent / P0", "Awaiting review", "Affected clients"],
    [
        len(visible),
        sum(e["payload"].get("priority") == "P0" for e in visible),
        sum(e["status"] == "PROPOSED" for e in visible),
        len({e["client_id"] for e in visible}),
    ],
):
    col.metric(title, count)

if not visible:
    st.info("No incidents match the selected statuses. Run a client scan to register an inventory.")
    st.stop()

st.write("")
selected = st.selectbox(
    "Inspect incident",
    [e["emergency_id"] for e in visible],
    format_func=lambda key: next(
        f"{e['client_id']} / {e['payload']['package']['name']} {e['payload']['package']['version']} · {e['status']}"
        for e in visible
        if e["emergency_id"] == key
    ),
)
incident = next(e for e in visible if e["emergency_id"] == selected)
payload, pkg = incident["payload"], incident["payload"]["package"]
try:
    agents = client.request("GET", f"/v1/emergencies/{selected}/agents")
    events = client.request("GET", f"/v1/clients/{incident['client_id']}/events")
    inventory = client.request("GET", f"/v1/clients/{incident['client_id']}/inventory")
except httpx.HTTPError as exc:
    st.error(f"Cannot load agent workspace: {exc}. Restart the API after updating the app.")
    st.stop()

command, fleet, evidence, review_tab, activity = st.tabs(
    ["Command center", "Fleet inventory", "Evidence", "Human review", "Activity"]
)
with command:
    upstream, response = st.columns([1, 3.7], gap="large")
    with upstream:
        rows = []
        packages = inventory.get("sbom", {}).get("packages", [])
        for item in packages[:18]:
            affected = item["name"] == pkg["name"] and item["version"] == pkg["version"]
            rows.append(
                f'<div class="package-row {"selected" if affected else ""}"><span>{escape(item["name"])}<br><span class="package-version">{escape(item["ecosystem"])} / {escape(item["version"])}</span></span><span>{"!" if affected else "·"}</span></div>'
            )
        html(
            '<div class="upstream"><div class="upstream-title">Upstream libraries</div><div class="upstream-sub">npm · PyPI / exact inventory</div>'
            + "".join(rows)
            + '<div class="upstream-sub" style="margin-top:18px">Unmarked packages have not been declared safe by this view.</div></div>'
        )
    with response:
        html(
            f'<div class="core"><div class="core-status">{pill(incident["status"])}</div><div class="core-title">Blast Radius core</div><div class="core-meta">Exact-version matching · {len(packages)} inventory entries · {escape(incident["client_id"])}</div><div class="core-alert">⚠ {escape(pkg["name"])} {escape(pkg["version"])} / {escape(payload["incident_type"].replace("_", " ").lower())}</div></div>'
        )
        actions_col, caption_col = st.columns([1.2, 2])
        if actions_col.button("Run response agents", type="primary", use_container_width=True):
            try:
                with st.spinner("Rechecking evidence and preparing containment policy…"):
                    client.request("POST", f"/v1/emergencies/{selected}/agents/run")
                st.session_state["agent_notice"] = (
                    "Scan complete. Patch plan ready. Containment requires human approval."
                )
                st.rerun()
            except httpx.HTTPError as exc:
                st.error(f"Agent run was not accepted: {exc}")
        caption_col.caption(
            "Rechecks advisories and prepares a block policy. Patch execution stays on the client."
        )
        if st.session_state.get("agent_notice"):
            st.success(st.session_state.pop("agent_notice"))
        html('<div class="branch"><span></span><span></span><span></span></div>')
        scanner_col, patch_col, contain_col = st.columns(3, gap="small")
        scanner, patch, containment = agents["scanner"], agents["patch"], agents["containment"]
        with scanner_col, st.container(key="scanner_agent"):
            html(
                '<div class="agent-heading blue">1 · Scanner agent</div><div class="agent-runtime">Exact inventory / advisory evidence</div>'
            )
            html(pill(scanner["status"], "green"))
            lines = [
                f"scan {pkg['ecosystem']} / {pkg['name']}",
                f"version {pkg['version']}",
                f"{scanner['advisories']} matching advisories",
            ]
            lines.extend(f"↳ {p['dependent']} ({p.get('version', '')})" for p in scanner["paths"][:5])
            if not scanner["paths"]:
                lines.append("No resolved dependent paths")
            lines.append("graph: complete" if scanner["graph_complete"] else "graph: partial / see evidence")
            html('<div class="agent-terminal" style="margin-top:14px">' + escape("\n".join(lines)) + "</div>")
            st.caption("Log hunting runs on your client.")
            st.code("sentinel hunt <logfiles>", language="bash")
        with patch_col, st.container(key="patch_agent"):
            html(
                '<div class="agent-heading orange">2 · Patch agent</div><div class="agent-runtime">Isolated worktree / tested fix PR</div>'
            )
            html(pill(patch["status"]))
            st.code(patch["diff"], language="diff")
            st.caption(f"Tests: {patch['tests']}")
            if patch.get("proposal"):
                st.link_button("Open fix pull request ↗", patch["proposal"]["pr_url"])
            else:
                st.caption("Copy the command below and run it in the client repository.")
            with st.expander("Client fix command"):
                st.code(patch["command"], language="bash")
                st.caption(
                    "Use poetry.lock for Poetry projects and choose a test command for that project. Add --open-pr to create a draft PR."
                )
        with contain_col, st.container(key="containment_agent"):
            html(
                '<div class="agent-heading green">3 · Containment agent</div><div class="agent-runtime">Block policy / deployment gate</div>'
            )
            html(
                pill(containment["status"], "green" if containment["status"] == "POLICY_ACTIVE" else "orange")
            )
            lines = []
            for action in containment["actions"]:
                marker = "✓" if action["status"] == "APPLIED" else "…"
                lines.append(
                    f"{marker} block {action['payload']['name']} {action['payload']['version']}\n  {action['status'].lower()}"
                )
            if not lines:
                lines = ["Ready to propose version block", "Run response agents to begin"]
            lines.extend(
                [
                    "WAF rules: manual connector",
                    "Service isolation: manual connector",
                    "Owner notification: manual action",
                ]
            )
            html('<div class="agent-terminal" style="margin-top:14px">' + escape("\n".join(lines)) + "</div>")
            st.code("sentinel gate <lockfile>", language="bash")
            st.caption("Require this gate in CI before deployment.")
    st.caption(
        "Workflow agents use deterministic evidence and client tools. No Claude/Cortex model execution is claimed by this local view."
    )

with fleet:
    st.subheader("Fleet inventory")
    st.dataframe(inventory.get("sbom", {}).get("packages", []), use_container_width=True, hide_index=True)
    st.caption(f"Snapshot: {inventory.get('revision', '')[:16]}")
    st.download_button(
        "Download inventory JSON",
        json.dumps(inventory, indent=2),
        file_name="blast-radius-inventory.json",
        mime="application/json",
    )
    st.subheader("Incident queue")
    st.dataframe(
        [
            {
                "client": e["client_id"],
                "package": e["payload"]["package"]["name"],
                "version": e["payload"]["package"]["version"],
                "priority": e["payload"].get("priority"),
                "status": e["status"],
            }
            for e in visible
        ],
        use_container_width=True,
        hide_index=True,
    )

with evidence:
    st.subheader("Response evidence")
    st.write("Recommended versions", payload.get("recommended_version", {}))
    st.write("Secrets at risk:", payload.get("secrets_at_risk", False))
    st.write("Advisories", payload.get("advisories", []))
    if payload.get("sre_brief"):
        st.text_area("AI brief · verify against evidence", payload["sre_brief"], height=200, disabled=True)
    st.write("Playbook", payload.get("playbook", []))
    with st.expander("Client dependency paths"):
        st.json(payload.get("client_blast_radius", {}))
    with st.expander("Watchlist paths · latest release declarations"):
        st.json(payload.get("blast_radius", []))
    with st.expander("Intel source and freshness"):
        st.json(payload.get("intel", {}))
    st.download_button(
        "Download response evidence",
        json.dumps(payload, indent=2),
        file_name="blast-radius-evidence.json",
        mime="application/json",
    )

with review_tab:
    patch_review, containment_review = st.columns(2, gap="large")
    with patch_review:
        st.subheader("Review fix proposal")
        st.caption(f"Snapshot: {incident['revision'][:16]} · Evidence: {incident['fingerprint'][:16]}")
        proposal = incident.get("proposal")
        if proposal:
            proposal = json.loads(proposal) if isinstance(proposal, str) else proposal
            st.link_button("Open proposed pull request", proposal["pr_url"])
            st.write("Target:", proposal["target_version"])
            st.code(" ".join(proposal["test_command"]), language="text")
            st.write("Tests passed:", proposal["test_passed"])
            st.write("Rollback:", proposal["rollback_plan"])
        if incident["status"] == "PROPOSED":
            with st.form(f"review-{selected}"):
                decision = st.radio("Decision", ["APPROVED", "REJECTED"])
                reason = st.text_area("Review notes (required)")
                if st.form_submit_button("Record review"):
                    if len(reason.strip()) < 3:
                        st.error("Add a review reason.")
                    else:
                        try:
                            client.request(
                                "POST",
                                f"/v1/emergencies/{selected}/review",
                                {"decision": decision, "reason": reason, "revision": incident["revision"]},
                            )
                            st.rerun()
                        except httpx.HTTPError as exc:
                            st.error(f"Review was not accepted: {exc}")
        else:
            st.info("A tested fix proposal is required before review.")
        if incident.get("reviewer"):
            st.write("Reviewer:", incident["reviewer"])
            st.write("Reason:", incident.get("reason"))
    with containment_review:
        st.subheader("Review containment")
        pending = [a for a in agents["containment"]["actions"] if a["status"] == "PROPOSED"]
        if not pending:
            st.caption(
                "Run response agents to prepare a policy. Approved policies are enforced by sentinel gate."
            )
        for action in pending:
            st.write(f"Block {action['payload']['name']} {action['payload']['version']}")
            with st.form(f"containment-{action['action_id']}"):
                decision = st.radio(
                    "Containment decision", ["APPROVED", "REJECTED"], key=f"decision-{action['action_id']}"
                )
                reason = st.text_area("Containment review notes", key=f"reason-{action['action_id']}")
                if st.form_submit_button("Record containment review"):
                    if len(reason.strip()) < 3:
                        st.error("Add a review reason.")
                    else:
                        try:
                            client.request(
                                "POST",
                                f"/v1/containment/{action['action_id']}/review",
                                {"decision": decision, "reason": reason, "revision": action["revision"]},
                            )
                            st.rerun()
                        except httpx.HTTPError as exc:
                            st.error(f"Containment review was not accepted: {exc}")

        for action in (a for a in agents["containment"]["actions"] if a["status"] == "APPLIED"):
            st.caption(f"Active block: {action['payload']['name']} {action['payload']['version']}")
            with st.expander("Revoke active block policy"):
                with st.form(f"revoke-{action['action_id']}"):
                    reason = st.text_area("Revocation reason", key=f"revoke-reason-{action['action_id']}")
                    if st.form_submit_button("Revoke policy"):
                        if len(reason.strip()) < 3:
                            st.error("Add a revocation reason.")
                        else:
                            try:
                                client.request(
                                    "POST",
                                    f"/v1/containment/{action['action_id']}/revoke",
                                    {
                                        "decision": "REJECTED",
                                        "reason": reason,
                                        "revision": action["revision"],
                                    },
                                )
                                st.rerun()
                            except httpx.HTTPError as exc:
                                st.error(f"Policy revocation was not accepted: {exc}")

with activity:
    st.subheader("Incident activity")
    for event in reversed(events[:30]):
        html(
            f'<div class="audit-event"><div class="audit-time">{escape(event["created_at"][:19])}</div><div><div class="audit-kind">{escape(event["kind"].replace("_", " "))}</div><span style="color:#94a3b3;font-size:12px">{escape(event["actor"])}</span></div></div>'
        )
    with st.expander("Audit trail and local IOC findings"):
        st.json(events)
