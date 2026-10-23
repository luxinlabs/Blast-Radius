"""Human review UI: all access and transitions still enforced by the API."""

import json
import os

import httpx
import streamlit as st

from vuln_sentinel.client import Client

st.set_page_config(page_title="Vuln Sentinel", page_icon="🛡", layout="wide")
st.title("Vuln Sentinel")
st.caption("Dependency incident response · Evidence first · Human approval required")

with st.sidebar:
    st.subheader("Review session")
    token = st.text_input("Access token", type="password", key="access_token")
    client_id = st.text_input("Client ID (blank for admin fleet view)", value="demo-app")
    st.button("Refresh")
    statuses = st.multiselect(
        "Status",
        ["OPEN", "PROPOSED", "APPROVED", "REJECTED", "SUPERSEDED"],
        default=["OPEN", "PROPOSED", "APPROVED", "REJECTED"],
    )
    st.caption("Approval records a review decision. Merge and deployment remain separate human actions.")

if not token:
    st.info("Enter your reviewer token to view incidents.")
    st.stop()

url = os.getenv("SENTINEL_URL", "http://127.0.0.1:8000")
try:
    client = Client(url, token, client_id)
    health = client.request("GET", "/health")
    if health.get("demo"):
        st.warning("LOCAL DEMO · synthetic fixture evidence · no live OSV or Marketplace connection")
    suffix = f"?client_id={client_id}" if client_id else ""
    emergencies = client.request("GET", f"/v1/emergencies{suffix}")
    notifications = client.request("GET", f"/v1/notifications{suffix}")
    impacts = client.request("GET", f"/v1/clients/{client_id}/impacts") if client_id else []
except (httpx.HTTPError, ValueError) as exc:
    st.error(f"Cannot load fleet: {exc}")
    st.stop()


def detail(n):
    p = n["payload"]
    if n["kind"] == "THREAT":
        return f"{p['package']['name']} {p['package']['version']} · {p['incident_type']}"
    if n["kind"] == "ACCESS_ANOMALY":
        return f"{p['rule']} · {p['principal']} · {p['count']} accesses"
    return f"{len(p['findings'])} indicator match(es)"


st.subheader("Notification center")
st.dataframe(
    [
        {
            "client": n["client_id"],
            "kind": n["kind"],
            "priority": n["priority"],
            "status": n["status"],
            "detail": detail(n),
            "agent actions": len((n["response"] or {}).get("actions", [])),
        }
        for n in notifications
    ],
    use_container_width=True,
    hide_index=True,
)
if impacts:
    st.subheader(f"Use-case impact · {client_id}")
    st.dataframe(
        [
            {
                "status": ("🔴 " if i["status"] == "compromised" else "🟢 ") + i["status"],
                "use case": i["use_case"],
                "package": i["package"],
                "criticality": i["criticality"],
                "functions affected": ", ".join(f["symbol"] for f in i["functionalities_affected"]),
            }
            for i in impacts
        ],
        use_container_width=True,
        hide_index=True,
    )

visible = [e for e in emergencies if e["status"] in statuses]
cols = st.columns(4)
for col, title, count in zip(
    cols,
    ["Incidents", "Urgent (P0)", "Awaiting review", "Clients"],
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

st.dataframe(
    [
        {
            "client": e["client_id"],
            "package": e["payload"]["package"]["name"],
            "version": e["payload"]["package"]["version"],
            "incident": e["payload"]["incident_type"],
            "priority": e["payload"].get("priority"),
            "status": e["status"],
        }
        for e in visible
    ],
    use_container_width=True,
    hide_index=True,
)

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
payload = incident["payload"]
left, right = st.columns([2, 1])
with left:
    st.subheader("Response evidence")
    pkg = payload["package"]
    st.write(f"**{pkg['name']} {pkg['version']}** · {payload['incident_type']}")
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
with right:
    st.subheader("Human review")
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
            submitted = st.form_submit_button("Record review")
            if submitted:
                if len(reason.strip()) < 3:
                    st.error("Add a review reason.")
                else:
                    try:
                        client.request(
                            "POST",
                            f"/v1/emergencies/{selected}/review",
                            {"decision": decision, "reason": reason, "revision": incident["revision"]},
                        )
                        st.success("Review recorded. No merge or deployment performed.")
                        st.rerun()
                    except httpx.HTTPError as exc:
                        st.error(f"Review was not accepted: {exc}")
    else:
        st.info("A tested fix proposal is required before review.")
    if incident.get("reviewer"):
        st.write("Reviewer:", incident["reviewer"])
        st.write("Reason:", incident.get("reason"))

with st.expander("Audit trail and local IOC findings"):
    try:
        st.json(client.request("GET", f"/v1/clients/{incident['client_id']}/events"))
    except httpx.HTTPError as exc:
        st.error(str(exc))
