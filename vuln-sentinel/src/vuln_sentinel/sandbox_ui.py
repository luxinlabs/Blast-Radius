"""Live sandbox controls; all access and execution approvals are enforced by the API."""

import httpx
import streamlit as st


@st.fragment(run_every="2s")
def render_sandbox(client, client_id):
    st.subheader("Client sandbox · live agents")
    st.caption(
        "One worker per configured client. Rule-based plans; copied files; human-approved Docker checks. No package installs, customer application tests, merges or deployments."
    )
    try:
        clients = client.request("GET", "/v1/sandbox/clients")
        if not clients:
            st.info(
                "No client repository is configured for this token. Use the admin token and a blank Client ID for the three demo organizations."
            )
            return
        names = [item["client_id"] for item in clients]
        selected = st.multiselect("Client workers", names, default=names, key="sandbox_clients")
        if st.button("Start client agents", key="start_sandbox_workers", type="primary"):
            if not selected:
                st.warning("Select at least one client.")
            else:
                client.request("POST", "/v1/sandbox/fleet/start", {"clients": selected})
                st.success("Client agents started. New notifications will be picked up automatically.")
        if st.button("Stop watching notifications", key="stop_sandbox_workers"):
            if selected:
                client.request("POST", "/v1/sandbox/fleet/stop", {"clients": selected})
                st.info(
                    "Workers are stopping. Already approved sandbox runs continue to completion or timeout."
                )
        st.write(
            " · ".join(
                f"{item['client_id']}: {'watching notifications' if item['running'] else 'stopped'}"
                + (f" / {item['error']}" if item["error"] else "")
                for item in clients
            )
        )
        suffix = f"?client_id={client_id}" if client_id else ""
        jobs = client.request("GET", "/v1/sandbox/jobs" + suffix)
        if not jobs:
            st.info(
                "Start the agents, then inject a demo event. Logs and execution requests will appear here."
            )
            st.code(
                "sentinel inject npm chalk 5.6.2 --advisory DEMO-CHALK\nsentinel inject pypi litellm 1.106.2 --advisory DEMO-LITELLM",
                language="bash",
            )
            return
        st.dataframe(
            [
                {
                    "client": job["client_id"],
                    "kind": job["payload"].get("kind"),
                    "state": job["state"],
                    "updated": job["updated_at"],
                }
                for job in jobs
            ],
            hide_index=True,
            use_container_width=True,
        )
        identity = st.selectbox(
            "Inspect client run",
            [job["job_id"] for job in jobs],
            format_func=lambda key: next(
                f"{j['client_id']} · {j['payload'].get('kind')} · {j['state']} · {key[:8]}"
                for j in jobs
                if j["job_id"] == key
            ),
            key="sandbox_job",
        )
        job = next(j for j in jobs if j["job_id"] == identity)
        data = job["payload"]
        logs = client.request("GET", f"/v1/sandbox/jobs/{identity}/logs")
        st.code(
            "\n".join(f"{row['at'][11:19]} [{row['level']}] {row['message']}" for row in logs),
            language="text",
        )
        st.caption(
            "Log refreshes every two seconds. Detector findings and sandbox checks are distinct; passing these checks does not establish full incident remediation."
        )
        if data.get("error"):
            st.error(data["error"])
        if data.get("summary"):
            st.write(data["summary"])
            st.caption(data["test_scope"])
            with st.expander(
                "Proposed patch and execution request", expanded=job["state"] == "AWAITING_APPROVAL"
            ):
                for name, patch in data["patches"].items():
                    st.write(name)
                    st.code(patch, language="diff")
                st.code(" ".join(data["command"]), language="bash")
                st.caption(
                    "Runs inside Docker with no network, a read-only root, limited CPU/memory/processes, and no client credentials. The host repository is never mounted."
                )
        if job["state"] == "AWAITING_APPROVAL":
            with st.form("sandbox-review-" + identity):
                decision = st.radio(
                    "Sandbox execution decision", ["APPROVED", "REJECTED"], key="sandbox-decision-" + identity
                )
                reason = st.text_input("Sandbox review reason", key="sandbox-reason-" + identity)
                if st.form_submit_button("Submit sandbox decision"):
                    if len(reason.strip()) < 3:
                        st.error("Enter a reason before approving execution.")
                    else:
                        client.request(
                            "POST",
                            f"/v1/sandbox/jobs/{identity}/review",
                            {"decision": decision, "reason": reason, "plan_digest": data["plan_digest"]},
                        )
                        st.rerun()
        if data.get("approved_by"):
            st.caption(f"Execution approved by {data['approved_by']}: {data['approval_reason']}")
    except httpx.HTTPError as exc:
        st.error(f"Client sandbox request failed: {exc}")
        st.caption(
            "Restart the updated API if sandbox routes return 404. If execution is blocked, start Docker and run: docker pull python:3.12-alpine"
        )
