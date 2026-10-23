"""Console client for the local multi-repository worker fleet.

One API supervisor starts a separately named worker for each configured client.
Execution approval remains a distinct reviewer action; this console cannot approve.
"""

import time


def supervise(client, clients=None, watch=False, once=False, stop=False, emit=print):
    if sum((watch, once, stop)) > 1:
        raise ValueError("Choose one of --watch, --once, or --stop")
    permitted = [row["client_id"] for row in client.request("GET", "/v1/sandbox/clients")]
    names = clients or permitted
    if not names or set(names) - set(permitted):
        raise ValueError("Select clients configured on this host and permitted for this token")
    action = "stop" if stop else "poll" if once else "start"
    result = client.request("POST", f"/v1/sandbox/fleet/{action}", {"clients": names})
    if not watch:
        return result
    emit("Watching " + ", ".join(names) + ". Code execution requires a separate reviewer approval.")
    seen = {}
    states = {}
    try:
        while True:
            for name in names:
                for job in client.request("GET", f"/v1/sandbox/jobs?client_id={name}"):
                    identity = job["job_id"]
                    if states.get(identity) != job["state"]:
                        emit(f"[{name}] {identity[:10]} → {job['state']}")
                        states[identity] = job["state"]
                    for row in client.request(
                        "GET", f"/v1/sandbox/jobs/{identity}/logs?after={seen.get(identity, 0)}"
                    ):
                        emit(f"[{row['at'][11:19]}] [{name}] [{row['level']}] {row['message']}")
                        seen[identity] = row["seq"]
            time.sleep(2)
    except KeyboardInterrupt:
        return {"log_stream": "stopped", "workers": "still watching; use client-agents --stop to stop them"}
