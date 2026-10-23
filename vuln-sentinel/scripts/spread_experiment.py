"""Run from vuln-sentinel: python scripts/spread_experiment.py 100 500 1000

Timed experiment: how fast Blast Radius finds a transitive compromise across a fleet.

Fresh temporary SQLite per run; never touches .sentinel/. Fleet: N synthetic clients; ~40% pull chalk
transitively through next (depth 2), the rest do not. Steps timed:
  1. inject compromised chalk 5.6.2 + fleet reconcile  -> time to exposure decision
  2. per-client impact lookup                          -> which business functions are hit
  3. deployment gate on every client inventory         -> time to block next builds
"""

import json
import os
import random
import statistics
import sys
import tempfile
import time

sys.path.insert(0, "src")
from vuln_sentinel import cli  # noqa: E402
from vuln_sentinel.models import SBOM, Package  # noqa: E402

cli.load_env()


# Same code layout for every client: checkout calls axios, the home page calls next (and so chalk).
USAGES = [
    {"ecosystem": "npm", "package": "axios", "file": "src/pay/checkout.js", "symbol": "chargeCard"},
    {"ecosystem": "npm", "package": "next", "file": "src/web/pages.js", "symbol": "renderHome"},
]


def inventory(exposed):
    pkgs = [
        Package(ecosystem="npm", name="axios", version="1.20.0", locator="node_modules/axios", direct=True),
        Package(ecosystem="npm", name="debug", version="4.4.3", locator="node_modules/debug", direct=True),
    ]
    if exposed:
        pkgs += [
            Package(
                ecosystem="npm",
                name="next",
                version="15.5.28",
                locator="node_modules/next",
                direct=True,
                dependencies=["node_modules/chalk"],
            ),
            Package(
                ecosystem="npm",
                name="chalk",
                version="5.6.2",
                locator="node_modules/chalk",
                direct=False,
            ),
        ]
    return SBOM(source="package-lock.json", packages=pkgs)


def run(n, seed=7):
    random.seed(seed)
    tmp = tempfile.mkdtemp()
    os.environ["SENTINEL_SQLITE_PATH"] = os.path.join(tmp, "state.sqlite")
    exposed = {f"client-{i:04d}": random.random() < 0.4 for i in range(n)}
    with cli.in_process_api() as call:
        for cid, hit in exposed.items():
            call("POST", "/v1/clients", {"client_id": cid, "name": cid})
            call("POST", f"/v1/clients/{cid}/sbom", inventory(hit).model_dump())
            call("POST", f"/v1/clients/{cid}/usecases", {"usages": USAGES})
        before = call("POST", "/v1/reconcile")

        t0 = time.perf_counter()
        call(
            "POST",
            "/v1/demo/threats",
            {"ecosystem": "npm", "package": "chalk", "versions": ["5.6.2"], "advisory_id": "DEMO-CHALK"},
        )
        rec = call("POST", "/v1/reconcile")
        t_detect = time.perf_counter() - t0

        t1 = time.perf_counter()
        flagged = [
            cid
            for cid in exposed
            if any(r["status"] == "compromised" for r in call("GET", f"/v1/clients/{cid}/impacts"))
        ]
        t_impact = time.perf_counter() - t1

        gate_times, blocked = [], 0
        for cid, hit in exposed.items():
            g0 = time.perf_counter()
            res = call("POST", f"/v1/clients/{cid}/gate", inventory(hit).model_dump())
            gate_times.append(time.perf_counter() - g0)
            blocked += not res["allowed"]

    truth = sum(exposed.values())
    return {
        "clients": n,
        "truly_exposed": truth,
        "incidents_opened": len(rec.get("emergency_ids", [])) if isinstance(rec, dict) else rec,
        "incidents_before_inject": len(before.get("emergency_ids", []))
        if isinstance(before, dict)
        else before,
        "impact_flagged": len(flagged),
        "gate_blocked": blocked,
        "gate_false_blocks": blocked - truth,
        "detect_seconds": round(t_detect, 3),
        "impact_lookup_seconds": round(t_impact, 3),
        "gate_median_ms": round(statistics.median(gate_times) * 1000, 1),
        "gate_total_seconds": round(sum(gate_times), 3),
    }


if __name__ == "__main__":
    for n in [int(x) for x in sys.argv[1:]] or [10, 100, 500]:
        print(json.dumps(run(n)), flush=True)
