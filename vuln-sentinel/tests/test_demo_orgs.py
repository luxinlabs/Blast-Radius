import json
from pathlib import Path

import pytest

from vuln_sentinel import cli

ORGS = Path(__file__).parents[1] / "examples" / "orgs"


@pytest.fixture
def env(tmp_path, monkeypatch):
    token = "admin-token-" + "x" * 32
    monkeypatch.setenv("SENTINEL_TOKENS", json.dumps({token: {"subject": "a", "role": "admin"}}))
    monkeypatch.setenv("SENTINEL_SQLITE_PATH", str(tmp_path / "state.sqlite"))
    return tmp_path


def test_each_fake_org_fails_differently_when_a_threat_lands(env):
    from vuln_sentinel.models import ThreatEvent

    scan = cli.demo_orgs(ORGS)
    assert scan["complete"] and scan["emergency_ids"] == []

    with cli.in_process_api() as call:
        call(
            "POST",
            "/v1/demo/threats",
            ThreatEvent(ecosystem="npm", package="chalk", versions=["5.6.2"]).model_dump(),
        )
        assert len(call("POST", "/v1/reconcile")["emergency_ids"]) == 2
        status = {
            org: {(r["use_case"], r["status"]) for r in call("GET", f"/v1/clients/{org}/impacts")}
            for org in ("acme-pay", "buildkit", "llm-gateway")
        }
        notes = call("GET", "/v1/notifications?status=NEW")
    assert ("web pages", "compromised") in status["acme-pay"]
    assert ("pay checkout", "safe") in status["acme-pay"]
    assert ("scripts build", "compromised") in status["buildkit"]
    assert {s for _, s in status["llm-gateway"]} == {"safe"}
    kinds = sorted((n["client_id"], n["kind"]) for n in notes)
    assert kinds == [
        ("acme-pay", "THREAT"),
        ("buildkit", "THREAT"),
        ("llm-gateway", "ACCESS_ANOMALY"),
        ("llm-gateway", "ACCESS_ANOMALY"),
        ("llm-gateway", "ACCESS_ANOMALY"),
    ]
