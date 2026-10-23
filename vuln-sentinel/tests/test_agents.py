from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from vuln_sentinel.client import Client


def run_agents(call, incident, role="agent"):
    result = call("POST", f"/v1/emergencies/{incident['emergency_id']}/agents/run", role=role)
    result.raise_for_status()
    return result.json()


def test_agent_coordinator_and_idempotent_proposals(stack, incident):
    _, call, _ = stack
    first = run_agents(call, incident)
    second = run_agents(call, incident)
    assert first["scanner"]["status"] == "COMPLETE"
    assert first["patch"]["target_version"] == "1.106.2"
    assert first["patch"]["tests"] == "Not run"
    assert first["containment"]["status"] == "AWAITING_APPROVAL"
    assert len(first["containment"]["actions"]) == len(second["containment"]["actions"]) == 1
    assert first["containment"]["manual_actions"]
    assert "WAF" in first["containment"]["manual_actions"][0]
    events = call("GET", "/v1/clients/app/events").json()
    assert sum(e["kind"] == "CONTAINMENT_PROPOSED" for e in events) == 1


def test_containment_approval_and_real_gate_enforcement(stack, incident):
    _, call, service = stack
    data = run_agents(call, incident)
    action = data["containment"]["actions"][0]
    review = {
        "decision": "APPROVED",
        "reason": "Block the compromised release",
        "revision": incident["revision"],
    }
    path = f"/v1/containment/{action['action_id']}/review"
    assert call("POST", path, review, "agent").status_code == 403
    assert call("POST", path, {**review, "revision": "stale"}, "reviewer").status_code == 409
    approved = call("POST", path, review, "reviewer")
    assert approved.status_code == 200, approved.text
    assert approved.json() == {
        "status": "APPLIED",
        "enforcement": "sentinel gate",
        "external_infrastructure_changed": False,
    }
    assert call("POST", path, review, "reviewer").status_code == 409
    # Prove the policy enforces independently of the advisory response.
    fixture = service.backend.data["packages"]["PyPI/litellm"]
    fixture["matches"] = []
    fixture["versions"].append("1.107.0")
    body = {
        "source": "requirements.txt",
        "packages": [{"ecosystem": "pypi", "name": "litellm", "version": "1.107.0"}],
    }
    gate = call("POST", "/v1/clients/app/gate", body, "agent").json()
    assert not gate["allowed"] and gate["policy_count"] == 1
    assert gate["blocked"][0]["reason"] == "Approved containment block"
    body["packages"][0]["version"] = "1.106.2"
    assert call("POST", "/v1/clients/app/gate", body, "agent").json()["allowed"]


def test_cross_tenant_and_reader_permissions(stack, incident):
    _, call, _ = stack
    path = f"/v1/emergencies/{incident['emergency_id']}/agents"
    assert call("GET", path, role="other").status_code == 403
    assert call("POST", path + "/run", role="other").status_code == 403
    assert call("POST", path + "/run", role="reader").status_code == 403
    assert call("GET", "/v1/clients/app/inventory", role="other").status_code == 403
    assert call("GET", "/v1/clients/app/inventory", role="reader").status_code == 200
    body = {"source": "test", "packages": [{"ecosystem": "npm", "name": "axios", "version": "1.20.0"}]}
    assert call("POST", "/v1/clients/app/gate", body, "other").status_code == 403


def test_stale_containment_cannot_be_approved(stack, incident):
    _, call, _ = stack
    action = run_agents(call, incident)["containment"]["actions"][0]
    body = {
        "source": "requirements.txt",
        "packages": [{"ecosystem": "pypi", "name": "litellm", "version": "1.106.2"}],
    }
    call("POST", "/v1/clients/app/sbom", body, "agent").raise_for_status()
    review = {"decision": "APPROVED", "reason": "Old evidence", "revision": incident["revision"]}
    assert (
        call("POST", f"/v1/containment/{action['action_id']}/review", review, "reviewer").status_code == 409
    )


def test_unknown_inventory_fails_gate_closed(stack):
    _, call, _ = stack
    body = {"source": "test", "packages": [{"ecosystem": "pypi", "name": "not-in-fixture", "version": "1.0"}]}
    result = call("POST", "/v1/clients/app/gate", body, "agent").json()
    assert not result["allowed"] and result["unknown"]


def test_dashboard_interactive_agent_run_and_containment_review(stack, incident, monkeypatch):
    _, call, _ = stack

    def request(self, method, path, body=None):
        response = call(method, path, body, "reviewer")
        response.raise_for_status()
        return response.json()

    monkeypatch.setattr(Client, "request", request)
    path = Path(__file__).resolve().parents[1] / "src/vuln_sentinel/dashboard.py"
    app = AppTest.from_file(str(path), default_timeout=20).run()
    app.text_input[0].set_value("reviewer")
    app.text_input[1].set_value("app")
    app.run()
    assert not app.exception
    assert "One bad library" in app.title[0].value
    next(b for b in app.button if b.label == "Run response agents").click().run()
    assert not app.exception, [e.message for e in app.exception]
    next(a for a in app.text_area if a.label == "Containment review notes").set_value(
        "Block confirmed malicious version"
    )
    next(b for b in app.button if b.label == "Record containment review").click().run()
    assert not app.exception
    actions = call("GET", f"/v1/emergencies/{incident['emergency_id']}/agents").json()["containment"]
    assert actions["status"] == "POLICY_ACTIVE"
    assert actions["actions"][0]["reviewer"] == "reviewer"


def test_gate_cli_denial_exit_status(monkeypatch, tmp_path, capsys):
    import sys

    from vuln_sentinel.cli import main

    lock = tmp_path / "requirements.txt"
    lock.write_text("litellm==1.107.0\n")
    monkeypatch.setenv("SENTINEL_TOKEN", "test")
    monkeypatch.setattr(Client, "request", lambda *args, **kwargs: {"allowed": False, "blocked": ["test"]})
    monkeypatch.setattr(sys, "argv", ["sentinel", "gate", str(lock)])
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 3


def test_reviewed_containment_can_be_revoked(stack, incident):
    _, call, service = stack
    action = run_agents(call, incident)["containment"]["actions"][0]
    body = {"decision": "APPROVED", "reason": "Confirmed containment", "revision": action["revision"]}
    call("POST", f"/v1/containment/{action['action_id']}/review", body, "reviewer").raise_for_status()
    revoke = {**body, "decision": "REJECTED", "reason": "Review confirms policy can be removed"}
    path = f"/v1/containment/{action['action_id']}/revoke"
    assert call("POST", path, revoke, "agent").status_code == 403
    assert call("POST", path, revoke, "other").status_code == 403
    assert call("POST", path, revoke, "reviewer").json()["status"] == "REVOKED"
    assert call("POST", path, revoke, "reviewer").status_code == 409
    sbom = {"source": "test", "packages": [{"ecosystem": "pypi", "name": "litellm", "version": "1.107.0"}]}
    result = call("POST", "/v1/clients/app/gate", sbom, "agent").json()
    assert not result["allowed"] and result["policy_count"] == 0
