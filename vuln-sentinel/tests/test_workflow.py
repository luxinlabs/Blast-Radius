import json
import sqlite3

import pytest
from conftest import proposal

from vuln_sentinel.models import SBOM, Package
from vuln_sentinel.service import client_blast_radius


def test_complete_workflow_requires_human(stack, incident):
    client, call, service = stack
    assert incident["payload"]["incident_type"] == "MALICIOUS_RELEASE"
    assert incident["payload"]["priority"] == "P0"
    assert not incident["payload"]["package"]["in_registry"]
    evidence = proposal(incident)
    result = call("POST", "/v1/clients/app/proposals", evidence, "agent")
    assert result.status_code == 200, result.text
    review = {
        "decision": "APPROVED",
        "reason": "Reviewed evidence and passing tests",
        "revision": incident["revision"],
    }
    assert (
        call("POST", f"/v1/emergencies/{incident['emergency_id']}/review", review, "agent").status_code == 403
    )
    result = call("POST", f"/v1/emergencies/{incident['emergency_id']}/review", review, "reviewer")
    assert result.status_code == 200, result.text
    assert result.json() == {"status": "APPROVED", "merged": False, "deployed": False}
    scan = call("POST", "/v1/clients/app/reconcile", role="agent").json()
    assert scan["emergency_ids"] == [incident["emergency_id"]]
    final = call("GET", "/v1/emergencies?client_id=app", role="agent").json()
    assert len(final) == 1 and final[0]["status"] == "APPROVED"
    events = call("GET", "/v1/clients/app/events", role="reader").json()
    assert {e["kind"] for e in events} >= {
        "CLIENT_REGISTERED",
        "SBOM_REGISTERED",
        "EMERGENCY_OPENED",
        "FIX_PROPOSED",
        "HUMAN_REVIEW",
    }
    # Persisted state survives constructing a new connection.
    with sqlite3.connect(service.store.settings.sqlite_path) as conn:
        assert conn.execute("SELECT status FROM emergencies").fetchone()[0] == "APPROVED"


def test_authentication_and_scope(stack, incident):
    client, call, _ = stack
    assert client.get("/health").status_code == 200
    assert client.get("/v1/emergencies").status_code == 401
    assert call("GET", "/v1/emergencies?client_id=app", role="other").status_code == 403
    assert call("GET", "/v1/emergencies", role="reader").status_code == 403
    assert call("POST", "/v1/clients/app/reconcile", role="reader").status_code == 403
    assert call("POST", "/v1/clients/app/proposals", proposal(incident), "reader").status_code == 403
    assert call("POST", "/v1/clients/app/proposals", proposal(incident), "other").status_code == 403
    assert call("GET", "/v1/clients/app/events", role="other").status_code == 403


@pytest.mark.parametrize(
    "updates", [{"test_passed": False}, {"target_version": "1.107.0"}, {"pr_url": "https://evil.invalid/fix"}]
)
def test_invalid_proposals(stack, incident, updates):
    _, call, _ = stack
    data = {**proposal(incident), **updates}
    assert call("POST", "/v1/clients/app/proposals", data, "agent").status_code in {409, 422}


def test_review_requires_proposal_and_matching_revision(stack, incident):
    _, call, _ = stack
    path = f"/v1/emergencies/{incident['emergency_id']}/review"
    review = {"decision": "APPROVED", "reason": "Test review", "revision": incident["revision"]}
    assert call("POST", path, review, "reviewer").status_code == 409
    assert call("POST", "/v1/clients/app/proposals", proposal(incident), "agent").status_code == 200
    assert call("POST", path, {**review, "revision": "stale"}, "reviewer").status_code == 409
    assert call("POST", path, {**review, "decision": "REJECTED"}, "reviewer").status_code == 200
    assert call("POST", "/v1/clients/app/proposals", proposal(incident), "agent").status_code == 200


def test_changed_inventory_retires_reviews(stack, incident):
    _, call, _ = stack
    assert call("POST", "/v1/clients/app/proposals", proposal(incident), "agent").status_code == 200
    changed = {
        "source": "requirements.txt",
        "packages": [{"ecosystem": "pypi", "name": "litellm", "version": "1.106.2"}],
    }
    call("POST", "/v1/clients/app/sbom", changed, "agent").raise_for_status()
    call("POST", "/v1/clients/app/reconcile", role="agent").raise_for_status()
    emergencies = call("GET", "/v1/emergencies?client_id=app", role="agent").json()
    assert emergencies[0]["status"] == "SUPERSEDED"
    review = {"decision": "APPROVED", "reason": "Stale review", "revision": incident["revision"]}
    assert (
        call("POST", f"/v1/emergencies/{incident['emergency_id']}/review", review, "reviewer").status_code
        == 409
    )


def test_withdrawal_retires_emergency(stack, incident):
    _, call, service = stack
    data = service.backend.data["packages"]["PyPI/litellm"]
    data["matches"] = []
    data["versions"].append("1.107.0")
    scan = call("POST", "/v1/clients/app/reconcile", role="agent").json()
    assert scan["complete"] and not scan["emergency_ids"]
    assert call("GET", "/v1/emergencies?client_id=app").json()[0]["status"] == "SUPERSEDED"


def test_changed_evidence_requires_new_review(stack, incident):
    _, call, service = stack
    call("POST", "/v1/clients/app/proposals", proposal(incident), "agent").raise_for_status()
    service.backend.data["packages"]["PyPI/litellm"]["secrets_at_risk"] = False
    review = {"decision": "APPROVED", "reason": "Evidence changed", "revision": incident["revision"]}
    assert (
        call("POST", f"/v1/emergencies/{incident['emergency_id']}/review", review, "reviewer").status_code
        == 409
    )
    emergencies = call("GET", "/v1/emergencies?client_id=app").json()
    assert sorted(e["status"] for e in emergencies) == ["OPEN", "SUPERSEDED"]


def test_unknown_coverage_and_failures_are_explicit(stack):
    _, call, service = stack
    body = {
        "source": "requirements.txt",
        "packages": [{"ecosystem": "pypi", "name": "unknown-package", "version": "1.0"}],
    }
    call("POST", "/v1/clients/app/sbom", body, "agent").raise_for_status()
    scan = call("POST", "/v1/clients/app/reconcile", role="agent").json()
    assert not scan["complete"] and len(scan["unknown"]) == 1

    def broken(*args, **kwargs):
        raise RuntimeError("private backend credentials must not escape")

    service.backend.respond = broken
    scan = call("POST", "/v1/clients/app/reconcile", role="agent").json()
    assert not scan["complete"] and scan["errors"][0]["error"] == "RuntimeError"
    assert "credentials" not in json.dumps(scan)


def test_exact_validation_and_missing_registry_match(stack):
    _, call, _ = stack
    for eco, name, version in [
        ("pypi", "litellm", ">=1"),
        ("cargo", "thing", "1.0.0"),
        ("npm", "axios", "latest"),
    ]:
        assert (
            call("POST", "/v1/respond", {"ecosystem": eco, "package": name, "version": version}).status_code
            == 422
        )
    result = call(
        "POST", "/v1/respond", {"ecosystem": "pip", "package": "LiteLLM", "version": "1.107.0"}
    ).json()
    assert result["incident_type"] == "MALICIOUS_RELEASE" and not result["package"]["in_registry"]


def test_exact_client_paths_cycles_and_duplicate_versions():
    sbom = SBOM(
        source="test",
        graph_complete=True,
        packages=[
            Package(ecosystem="npm", name="root", version="1.0.0", locator="root", dependencies=["a", "b"]),
            Package(ecosystem="npm", name="dep", version="1.0.0", locator="a", dependencies=["root"]),
            Package(ecosystem="npm", name="dep", version="2.0.0", locator="b"),
        ],
    )
    paths = client_blast_radius(sbom, sbom.packages[1])
    assert paths["dependents"] == [
        {"dependent": "root", "version": "1.0.0", "locator": "root", "hops": 1, "path": ["root", "a"]}
    ]


def test_mcp_transport_and_tool_scopes(stack):
    _, call, _ = stack
    headers = {"Accept": "application/json, text/event-stream"}
    # Use the actual SDK Streamable HTTP ASGI app, not a tool-function mock.
    client = stack[0]
    from conftest import TOKENS

    headers["Authorization"] = f"Bearer {TOKENS['reader']}"
    init = client.post(
        "/mcp/",
        headers=headers,
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "1"},
            },
        },
    )
    assert init.status_code == 200, init.text
    tools = client.post("/mcp/", headers=headers, json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    names = {t["name"] for t in tools.json()["result"]["tools"]}
    assert names == {
        "respond",
        "get_package_risk",
        "get_blast_radius",
        "list_emergencies",
        "register_sbom",
        "report_scan",
        "submit_fix_proposal",
    }
    resp = client.post(
        "/mcp/",
        headers=headers,
        json={
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "respond",
                "arguments": {"ecosystem": "npm", "package": "axios", "version": "1.14.1"},
            },
        },
    )
    data = resp.json()["result"]
    assert not data.get("isError", False), resp.text
    assert "MALICIOUS_RELEASE" in json.dumps(data)
    denied = client.post(
        "/mcp/",
        headers=headers,
        json={
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "register_sbom",
                "arguments": {
                    "client_id": "app",
                    "sbom": {
                        "source": "test",
                        "packages": [{"ecosystem": "npm", "name": "axios", "version": "1.14.1"}],
                    },
                },
            },
        },
    )
    assert denied.json()["result"]["isError"]
    assert client.post("/mcp/", json={}).status_code == 401


def test_target_revalidated_at_review(stack, incident):
    _, call, service = stack
    call("POST", "/v1/clients/app/proposals", proposal(incident), "agent").raise_for_status()
    service.backend.data["packages"]["PyPI/litellm"]["versions"] = []
    review = {"decision": "APPROVED", "reason": "Review target", "revision": incident["revision"]}
    result = call("POST", f"/v1/emergencies/{incident['emergency_id']}/review", review, "reviewer")
    assert result.status_code == 409


def test_reviewer_cannot_review_own_proposal(stack, incident):
    _, call, _ = stack
    call("POST", "/v1/clients/app/proposals", proposal(incident), "admin").raise_for_status()
    review = {"decision": "APPROVED", "reason": "Self review", "revision": incident["revision"]}
    assert (
        call("POST", f"/v1/emergencies/{incident['emergency_id']}/review", review, "admin").status_code == 403
    )


def test_request_size_limit(stack):
    from conftest import TOKENS

    client = stack[0]
    result = client.post(
        "/v1/respond",
        content=b"{}",
        headers={"Authorization": f"Bearer {TOKENS['agent']}", "Content-Length": "9000000"},
    )
    assert result.status_code == 413
