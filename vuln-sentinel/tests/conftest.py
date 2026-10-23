import pytest
from fastapi.testclient import TestClient

from vuln_sentinel.backend import DemoBackend
from vuln_sentinel.config import Principal, Settings
from vuln_sentinel.server import create_app
from vuln_sentinel.service import Service
from vuln_sentinel.store import Store

TOKENS = {
    role: role + "-test-token-" + "x" * 32 for role in ["admin", "agent", "reviewer", "reader", "other"]
}


@pytest.fixture
def stack(tmp_path):
    tokens = {
        token: Principal(
            subject=role,
            role=role if role != "other" else "agent",
            client_id=None if role == "admin" else "other-app" if role == "other" else "app",
        )
        for role, token in TOKENS.items()
    }
    settings = Settings(sqlite_path=str(tmp_path / "state.sqlite"), tokens=tokens)
    backend = DemoBackend()
    service = Service(backend, Store(settings))
    with TestClient(create_app(settings, service), base_url="http://127.0.0.1") as client:

        def call(method, path, body=None, role="admin"):
            return client.request(
                method, path, json=body, headers={"Authorization": f"Bearer {TOKENS[role]}"}
            )

        assert call("POST", "/v1/clients", {"client_id": "app", "name": "Test app"}).status_code == 200
        yield client, call, service


@pytest.fixture
def incident(stack):
    _, call, _ = stack
    sbom = {
        "source": "requirements.txt",
        "packages": [{"ecosystem": "pypi", "name": "litellm", "version": "1.107.0"}],
    }
    result = call("POST", "/v1/clients/app/sbom", sbom, "agent")
    assert result.status_code == 200, result.text
    scan = call("POST", "/v1/clients/app/reconcile", role="agent")
    assert scan.json()["complete"], scan.text
    emergencies = call("GET", "/v1/emergencies?client_id=app", role="agent").json()
    assert len(emergencies) == 1
    return emergencies[0]


def proposal(emergency):
    return {
        "emergency_id": emergency["emergency_id"],
        "target_version": "1.106.2",
        "pr_url": "https://github.com/example/app/pull/42",
        "test_command": ["pytest"],
        "test_passed": True,
        "rollback_plan": "Revert the fix commit and restore the original lockfile.",
    }
