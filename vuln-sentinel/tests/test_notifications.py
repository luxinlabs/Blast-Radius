RESPONSE = {
    "summary": "Pin litellm and rotate its provider keys",
    "actions": [
        {
            "type": "PIN_VERSION",
            "target": "requirements.txt",
            "rationale": "Installed version is a malicious release",
            "artifacts": [{"kind": "patch", "ref": "requirements.txt", "content": "--- a\n+++ b\n"}],
        },
        {"type": "ROTATE_SECRET", "target": "LLM provider keys", "rationale": "Reachable from the gateway"},
    ],
}


def test_threat_notification_round_trip(stack, incident):
    _, call, _ = stack
    (note,) = call("GET", "/v1/notifications?client_id=app&status=NEW", role="agent").json()
    assert note["notification_id"] == incident["emergency_id"]
    assert (note["kind"], note["priority"], note["status"]) == ("THREAT", "P0", "NEW")
    assert note["payload"]["package"]["name"] == "litellm"

    url = f"/v1/notifications/{note['notification_id']}/response"
    assert call("POST", url, RESPONSE, "reader").status_code == 403
    assert call("POST", url, RESPONSE, "other").status_code == 403
    assert (
        call(
            "POST", url, {**RESPONSE, "actions": [{**RESPONSE["actions"][0], "type": "RUN_SHELL"}]}, "agent"
        ).status_code
        == 422
    )
    assert call("POST", url, RESPONSE, "agent").json() == {
        "status": "RESPONDED",
        "requires_human_approval": True,
    }
    assert call("POST", url, RESPONSE, "agent").status_code == 409

    assert call("GET", "/v1/notifications?client_id=app&status=NEW", role="agent").json() == []
    (done,) = call("GET", "/v1/notifications?client_id=app", role="agent").json()
    assert done["status"] == "RESPONDED" and done["response"]["actions"][1]["type"] == "ROTATE_SECRET"


def test_stale_threat_notification_cannot_be_answered(stack, incident):
    _, call, service = stack
    call(
        "POST",
        "/v1/clients/app/sbom",
        {"source": "x", "packages": [{"ecosystem": "pypi", "name": "requests", "version": "2.32.5"}]},
        "agent",
    )
    assert service.store.list_emergencies("app")[0]["status"] == "SUPERSEDED"
    url = f"/v1/notifications/{incident['emergency_id']}/response"
    assert call("POST", url, RESPONSE, "agent").status_code == 409


def test_ioc_match_notifies_once(stack):
    _, call, _ = stack
    report = {
        "findings": [{"indicator": "203.0.113.42", "kind": "ip", "count": 2, "source": "a.log"}],
        "summary": "s",
    }
    for _ in range(2):
        call("POST", "/v1/clients/app/reports", report, "agent").raise_for_status()
    (note,) = call("GET", "/v1/notifications?client_id=app", role="agent").json()
    assert (note["kind"], note["priority"]) == ("IOC_MATCH", "P1")


def test_fleet_notifications_are_admin_only(stack):
    _, call, _ = stack
    assert call("GET", "/v1/notifications", role="agent").status_code == 403
    assert call("GET", "/v1/notifications").status_code == 200
