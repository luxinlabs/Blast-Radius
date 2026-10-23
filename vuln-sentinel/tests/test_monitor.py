import json
from datetime import timedelta

import pytest

from vuln_sentinel.monitor import detect, parse_events, parse_secure

SECURE = parse_secure("OPENAI_KEY: gateway\nSTRIPE_KEY: billing\nDB_PASSWORD  # anyone may read\n")


def log(*rows):
    return parse_events(
        "\n".join(json.dumps(dict(zip(("ts", "principal", "resource", "ip"), r))) for r in rows)
    )


def test_parse_secure_lists_allowed_principals():
    assert SECURE == {"OPENAI_KEY": {"gateway"}, "STRIPE_KEY": {"billing"}, "DB_PASSWORD": set()}


def test_normal_service_access_is_not_flagged():
    events = log(
        ("2026-10-23T09:00:00Z", "gateway", "OPENAI_KEY", "10.0.0.5"),
        ("2026-10-23T09:00:30Z", "gateway", "OPENAI_KEY", "10.0.0.5"),
    )
    assert detect(events, SECURE) == []


def test_burst_by_unlisted_principal_from_new_ip_trips_every_rule():
    rows = [("2026-10-23T05:00:00Z", "ci-7", "build.log", "10.0.1.9")]
    rows += [
        (f"2026-10-23T05:3{i}:00Z", "ci-7", name, "198.51.100.23")
        for i, name in enumerate(["OPENAI_KEY", "STRIPE_KEY", "DB_PASSWORD", "OPENAI_KEY", "STRIPE_KEY"])
    ]
    found = {f["rule"]: f for f in detect(log(*rows), SECURE)}
    assert set(found) == {"UNAUTHORIZED_PRINCIPAL", "EXCESSIVE_ACCESS", "NEW_SOURCE_IP"}
    assert found["EXCESSIVE_ACCESS"]["count"] == 5
    assert found["UNAUTHORIZED_PRINCIPAL"]["resources"] == ["OPENAI_KEY", "STRIPE_KEY"]
    assert found["NEW_SOURCE_IP"]["ips"] == ["198.51.100.23"]


def test_slow_access_stays_under_the_burst_limit():
    rows = [(f"2026-10-23T0{i}:00:00Z", "ops", "DB_PASSWORD", "10.0.0.2") for i in range(6)]
    assert detect(log(*rows), SECURE, window=timedelta(minutes=10)) == []


def test_malformed_events_fail_loudly():
    with pytest.raises(ValueError, match="line 2"):
        parse_events('{"ts": "2026-10-23T05:00:00Z", "principal": "a", "resource": "b", "ip": "c"}\nnot json')
    with pytest.raises(ValueError, match="line 1"):
        parse_events('{"ts": "2026-10-23T05:00:00", "principal": "a", "resource": "b", "ip": "c"}')


def test_access_report_notifies_per_finding_once(stack):
    _, call, _ = stack
    finding = {
        "rule": "UNAUTHORIZED_PRINCIPAL",
        "principal": "ci-7",
        "resources": ["OPENAI_KEY"],
        "count": 2,
        "first_seen": "2026-10-23T05:30:00+00:00",
        "last_seen": "2026-10-23T05:31:00+00:00",
        "ips": ["198.51.100.23"],
    }
    for _ in range(2):
        assert (
            call("POST", "/v1/clients/app/access", {"findings": [finding]}, "agent").json()["findings"] == 1
        )
    (note,) = call("GET", "/v1/notifications?client_id=app", role="agent").json()
    assert (note["kind"], note["priority"]) == ("ACCESS_ANOMALY", "P0")
    assert call("POST", "/v1/clients/other-app/access", {"findings": [finding]}, "agent").status_code == 403
