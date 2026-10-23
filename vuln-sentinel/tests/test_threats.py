SBOM = {
    "source": "requirements.txt",
    "packages": [
        {"ecosystem": "pypi", "name": "litellm", "version": "1.106.2", "locator": "litellm", "direct": True},
        {"ecosystem": "pypi", "name": "requests", "version": "2.32.5", "locator": "requests", "direct": True},
    ],
}
USAGES = {
    "usages": [
        {"ecosystem": "pypi", "package": "litellm", "file": "gateway/router.py", "symbol": "route"},
        {"ecosystem": "pypi", "package": "requests", "file": "support/tickets.py", "symbol": "fetch"},
    ]
}
THREAT = {"ecosystem": "pypi", "package": "litellm", "versions": ["1.106.2"], "advisory_id": "DEMO-1"}


def test_injected_threat_fails_only_the_use_cases_that_call_the_package(stack):
    _, call, _ = stack
    call("POST", "/v1/clients/app/sbom", SBOM, "agent").raise_for_status()
    call("POST", "/v1/clients/app/usecases", USAGES, "agent").raise_for_status()
    assert {r["status"] for r in call("GET", "/v1/clients/app/impacts", role="reader").json()} == {"safe"}

    assert call("POST", "/v1/demo/threats", THREAT, "agent").status_code == 403
    assert call("POST", "/v1/demo/threats", THREAT).json()["injected"]
    scan = call("POST", "/v1/reconcile").json()
    assert scan["complete"] and len(scan["emergency_ids"]) == 1

    emergency = call("GET", "/v1/emergencies?client_id=app", role="agent").json()[0]
    assert emergency["payload"]["incident_type"] == "MALICIOUS_RELEASE"
    assert emergency["payload"]["recommended_version"] == {}
    assert emergency["payload"]["advisories"][0]["advisory_id"] == "DEMO-1"
    impacts = {r["use_case"]: r for r in call("GET", "/v1/clients/app/impacts", role="reader").json()}
    assert impacts["gateway router"]["status"] == "compromised"
    assert impacts["gateway router"]["package"] == "PyPI/litellm@1.106.2"
    assert impacts["gateway router"]["functionalities_affected"] == [
        {"file": "gateway/router.py", "symbol": "route", "via": "litellm"}
    ]
    assert impacts["support tickets"]["status"] == "safe"


def test_impacts_are_tenant_scoped(stack):
    _, call, _ = stack
    assert call("GET", "/v1/clients/app/impacts", role="other").status_code == 403
