import json
from collections import deque

from .models import SBOM, Package


def client_blast_radius(sbom, package):
    """Shortest reverse paths over actual lockfile locators, including duplicate versions."""
    by_id = {p.locator or f"{p.ecosystem}:{p.name}@{p.version}": p for p in sbom.packages}
    reverse = {key: [] for key in by_id}
    for key, p in by_id.items():
        for child in p.dependencies:
            reverse[child].append(key)
    targets = [
        key
        for key, p in by_id.items()
        if (p.ecosystem, p.name, p.version) == (package.ecosystem, package.name, package.version)
    ]
    queue = deque((key, [key]) for key in targets)
    visited, results = set(targets), []
    while queue:
        child, path = queue.popleft()
        for parent in reverse[child]:
            if parent in visited:
                continue
            visited.add(parent)
            chain = [parent, *path]
            results.append(
                {
                    "dependent": by_id[parent].name,
                    "version": by_id[parent].version,
                    "locator": parent,
                    "hops": len(chain) - 1,
                    "path": chain,
                }
            )
            queue.append((parent, chain))
    return {
        "source": "client_lockfile",
        "graph_complete": sbom.graph_complete,
        "dependents": results,
        "warnings": sbom.warnings,
    }


def client_impact(use_cases, package, blast):
    """Use cases whose code calls the package, or a package that depends on it."""
    names = {package.name, *(d["dependent"] for d in blast["dependents"])}
    impacts = []
    for case in use_cases:
        hits = [u for u in case["usages"] if u["ecosystem"] == package.ecosystem and u["package"] in names]
        if hits:
            impacts.append(
                {
                    "package": f"{package.ecosystem}/{package.name}@{package.version}",
                    "use_case": case["name"],
                    "criticality": case["criticality"],
                    "status": "compromised",
                    "functionalities_affected": [
                        {"file": u["file"], "symbol": u["symbol"], "via": u["package"]} for u in hits
                    ],
                }
            )
    return impacts


class Service:
    def __init__(self, backend, store):
        self.backend, self.store = backend, store

    def respond(self, request):
        if hasattr(self.backend, "load_intel"):
            self.backend.load_intel()
        result = self.backend.respond(request.ecosystem, request.package, request.version, request.ai_brief)
        return self.backend.intel.enrich(self.with_threats(result))

    def with_threats(self, result):
        """Overlay injected threat events: a matching version is a malicious release with no safe fallback."""
        pkg = result["package"]
        for threat in self.store.threats(pkg["ecosystem"], pkg["name"]):
            if pkg["version"] in threat["versions"]:
                advisories = [
                    {
                        "advisory_id": threat["advisory_id"],
                        "severity": "CRITICAL",
                        "summary": "Injected threat event",
                    },
                    *result.get("advisories", []),
                ]
                safe = {
                    k: v
                    for k, v in result.get("recommended_version", {}).items()
                    if v not in threat["versions"]
                }
                return {
                    **result,
                    "incident_type": "MALICIOUS_RELEASE",
                    "advisories": advisories,
                    "advisory_count": len(advisories),
                    "recommended_version": safe,
                    "secrets_at_risk": True,
                    "synthetic": True,
                }
        return result

    def impacts(self, client):
        """Per (package, use case) status: compromised from open emergencies, otherwise safe."""
        cases = self.store.get_use_cases(client)
        rows = [
            i
            for e in self.store.list_emergencies(client)
            if e["status"] != "SUPERSEDED"
            for i in e["payload"].get("client_impact", [])
        ]
        hit = {r["use_case"] for r in rows}
        for case in cases:
            if case["name"] not in hit:
                rows += [
                    {
                        "package": f"{case['usages'][0]['ecosystem']}/{name}",
                        "use_case": case["name"],
                        "criticality": case["criticality"],
                        "status": "safe",
                        "functionalities_affected": [],
                    }
                    for name in sorted({u["package"] for u in case["usages"]})
                ]
        return rows

    def reconcile(self, actor, client=None):
        from .models import ResponseRequest

        incidents, errors, unknown, checked = [], [], [], 0
        cache = {}
        for snapshot in self.store.latest_sboms(client):
            sbom = SBOM.model_validate_json(snapshot["payload"])
            use_cases = self.store.get_use_cases(snapshot["client_id"])
            unique = {(p.ecosystem, p.name, p.version): p for p in sbom.packages}
            for key, package in unique.items():
                try:
                    if key not in cache:
                        cache[key] = self.respond(
                            ResponseRequest(
                                ecosystem=package.ecosystem, package=package.name, version=package.version
                            )
                        )
                    blast = client_blast_radius(sbom, package)
                    result = {
                        **cache[key],
                        "client_blast_radius": blast,
                        "client_impact": client_impact(use_cases, package, blast),
                    }
                    checked += 1
                    if result["incident_type"] == "UNKNOWN":
                        unknown.append({"client_id": snapshot["client_id"], "package": package.model_dump()})
                    elif result["incident_type"] != "NONE":
                        identity = self.store.open_emergency(
                            snapshot["client_id"], snapshot["revision"], result, actor
                        )
                        incidents.append(identity)
                        self.store.retire_package(
                            snapshot["client_id"], snapshot["revision"], package, identity, actor
                        )
                    else:
                        self.store.retire_package(
                            snapshot["client_id"], snapshot["revision"], package, None, actor
                        )
                except Exception as exc:
                    errors.append(
                        {
                            "client_id": snapshot["client_id"],
                            "package": package.name,
                            "error": type(exc).__name__,
                        }
                    )
        return {
            "checked": checked,
            "emergency_ids": incidents,
            "unknown": unknown,
            "errors": errors,
            "complete": not errors and not unknown,
        }

    def propose(self, principal, client, proposal):
        principal.require("admin", "agent")
        principal.tenant(client)
        scan = self.reconcile(principal.subject, client)
        if scan["errors"] or scan["unknown"]:
            raise ValueError("Current inventory could not be fully revalidated")
        emergency = self.store.get_emergency(proposal.emergency_id)
        if emergency["client_id"] != client:
            raise PermissionError("Client scope mismatch")
        if not proposal.test_passed:
            raise ValueError("A passing test run is required")
        pkg = emergency["payload"]["package"]
        target = Package(ecosystem=pkg["ecosystem"], name=pkg["name"], version=proposal.target_version)
        recommended = emergency["payload"].get("recommended_version", {})
        if target.version not in {recommended.get("same_major"), recommended.get("latest_clean")}:
            raise ValueError("Target must be a recommended safe version")
        from .models import ResponseRequest

        fresh = self.respond(
            ResponseRequest(ecosystem=target.ecosystem, package=target.name, version=target.version)
        )
        if fresh["incident_type"] not in {"NONE", "TRUST_STORE"}:
            raise ValueError("Target failed current advisory/availability validation")
        return self.store.propose(client, proposal, principal.subject)

    def review(self, principal, identity, review):
        principal.require("admin", "reviewer")
        emergency = self.store.get_emergency(identity)
        principal.tenant(emergency["client_id"])
        scan = self.reconcile(principal.subject, emergency["client_id"])
        if scan["errors"] or scan["unknown"]:
            raise ValueError("Current inventory could not be fully revalidated")
        submitted = json.loads(emergency["proposal"]) if emergency.get("proposal") else {}
        if submitted.get("target_version"):
            from .models import ResponseRequest

            pkg = emergency["payload"]["package"]
            target = self.respond(
                ResponseRequest(
                    ecosystem=pkg["ecosystem"], package=pkg["name"], version=submitted["target_version"]
                )
            )
            if target["incident_type"] not in {"NONE", "TRUST_STORE"}:
                raise ValueError("Proposed target is no longer safe/available; submit a new proposal")
        if submitted.get("submitted_by") == principal.subject:
            raise PermissionError("A proposal must be reviewed by another identity")
        # Agent tokens cannot review; reviewer identity is always from authentication.
        return self.store.review(identity, review, principal.subject, emergency["client_id"])
