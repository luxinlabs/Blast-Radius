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


class Service:
    def __init__(self, backend, store):
        self.backend, self.store = backend, store

    def respond(self, request):
        if hasattr(self.backend, "load_intel"):
            self.backend.load_intel()
        result = self.backend.respond(request.ecosystem, request.package, request.version, request.ai_brief)
        return self.backend.intel.enrich(result)

    def reconcile(self, actor, client=None):
        from .models import ResponseRequest

        incidents, errors, unknown, checked = [], [], [], 0
        cache = {}
        for snapshot in self.store.latest_sboms(client):
            sbom = SBOM.model_validate_json(snapshot["payload"])
            unique = {(p.ecosystem, p.name, p.version): p for p in sbom.packages}
            for key, package in unique.items():
                try:
                    if key not in cache:
                        cache[key] = self.respond(
                            ResponseRequest(
                                ecosystem=package.ecosystem, package=package.name, version=package.version
                            )
                        )
                    result = {**cache[key], "client_blast_radius": client_blast_radius(sbom, package)}
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
