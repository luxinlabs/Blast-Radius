"""Three explicit incident workflows. Decisions use structured evidence, not invented AI output."""

import json
import shlex

from .models import ResponseRequest
from .store import digest


class ScannerAgent:
    name = "Scanner agent"

    @staticmethod
    def run(service, actor, client_id):
        return service.reconcile(actor, client_id)

    @staticmethod
    def inspect(emergency):
        data = emergency["payload"]
        paths = data.get("client_blast_radius", {})
        return {
            "name": ScannerAgent.name,
            "status": "COMPLETE",
            "runtime": "Exact-version advisory matching",
            "advisories": data.get("advisory_count", len(data.get("advisories", []))),
            "paths": paths.get("dependents", []),
            "graph_complete": paths.get("graph_complete", False),
            "warnings": paths.get("warnings", []),
            "coverage": data.get("coverage", "Snowflake catalog"),
            "log_hunting": "Client-local: sentinel hunt <logfiles>; findings appear in the audit trail",
        }


class PatchAgent:
    name = "Patch agent"

    @staticmethod
    def execute(client, lockfile, emergency_id, test_command, open_pr=False):
        return client.fix(lockfile, emergency_id, test_command, open_pr)

    @staticmethod
    def inspect(emergency):
        data = emergency["payload"]
        pkg, safe = data["package"], data.get("recommended_version", {})
        target = safe.get("same_major") or safe.get("latest_clean")
        proposal = emergency.get("proposal")
        proposal = json.loads(proposal) if isinstance(proposal, str) else proposal
        path = "package-lock.json" if pkg["ecosystem"] == "npm" else "requirements.txt"
        command = shlex.join(
            [
                "sentinel",
                "fix",
                path,
                "--emergency",
                emergency["emergency_id"],
                "--test",
                "npm test"
                if pkg["ecosystem"] == "npm"
                else "uv run --with-requirements requirements.txt pytest",
            ]
        )
        return {
            "name": PatchAgent.name,
            "status": "PROPOSED" if proposal else "READY" if target else "NO_FIX",
            "runtime": "Isolated client Git worktree",
            "target_version": target,
            "diff": f"- {pkg['name']}=={pkg['version']}\n+ {pkg['name']}=={target}"
            if target
            else "No verified safe version available",
            "command": command,
            "proposal": proposal,
            "tests": "Reported passing" if proposal and proposal.get("test_passed") else "Not run",
            "requires_human_approval": True,
        }


class ContainmentAgent:
    name = "Containment agent"

    @staticmethod
    def propose(store, emergency, actor):
        data = emergency["payload"]
        if emergency["status"] == "SUPERSEDED" or data["incident_type"] in {"NONE", "UNKNOWN", "TRUST_STORE"}:
            return None
        pkg = data["package"]
        policy = {
            "action": "BLOCK_VERSION",
            "ecosystem": pkg["ecosystem"],
            "name": pkg["name"],
            "version": pkg["version"],
            "enforcement": "sentinel gate",
            "triggered_by": actor,
        }
        identity = digest([emergency["emergency_id"], "BLOCK_VERSION"])
        return store.propose_containment(identity, emergency, policy, "system:containment-agent")

    @staticmethod
    def inspect(actions):
        return {
            "name": ContainmentAgent.name,
            "status": "POLICY_ACTIVE"
            if any(a["status"] == "APPLIED" for a in actions)
            else "AWAITING_APPROVAL"
            if any(a["status"] == "PROPOSED" for a in actions)
            else "READY",
            "runtime": "Persistent policy and deployment gate",
            "actions": actions,
            "manual_actions": [
                "Configure a WAF connector before changing rules",
                "Confirm host/service ownership before isolation",
                "Notify owners through your incident channel",
            ],
            "requires_human_approval": True,
        }


class AgentCoordinator:
    def __init__(self, service):
        self.service = service

    def emergency(self, principal, identity):
        emergency = self.service.store.get_emergency(identity)
        principal.tenant(emergency["client_id"])
        return emergency

    def inspect(self, principal, identity):
        emergency = self.emergency(principal, identity)
        actions = self.service.store.containment_actions(emergency["client_id"], identity)
        return {
            "emergency_id": identity,
            "scanner": ScannerAgent.inspect(emergency),
            "patch": PatchAgent.inspect(emergency),
            "containment": ContainmentAgent.inspect(actions),
        }

    def run(self, principal, identity):
        principal.require("admin", "agent", "reviewer")
        emergency = self.emergency(principal, identity)
        scan = ScannerAgent.run(self.service, principal.subject, emergency["client_id"])
        current = self.emergency(principal, identity)
        if scan["errors"] or scan["unknown"] or current["status"] == "SUPERSEDED":
            raise ValueError(
                "Evidence changed or coverage is incomplete; refresh the incident before running agents"
            )
        ContainmentAgent.propose(self.service.store, current, principal.subject)
        return {**self.inspect(principal, identity), "scan": scan}

    def review(self, principal, identity, review):
        principal.require("admin", "reviewer")
        action = self.service.store.get_containment(identity)
        principal.tenant(action["client_id"])
        if principal.subject == action["requested_by"]:
            raise PermissionError("A separate reviewer is required")
        scan = ScannerAgent.run(self.service, principal.subject, action["client_id"])
        if scan["errors"] or scan["unknown"]:
            raise ValueError("Current inventory could not be fully revalidated")
        emergency = self.emergency(principal, action["emergency_id"])
        if emergency["status"] == "SUPERSEDED":
            raise ValueError("Containment evidence is stale; refresh the incident")
        return self.service.store.review_containment(action, review, principal.subject)

    def revoke(self, principal, identity, review):
        principal.require("admin", "reviewer")
        action = self.service.store.get_containment(identity)
        principal.tenant(action["client_id"])
        if review.decision != "REJECTED":
            raise ValueError("Revocation requires a REJECTED decision and a reason")
        return self.service.store.revoke_containment(action, review, principal.subject)

    def gate(self, principal, client_id, sbom):
        principal.tenant(client_id)
        policies = [a for a in self.service.store.containment_actions(client_id) if a["status"] == "APPLIED"]
        blocked, unknown = [], []
        for package in sbom.packages:
            for action in policies:
                rule = action["payload"]
                if (package.ecosystem, package.name, package.version) == (
                    rule["ecosystem"],
                    rule["name"],
                    rule["version"],
                ):
                    blocked.append(
                        {
                            "package": package.model_dump(),
                            "action_id": action["action_id"],
                            "reason": "Approved containment block",
                        }
                    )
            response = self.service.respond(
                ResponseRequest(ecosystem=package.ecosystem, package=package.name, version=package.version)
            )
            if response["incident_type"] == "UNKNOWN":
                unknown.append(package.model_dump())
            elif response["incident_type"] not in {"NONE", "TRUST_STORE"}:
                blocked.append({"package": package.model_dump(), "reason": response["incident_type"]})
        result = {
            "allowed": not blocked and not unknown,
            "blocked": blocked,
            "unknown": unknown,
            "policy_count": len(policies),
            "enforcement": "Caller must require a successful sentinel gate exit before deployment",
        }
        with self.service.store.transaction() as conn:
            self.service.store.event(conn, client_id, principal.subject, "DEPLOYMENT_GATE", result)
        return result
