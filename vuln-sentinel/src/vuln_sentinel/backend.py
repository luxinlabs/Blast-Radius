import copy
import json
import os
from pathlib import Path

from .intel import Intel
from .models import normalize


class DemoBackend:
    """Deliberately small, labeled fixture. Never claims to represent current OSV data."""

    def __init__(self, fixture=None):
        path = Path(fixture) if fixture else Path(__file__).with_name("demo.json")
        self.data = json.loads(path.read_text())
        self.intel = Intel(records=self.data.get("intel", []))

    def respond(self, ecosystem, name, version, ai_brief=False):
        eco, name = normalize(ecosystem, name)
        item = self.data["packages"].get(f"{eco}/{name}")
        if item is None:
            return {
                "package": {"ecosystem": eco, "name": name, "version": version},
                "incident_type": "UNKNOWN",
                "coverage": "not_in_demo_fixture",
                "advisories": [],
                "requires_human_approval": True,
                "demo": True,
            }
        result = copy.deepcopy(item)
        matches = [a for a in result.pop("matches", []) if version in a.pop("versions")]
        versions = result.pop("versions")
        result["package"] = {
            "ecosystem": eco,
            "name": name,
            "version": version,
            "in_registry": version in versions,
        }
        result["advisories"] = matches
        result["advisory_count"] = len(matches)
        result["incident_type"] = (
            "MALICIOUS_RELEASE"
            if any(a["advisory_id"].startswith("MAL-") for a in matches)
            else "VULNERABILITY"
            if matches
            else "UNAVAILABLE"
            if version not in versions
            else "TRUST_STORE"
            if name == "certifi"
            else "NONE"
        )
        result.update(requires_human_approval=True, demo=True, coverage="fixture_only")
        if result["incident_type"] == "NONE":
            result["playbook"] = []
        if ai_brief:
            result["sre_brief"] = (
                f"DEMO fixture: {name} {version}: {result['incident_type']}. Human review required."
            )
        return result

    def package_risk(self, ecosystem, name):
        eco, name = normalize(ecosystem, name)
        item = self.data["packages"].get(f"{eco}/{name}")
        return {
            "ecosystem": eco,
            "name": name,
            "demo": True,
            "coverage": "fixture_only",
            "known": item is not None,
            "risk": copy.deepcopy(item),
        }

    def blast_radius(self, ecosystem, name):
        eco, name = normalize(ecosystem, name)
        return copy.deepcopy(self.data["packages"].get(f"{eco}/{name}", {}).get("blast_radius", []))


class SnowflakeBackend:
    def __init__(self, settings):
        self.settings = settings
        self.intel = Intel(path=os.getenv("SENTINEL_INTEL_FILE"))

    def query(self, sql, args=()):
        import snowflake.connector

        with snowflake.connector.connect(
            connection_name=self.settings.connection_name, paramstyle="qmark"
        ) as conn:
            with conn.cursor() as cursor:
                cursor.execute(sql, tuple(args))
                names = [d[0].lower() for d in cursor.description]
                return [dict(zip(names, row)) for row in cursor.fetchall()]

    def respond(self, ecosystem, name, version, ai_brief=False):
        eco, name = normalize(ecosystem, name)
        rows = self.query("CALL VULN_SENTINEL_DB.SERVING.RESPOND(?,?,?,?)", [eco, name, version, ai_brief])
        result = next(iter(rows[0].values()))
        result = json.loads(result) if isinstance(result, str) else result
        if "error" in result:
            return {
                "package": {"ecosystem": eco, "name": name, "version": version},
                "incident_type": "UNKNOWN",
                "coverage": "not_in_catalog",
                "advisories": [],
                "error": result["error"],
                "requires_human_approval": True,
            }

        # Existing procedure emits some nested fields as JSON strings and uppercase keys.
        def normalize_result(value):
            if isinstance(value, dict):
                return {k.lower(): normalize_result(v) for k, v in value.items()}
            if isinstance(value, list):
                return [normalize_result(v) for v in value]
            return value

        return normalize_result(result)

    def package_risk(self, ecosystem, name):
        eco, name = normalize(ecosystem, name)
        return self.query(
            "SELECT * FROM VULN_SENTINEL_DB.SERVING.V_PACKAGE_RISK_ENRICHED WHERE ecosystem=? AND name=?",
            [eco, name],
        )

    def blast_radius(self, ecosystem, name):
        eco, name = normalize(ecosystem, name)
        return self.query(
            "SELECT * FROM VULN_SENTINEL_DB.SERVING.V_BLAST_RADIUS WHERE ecosystem=? AND compromised=? ORDER BY hops",
            [eco, name],
        )

    def load_intel(self):
        rows = self.query(
            "SELECT kind,indicator,score,source,observed_at,expires_at FROM VULN_SENTINEL_DB.INTEL.SIGNAL_FEED WHERE expires_at IS NULL OR expires_at>CURRENT_TIMESTAMP()"
        )
        self.intel = Intel(
            records=[
                {
                    **r,
                    "observed_at": str(r["observed_at"]),
                    "expires_at": r["expires_at"].isoformat() if r["expires_at"] else None,
                }
                for r in rows
            ]
        )
