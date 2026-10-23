"""Provider-neutral intelligence. No implicit listing acceptance or subscriptions."""

import ipaddress
import json
from datetime import datetime, timezone
from pathlib import Path


class Intel:
    def __init__(self, path=None, records=None):
        self.records = (
            records if records is not None else (json.loads(Path(path).read_text()) if path else [])
        )
        for row in self.records:
            if row["kind"] not in {"kev", "exploit", "ip", "domain", "tor", "ai_endpoint"}:
                raise ValueError("Unknown intelligence kind")
            if not row.get("source") or not row.get("observed_at"):
                raise ValueError("Intelligence requires source and observed_at")
            if row["kind"] == "exploit" and not 0 <= float(row["score"]) <= 1:
                raise ValueError("Exploit score must be normalized to [0,1]")
            if row.get("expires_at"):
                datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00")).astimezone(timezone.utc)

    def active(self):
        current = datetime.now(timezone.utc)
        return [
            r
            for r in self.records
            if not r.get("expires_at")
            or datetime.fromisoformat(r["expires_at"].replace("Z", "+00:00")) > current
        ]

    def enrich(self, response):
        cves = set(response.get("matched_cve_ids", []))
        for advisory in response.get("advisories", []):
            for field in ("cve_ids", "aliases"):
                values = advisory.get(field) or []
                if isinstance(values, str):
                    try:
                        values = json.loads(values)
                    except ValueError:
                        values = [values]
                cves.update(v for v in values if v.startswith("CVE-"))
        hits = [r for r in self.active() if r["kind"] in {"kev", "exploit"} and r["indicator"] in cves]
        exploited = any(r["kind"] == "kev" for r in hits)
        score = max((float(r["score"]) for r in hits if r["kind"] == "exploit"), default=None)
        incident = response.get("incident_type")
        priority = (
            "P0"
            if incident == "MALICIOUS_RELEASE" or exploited
            else (
                "P1"
                if incident == "VULNERABILITY" and (score or 0) >= 0.7
                else "P2"
                if incident == "VULNERABILITY"
                else "P3"
            )
        )
        return {
            **response,
            "intel": {"known_exploited": exploited, "exploit_score": score, "evidence": hits},
            "priority": priority,
        }

    def indicators(self):
        return [r for r in self.active() if r["kind"] in {"ip", "domain", "tor", "ai_endpoint"}]


def normalize_indicator(value, kind):
    if kind == "ip":
        return str(ipaddress.ip_address(value))
    return value.lower().rstrip(".")
