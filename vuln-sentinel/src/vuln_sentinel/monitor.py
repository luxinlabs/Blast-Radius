"""Secure-resource access monitor. Only resource names and principals leave the client, never values."""

import json
from collections import defaultdict
from datetime import datetime, timedelta


def parse_secure(text):
    """`RESOURCE` or `RESOURCE: principal, principal` per line; listed principals are the only ones allowed."""
    secure = {}
    for line in text.splitlines():
        name, _, allowed = line.split("#")[0].partition(":")
        if name.strip():
            secure[name.strip()] = {p.strip() for p in allowed.split(",") if p.strip()}
    return secure


def parse_events(text):
    """JSON lines with ts (timezone-aware ISO), principal, resource and ip."""
    events = []
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
            ts = datetime.fromisoformat(event["ts"].replace("Z", "+00:00"))
            if ts.tzinfo is None:
                raise ValueError("Timestamp needs a timezone")
            events.append(
                {"ts": ts, "principal": event["principal"], "resource": event["resource"], "ip": event["ip"]}
            )
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            raise ValueError(f"Malformed access event on line {number}") from exc
    return sorted(events, key=lambda e: e["ts"])


def finding(rule, principal, events):
    return {
        "rule": rule,
        "principal": principal,
        "resources": sorted({e["resource"] for e in events}),
        "count": len(events),
        "first_seen": events[0]["ts"].isoformat(),
        "last_seen": events[-1]["ts"].isoformat(),
        "ips": sorted({e["ip"] for e in events}),
    }


def detect(events, secure, window=timedelta(minutes=10), limit=5):
    """Flag unlisted principals, bursts of `limit` secure accesses inside `window`, and unfamiliar IPs.

    A principal's familiar IPs are those it used on resources not marked secure.
    """
    familiar, hits = defaultdict(set), defaultdict(list)
    for e in events:
        if e["resource"] in secure:
            hits[e["principal"]].append(e)
        else:
            familiar[e["principal"]].add(e["ip"])
    findings = []
    for principal, seen in sorted(hits.items()):
        denied = [e for e in seen if secure[e["resource"]] and principal not in secure[e["resource"]]]
        if denied:
            findings.append(finding("UNAUTHORIZED_PRINCIPAL", principal, denied))
        start, burst = 0, []
        for end in range(len(seen)):
            while seen[end]["ts"] - seen[start]["ts"] > window:
                start += 1
            burst = max(burst, seen[start : end + 1], key=len)
        if len(burst) >= limit:
            findings.append(finding("EXCESSIVE_ACCESS", principal, burst))
        fresh = [e for e in seen if familiar[principal] and e["ip"] not in familiar[principal]]
        if fresh:
            findings.append(finding("NEW_SOURCE_IP", principal, fresh))
    return findings
