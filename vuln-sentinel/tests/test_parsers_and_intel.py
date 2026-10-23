import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from vuln_sentinel.client import hunt_logs
from vuln_sentinel.intel import Intel
from vuln_sentinel.lockfiles import parse_lockfile

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def test_example_formats():
    npm = parse_lockfile(EXAMPLES / "package-lock.json")
    assert npm.graph_complete
    assert {(p.name, p.version) for p in npm.packages} == {
        ("axios", "1.14.1"),
        ("next", "15.2.2"),
        ("chalk", "5.6.1"),
    }
    assert next(p for p in npm.packages if p.name == "next").dependencies == ["node_modules/chalk"]
    for file in ["requirements.txt", "poetry.lock"]:
        sbom = parse_lockfile(EXAMPLES / file)
        assert len(sbom.packages) == 2 and not sbom.graph_complete and sbom.warnings


def test_npm_resolves_nearest_nested_and_scoped_dependencies(tmp_path):
    data = {
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"parent": "1.0.0"}},
            "node_modules/parent": {"version": "1.0.0", "dependencies": {"@scope/dep": "1"}},
            "node_modules/@scope/dep": {"version": "2.0.0"},
            "node_modules/parent/node_modules/@scope/dep": {"version": "1.0.0"},
        },
    }
    path = tmp_path / "package-lock.json"
    path.write_text(json.dumps(data))
    sbom = parse_lockfile(path)
    parent = next(p for p in sbom.packages if p.name == "parent")
    assert parent.dependencies == ["node_modules/parent/node_modules/@scope/dep"]
    assert sum(p.name == "@scope/dep" for p in sbom.packages) == 2


def test_v1_nested_dependency_tree(tmp_path):
    path = tmp_path / "package-lock.json"
    path.write_text(
        json.dumps(
            {
                "lockfileVersion": 1,
                "dependencies": {
                    "root": {
                        "version": "1.0.0",
                        "requires": {"child": "^2"},
                        "dependencies": {"child": {"version": "2.0.0"}},
                    }
                },
            }
        )
    )
    sbom = parse_lockfile(path)
    assert len(sbom.packages) == 2
    assert next(p for p in sbom.packages if p.name == "root").dependencies == [
        "node_modules/root/node_modules/child"
    ]


@pytest.mark.parametrize(
    "line",
    [
        "requests>=2",
        "requests==2.*",
        "-r more.txt",
        "-e .",
        "requests @ https://example.com/a.whl",
        "requests==2.0 --hash=sha256:abc",
    ],
)
def test_reject_unresolved_requirements(tmp_path, line):
    path = tmp_path / "requirements.txt"
    path.write_text(line)
    with pytest.raises(ValueError):
        parse_lockfile(path)


def test_requirements_normalization_extras_and_markers(tmp_path):
    path = tmp_path / "requirements.txt"
    path.write_text('Foo_Bar[extra]==1.2.0 ; python_version >= "3.10" # comment\n')
    sbom = parse_lockfile(path)
    assert sbom.packages[0].name == "foo-bar" and sbom.packages[0].version == "1.2.0"
    assert len(sbom.warnings) == 2


def test_log_hunt_exact_and_private():
    indicators = [
        {"kind": "ip", "indicator": "203.0.113.42"},
        {"kind": "domain", "indicator": "ioc.example.invalid"},
    ]
    result = hunt_logs([EXAMPLES / "demo.log"], indicators)
    assert {r["indicator"]: r["count"] for r in result["findings"]} == {
        "203.0.113.42": 1,
        "ioc.example.invalid": 1,
    }
    assert "DO_NOT_UPLOAD" not in json.dumps(result)
    assert "notioc" not in json.dumps(result)


def test_intel_priority_sources_and_expiry():
    stale = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    rows = [
        {
            "kind": "kev",
            "indicator": "CVE-1",
            "source": "licensed-feed",
            "observed_at": "2026-01-01T00:00:00Z",
        },
        {
            "kind": "exploit",
            "indicator": "CVE-2",
            "score": 0.99,
            "source": "expired",
            "observed_at": "2025-01-01T00:00:00Z",
            "expires_at": stale,
        },
    ]
    intel = Intel(records=rows)
    result = intel.enrich({"incident_type": "VULNERABILITY", "advisories": [{"cve_ids": ["CVE-1", "CVE-2"]}]})
    assert result["priority"] == "P0" and result["intel"]["known_exploited"]
    assert result["intel"]["exploit_score"] is None
    assert result["intel"]["evidence"][0]["source"] == "licensed-feed"
