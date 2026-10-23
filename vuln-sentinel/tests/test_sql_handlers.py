"""Execute the actual embedded Python UDF/procedure bodies locally.
Snowflake DDL compilation and query planning still require Snowflake deployment checks.
"""

import re
from pathlib import Path

import pytest

SQL = Path(__file__).resolve().parents[1] / "sql" / "11_response_safety.sql"


def handlers():
    text = SQL.read_text()
    bodies = re.findall(r"AS '\n(.*?)\n';", text, re.S)
    assert len(bodies) == 2
    namespaces = []
    for body in bodies:
        # Snowflake string literal decoding (doubled quotes and backslash escapes).
        body = body.replace("''", "'").replace("\\\\", "\\")
        scope = {}
        exec(compile(body, str(SQL), "exec"), scope)
        namespaces.append(scope)
    return namespaces


@pytest.mark.parametrize(
    "eco,ver,intro,fixed,last,versions,expected",
    [
        ("npm", "1.0.0", "0", "1.0.1", None, [], True),
        ("npm", "1.0.1", "0", "1.0.1", None, [], False),
        ("npm", "1.0.0-beta.2", "1.0.0-beta.1", "1.0.0", None, [], True),
        ("npm", "1.0.0-beta.10", "1.0.0-beta.2", "1.0.0", None, [], True),
        ("npm", "1.0.0-beta.1", "1.0.0", None, None, [], False),
        ("npm", "1.2.3", None, None, None, ["1.2.3"], True),
        ("npm", "1.2.4", None, None, None, ["1.2.3"], False),
        ("npm", "garbage", "0", "2.0.0", None, [], None),
        ("PyPI", "1.0rc1", "0", "1.0", None, [], True),
        ("PyPI", "1.0.post1", "1.0", "1.1", None, [], True),
        ("PyPI", "1!1.0", "0", "2.0", None, [], False),
        ("PyPI", "1.0", "0", None, "1.0", [], True),
        ("PyPI", "1.1", "0", None, "1.0", [], False),
    ],
)
def test_embedded_version_rules(eco, ver, intro, fixed, last, versions, expected):
    udf, _ = handlers()
    assert udf["f"](eco, ver, intro, fixed, last, versions) is expected


def test_candidate_query_covers_non_watchlist_and_fails_closed():
    _, proc = handlers()
    queries = []

    def q(session, sql, params):
        queries.append(sql)
        if "CORE.PACKAGES p" in sql:
            return [
                {
                    "LATEST_VERSION": "1.2.0",
                    "MONTHLY_DOWNLOADS": 10,
                    "RUNS_WHERE": None,
                    "HANDLES_SECRETS": False,
                    "SECRET_TYPES": None,
                    "DEMO_REASON": None,
                }
            ]
        if "SELECT DISTINCT a.advisory_id" in sql:
            return [
                {
                    "ADVISORY_ID": "TEST-1",
                    "INCIDENT_TYPE": "VULNERABILITY",
                    "SEVERITY": "HIGH",
                    "SUMMARY": "Test",
                    "CVE_IDS": [],
                    "ALIASES": [],
                    "PUBLISHED": None,
                    "FIXED": "1.0.1",
                    "DETAILS": "Test",
                }
            ]
        if "SELECT version, yanked" in sql:
            return [{"VERSION": "1.0.0", "YANKED": False, "DEPRECATED": None, "PUBLISHED_AT": None}]
        if "SELECT v.version" in sql:
            assert "bad.version IS NULL" in sql and "IS_AFFECTED" in sql and "), TRUE)" in sql
            assert "PACKAGE_VERSION_RISK" not in sql
            return [{"VERSION": "1.2.0"}, {"VERSION": "1.1.0"}]
        return []

    proc["q"] = q
    result = proc["run"](None, "npm", "outside-watchlist", "1.0.0", False)
    assert result["recommended_version"]["same_major"] == "1.2.0"
    assert result["recommended_version"]["lowest_clean_upgrade"] == "1.1.0"
    assert result["requires_human_approval"]
