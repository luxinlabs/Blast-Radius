"""Fixed, offline sandbox harness. Never executes code supplied in a notification.

The approved patch and input files are data. Checks are containment-policy and
syntax smoke checks, not an application's full test suite or proof of remediation.
"""

import ast
import json
import re
import sys
from pathlib import Path


def check(files, checks):
    for name, content in files.items():
        if name.endswith(".py"):
            ast.parse(content, filename=name)
    for item in checks:
        content = files.get(item["file"], "")
        if item["kind"] == "disabled_module":
            assert "BLAST_RADIUS_DISABLED" in content, "affected module has no approved disable guard"
            if item["file"].endswith(".py"):
                tree = ast.parse(content)
                assert not any(isinstance(n, (ast.Import, ast.ImportFrom)) for n in ast.walk(tree)), (
                    "disabled module still imports dependencies"
                )
                functions = [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
                assert functions and all(isinstance(n.body[0], ast.Raise) for n in functions), (
                    "feature guard missing"
                )
            else:
                assert not re.search(r"\b(?:import|require)\b", content), (
                    "disabled module still loads dependencies"
                )
                assert "throw new Error" in content, "JavaScript disable guard missing"
        elif item["kind"] == "pin":
            if item["file"].endswith(".json"):
                data = json.loads(content)
                versions = [
                    v.get("version")
                    for path, v in data.get("packages", {}).items()
                    if path.endswith("node_modules/" + item["name"])
                ]
                assert versions and all(v == item["version"] for v in versions), (
                    "lockfile candidate is not pinned"
                )
            else:
                assert re.search(
                    r"^" + re.escape(item["name"]) + r"==" + re.escape(item["version"]) + r"\s*$",
                    content,
                    re.M,
                ), "candidate is not pinned"
        elif item["kind"] == "access_policy":
            assert content, "no reviewed access policy present"
            assert item["principal"] in json.loads(content)["deny_principals"], (
                "principal is not denied in proposed policy"
            )
        elif item["kind"] == "investigation":
            assert content and "Human investigation required" in content, "no investigation plan present"
    return True


def exercise(bundle, emit=print, workdir=Path("/work")):
    emit(
        "CHECK_SCOPE containment policy and syntax smoke checks; no package installation or customer application tests"
    )
    try:
        check(bundle["before"], bundle["checks"])
    except (AssertionError, SyntaxError, ValueError) as exc:
        emit("BASELINE_FAIL " + str(exc))
    else:
        emit("BASELINE_PASS existing input already satisfies the proposed checks")
    for name, content in bundle["after"].items():
        target = workdir / name
        target.resolve().relative_to(workdir.resolve())
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
        emit("PATCH_APPLIED " + name)
    check(bundle["after"], bundle["checks"])
    emit("PATCHED_CHECKS_PASS approved copy satisfies policy and syntax checks")
    emit("ORIGINAL_REPOSITORY_UNCHANGED no merge, deploy, secret rotation, or principal revocation performed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(exercise(json.loads(Path("/bundle/bundle.json").read_text())))
    except Exception as exc:
        print("PATCHED_CHECKS_FAIL " + str(exc), flush=True)
        sys.exit(1)
