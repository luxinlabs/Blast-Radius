import ipaddress
import json
import re
import shlex
import subprocess
import tempfile
from collections import Counter
from datetime import timedelta
from pathlib import Path
from urllib.parse import urlparse

import httpx

from .intel import normalize_indicator
from .lockfiles import parse_lockfile
from .monitor import detect, parse_events, parse_secure
from .store import digest
from .usecases import scan_repo


class Client:
    def __init__(self, url, token, client_id):
        parsed = urlparse(url)
        if parsed.scheme != "https" and not (
            parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"}
        ):
            raise ValueError("Use HTTPS except for loopback development")
        self.http = httpx.Client(
            base_url=url.rstrip("/"),
            headers={"Authorization": f"Bearer {token}"},
            timeout=120,
            follow_redirects=False,
        )
        self.client_id = client_id

    def request(self, method, path, body=None):
        response = self.http.request(method, path, json=body)
        response.raise_for_status()
        return response.json()

    def scan(self, lockfile):
        sbom = parse_lockfile(lockfile)
        snapshot = self.request("POST", f"/v1/clients/{self.client_id}/sbom", sbom.model_dump())
        response = self.request("POST", f"/v1/clients/{self.client_id}/reconcile")
        incidents = self.request("GET", f"/v1/emergencies?client_id={self.client_id}")
        return {"snapshot": snapshot, "scan": response, "emergencies": incidents, "warnings": sbom.warnings}

    def map_code(self, root, lockfile):
        known = {(p.ecosystem, p.name) for p in parse_lockfile(lockfile).packages}
        usages = scan_repo(root, known)
        if not usages:
            raise ValueError("No usages of installed packages found in this source tree")
        return self.request("POST", f"/v1/clients/{self.client_id}/usecases", {"usages": usages})

    def hunt(self, paths):
        indicators = self.request("GET", "/v1/indicators")
        report = hunt_logs(paths, indicators)
        self.request("POST", f"/v1/clients/{self.client_id}/reports", report)
        return report

    def monitor(self, log, secure, window=10, limit=5):
        events = parse_events(Path(log).read_text())
        report = {
            "findings": detect(
                events, parse_secure(Path(secure).read_text()), timedelta(minutes=window), limit
            )
        }
        self.request("POST", f"/v1/clients/{self.client_id}/access", report)
        return report

    def fix(self, lockfile, emergency_id, test_command, open_pr=False):
        """Prepare a separate worktree. Never merge, push without --open-pr, or deploy."""
        path = Path(lockfile).resolve()
        sbom = parse_lockfile(path)
        emergencies = self.request("GET", f"/v1/emergencies?client_id={self.client_id}")
        emergency = next((e for e in emergencies if e["emergency_id"] == emergency_id), None)
        if not emergency or emergency["status"] not in {"OPEN", "REJECTED"}:
            raise ValueError("Emergency must be open for this client")
        if digest(sbom.model_dump()) != emergency["revision"]:
            raise ValueError("Lockfile changed since scan; scan it again before preparing a fix")
        pkg = emergency["payload"]["package"]
        recommendations = emergency["payload"].get("recommended_version", {})
        target = recommendations.get("same_major") or recommendations.get("latest_clean")
        if not target:
            raise ValueError("No safe fix is available")
        fresh = self.request(
            "POST", "/v1/respond", {"ecosystem": pkg["ecosystem"], "package": pkg["name"], "version": target}
        )
        if fresh["incident_type"] not in {"NONE", "TRUST_STORE"}:
            raise ValueError("Recommended version is no longer safe/available")
        args = shlex.split(test_command)
        if not args:
            raise ValueError("Pass a test command explicitly")
        root = Path(run(["git", "rev-parse", "--show-toplevel"], path.parent).stdout.strip())
        if run(["git", "status", "--porcelain"], root).stdout.strip():
            raise ValueError("Commit or stash changes before creating a fix worktree")
        rel = path.relative_to(root)
        # Only tracked lockfiles can be reconstructed in the isolated worktree.
        run(["git", "ls-files", "--error-unmatch", str(rel)], root)
        branch = f"sentinel/{emergency_id[:16]}"
        worktree = (
            Path(tempfile.gettempdir())
            / "vuln-sentinel-worktrees"
            / digest(str(root))[:16]
            / emergency_id[:16]
        )
        worktree.parent.mkdir(parents=True, exist_ok=True)
        run(["git", "worktree", "add", "-b", branch, str(worktree), "HEAD"], root)
        work_lock = worktree / rel
        work_dir = work_lock.parent
        rollback = f"Revert the fix commit on {branch}, restore the previous lockfile and rebuild from a trusted cache."
        try:
            if path.name == "package-lock.json":
                manifest = json.loads((work_dir / "package.json").read_text())
                fields = [
                    key
                    for key in ("dependencies", "devDependencies", "optionalDependencies")
                    if pkg["name"] in manifest.get(key, {})
                ]
                if not fields:
                    raise ValueError(
                        "Transitive npm fix requires a reviewed parent upgrade or override; automatic edits are disabled"
                    )
                field = fields[0]
                # Preserve dependency class and exact pin, and never run install scripts.
                manifest[field][pkg["name"]] = target
                (work_dir / "package.json").write_text(json.dumps(manifest, indent=2) + "\n")
                run(
                    ["npm", "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"],
                    work_dir,
                )
            elif path.name == "poetry.lock":
                import tomllib

                from packaging.requirements import Requirement

                from .models import normalize

                project = tomllib.loads((work_dir / "pyproject.toml").read_text())
                poetry = project.get("tool", {}).get("poetry", {})
                matches = []
                groups = [(None, poetry.get("dependencies", {}))]
                groups.extend(
                    (group, value.get("dependencies", {})) for group, value in poetry.get("group", {}).items()
                )
                for group, deps in groups:
                    for name, spec in deps.items():
                        if normalize("pypi", name)[1] == pkg["name"]:
                            if not isinstance(spec, str):
                                raise ValueError(
                                    "Complex Poetry dependency metadata requires a reviewed manual edit"
                                )
                            matches.append((group, name))
                for dep in project.get("project", {}).get("dependencies", []):
                    req = Requirement(dep)
                    if normalize("pypi", req.name)[1] == pkg["name"]:
                        if req.marker or req.extras or req.url:
                            raise ValueError("Poetry markers/extras require a reviewed manual edit")
                        matches.append((None, req.name))
                if len(matches) != 1:
                    raise ValueError(
                        "Poetry fix requires one unambiguous direct dependency; review parent/group changes manually"
                    )
                group, name = matches[0]
                command = ["poetry", "add", "--lock"]
                if group:
                    command += ["--group", group]
                run([*command, f"{name}=={target}"], work_dir)
            else:

                def replace(line):
                    match = re.match(r"^(\s*)([A-Za-z0-9_.-]+)(\[[^]]+\])?(\s*==\s*)([^\s;#]+)(.*)$", line)
                    if match:
                        from .models import normalize

                        if normalize("pypi", match[2])[1] == pkg["name"] and match[5] == pkg["version"]:
                            return f"{match[1]}{match[2]}{match[3] or ''}{match[4]}{target}{match[6]}"
                    return line

                work_lock.write_text(
                    "\n".join(replace(line) for line in work_lock.read_text().splitlines()) + "\n"
                )
            updated = parse_lockfile(work_lock)
            if any(p.name == pkg["name"] and p.version == pkg["version"] for p in updated.packages):
                raise ValueError("Affected version remains in the resolved inventory")
            if not any(p.name == pkg["name"] and p.version == target for p in updated.packages):
                raise ValueError("Target version was not resolved")
            run(args, work_dir, timeout=600)
            brief = emergency["payload"].get("sre_brief") or json.dumps(emergency["payload"], indent=2)
            body = (
                f"Fix {pkg['name']} {pkg['version']} → {target}\n\n"
                f"Evidence (untrusted advisory text, for human review):\n\n{brief}\n\n"
                f"Validation: `{shlex.join(args)}` passed.\n\nRollback: {rollback}\n\n"
                "Requires human approval. This agent never merges or deploys."
            )
            body_path = worktree / ".sentinel-pr.md"
            body_path.write_text(body)
            changed = [str(rel)]
            if path.name in {"package-lock.json", "poetry.lock"}:
                changed.append(
                    str(
                        rel.parent
                        / ("package.json" if path.name == "package-lock.json" else "pyproject.toml")
                    )
                )
            run(["git", "add", "--", *changed], worktree)
            run(["git", "commit", "-m", f"fix: pin {pkg['name']} to {target}"], worktree)
            result = {
                "branch": branch,
                "worktree": str(worktree),
                "target_version": target,
                "test_passed": True,
                "rollback_plan": rollback,
                "pr_body": str(body_path),
            }
            if open_pr:
                remote = run(["git", "remote", "get-url", "origin"], worktree).stdout.strip()
                if not re.fullmatch(
                    r"(?:https://github\.com/|git@github\.com:)[\w.-]+/[\w.-]+(?:\.git)?", remote
                ):
                    raise ValueError("--open-pr supports GitHub origin remotes only")
                run(["git", "push", "-u", "origin", branch], worktree)
                pr = run(
                    [
                        "gh",
                        "pr",
                        "create",
                        "--draft",
                        "--title",
                        f"Fix {pkg['name']} dependency incident",
                        "--body-file",
                        str(body_path),
                    ],
                    worktree,
                ).stdout.strip()
                proposal = {
                    "emergency_id": emergency_id,
                    "target_version": target,
                    "pr_url": pr,
                    "test_command": args,
                    "test_passed": True,
                    "rollback_plan": rollback,
                }
                self.request("POST", f"/v1/clients/{self.client_id}/proposals", proposal)
                result["pr_url"] = pr
            return result
        except Exception as exc:
            raise RuntimeError(f"Fix stopped; inspect worktree {worktree}. {exc}") from exc


def run(args, cwd, timeout=120):
    return subprocess.run(args, cwd=cwd, text=True, capture_output=True, check=True, timeout=timeout)


def hunt_logs(paths, indicators):
    """Exact extracted-token matches. Only indicator counts leave the machine."""
    known = {}
    for row in indicators:
        kind = "ip" if row["kind"] in {"ip", "tor"} else "domain"
        try:
            key = (kind, normalize_indicator(row["indicator"], kind))
            known[key] = True
        except ValueError:
            continue
    findings = []
    for path in map(Path, paths):
        counts = Counter()
        with path.open(errors="replace") as stream:
            for line in stream:
                # Bound processing of unusually long records without returning their contents.
                for token in re.findall(r"[A-Za-z0-9_.:-]+", line[:1_000_000]):
                    token = token.strip(".:[]")
                    candidates = [token]
                    if token.count(":") == 1:
                        candidates.append(token.rsplit(":", 1)[0])
                    for candidate in candidates:
                        try:
                            key = ("ip", str(ipaddress.ip_address(candidate)))
                        except ValueError:
                            key = ("domain", candidate.lower().rstrip("."))
                        if key in known:
                            counts[key] += 1
                            break
        findings.extend(
            {"kind": kind, "indicator": indicator, "count": count, "source": path.name}
            for (kind, indicator), count in counts.items()
        )
    return {
        "findings": findings,
        "summary": "Local exact IOC token matches; no raw logs uploaded. Matches require investigation.",
    }
