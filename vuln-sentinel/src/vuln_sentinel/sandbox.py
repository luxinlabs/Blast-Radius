"""Notification-driven client fleet with durable logs and approval-bound Docker checks.

This local demo worker uses explicit rules, not an unconfigured LLM. It generates
reviewable code from allowlisted source files; it never runs notification commands.
"""

import ast
import difflib
import json
import os
import queue
import re
import shutil
import sqlite3
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path, PurePosixPath

from .models import AgentResponse, ResponseRequest
from .store import digest, encode, now


class JobStore:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connection() as c:
            c.execute(
                "CREATE TABLE IF NOT EXISTS jobs (job_id TEXT PRIMARY KEY, client_id TEXT NOT NULL, notification_id TEXT NOT NULL, state TEXT NOT NULL, payload TEXT NOT NULL, updated_at TEXT NOT NULL)"
            )
            c.execute(
                "CREATE TABLE IF NOT EXISTS logs (seq INTEGER PRIMARY KEY AUTOINCREMENT, job_id TEXT NOT NULL, at TEXT NOT NULL, level TEXT NOT NULL, message TEXT NOT NULL)"
            )
            # An interrupted worker never silently reruns approved code after a restart.
            for row in c.execute(
                "SELECT job_id,payload FROM jobs WHERE state IN ('PLANNING','QUEUED','RUNNING')"
            ).fetchall():
                payload = json.loads(row[1])
                owner = payload.get("owner_pid")
                if owner:
                    try:
                        os.kill(owner, 0)
                        continue
                    except PermissionError:
                        continue
                    except ProcessLookupError:
                        pass
                payload["error"] = "Server restarted; inspect this run and prepare a new notification."
                c.execute(
                    "UPDATE jobs SET state='INTERRUPTED',payload=?,updated_at=? WHERE job_id=?",
                    (encode(payload), now(), row[0]),
                )

    @contextmanager
    def connection(self):
        c = sqlite3.connect(self.path, timeout=30)
        try:
            c.execute("PRAGMA journal_mode=WAL")
            c.execute("BEGIN IMMEDIATE")
            yield c
            c.commit()
        except Exception:
            c.rollback()
            raise
        finally:
            c.close()

    def claim(self, client, note):
        identity = digest([client, note["notification_id"], note.get("updated_at")])
        with self.connection() as c:
            result = c.execute(
                "INSERT OR IGNORE INTO jobs VALUES (?,?,?,?,?,?)",
                (
                    identity,
                    client,
                    note["notification_id"],
                    "PLANNING",
                    encode({"kind": note["kind"], "owner_pid": os.getpid()}),
                    now(),
                ),
            )
            return identity if result.rowcount else None

    def get(self, identity):
        with self.connection() as c:
            c.row_factory = sqlite3.Row
            row = c.execute("SELECT * FROM jobs WHERE job_id=?", (identity,)).fetchone()
        if not row:
            raise ValueError("Unknown sandbox job")
        return {**dict(row), "payload": json.loads(row["payload"])}

    def list(self, client=None):
        with self.connection() as c:
            c.row_factory = sqlite3.Row
            rows = c.execute(
                "SELECT * FROM jobs"
                + (" WHERE client_id=?" if client else "")
                + " ORDER BY updated_at DESC LIMIT 200",
                (client,) if client else (),
            ).fetchall()
        return [{**dict(row), "payload": json.loads(row["payload"])} for row in rows]

    def update(self, identity, state, payload=None, expected=None):
        with self.connection() as c:
            fields, params = "state=?,updated_at=?", [state, now()]
            if payload is not None:
                fields += ",payload=?"
                params.append(encode(payload))
            params.append(identity)
            where = "job_id=?"
            if expected:
                where += " AND state=?"
                params.append(expected)
            if c.execute(f"UPDATE jobs SET {fields} WHERE {where}", params).rowcount != 1:
                raise ValueError("Sandbox job changed; refresh before reviewing")

    def log(self, identity, level, message):
        with self.connection() as c:
            c.execute(
                "INSERT INTO logs(job_id,at,level,message) VALUES (?,?,?,?)",
                (identity, now(), level, str(message)[:4000]),
            )

    def logs(self, identity, after=0):
        with self.connection() as c:
            c.row_factory = sqlite3.Row
            return [
                dict(row)
                for row in c.execute(
                    "SELECT * FROM logs WHERE job_id=? AND seq>? ORDER BY seq LIMIT 1000", (identity, after)
                ).fetchall()
            ]


def safe_source(root, relative):
    path = PurePosixPath(relative)
    if path.is_absolute() or ".." in path.parts or any(p.startswith(".") for p in path.parts):
        raise ValueError("Source paths must stay inside the configured repository")
    if path.suffix not in {".py", ".js", ".json", ".txt"} or str(path) == "secure.txt":
        raise ValueError("Source type is not allowlisted")
    base = root.resolve()
    target = base.joinpath(*path.parts)
    if any(parent.is_symlink() for parent in [target, *target.parents] if parent != base.parent):
        raise ValueError("Symlinked source paths are not accepted")
    target.resolve().relative_to(base)
    if not target.is_file() or target.stat().st_size > 200_000:
        raise ValueError("Source file missing or exceeds the sandbox limit")
    return target.read_text()


def disabled_module(source, suffix):
    message = "BLAST_RADIUS_DISABLED: feature paused pending security review"
    if suffix == ".py":
        tree = ast.parse(source)
        names = [
            (n.name, isinstance(n, ast.AsyncFunctionDef))
            for n in tree.body
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]
        if not names:
            raise ValueError("No top-level Python functions to disable")
        return "# Temporary containment; removes imports from this copied module.\n" + "\n".join(
            f"{'async ' if asynchronous else ''}def {name}(*args, **kwargs):\n    raise RuntimeError({message!r})\n"
            for name, asynchronous in names
        )
    names = re.findall(r"export\s+(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(", source)
    if not names:
        raise ValueError("No exported JavaScript functions to disable")
    return "// Temporary containment; removes imports from this copied module.\n" + "\n".join(
        f"export function {name}(...args) {{\n  throw new Error({json.dumps(message)});\n}}\n"
        for name in names
    )


def plan_fingerprint(plan):
    return digest({key: plan[key] for key in ("bundle", "runner_digest", "image", "command")})


def plan_notification(note, repository):
    payload, kind = note["payload"], note["kind"]
    before, after, checks, actions = {}, {}, [], []
    summary = ""
    if kind == "THREAT":
        pkg = payload["package"]
        safe = payload.get("recommended_version", {})
        candidate = safe.get("same_major") or safe.get("latest_clean")
        # A candidate may be absent after a demo injection. Never invent one.
        if candidate and not payload.get("client_blast_radius", {}).get("dependents"):
            filename = "requirements.txt" if pkg["ecosystem"] == "PyPI" else "package-lock.json"
            source = safe_source(repository, filename)
            if pkg["ecosystem"] == "PyPI":
                updated, count = re.subn(
                    r"^" + re.escape(pkg["name"]) + r"==" + re.escape(pkg["version"]) + r"\s*$",
                    f"{pkg['name']}=={candidate}",
                    source,
                    flags=re.M,
                )
                if not count:
                    raise ValueError("The installed pin is not present in the configured repository")
            else:
                data = json.loads(source)
                count = 0
                for location, item in data.get("packages", {}).items():
                    if (
                        location.endswith("node_modules/" + pkg["name"])
                        and item.get("version") == pkg["version"]
                    ):
                        item["version"] = candidate
                        count += 1
                if not count:
                    raise ValueError("Installed version is not present in the configured lockfile")
                root = data.get("packages", {}).get("", {})
                for field in ("dependencies", "devDependencies", "optionalDependencies"):
                    if pkg["name"] in root.get(field, {}):
                        root[field][pkg["name"]] = candidate
                updated = json.dumps(data, indent=2) + "\n"
            before[filename], after[filename] = source, updated
            checks.append({"kind": "pin", "file": filename, "name": pkg["name"], "version": candidate})
            summary = f"Recommend {pkg['name']} {pkg['version']} → {candidate}. Lockfile edit is a proposal; a package-manager regeneration and application tests are still required."
            actions.append({"type": "PIN_VERSION", "target": filename, "rationale": summary})
        else:
            files = sorted(
                {
                    f["file"]
                    for case in payload.get("client_impact", [])
                    for f in case.get("functionalities_affected", [])
                }
            )
            for filename in files[:12]:
                source = safe_source(repository, filename)
                before[filename] = source
                after[filename] = disabled_module(source, PurePosixPath(filename).suffix)
                checks.append({"kind": "disabled_module", "file": filename})
                actions.append(
                    {
                        "type": "DISABLE_FEATURE",
                        "target": filename,
                        "rationale": "No direct verified pin is available. Recommend a reversible whole-module pause in the sandbox; removes dependency imports and may affect every function in this module.",
                    }
                )
            summary = f"{pkg['name']} {pkg['version']}: no automatic direct pin. Recommend temporarily disabling affected modules; do not install or execute the suspect dependency."
        actions.append(
            {
                "type": "BLOCK_VERSION",
                "target": f"{pkg['ecosystem']}/{pkg['name']}@{pkg['version']}",
                "rationale": "Propose blocking the version through the existing human-reviewed containment gate.",
            }
        )
    elif kind == "ACCESS_ANOMALY":
        filename = "proposed-access-policy.json"
        principal = payload["principal"]
        after[filename] = (
            json.dumps(
                {
                    "deny_principals": [principal],
                    "resources": payload.get("resources", []),
                    "simulation_only": True,
                },
                indent=2,
            )
            + "\n"
        )
        checks.append({"kind": "access_policy", "file": filename, "principal": principal})
        summary = f"Access anomaly {payload['rule']} for {principal}: propose an access-policy change and issuer-side investigation."
        actions.extend(
            [
                {
                    "type": "REVOKE_PRINCIPAL",
                    "target": principal,
                    "rationale": "Owner must verify identity and revoke at the actual issuer; this sandbox only tests a proposed deny policy.",
                },
                {
                    "type": "HUNT_LOGS",
                    "target": "incident access window",
                    "rationale": "Review the aggregate findings and correlate with client-local logs.",
                },
            ]
        )
    elif kind == "IOC_MATCH":
        summary = (
            "IOC matches are investigation leads. Recommend local correlation before asserting compromise."
        )
        actions.append(
            {"type": "HUNT_LOGS", "target": "client-local indicator findings", "rationale": summary}
        )
    else:
        raise ValueError("Unsupported notification kind")
    if not checks:
        after["investigation.md"] = "# Human investigation required\n\n" + summary + "\n"
        checks.append({"kind": "investigation", "file": "investigation.md"})
    patches = {
        name: "".join(
            difflib.unified_diff(
                before.get(name, "").splitlines(True),
                content.splitlines(True),
                fromfile="a/" + name,
                tofile="b/" + name,
            )
        )
        for name, content in after.items()
    }
    for action in actions:
        action["artifacts"] = [
            {"kind": "patch", "ref": name, "content": patch}
            for name, patch in patches.items()
            if name == action["target"]
        ]
        if not action["artifacts"]:
            action["artifacts"] = [
                {
                    "kind": "runbook",
                    "ref": "human-review",
                    "content": summary + "\nHuman approval and infrastructure integration are required.",
                }
            ]
    response = AgentResponse(
        summary=("SYNTHETIC DEMO. " if payload.get("synthetic") else "") + summary, actions=actions
    )
    bundle = {"before": before, "after": after, "checks": checks}
    plan = {
        "summary": response.summary,
        "package": payload.get("package"),
        "bundle": bundle,
        "runner_digest": digest(Path(__file__).with_name("sandbox_runner.py").read_text()),
        "image": os.getenv("SENTINEL_SANDBOX_IMAGE", "python:3.12-alpine"),
        "patches": patches,
        "response": response.model_dump(),
        "command": ["python", "-I", "-S", "-u", "/bundle/runner.py"],
        "test_scope": "Containment policy and syntax smoke checks; not customer application tests",
    }
    plan["plan_digest"] = plan_fingerprint(plan)
    return plan


class DockerSandbox:
    def __init__(self, root, image=None):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.image = image or os.getenv("SENTINEL_SANDBOX_IMAGE", "python:3.12-alpine")
        if not re.fullmatch(r"[\w./:@-]+", self.image) or self.image.startswith("-"):
            raise ValueError("Invalid sandbox image")

    def available(self):
        if not shutil.which("docker"):
            return False
        try:
            subprocess.run(
                ["docker", "info", "--format", "{{.ServerVersion}}"],
                capture_output=True,
                check=True,
                timeout=3,
            )
            subprocess.run(
                ["docker", "image", "inspect", self.image], capture_output=True, check=True, timeout=3
            )
            return True
        except (OSError, subprocess.SubprocessError):
            return False

    def command(self, identity, directory):
        return [
            "docker",
            "run",
            "--rm",
            "--pull",
            "never",
            "--name",
            "br-" + identity[:24],
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--memory",
            "128m",
            "--memory-swap",
            "128m",
            "--cpus",
            "0.5",
            "--pids-limit",
            "32",
            "--user",
            "65534:65534",
            "--tmpfs",
            "/work:rw,noexec,nosuid,size=32m,uid=65534,gid=65534",
            "--workdir",
            "/work",
            "--mount",
            f"type=bind,src={directory},dst=/bundle,readonly",
            self.image,
            "python",
            "-I",
            "-S",
            "-u",
            "/bundle/runner.py",
        ]

    def run(self, identity, plan, emit, cancel):
        if plan_fingerprint(plan) != plan["plan_digest"]:
            raise ValueError("Approved plan was modified")
        if plan["image"] != self.image or plan["runner_digest"] != digest(
            Path(__file__).with_name("sandbox_runner.py").read_text()
        ):
            raise ValueError("Sandbox image or check harness changed after planning; request a fresh review")
        directory = self.root / identity
        directory.mkdir(exist_ok=False)
        (directory / "bundle.json").write_text(encode(plan["bundle"]))
        shutil.copyfile(Path(__file__).with_name("sandbox_runner.py"), directory / "runner.py")
        args = self.command(identity, directory)
        emit("COMMAND " + " ".join(args))
        output = queue.Queue()
        process = subprocess.Popen(
            args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
        )

        def read():
            for line in process.stdout:
                output.put(line.rstrip())
            output.put(None)

        threading.Thread(target=read, daemon=True).start()
        deadline = time.monotonic() + 60
        passed = False
        try:
            while True:
                if cancel.is_set() or time.monotonic() > deadline:
                    raise TimeoutError("Sandbox cancelled or exceeded its 60-second deadline")
                try:
                    line = output.get(timeout=0.2)
                except queue.Empty:
                    continue
                if line is None:
                    break
                emit(line)
                passed = passed or line.startswith("PATCHED_CHECKS_PASS ")
            code = process.wait(timeout=5)
            if code:
                raise RuntimeError(f"Sandbox exited with code {code}; inspect the log")
            if not passed:
                raise RuntimeError("Sandbox did not confirm that the patched checks passed")
        finally:
            if process.poll() is None:
                subprocess.run(["docker", "rm", "-f", "br-" + identity[:24]], capture_output=True, timeout=5)
                process.kill()
                process.wait(timeout=5)
            process.stdout.close()


class ClientFleet:
    def __init__(self, service, settings, repositories=None, engine=None):
        self.service = service
        base = Path(settings.sqlite_path).resolve().parent
        default = Path(__file__).resolve().parents[2] / "examples" / "orgs"
        raw = (
            repositories if repositories is not None else json.loads(os.getenv("SENTINEL_CLIENT_REPOS", "{}"))
        )
        self.repositories = (
            {name: Path(path).resolve() for name, path in raw.items()}
            if raw
            else {p.name: p.resolve() for p in default.iterdir() if p.is_dir()}
            if default.exists()
            else {}
        )
        self.jobs = JobStore(base / "client-jobs.sqlite")
        self.engine = engine or DockerSandbox(base / "sandbox-runs")
        self.workers, self.worker_errors = {}, {}
        self.lock = threading.RLock()
        self.cancel = threading.Event()
        self.pool = ThreadPoolExecutor(max_workers=3, thread_name_prefix="br-sandbox")

    def validate_candidates(self, plan):
        package = plan.get("package")
        for item in plan["bundle"]["checks"]:
            if item["kind"] == "pin":
                fresh = self.service.respond(
                    ResponseRequest(
                        ecosystem=package["ecosystem"], package=item["name"], version=item["version"]
                    )
                )
                if fresh["incident_type"] not in {"NONE", "TRUST_STORE"}:
                    raise ValueError(
                        "Candidate version is no longer verified safe/available; request another plan"
                    )

    def drain(self, client):
        if client not in self.repositories:
            raise ValueError("Client repository is not configured on this host")
        for note in self.service.store.notifications(client, "NEW"):
            identity = self.jobs.claim(client, note)
            if not identity:
                continue
            self.jobs.log(identity, "INFO", f"Client agent {client} received {note['kind']} notification")
            try:
                self.jobs.log(
                    identity,
                    "ERROR",
                    "Detector reported: "
                    + (note["payload"].get("incident_type") or note["payload"].get("rule") or "IOC_MATCH"),
                )
                plan = plan_notification(note, self.repositories[client])
                self.validate_candidates(plan)
                plan["image"] = getattr(self.engine, "image", plan["image"])
                plan["plan_digest"] = plan_fingerprint(plan)
                self.jobs.log(identity, "INFO", plan["summary"])
                self.service.store.respond_notification(
                    note["notification_id"],
                    AgentResponse.model_validate(plan["response"]),
                    f"client-agent:{client}",
                )
                self.jobs.update(
                    identity,
                    "AWAITING_APPROVAL",
                    {**plan, "kind": note["kind"], "owner_pid": os.getpid()},
                    expected="PLANNING",
                )
                self.jobs.log(
                    identity,
                    "APPROVAL",
                    "Request: run the displayed checks on an isolated copy. No commands have executed.",
                )
            except Exception as exc:
                self.jobs.update(
                    identity,
                    "PLAN_FAILED",
                    {"kind": note["kind"], "error": str(exc)[:1000]},
                    expected="PLANNING",
                )
                self.jobs.log(identity, "ERROR", str(exc))

    def start(self, principal, clients):
        principal.require("admin", "agent")
        with self.lock:
            for client in clients:
                principal.tenant(client)
                if client not in self.repositories:
                    raise ValueError("Client repository is not configured on this host")
            for client in clients:
                if client in self.workers and self.workers[client][0].is_alive():
                    continue
                stop = threading.Event()

                def loop(name=client, halt=stop):
                    while not halt.is_set():
                        try:
                            self.drain(name)
                            self.worker_errors.pop(name, None)
                        except Exception as exc:
                            self.worker_errors[name] = type(exc).__name__
                        halt.wait(2)

                thread = threading.Thread(target=loop, daemon=True, name="client-agent:" + client)
                self.workers[client] = thread, stop
                thread.start()
        return {
            "running": clients,
            "planner": "rule-based demo client",
            "code_execution": "requires explicit approval",
        }

    def stop(self, principal, clients):
        principal.require("admin", "agent")
        for client in clients:
            principal.tenant(client)
        for client in clients:
            worker = self.workers.get(client)
            if worker:
                worker[1].set()
        return {"stopping": clients, "approved_sandbox_runs": "continue until complete or timeout"}

    def decide(self, principal, identity, approval):
        principal.require("admin", "reviewer")
        job = self.jobs.get(identity)
        principal.tenant(job["client_id"])
        if job["state"] != "AWAITING_APPROVAL" or approval.plan_digest != job["payload"].get("plan_digest"):
            raise ValueError("Job or displayed plan changed; refresh before reviewing")
        if approval.decision == "REJECTED":
            self.jobs.update(identity, "REJECTED", expected="AWAITING_APPROVAL")
            self.jobs.log(identity, "REVIEW", f"{principal.subject} rejected execution: {approval.reason}")
            return {"state": "REJECTED"}
        if job["payload"]["kind"] == "THREAT":
            scan = self.service.reconcile(principal.subject, job["client_id"])
            emergency = self.service.store.get_emergency(job["notification_id"])
            if not scan["complete"] or emergency["status"] == "SUPERSEDED":
                raise ValueError("Notification evidence is stale or incomplete; prepare a new plan")
        for filename, source in job["payload"]["bundle"]["before"].items():
            if safe_source(self.repositories[job["client_id"]], filename) != source:
                raise ValueError("Client source changed after planning; prepare a new notification")
        self.validate_candidates(job["payload"])
        if not self.engine.available():
            self.jobs.log(
                identity,
                "BLOCKED",
                "Docker or prepared sandbox image unavailable. Start Docker and pull python:3.12-alpine, then retry approval.",
            )
            raise ValueError(
                "Docker sandbox unavailable. Start Docker and prepare the configured image; no host-code fallback is used."
            )
        approved_plan = {
            **job["payload"],
            "owner_pid": os.getpid(),
            "approved_by": principal.subject,
            "approval_reason": approval.reason,
        }
        self.jobs.update(identity, "QUEUED", approved_plan, expected="AWAITING_APPROVAL")
        self.jobs.log(identity, "REVIEW", f"{principal.subject} approved this exact plan: {approval.reason}")
        self.pool.submit(self.execute, identity)
        return {"state": "QUEUED", "original_repository_changed": False}

    def execute(self, identity):
        try:
            self.jobs.update(identity, "RUNNING", expected="QUEUED")
            plan = self.jobs.get(identity)["payload"]
            self.jobs.log(
                identity,
                "INFO",
                "Starting restricted Docker sandbox; network disabled, root read-only, no credentials forwarded",
            )
            self.engine.run(identity, plan, lambda line: self.jobs.log(identity, "OUTPUT", line), self.cancel)
            self.jobs.update(identity, "CHECKS_PASSED", expected="RUNNING")
            self.jobs.log(
                identity,
                "INFO",
                "Checks passed on the isolated copy. Full application tests and human review still required; nothing merged or deployed.",
            )
        except Exception as exc:
            self.jobs.update(identity, "EXECUTION_FAILED")
            self.jobs.log(identity, "ERROR", str(exc))
            self.jobs.log(
                identity,
                "RECOMMENDATION",
                "Inspect the failing check and prepare a revised patch; no automatic retry or deployment.",
            )

    def close(self):
        self.cancel.set()
        for thread, stop in self.workers.values():
            stop.set()
        for thread, stop in self.workers.values():
            thread.join(timeout=3)
        self.pool.shutdown(wait=True, cancel_futures=True)
