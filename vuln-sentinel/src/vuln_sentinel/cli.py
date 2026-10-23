import argparse
import json
import os
import secrets
import shlex
import sys
import time
from pathlib import Path


def load_env():
    path = Path(".env")
    if path.exists():
        # Deliberately small dotenv reader; never evaluates shell code.
        for line in path.read_text().splitlines():
            if line.strip() and not line.lstrip().startswith("#"):
                key, _, raw = line.removeprefix("export ").partition("=")
                values = shlex.split(raw)
                if values:
                    os.environ.setdefault(key.strip(), values[0])


def init_demo():
    path = Path(".env")
    if path.exists():
        raise ValueError(".env already exists; keep its credentials or remove it explicitly")
    tokens = {}
    for role, subject in [("admin", "local-admin"), ("agent", "local-agent"), ("reviewer", "local-reviewer")]:
        token = secrets.token_urlsafe(32)
        tokens[token] = {
            "subject": subject,
            "role": role,
            **({"client_id": "demo-app"} if role != "admin" else {}),
        }
    roles = {p["role"]: t for t, p in tokens.items()}
    values = {
        "SENTINEL_BACKEND": "demo",
        "SENTINEL_URL": "http://127.0.0.1:8000",
        "SENTINEL_CLIENT_ID": "demo-app",
        "SENTINEL_TOKENS": json.dumps(tokens),
        "SENTINEL_TOKEN": roles["agent"],
        "SENTINEL_ADMIN_TOKEN": roles["admin"],
        "SENTINEL_REVIEWER_TOKEN": roles["reviewer"],
    }
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as stream:
        stream.write("# Generated local demo credentials. Do not commit.\n")
        stream.writelines(f"export {key}={shlex.quote(value)}\n" for key, value in values.items())
    print("Created .env with separate admin, agent and reviewer tokens (mode 0600).")


def demo():
    """Socket-free walkthrough, persisted for the local dashboard. No real PR is created."""
    from fastapi.testclient import TestClient

    from .config import Settings
    from .models import SBOM, Package
    from .server import create_app

    settings = Settings.from_env()
    if settings.backend != "demo":
        raise ValueError("The walkthrough only supports SENTINEL_BACKEND=demo")
    tokens = {p.role: token for token, p in settings.tokens.items()}
    sbom = SBOM(
        source="requirements.txt",
        packages=[
            Package(
                ecosystem="pypi",
                name="litellm",
                version="1.107.0",
                locator="requirements:litellm@1.107.0",
                direct=True,
            )
        ],
    )
    with TestClient(create_app(settings)) as client:

        def call(method, path, body=None, role="admin"):
            r = client.request(method, path, json=body, headers={"Authorization": f"Bearer {tokens[role]}"})
            r.raise_for_status()
            return r.json()

        call("POST", "/v1/clients", {"client_id": "demo-app", "name": "Local demo application"})
        call("POST", "/v1/clients/demo-app/sbom", sbom.model_dump(), "agent")
        scan = call("POST", "/v1/clients/demo-app/reconcile", role="agent")
        emergency = next(
            e
            for e in call("GET", "/v1/emergencies?client_id=demo-app")
            if e["emergency_id"] in scan["emergency_ids"]
        )
        # This walkthrough intentionally does not claim to have created or tested a real PR.
        call(
            "POST",
            "/v1/clients/demo-app/reports",
            {
                "findings": [
                    {"indicator": "203.0.113.42", "kind": "ip", "count": 2, "source": "synthetic-demo.log"}
                ],
                "summary": "SIMULATION: synthetic TEST-NET indicator matches",
            },
            "agent",
        )
        return {
            "mode": "DEMO",
            "scan": scan,
            "emergency_id": emergency["emergency_id"],
            "status": emergency["status"],
            "next": "Open the dashboard. Integration tests exercise proposals and human reviews using simulated PR evidence.",
        }


def main():
    parser = argparse.ArgumentParser(description="Blast Radius · exact versions · human-reviewed fixes")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init-demo")
    sub.add_parser("demo")
    serve = sub.add_parser("serve")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    dashboard = sub.add_parser("dashboard")
    dashboard.add_argument("--port", type=int, default=8501)
    scan = sub.add_parser("scan")
    scan.add_argument("lockfile")
    agents = sub.add_parser("agents")
    agents.add_argument("--emergency", required=True)
    agents.add_argument("--inspect", action="store_true")
    gate = sub.add_parser("gate")
    gate.add_argument("lockfile")
    hunt = sub.add_parser("hunt")
    hunt.add_argument("logs", nargs="+")
    fix = sub.add_parser("fix")
    fix.add_argument("lockfile")
    fix.add_argument("--emergency", required=True)
    fix.add_argument("--test", required=True, help="Explicit command, executed without a shell")
    fix.add_argument("--open-pr", action="store_true", help="Push a branch and create a draft GitHub PR")
    reconcile = sub.add_parser("reconcile")
    reconcile.add_argument(
        "--interval", type=int, default=0, help="Seconds between fleet scans; default runs once"
    )
    args = parser.parse_args()
    try:
        if args.command == "init-demo":
            init_demo()
            return
        load_env()
        if args.command == "serve":
            import uvicorn

            uvicorn.run(
                "vuln_sentinel.server:create_app", factory=True, host=args.host, port=args.port, workers=1
            )
            return
        if args.command == "dashboard":
            import subprocess

            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "streamlit",
                    "run",
                    str(Path(__file__).with_name("dashboard.py")),
                    "--server.address",
                    "127.0.0.1",
                    "--server.port",
                    str(args.port),
                    "--browser.gatherUsageStats",
                    "false",
                ],
                check=True,
            )
            return
        if args.command == "demo":
            result = demo()
        else:
            from .client import Client

            client = Client(
                os.getenv("SENTINEL_URL", "http://127.0.0.1:8000"),
                os.environ["SENTINEL_TOKEN"],
                os.getenv("SENTINEL_CLIENT_ID", "demo-app"),
            )
            if args.command == "scan":
                result = client.scan(args.lockfile)
            elif args.command == "agents":
                result = client.request(
                    "GET" if args.inspect else "POST",
                    f"/v1/emergencies/{args.emergency}/agents" + ("" if args.inspect else "/run"),
                )
            elif args.command == "gate":
                from .lockfiles import parse_lockfile

                result = client.request(
                    "POST", f"/v1/clients/{client.client_id}/gate", parse_lockfile(args.lockfile).model_dump()
                )
            elif args.command == "hunt":
                result = client.hunt(args.logs)
            elif args.command == "fix":
                from .agents import PatchAgent

                result = PatchAgent.execute(client, args.lockfile, args.emergency, args.test, args.open_pr)
            else:
                if args.interval and args.interval < 60:
                    raise ValueError("Reconcile interval must be at least 60 seconds")
                while True:
                    result = client.request("POST", "/v1/reconcile")
                    if not args.interval:
                        break
                    print(json.dumps(result, indent=2), flush=True)
                    time.sleep(args.interval)
        print(json.dumps(result, indent=2, default=str))
        if args.command == "gate" and not result["allowed"]:
            sys.exit(3)
        if args.command in {"scan", "reconcile"}:
            report = result.get("scan", result)
            if not report.get("complete", False):
                sys.exit(2)
    except (ValueError, RuntimeError, KeyError) as exc:
        parser.exit(1, f"sentinel: {exc}\n")
