import shlex
import subprocess
import sys
from pathlib import Path

import pytest
from conftest import proposal
from streamlit.testing.v1 import AppTest

import vuln_sentinel.client as client_module
from vuln_sentinel.client import Client
from vuln_sentinel.lockfiles import parse_lockfile


def git(path, *args):
    return subprocess.run(["git", *args], cwd=path, capture_output=True, text=True, check=True).stdout.strip()


def prepare_project(tmp_path, call, failing=False):
    project = tmp_path / "repo"
    project.mkdir()
    lock = project / "requirements.txt"
    lock.write_text("litellm==1.107.0\n")
    (project / "check.py").write_text(
        "from pathlib import Path\nassert Path('requirements.txt').read_text().strip() == 'litellm==1.106.2'\n"
        + ("raise SystemExit(1)\n" if failing else "")
    )
    git(project, "init", "-b", "main")
    git(project, "config", "user.name", "Local Test")
    git(project, "config", "user.email", "local-test@example.invalid")
    git(project, "config", "core.hooksPath", "/dev/null")
    git(project, "add", ".")
    git(project, "commit", "-m", "test fixture")
    call("POST", "/v1/clients/app/sbom", parse_lockfile(lock).model_dump(), "agent").raise_for_status()
    scan = call("POST", "/v1/clients/app/reconcile", role="agent").json()
    emergency = scan["emergency_ids"][0]
    client = Client("http://127.0.0.1:8000", "test", "app")

    def request(method, path, body=None):
        result = call(method, path, body, "agent")
        result.raise_for_status()
        return result.json()

    client.request = request
    return project, lock, emergency, client


def test_fix_creates_tested_isolated_commit_without_push(stack, tmp_path):
    _, call, _ = stack
    root, lock, emergency, client = prepare_project(tmp_path, call)
    original_head = git(root, "rev-parse", "HEAD")
    result = client.fix(lock, emergency, f"{shlex.quote(sys.executable)} check.py")
    worktree = Path(result["worktree"])
    assert result["test_passed"]
    assert lock.read_text() == "litellm==1.107.0\n"
    assert (worktree / "requirements.txt").read_text() == "litellm==1.106.2\n"
    assert git(root, "rev-parse", "HEAD") == original_head
    assert git(root, "branch", "--show-current") == "main"
    assert git(worktree, "rev-parse", "HEAD") != original_head
    assert "human approval" in Path(result["pr_body"]).read_text()
    assert git(root, "status", "--porcelain") == ""
    assert "pr_url" not in result
    assert call("GET", "/v1/emergencies?client_id=app").json()[0]["status"] == "OPEN"


def test_failed_tests_prevent_commit_and_proposal(stack, tmp_path):
    _, call, _ = stack
    root, lock, emergency, client = prepare_project(tmp_path, call, failing=True)
    original = git(root, "rev-parse", "HEAD")
    with pytest.raises(RuntimeError, match="Fix stopped"):
        client.fix(lock, emergency, f"{shlex.quote(sys.executable)} check.py", open_pr=True)
    assert git(root, "rev-parse", f"sentinel/{emergency[:16]}") == original
    assert call("GET", "/v1/emergencies?client_id=app").json()[0]["status"] == "OPEN"


def test_draft_pr_submission_boundary(stack, tmp_path, monkeypatch):
    _, call, _ = stack
    root, lock, emergency, client = prepare_project(tmp_path, call)
    git(root, "remote", "add", "origin", "https://github.com/example/app.git")
    real_run = client_module.run
    external = []

    def run(args, cwd, timeout=120):
        if args[:2] == ["git", "push"] or args[:3] == ["gh", "pr", "create"]:
            external.append(args)
            return subprocess.CompletedProcess(
                args, 0, "https://github.com/example/app/pull/42\n" if args[0] == "gh" else "", ""
            )
        return real_run(args, cwd, timeout)

    monkeypatch.setattr(client_module, "run", run)
    result = client.fix(lock, emergency, f"{shlex.quote(sys.executable)} check.py", open_pr=True)
    assert result["pr_url"].endswith("/pull/42")
    assert "--draft" in external[1] and "--body-file" in external[1]
    assert all("merge" not in command for command in external)
    assert call("GET", "/v1/emergencies?client_id=app").json()[0]["status"] == "PROPOSED"


def test_changed_local_inventory_prevents_fix(stack, tmp_path):
    _, call, _ = stack
    _, lock, emergency, client = prepare_project(tmp_path, call)
    lock.write_text("litellm==1.106.2\n")
    with pytest.raises(ValueError, match="changed since scan"):
        client.fix(lock, emergency, "pytest")


def test_dashboard_login_and_review(stack, incident, monkeypatch):
    _, call, _ = stack
    call("POST", "/v1/clients/app/proposals", proposal(incident), "agent").raise_for_status()

    def request(self, method, path, body=None):
        result = call(method, path, body, "reviewer")
        result.raise_for_status()
        return result.json()

    monkeypatch.setattr(Client, "request", request)
    dashboard = Path(__file__).resolve().parents[1] / "src" / "vuln_sentinel" / "dashboard.py"
    app = AppTest.from_file(str(dashboard), default_timeout=20).run()
    assert not app.exception
    assert "Enter your reviewer token" in app.info[0].value
    app.text_input[0].set_value("local-reviewer-token")
    app.text_input[1].set_value("app")
    app.run()
    assert not app.exception, [e.message for e in app.exception]
    assert len(app.metric) == 4
    assert "Notification center" in [h.value for h in app.subheader]
    notes = next(area for area in app.text_area if area.label == "Review notes (required)")
    notes.set_value("Reviewed fixture evidence and passing tests")
    next(button for button in app.button if button.label == "Record review").click().run()
    assert not app.exception
    state = call("GET", "/v1/emergencies?client_id=app").json()
    assert state[0]["status"] == "APPROVED"
