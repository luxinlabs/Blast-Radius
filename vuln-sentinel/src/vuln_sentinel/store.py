"""Identical tracking model for SQLite demos and Snowflake deployment.

All mutations are transactional. Emergency IDs include the SBOM revision and evidence digest,
so re-scans are idempotent and changed evidence always needs a new review.
"""

import hashlib
import json
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

TABLES = {
    "clients": "client_id VARCHAR PRIMARY KEY, name VARCHAR NOT NULL, created_at VARCHAR NOT NULL",
    "client_sbom": "client_id VARCHAR NOT NULL, revision VARCHAR NOT NULL, payload VARCHAR NOT NULL, created_at VARCHAR NOT NULL, PRIMARY KEY(client_id, revision)",
    "emergencies": "emergency_id VARCHAR PRIMARY KEY, client_id VARCHAR NOT NULL, revision VARCHAR NOT NULL, fingerprint VARCHAR NOT NULL, status VARCHAR NOT NULL, payload VARCHAR NOT NULL, proposal VARCHAR, reviewer VARCHAR, reason VARCHAR, created_at VARCHAR NOT NULL, updated_at VARCHAR NOT NULL",
    "agent_events": "event_id VARCHAR PRIMARY KEY, client_id VARCHAR NOT NULL, actor VARCHAR NOT NULL, kind VARCHAR NOT NULL, payload VARCHAR NOT NULL, created_at VARCHAR NOT NULL",
    "threat_events": "event_id VARCHAR PRIMARY KEY, ecosystem VARCHAR NOT NULL, name VARCHAR NOT NULL, payload VARCHAR NOT NULL, created_at VARCHAR NOT NULL",
    "notifications": "notification_id VARCHAR PRIMARY KEY, client_id VARCHAR NOT NULL, kind VARCHAR NOT NULL, priority VARCHAR NOT NULL, status VARCHAR NOT NULL, payload VARCHAR NOT NULL, response VARCHAR, created_at VARCHAR NOT NULL, updated_at VARCHAR NOT NULL",
    "use_cases": "client_id VARCHAR PRIMARY KEY, payload VARCHAR NOT NULL, created_at VARCHAR NOT NULL",
}


def encode(obj):
    return json.dumps(obj, sort_keys=True, default=str, separators=(",", ":"))


def digest(obj):
    return hashlib.sha256(encode(obj).encode()).hexdigest()


def now():
    return datetime.now(timezone.utc).isoformat()


class Store:
    def __init__(self, settings):
        self.settings = settings
        self.lock = threading.RLock()
        if settings.backend == "demo":
            Path(settings.sqlite_path).parent.mkdir(parents=True, exist_ok=True)
            with self.transaction() as conn:
                for table, columns in TABLES.items():
                    conn.execute(f"CREATE TABLE IF NOT EXISTS {table} ({columns})")

    def connect(self):
        if self.settings.backend == "demo":
            conn = sqlite3.connect(self.settings.sqlite_path, timeout=30)
            conn.execute("PRAGMA journal_mode=WAL")
            return conn
        import snowflake.connector

        return snowflake.connector.connect(
            connection_name=self.settings.connection_name, paramstyle="qmark", autocommit=False
        )

    def table(self, name):
        assert name in TABLES
        return name if self.settings.backend == "demo" else f"VULN_SENTINEL_DB.SERVING.{name}"

    @contextmanager
    def transaction(self):
        with self.lock:
            conn = self.connect()
            try:
                if self.settings.backend == "demo":
                    conn.execute("BEGIN IMMEDIATE")
                else:
                    conn.cursor().execute("BEGIN")
                    # One enforced hybrid row serializes API and native-task writers.
                    lock = conn.cursor().execute(
                        "UPDATE VULN_SENTINEL_DB.SERVING.TRACKING_LOCK SET generation=generation+1 WHERE lock_id=1"
                    )
                    if lock.rowcount != 1:
                        raise RuntimeError("Tracking lock missing; apply migration 10 first")
                yield conn
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()

    def execute(self, conn, sql, params=()):
        cursor = conn.cursor()
        cursor.execute(sql, tuple(params))
        return cursor

    def rows(self, conn, sql, params=()):
        cursor = self.execute(conn, sql, params)
        names = [c[0].lower() for c in cursor.description]
        return [dict(zip(names, row)) for row in cursor.fetchall()]

    def event(self, conn, client, actor, kind, payload):
        self.execute(
            conn,
            f"INSERT INTO {self.table('agent_events')} VALUES (?,?,?,?,?,?)",
            [uuid.uuid4().hex, client, actor, kind, encode(payload), now()],
        )

    def create_client(self, client_id, name, actor):
        with self.transaction() as c:
            if self.rows(c, f"SELECT client_id FROM {self.table('clients')} WHERE client_id=?", [client_id]):
                return {"client_id": client_id, "created": False}
            self.execute(c, f"INSERT INTO {self.table('clients')} VALUES (?,?,?)", [client_id, name, now()])
            self.event(c, client_id, actor, "CLIENT_REGISTERED", {"name": name})
        return {"client_id": client_id, "created": True}

    def register_sbom(self, client, sbom, actor):
        payload = sbom.model_dump()
        revision = digest(payload)
        with self.transaction() as c:
            if not self.rows(c, f"SELECT client_id FROM {self.table('clients')} WHERE client_id=?", [client]):
                raise ValueError("Register this client with an admin token first")
            existing = self.rows(
                c,
                f"SELECT revision FROM {self.table('client_sbom')} WHERE client_id=? AND revision=?",
                [client, revision],
            )
            if existing:
                self.execute(
                    c,
                    f"UPDATE {self.table('client_sbom')} SET created_at=? WHERE client_id=? AND revision=?",
                    [now(), client, revision],
                )
            self.execute(
                c,
                f"UPDATE {self.table('emergencies')} SET status='SUPERSEDED',updated_at=? WHERE client_id=? AND revision<>? AND status<>'SUPERSEDED'",
                [now(), client, revision],
            )
            if not existing:
                self.execute(
                    c,
                    f"INSERT INTO {self.table('client_sbom')} VALUES (?,?,?,?)",
                    [client, revision, encode(payload), now()],
                )
                self.event(
                    c,
                    client,
                    actor,
                    "SBOM_REGISTERED",
                    {"revision": revision, "packages": len(sbom.packages)},
                )
        return {"client_id": client, "revision": revision, "packages": len(sbom.packages)}

    def set_use_cases(self, client, use_cases, actor):
        with self.transaction() as c:
            self.execute(c, f"DELETE FROM {self.table('use_cases')} WHERE client_id=?", [client])
            self.execute(
                c, f"INSERT INTO {self.table('use_cases')} VALUES (?,?,?)", [client, encode(use_cases), now()]
            )
            self.event(c, client, actor, "USE_CASES_MAPPED", {"use_cases": len(use_cases)})
        return {"client_id": client, "use_cases": len(use_cases)}

    def get_use_cases(self, client):
        with self.transaction() as c:
            rows = self.rows(c, f"SELECT payload FROM {self.table('use_cases')} WHERE client_id=?", [client])
        return json.loads(rows[0]["payload"]) if rows else []

    def add_threat(self, threat, actor):
        with self.transaction() as c:
            self.execute(
                c,
                f"INSERT INTO {self.table('threat_events')} VALUES (?,?,?,?,?)",
                [uuid.uuid4().hex, threat.ecosystem, threat.package, encode(threat.model_dump()), now()],
            )
            self.event(c, "fleet", actor, "THREAT_INJECTED", threat.model_dump())
        return {"injected": True, **threat.model_dump()}

    def threats(self, ecosystem, name):
        with self.transaction() as c:
            rows = self.rows(
                c,
                f"SELECT payload FROM {self.table('threat_events')} WHERE ecosystem=? AND name=?",
                [ecosystem, name],
            )
        return [json.loads(r["payload"]) for r in rows]

    def latest_sboms(self, client=None):
        with self.transaction() as c:
            where, args = (" WHERE client_id=?", [client]) if client else ("", [])
            rows = self.rows(
                c,
                f"SELECT * FROM {self.table('client_sbom')}{where} ORDER BY created_at DESC, revision DESC",
                args,
            )
        latest = {}
        for row in rows:
            latest.setdefault(row["client_id"], row)
        return list(latest.values())

    def assert_current(self, conn, client, revision):
        rows = self.rows(
            conn,
            f"SELECT revision FROM {self.table('client_sbom')} WHERE client_id=? ORDER BY created_at DESC,revision DESC LIMIT 1",
            [client],
        )
        if not rows or rows[0]["revision"] != revision:
            raise ValueError("Inventory changed during reconciliation; scan again")

    def open_emergency(self, client, revision, response, actor):
        # Exclude AI prose and timestamps: evidence changes, not model wording, reopen review.
        evidence = {k: v for k, v in response.items() if k not in {"sre_brief", "checked_at"}}
        fingerprint = digest(evidence)
        identity = digest([client, revision, fingerprint])
        with self.transaction() as c:
            self.assert_current(c, client, revision)
            old = self.rows(
                c,
                f"SELECT emergency_id,status FROM {self.table('emergencies')} WHERE emergency_id=?",
                [identity],
            )
            if old:
                if old[0]["status"] == "SUPERSEDED":
                    self.execute(
                        c,
                        f"UPDATE {self.table('emergencies')} SET status='OPEN',proposal=NULL,reviewer=NULL,reason=NULL,updated_at=? WHERE emergency_id=?",
                        [now(), identity],
                    )
                    self.execute(
                        c,
                        f"UPDATE {self.table('notifications')} SET status='NEW',response=NULL,updated_at=? WHERE notification_id=?",
                        [now(), identity],
                    )
                    self.event(c, client, actor, "EMERGENCY_REOPENED", {"emergency_id": identity})
                return identity
            pkg = response["package"]
            # Supersede only the same package + installed version on this revision.
            active = self.rows(
                c,
                f"SELECT emergency_id,payload FROM {self.table('emergencies')} WHERE client_id=? AND revision=? AND status<>'SUPERSEDED'",
                [client, revision],
            )
            for row in active:
                if json.loads(row["payload"])["package"] == pkg:
                    self.execute(
                        c,
                        f"UPDATE {self.table('emergencies')} SET status='SUPERSEDED',updated_at=? WHERE emergency_id=?",
                        [now(), row["emergency_id"]],
                    )
            self.execute(
                c,
                f"INSERT INTO {self.table('emergencies')} VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                [
                    identity,
                    client,
                    revision,
                    fingerprint,
                    "OPEN",
                    encode(response),
                    None,
                    None,
                    None,
                    now(),
                    now(),
                ],
            )
            self.notify(c, identity, client, "THREAT", response.get("priority", "P3"), response)
            self.event(c, client, actor, "EMERGENCY_OPENED", {"emergency_id": identity})
        return identity

    def notify(self, conn, identity, client, kind, priority, payload):
        """Add to the notification center once; the identity makes repeats idempotent."""
        if not self.rows(
            conn, f"SELECT 1 AS x FROM {self.table('notifications')} WHERE notification_id=?", [identity]
        ):
            self.execute(
                conn,
                f"INSERT INTO {self.table('notifications')} VALUES (?,?,?,?,?,?,?,?,?)",
                [identity, client, kind, priority, "NEW", encode(payload), None, now(), now()],
            )

    def notifications(self, client=None, status=None):
        with self.transaction() as c:
            clauses = [("client_id=?", client), ("status=?", status)]
            where = " AND ".join(sql for sql, value in clauses if value)
            rows = self.rows(
                c,
                f"SELECT * FROM {self.table('notifications')}{' WHERE ' + where if where else ''} ORDER BY created_at DESC",
                [value for _, value in clauses if value],
            )
        for row in rows:
            row["payload"] = json.loads(row["payload"])
            row["response"] = json.loads(row["response"]) if row["response"] else None
        return rows

    def respond_notification(self, identity, response, actor):
        with self.transaction() as c:
            rows = self.rows(
                c,
                f"SELECT client_id,kind FROM {self.table('notifications')} WHERE notification_id=?",
                [identity],
            )
            if not rows:
                raise ValueError("Unknown notification")
            client = rows[0]["client_id"]
            if rows[0]["kind"] == "THREAT":
                live = self.rows(
                    c,
                    f"SELECT 1 AS x FROM {self.table('emergencies')} WHERE emergency_id=? AND status<>'SUPERSEDED'",
                    [identity],
                )
                if not live:
                    raise ValueError("Notification is stale; its incident was superseded")
            cursor = self.execute(
                c,
                f"UPDATE {self.table('notifications')} SET status='RESPONDED',response=?,updated_at=? WHERE notification_id=? AND status='NEW'",
                [encode(response.model_dump()), now(), identity],
            )
            if cursor.rowcount != 1:
                raise ValueError("Notification is not awaiting a response")
            self.event(
                c, client, actor, "AGENT_RESPONDED", {"notification_id": identity, **response.model_dump()}
            )
        return {"status": "RESPONDED", "requires_human_approval": True}

    def get_notification(self, identity):
        with self.transaction() as c:
            rows = self.rows(
                c, f"SELECT client_id FROM {self.table('notifications')} WHERE notification_id=?", [identity]
            )
        if not rows:
            raise ValueError("Unknown notification")
        return rows[0]

    def list_emergencies(self, client=None):
        with self.transaction() as c:
            where, args = (" WHERE client_id=?", [client]) if client else ("", [])
            rows = self.rows(
                c, f"SELECT * FROM {self.table('emergencies')}{where} ORDER BY created_at DESC", args
            )
        for row in rows:
            row["payload"] = json.loads(row["payload"])
            row["proposal"] = json.loads(row["proposal"]) if row["proposal"] else None
        return rows

    def get_emergency(self, identity):
        with self.transaction() as c:
            rows = self.rows(c, f"SELECT * FROM {self.table('emergencies')} WHERE emergency_id=?", [identity])
        if not rows:
            raise ValueError("Unknown emergency")
        row = rows[0]
        row["payload"] = json.loads(row["payload"])
        return row

    def propose(self, client, proposal, actor):
        with self.transaction() as c:
            cursor = self.execute(
                c,
                f"UPDATE {self.table('emergencies')} SET status='PROPOSED',proposal=?,reviewer=NULL,reason=NULL,updated_at=? WHERE emergency_id=? AND client_id=? AND status IN ('OPEN','REJECTED')",
                [
                    encode({**proposal.model_dump(), "submitted_by": actor}),
                    now(),
                    proposal.emergency_id,
                    client,
                ],
            )
            if cursor.rowcount != 1:
                raise ValueError("Emergency is not open for a proposal")
            self.event(c, client, actor, "FIX_PROPOSED", proposal.model_dump())
        return {"status": "PROPOSED", "requires_human_approval": True}

    def review(self, identity, review, actor, client):
        with self.transaction() as c:
            self.assert_current(c, client, review.revision)
            cursor = self.execute(
                c,
                f"UPDATE {self.table('emergencies')} SET status=?,reviewer=?,reason=?,updated_at=? WHERE emergency_id=? AND client_id=? AND revision=? AND status='PROPOSED'",
                [review.decision, actor, review.reason, now(), identity, client, review.revision],
            )
            if cursor.rowcount != 1:
                raise ValueError("Review requires a current, proposed emergency and matching revision")
            self.event(c, client, actor, "HUMAN_REVIEW", {"emergency_id": identity, **review.model_dump()})
        return {"status": review.decision, "merged": False, "deployed": False}

    def report(self, client, report, actor):
        with self.transaction() as c:
            self.event(c, client, actor, "SCAN_REPORTED", report.model_dump())
            if report.findings:
                self.notify(
                    c,
                    digest([client, "IOC_MATCH", report.model_dump()]),
                    client,
                    "IOC_MATCH",
                    "P1",
                    report.model_dump(),
                )
        return {"accepted": True, "findings": len(report.findings)}

    def events(self, client):
        with self.transaction() as c:
            return self.rows(
                c,
                f"SELECT * FROM {self.table('agent_events')} WHERE client_id=? ORDER BY created_at DESC LIMIT 200",
                [client],
            )

    def retire_package(self, client, revision, package, keep_id, actor):
        with self.transaction() as c:
            self.assert_current(c, client, revision)
            rows = self.rows(
                c,
                f"SELECT emergency_id,payload FROM {self.table('emergencies')} WHERE client_id=? AND revision=? AND status<>'SUPERSEDED'",
                [client, revision],
            )
            for row in rows:
                prior = json.loads(row["payload"])["package"]

                def key(p):
                    return p["ecosystem"], p["name"], p["version"]

                current = package.model_dump()
                if row["emergency_id"] != keep_id and key(prior) == key(current):
                    self.execute(
                        c,
                        f"UPDATE {self.table('emergencies')} SET status='SUPERSEDED',updated_at=? WHERE emergency_id=?",
                        [now(), row["emergency_id"]],
                    )
                    self.event(
                        c,
                        client,
                        actor,
                        "EMERGENCY_SUPERSEDED",
                        {"emergency_id": row["emergency_id"], "reason": "new response evidence"},
                    )
