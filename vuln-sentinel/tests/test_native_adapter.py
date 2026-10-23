"""Run the native Snowpark adapter with a local SQL engine and mocked RESPOND boundary."""

import json
import sqlite3
from types import SimpleNamespace

from vuln_sentinel.snowflake_runtime import reconcile


class Row:
    def __init__(self, names, values):
        self.names, self.values = names, values

    def as_dict(self):
        return dict(zip(self.names, self.values))

    def __iter__(self):
        return iter(self.values)

    def __getitem__(self, index):
        return self.values[index]


class Session:
    def __init__(self, path, backend):
        self.conn = sqlite3.connect(path, isolation_level=None)
        self.conn.execute("CREATE TABLE tracking_lock (lock_id INTEGER PRIMARY KEY,generation INTEGER)")
        self.conn.execute("INSERT INTO tracking_lock VALUES (1,0)")
        self.conn.execute("CREATE TABLE signal_feed (kind,indicator,score,source,observed_at,expires_at)")
        self.backend = backend

    def sql(self, sql, params=None):
        params = params or []
        if sql.startswith("CALL "):
            result = self.backend.respond(*params)
            return self.frame(["result"], [(json.dumps(result),)])
        sql = sql.replace("VULN_SENTINEL_DB.SERVING.", "").replace("VULN_SENTINEL_DB.INTEL.", "")
        sql = sql.replace("CURRENT_TIMESTAMP()", "CURRENT_TIMESTAMP")
        cursor = self.conn.execute(sql, params)
        if cursor.description:
            return self.frame([c[0] for c in cursor.description], cursor.fetchall())
        return self.frame(["count"], [(max(cursor.rowcount, 0),)])

    def frame(self, names, values):
        return SimpleNamespace(
            collect=lambda: [Row(names, v) for v in values],
            schema=SimpleNamespace(fields=[SimpleNamespace(name=n) for n in names]),
        )


def test_native_task_reuses_response_tracking_and_is_idempotent(stack, incident):
    _, _, service = stack
    session = Session(service.store.settings.sqlite_path, service.backend)
    try:
        first = reconcile(session)
        second = reconcile(session)
        assert first["complete"] and second["complete"]
        assert first["emergency_ids"] == second["emergency_ids"] == [incident["emergency_id"]]
        assert len(service.store.list_emergencies("app")) == 1
    finally:
        session.conn.close()
