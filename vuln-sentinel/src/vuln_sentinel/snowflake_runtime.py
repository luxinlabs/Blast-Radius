"""Native task adapter. Uses the same reconciliation and tracking code as the API."""

from .backend import SnowflakeBackend
from .config import Settings
from .service import Service
from .store import Store


class Cursor:
    def __init__(self, session):
        self.session = session
        self.description, self.result, self.rowcount = [], [], -1

    def execute(self, sql, args=()):
        frame = self.session.sql(sql, params=list(args))
        rows = frame.collect()
        names = list(rows[0].as_dict()) if rows else [field.name for field in frame.schema.fields]
        self.description = [(name,) for name in names]
        self.result = [tuple(row) for row in rows]
        if sql.lstrip().upper().startswith(("UPDATE", "INSERT", "DELETE")):
            self.rowcount = int(rows[0][0]) if rows else 0
        return self

    def fetchall(self):
        return self.result


class Connection:
    def __init__(self, session):
        self.session = session

    def cursor(self):
        return Cursor(self.session)

    def commit(self):
        self.session.sql("COMMIT").collect()

    def rollback(self):
        self.session.sql("ROLLBACK").collect()

    def close(self):
        pass


class NativeStore(Store):
    def __init__(self, settings, session):
        self.session = session
        super().__init__(settings)

    def connect(self):
        return Connection(self.session)


class NativeBackend(SnowflakeBackend):
    def __init__(self, settings, session):
        self.session = session
        super().__init__(settings)

    def query(self, sql, args=()):
        return [
            {k.lower(): v for k, v in row.as_dict().items()}
            for row in self.session.sql(sql, params=list(args)).collect()
        ]


def reconcile(session):
    settings = Settings(backend="snowflake")
    service = Service(NativeBackend(settings, session), NativeStore(settings, session))
    return service.reconcile("snowflake:TASK_MATCH_CLIENTS")
