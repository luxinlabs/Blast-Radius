import json
import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Principal:
    subject: str
    role: str
    client_id: str | None = None

    def require(self, *roles):
        if self.role not in roles:
            raise PermissionError("Insufficient role")

    def tenant(self, client_id):
        if self.role != "admin" and self.client_id != client_id:
            raise PermissionError("Client scope mismatch")


@dataclass
class Settings:
    backend: str = "demo"
    sqlite_path: str = ".sentinel/state.sqlite"
    connection_name: str = "vuln_sentinel"
    tokens: dict[str, Principal] | None = None

    @classmethod
    def from_env(cls):
        raw = json.loads(os.getenv("SENTINEL_TOKENS", "{}"))
        tokens = {token: Principal(**value) for token, value in raw.items()}
        if not tokens or any(len(t) < 24 for t in tokens):
            raise ValueError("SENTINEL_TOKENS must contain bearer tokens of at least 24 characters")
        for p in tokens.values():
            if p.role not in {"admin", "reviewer", "agent", "reader"}:
                raise ValueError("Unknown principal role")
            if p.role != "admin" and not p.client_id:
                raise ValueError("Non-admin tokens require a client_id")
        backend = os.getenv("SENTINEL_BACKEND", "demo")
        if backend not in {"demo", "snowflake"}:
            raise ValueError("SENTINEL_BACKEND must be demo or snowflake")
        return cls(
            backend,
            os.getenv("SENTINEL_SQLITE_PATH", ".sentinel/state.sqlite"),
            os.getenv("SNOWFLAKE_CONNECTION_NAME", "vuln_sentinel"),
            tokens,
        )
