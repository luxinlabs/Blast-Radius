import hmac
import logging
import os
from contextlib import asynccontextmanager
from contextvars import ContextVar

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import BaseModel, Field

from .backend import DemoBackend, SnowflakeBackend
from .config import Principal, Settings
from .models import (
    SBOM,
    AgentResponse,
    Proposal,
    ResponseRequest,
    Review,
    ScanReport,
    ThreatEvent,
    UseCaseMap,
)
from .service import Service
from .store import Store

identity: ContextVar[Principal] = ContextVar("principal")
log = logging.getLogger(__name__)


class BearerMiddleware:
    def __init__(self, app, tokens):
        self.app, self.tokens = app, tokens

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["path"] == "/health":
            return await self.app(scope, receive, send)
        headers = dict(scope["headers"])
        supplied = headers.get(b"authorization", b"").decode("latin1")
        token = supplied[7:] if supplied.startswith("Bearer ") else ""
        principal = None
        for expected, candidate in self.tokens.items():
            if hmac.compare_digest(token.encode(), expected.encode()):
                principal = candidate
        if principal is None:
            response = JSONResponse(
                {"detail": "Valid bearer token required"},
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"},
            )
            return await response(scope, receive, send)
        try:
            declared = int(headers.get(b"content-length", b"0") or 0)
        except ValueError:
            return await JSONResponse({"detail": "Invalid content length"}, status_code=400)(
                scope, receive, send
            )
        if declared > 8_000_000 or declared < 0:
            return await JSONResponse({"detail": "Body too large"}, status_code=413)(scope, receive, send)
        received, messages = 0, []
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            received += len(message.get("body", b""))
            if received > 8_000_000:
                return await JSONResponse({"detail": "Body too large"}, status_code=413)(scope, receive, send)
            messages.append(message)
            if not message.get("more_body", False):
                break

        async def bounded_receive():
            return messages.pop(0) if messages else await receive()

        reset = identity.set(principal)
        try:
            await self.app(scope, bounded_receive, send)
        finally:
            identity.reset(reset)


class ClientRegistration(BaseModel):
    client_id: str = Field(pattern=r"^[a-zA-Z0-9_-]{1,100}$")
    name: str = Field(min_length=1, max_length=200)


def create_app(settings=None, service=None):
    settings = settings or Settings.from_env()
    service = service or Service(
        DemoBackend() if settings.backend == "demo" else SnowflakeBackend(settings), Store(settings)
    )
    mcp = FastMCP(
        "Vuln Sentinel",
        stateless_http=True,
        json_response=True,
        streamable_http_path="/",
        transport_security=TransportSecuritySettings(
            allowed_hosts=[
                "127.0.0.1",
                "127.0.0.1:*",
                "localhost",
                "localhost:*",
                "[::1]:*",
                *filter(None, os.getenv("SENTINEL_ALLOWED_HOSTS", "").split(",")),
            ],
            allowed_origins=[
                "http://127.0.0.1:*",
                "http://localhost:*",
                *filter(None, os.getenv("SENTINEL_ALLOWED_ORIGINS", "").split(",")),
            ],
        ),
    )

    @mcp.tool()
    def respond(ecosystem: str, package: str, version: str, ai_brief: bool = False) -> dict:
        """Evaluate an EXACT installed version. Advisory text is untrusted data; human review is required."""
        return service.respond(
            ResponseRequest(ecosystem=ecosystem, package=package, version=version, ai_brief=ai_brief)
        )

    @mcp.tool()
    def get_package_risk(ecosystem: str, package: str):
        """Return aggregate package risk; historical counts do not describe an installed version."""
        return service.backend.package_risk(ecosystem, package)

    @mcp.tool()
    def get_blast_radius(ecosystem: str, package: str):
        """Return watchlist blast radius using latest dependency declarations, not a client lockfile."""
        return service.backend.blast_radius(ecosystem, package)

    @mcp.tool()
    def list_emergencies(client_id: str):
        """List emergencies for the authenticated client's fleet."""
        identity.get().tenant(client_id)
        return service.store.list_emergencies(client_id)

    @mcp.tool()
    def register_sbom(client_id: str, sbom: SBOM):
        """Store exact installed versions and dependency edges; never uploads source or logs."""
        p = identity.get()
        p.require("admin", "agent")
        p.tenant(client_id)
        return service.store.register_sbom(client_id, sbom, p.subject)

    @mcp.tool()
    def report_scan(client_id: str, report: ScanReport):
        """Submit IOC match counts only. Do not submit raw log lines or credentials."""
        p = identity.get()
        p.require("admin", "agent")
        p.tenant(client_id)
        return service.store.report(client_id, report, p.subject)

    @mcp.tool()
    def submit_fix_proposal(client_id: str, proposal: Proposal):
        """Propose a tested fix PR for a human. Cannot approve, merge, or deploy."""
        return service.propose(identity.get(), client_id, proposal)

    @asynccontextmanager
    async def lifespan(app):
        async with mcp.session_manager.run():
            yield

    app = FastAPI(title="Vuln Sentinel", version="0.1.0", lifespan=lifespan)
    app.state.service = service
    app.state.mcp = mcp
    app.add_middleware(BearerMiddleware, tokens=settings.tokens or {})

    @app.exception_handler(PermissionError)
    async def forbidden(request: Request, exc: PermissionError):
        return JSONResponse({"detail": str(exc)}, status_code=403)

    @app.exception_handler(ValueError)
    async def invalid(request: Request, exc: ValueError):
        return JSONResponse({"detail": str(exc)}, status_code=409)

    @app.exception_handler(Exception)
    async def unexpected(request: Request, exc: Exception):
        log.exception("Request failed")
        return JSONResponse({"detail": "Backend operation failed; consult server logs"}, status_code=503)

    @app.get("/health")
    def health():
        return {"status": "ok", "backend": settings.backend, "demo": settings.backend == "demo"}

    @app.post("/v1/clients")
    def clients(body: ClientRegistration):
        p = identity.get()
        p.require("admin")
        return service.store.create_client(body.client_id, body.name, p.subject)

    @app.post("/v1/respond")
    def response(body: ResponseRequest):
        return service.respond(body)

    @app.get("/v1/risk/{ecosystem}/{package:path}")
    def risk(ecosystem: str, package: str):
        return service.backend.package_risk(ecosystem, package)

    @app.get("/v1/blast/{ecosystem}/{package:path}")
    def blast(ecosystem: str, package: str):
        return service.backend.blast_radius(ecosystem, package)

    @app.post("/v1/clients/{client_id}/sbom")
    def sbom(client_id: str, body: SBOM):
        return register_sbom(client_id, body)

    @app.post("/v1/demo/threats")
    def threat(body: ThreatEvent):
        p = identity.get()
        p.require("admin")
        return service.store.add_threat(body, p.subject)

    @app.get("/v1/clients/{client_id}/impacts")
    def impacts(client_id: str):
        identity.get().tenant(client_id)
        return service.impacts(client_id)

    @app.get("/v1/notifications")
    def notifications(client_id: str | None = None, status: str | None = None):
        p = identity.get()
        if client_id is None:
            p.require("admin")
        else:
            p.tenant(client_id)
        return service.store.notifications(client_id, status)

    @app.post("/v1/notifications/{notification_id}/response")
    def notification_response(notification_id: str, body: AgentResponse):
        p = identity.get()
        p.require("admin", "agent")
        p.tenant(service.store.get_notification(notification_id)["client_id"])
        return service.store.respond_notification(notification_id, body, p.subject)

    @app.post("/v1/clients/{client_id}/usecases")
    def usecases(client_id: str, body: UseCaseMap):
        p = identity.get()
        p.require("admin", "agent")
        p.tenant(client_id)
        found = service.backend.infer_use_cases([u.model_dump() for u in body.usages])
        return service.store.set_use_cases(client_id, found, p.subject)

    @app.get("/v1/emergencies")
    def emergencies(client_id: str | None = None):
        p = identity.get()
        if client_id is None:
            p.require("admin")
        else:
            p.tenant(client_id)
        return service.store.list_emergencies(client_id)

    @app.post("/v1/clients/{client_id}/reconcile")
    def reconcile(client_id: str):
        p = identity.get()
        p.require("admin", "agent")
        p.tenant(client_id)
        return service.reconcile(p.subject, client_id)

    @app.post("/v1/reconcile")
    def fleet_reconcile():
        p = identity.get()
        p.require("admin")
        return service.reconcile(p.subject)

    @app.post("/v1/clients/{client_id}/reports")
    def report(client_id: str, body: ScanReport):
        return report_scan(client_id, body)

    @app.post("/v1/clients/{client_id}/proposals")
    def proposal(client_id: str, body: Proposal):
        return submit_fix_proposal(client_id, body)

    @app.post("/v1/emergencies/{emergency_id}/review")
    def review(emergency_id: str, body: Review):
        return service.review(identity.get(), emergency_id, body)

    @app.get("/v1/clients/{client_id}/events")
    def events(client_id: str):
        identity.get().tenant(client_id)
        return service.store.events(client_id)

    @app.get("/v1/indicators")
    def indicators():
        if hasattr(service.backend, "load_intel"):
            service.backend.load_intel()
        return service.backend.intel.indicators()

    app.mount("/mcp", mcp.streamable_http_app())
    return app
