"""The Anzen server: OTLP ingest + rule scanning + read API.

Ingest speaks OTLP/HTTP in both encodings:
- `POST /v1/logs` (primary) — Claude Code / Cowork native telemetry events.
- `POST /v1/metrics` — accepted for endpoint liveness; aggregates are NOT
  accrued from metrics (cost/tokens come from `api_request` events, which are
  idempotent per record — cumulative metric sums would double count).

Auth: set `ANZEN_API_KEYS` (comma-separated) to require
`Authorization: Bearer <key>` on every route except /healthz. Unset = open
(local development).
"""

from __future__ import annotations

import json
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from google.protobuf.json_format import MessageToDict
from google.protobuf.message import DecodeError
from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import (
    ExportLogsServiceRequest,
)
from opentelemetry.proto.collector.metrics.v1.metrics_service_pb2 import (
    ExportMetricsServiceRequest,
)
from pydantic import BaseModel

from ..report import build_report
from ..rules import Rule, match_action
from ..store import Action, ActionType, Store
from .normalize import Decision, iter_log_records, normalize_log_record


def _decode(body: bytes, content_type: str, message_cls) -> dict[str, Any]:
    if "json" in content_type:
        return json.loads(body)
    message = message_cls()
    message.ParseFromString(body)
    return MessageToDict(message)


def _ingest_decision(store: Store, decision: Decision) -> None:
    """Merge onto the matching tool action, or keep as a standalone record."""
    if store.apply_decision(
        decision.session_id, decision.tool_use_id, decision.decision, decision.source
    ):
        return
    store.insert_action(Action(
        session_id=decision.session_id,
        span_id=f"tool_decision:{decision.tool_use_id}",
        timestamp=0.0,
        action_type=ActionType.permission_decision,
        name="tool_decision",
        tool_use_id=decision.tool_use_id,
        decision=decision.decision,
        decision_source=decision.source,
    ))


def ingest_logs(store: Store, payload: dict[str, Any], rules: list[Rule]) -> set[str]:
    """Normalize and persist one ExportLogsServiceRequest dict. Returns touched session ids."""
    touched: set[str] = set()
    for record, resource_attrs in iter_log_records(payload):
        n = normalize_log_record(record, resource_attrs)
        # session row must exist before the action (FK); token/cost deltas
        # only accrue on the first delivery of a record.
        delta = (n.session.input_tokens, n.session.output_tokens, n.session.cost_usd)
        n.session.input_tokens = n.session.output_tokens = 0
        n.session.cost_usd = 0.0
        store.upsert_session(n.session)
        touched.add(n.session.id)
        if n.endpoint is not None:
            store.upsert_endpoint(n.endpoint)
        for item in n.inventory:
            store.upsert_inventory_item(item)
        if n.decision is not None:
            _ingest_decision(store, n.decision)
        if n.action is not None:
            inserted = store.insert_action(n.action)
            if inserted is not None:
                if delta != (0, 0, 0.0):
                    n.session.input_tokens, n.session.output_tokens, n.session.cost_usd = delta
                    store.upsert_session(n.session)
                n.action.id = inserted
                store.add_findings(match_action(n.action, rules))
    return touched


class ApprovalBody(BaseModel):
    approved: bool | None


def create_app(
    store: Store, rules: list[Rule], api_keys: set[str] | None = None
) -> FastAPI:
    app = FastAPI(title="anzen", docs_url=None, redoc_url=None)

    async def require_auth(request: Request) -> None:
        if not api_keys:
            return
        header = request.headers.get("Authorization", "")
        token = header.removeprefix("Bearer ").strip()
        if token not in api_keys:
            raise HTTPException(status_code=401, detail="invalid or missing API key")

    authed = Depends(require_auth)

    # -- ingest ------------------------------------------------------------

    @app.post("/v1/logs", dependencies=[authed])
    async def v1_logs(request: Request) -> Response:
        body = await request.body()
        try:
            payload = _decode(
                body, request.headers.get("Content-Type", ""), ExportLogsServiceRequest
            )
            ingest_logs(store, payload, rules)
        except (json.JSONDecodeError, DecodeError, ValueError, KeyError, TypeError) as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        return Response(content=b"{}", media_type="application/json")

    @app.post("/v1/metrics", dependencies=[authed])
    async def v1_metrics(request: Request) -> Response:
        body = await request.body()
        try:
            _decode(body, request.headers.get("Content-Type", ""), ExportMetricsServiceRequest)
        except (json.JSONDecodeError, DecodeError, ValueError, KeyError, TypeError) as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        # accepted so exporters don't retry-loop; aggregates come from events
        return Response(content=b"{}", media_type="application/json")

    # -- read API ----------------------------------------------------------

    @app.get("/api/stats", dependencies=[authed])
    def api_stats() -> dict:
        return store.stats()

    @app.get("/api/endpoints", dependencies=[authed])
    def api_endpoints() -> list:
        return store.list_endpoints()

    @app.get("/api/inventory", dependencies=[authed])
    def api_inventory(kind: str | None = None) -> list:
        return store.list_inventory(kind)

    @app.patch("/api/inventory/{item_id}", dependencies=[authed])
    def api_inventory_review(item_id: int, body: ApprovalBody) -> dict:
        store.set_inventory_approval(item_id, body.approved)
        return {"id": item_id, "approved": body.approved}

    @app.get("/api/sessions", dependencies=[authed])
    def api_sessions() -> list:
        return store.list_sessions()

    @app.get("/api/sessions/{session_id}", dependencies=[authed])
    def api_session(session_id: str) -> dict:
        session = store.get_session(session_id)
        if session is None:
            raise HTTPException(status_code=404, detail=f"no session matching {session_id!r}")
        return {
            "session": session,
            "actions": store.get_actions(session.id),
            "findings": store.get_findings(session.id),
        }

    @app.get("/api/sessions/{session_id}/report.md", dependencies=[authed])
    def api_report(session_id: str) -> Response:
        try:
            _, markdown = build_report(store, session_id)
        except KeyError:
            raise HTTPException(status_code=404, detail=f"no session matching {session_id!r}")
        return Response(content=markdown, media_type="text/markdown")

    @app.get("/api/findings", dependencies=[authed])
    def api_findings(severity: str | None = None, since: float | None = None) -> list:
        return store.list_findings(severity=severity, since=since)

    @app.get("/healthz")
    def healthz() -> dict:
        return {"status": "ok"}

    return app
