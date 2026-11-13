"""OpenAI-compatible proxy. Point any OpenAI SDK at http://localhost:8000/v1 and PII never leaves."""
from __future__ import annotations

import hashlib
import json
import os
import time
from typing import Any

import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse

STATIC = os.path.join(os.path.dirname(__file__), "static")

from .audit import AuditLog
from .detect import build_detector
from .policy import Policy
from .pseudonym import Pseudonymizer, summarize
from .restore import StreamRestorer, restore
from .vault import Vault


def _session_id(messages: list[dict], explicit: str | None) -> str:
    """Explicit X-Veil-Session header, else derived from the first user message so every turn of
    the same chat reuses the same pseudonyms."""
    if explicit:
        return explicit
    first = next((m for m in messages if m.get("role") == "user"), messages[0] if messages else {})
    content = first.get("content", "")
    if not isinstance(content, str):
        content = json.dumps(content, sort_keys=True)
    return "auto-" + hashlib.sha256(content.encode()).hexdigest()[:16]


def _mask_content(pz: Pseudonymizer, session: str, content: Any, counts: dict[str, int]) -> Any:
    def add(reps):
        for k, v in summarize(reps).items():
            counts[k] = counts.get(k, 0) + v

    if isinstance(content, str):
        masked, reps = pz.mask(session, content)
        add(reps)
        return masked
    if isinstance(content, list):  # multimodal / content-part format
        parts = []
        for part in content:
            if isinstance(part, dict) and part.get("type") == "text":
                masked, reps = pz.mask(session, part.get("text", ""))
                add(reps)
                part = {**part, "text": masked}
            parts.append(part)
        return parts
    return content


def create_app(
    upstream_base_url: str | None = None,
    upstream_api_key: str | None = None,
    pseudonymizer: Pseudonymizer | None = None,
    audit: AuditLog | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> FastAPI:
    base = (upstream_base_url or os.getenv("VEIL_UPSTREAM_BASE_URL", "http://localhost:11434/v1")).rstrip("/")
    key = upstream_api_key if upstream_api_key is not None else os.getenv("VEIL_UPSTREAM_API_KEY", "")
    db_path = os.getenv("VEIL_DB_PATH", "veil.db")
    pz = pseudonymizer or Pseudonymizer(build_detector(), Vault(db_path), Policy.load())
    log = audit or AuditLog(db_path)
    app = FastAPI(title="Veil", version="0.1.0")

    def client() -> httpx.AsyncClient:
        headers = {"Authorization": f"Bearer {key}"} if key else {}
        return httpx.AsyncClient(base_url=base, headers=headers, timeout=120, transport=transport)

    @app.get("/")
    async def ui():
        return FileResponse(os.path.join(STATIC, "index.html"))

    @app.get("/ui/status")
    async def ui_status():
        return {"detectors": pz.detector.name, "upstream": base,
                "model": os.getenv("VEIL_MODEL", ""), "has_key": bool(key),
                "masked_types": sorted(pz.policy.mask), "audit": log.verify()}

    @app.get("/healthz")
    async def healthz():
        return {"ok": True, "detectors": pz.detector.name, "upstream": base}

    @app.get("/v1/models")
    async def models():
        async with client() as c:
            r = await c.get("/models")
            return JSONResponse(r.json(), status_code=r.status_code)

    @app.post("/v1/chat/completions")
    async def chat(request: Request, x_veil_session: str | None = Header(default=None)):
        body = await request.json()
        messages = body.get("messages") or []
        if not messages:
            raise HTTPException(400, "messages required")
        session = _session_id(messages, x_veil_session)
        t0 = time.perf_counter()
        counts: dict[str, int] = {}
        body["messages"] = [{**m, "content": _mask_content(pz, session, m.get("content"), counts)} for m in messages]
        mask_ms = round((time.perf_counter() - t0) * 1000, 1)
        mapping = pz.restore_map(session)
        log.append({"event": "chat", "session": session, "model": body.get("model"),
                    "masked": counts, "mask_ms": mask_ms, "stream": bool(body.get("stream"))})

        if not body.get("stream"):
            async with client() as c:
                r = await c.post("/chat/completions", json=body)
            data = r.json()
            for ch in data.get("choices", []):
                msg = ch.get("message") or {}
                if isinstance(msg.get("content"), str):
                    msg["content"] = restore(msg["content"], mapping)
            return JSONResponse(data, status_code=r.status_code, headers={"X-Veil-Session": session})

        async def stream():
            restorers: dict[int, StreamRestorer] = {}
            last: dict | None = None
            async with client() as c:
                async with c.stream("POST", "/chat/completions", json=body) as r:
                    async for line in r.aiter_lines():
                        if not line.startswith("data:"):
                            continue
                        payload = line[5:].strip()
                        if payload == "[DONE]":
                            break
                        chunk = json.loads(payload)
                        last = chunk
                        for ch in chunk.get("choices", []):
                            delta = ch.get("delta") or {}
                            if isinstance(delta.get("content"), str):
                                rs = restorers.setdefault(ch.get("index", 0), StreamRestorer(mapping))
                                delta["content"] = rs.feed(delta["content"])
                        yield f"data: {json.dumps(chunk)}\n\n"
            # Release anything still held back.
            for idx, rs in restorers.items():
                tail = rs.flush()
                if tail and last is not None:
                    extra = {**last, "choices": [{"index": idx, "delta": {"content": tail}, "finish_reason": None}]}
                    yield f"data: {json.dumps(extra)}\n\n"
            yield "data: [DONE]\n\n"

        return StreamingResponse(stream(), media_type="text/event-stream", headers={"X-Veil-Session": session})

    @app.post("/v1/mask")
    async def mask(payload: dict):
        session = payload.get("session") or "adhoc"
        masked, reps = pz.mask(session, payload["text"])
        if not payload.get("preview"):  # live UI previews send nothing outbound, so they aren't audited
            log.append({"event": "mask", "session": session, "masked": summarize(reps)})
        # Originals go back only to the caller who sent them (local UI); they are never sent upstream or logged.
        return {"session": session, "masked": masked, "counts": summarize(reps),
                "entities": [{"type": r.entity_type, "start": r.start, "end": r.end, "source": r.source,
                              "mstart": r.mstart, "mend": r.mend, "original": r.original, "fake": r.fake}
                             for r in reps]}

    @app.post("/v1/unmask")
    async def unmask(payload: dict):
        return {"text": restore(payload["text"], pz.restore_map(payload["session"]))}

    @app.get("/audit/verify")
    async def audit_verify():
        return log.verify()

    @app.get("/audit/tail")
    async def audit_tail(limit: int = 50):
        return log.tail(limit)

    return app


app = None
if os.getenv("VEIL_AUTOSTART", "1") == "1" and __name__ != "__main__":
    # `uvicorn veil.gateway:app` path; skipped in tests via VEIL_AUTOSTART=0.
    try:
        app = create_app()
    except Exception as e:  # pragma: no cover - surfaced on first request instead of import
        _err = e

        app = FastAPI()

        @app.get("/healthz")
        async def broken():
            return JSONResponse({"ok": False, "error": repr(_err)}, status_code=500)
