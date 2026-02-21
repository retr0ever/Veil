import asyncio
import json
import os
import secrets
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from .db.database import get_db, init_db
from .services import crusoe_classifier, claude_classifier
from .agents import peek, poke, patch

load_dotenv()


# --- WebSocket manager for live dashboard ---
class ConnectionManager:
    def __init__(self):
        self.connections: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.connections.append(ws)

    def disconnect(self, ws: WebSocket):
        self.connections.remove(ws)

    async def broadcast(self, data: dict):
        dead = []
        for ws in self.connections:
            try:
                await ws.send_json(data)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.connections.remove(ws)


ws_manager = ConnectionManager()

# --- Agent loop state ---
agent_running = False


async def agent_loop():
    """Background loop: Peek -> Poke -> Patch, repeat."""
    global agent_running
    agent_running = True

    # Wait for server to be ready before starting agents
    await asyncio.sleep(5)

    while agent_running:
        try:
            # 1. Peek: discover new techniques
            await ws_manager.broadcast({"type": "agent", "agent": "peek", "status": "running", "detail": "Scanning for new attack techniques..."})
            discovered = await peek.run()
            await ws_manager.broadcast({"type": "agent", "agent": "peek", "status": "done", "detail": f"Found {discovered} new techniques"})

            await asyncio.sleep(2)

            # 2. Poke: test defences
            await ws_manager.broadcast({"type": "agent", "agent": "poke", "status": "running", "detail": "Red-teaming current defences..."})
            bypasses = await poke.run()
            await ws_manager.broadcast({"type": "agent", "agent": "poke", "status": "done", "detail": f"Found {len(bypasses)} bypasses"})

            await asyncio.sleep(2)

            # 3. Patch: fix bypasses
            if bypasses:
                await ws_manager.broadcast({"type": "agent", "agent": "patch", "status": "running", "detail": f"Patching {len(bypasses)} bypasses..."})
                result = await patch.run(bypasses)
                await ws_manager.broadcast({"type": "agent", "agent": "patch", "status": "done", "detail": f"Patched {result['patched']} vulnerabilities"})
            else:
                await ws_manager.broadcast({"type": "agent", "agent": "patch", "status": "idle", "detail": "No bypasses to fix"})

            # Broadcast updated stats
            stats = await get_stats_data()
            await ws_manager.broadcast({"type": "stats", **stats})

        except Exception as e:
            await ws_manager.broadcast({"type": "agent", "agent": "system", "status": "error", "detail": str(e)})

        # Wait before next cycle
        await asyncio.sleep(30)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    task = asyncio.create_task(agent_loop())
    yield
    global agent_running
    agent_running = False
    task.cancel()


app = FastAPI(title="Veil", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --- Models ---
class AddSiteRequest(BaseModel):
    url: str


class ClassifyRequest(BaseModel):
    message: str


# --- Helpers ---
async def get_current_rules():
    db = await get_db()
    cursor = await db.execute("SELECT crusoe_prompt, claude_prompt, version FROM rules ORDER BY version DESC LIMIT 1")
    row = await cursor.fetchone()
    await db.close()
    if row:
        return {"crusoe_prompt": row[0], "claude_prompt": row[1], "version": row[2]}
    return None


async def get_stats_data():
    db = await get_db()
    total = (await (await db.execute("SELECT COUNT(*) FROM request_log")).fetchone())[0]
    blocked = (await (await db.execute("SELECT COUNT(*) FROM request_log WHERE blocked = 1")).fetchone())[0]
    threats = (await (await db.execute("SELECT COUNT(*) FROM threats")).fetchone())[0]
    threats_blocked = (await (await db.execute("SELECT COUNT(*) FROM threats WHERE blocked = 1")).fetchone())[0]
    rules_version = (await (await db.execute("SELECT MAX(version) FROM rules")).fetchone())[0] or 1
    await db.close()
    return {
        "total_requests": total,
        "blocked_requests": blocked,
        "total_threats": threats,
        "threats_blocked": threats_blocked,
        "block_rate": round(threats_blocked / max(threats, 1) * 100, 1),
        "rules_version": rules_version,
    }


async def classify_request(raw_request: str):
    """Run the two-stage classification on a raw HTTP request string."""
    rules = await get_current_rules()
    if not rules:
        return {"classification": "SUSPICIOUS", "confidence": 0.5, "blocked": False, "attack_type": "none", "classifier": "none", "reason": "No rules loaded"}

    # Stage 1: Crusoe fast check
    crusoe_result = await crusoe_classifier.classify(raw_request, rules["crusoe_prompt"])
    classification = crusoe_result.get("classification", "SUSPICIOUS")
    confidence = crusoe_result.get("confidence", 0.5)

    blocked = False
    final_result = crusoe_result

    # Stage 2: If suspicious/malicious, escalate to Claude
    if classification in ("SUSPICIOUS", "MALICIOUS"):
        claude_result = await claude_classifier.classify(raw_request, rules["claude_prompt"])
        final_result = claude_result
        classification = claude_result.get("classification", "SUSPICIOUS")
        confidence = claude_result.get("confidence", 0.5)

    if classification == "MALICIOUS" and confidence > 0.6:
        blocked = True

    # Log
    db = await get_db()
    await db.execute(
        """INSERT INTO request_log (timestamp, raw_request, classification, confidence, classifier, blocked, attack_type, response_time_ms)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            datetime.utcnow().isoformat(),
            raw_request[:500],
            classification,
            confidence,
            final_result.get("classifier", "unknown"),
            1 if blocked else 0,
            final_result.get("attack_type", "none"),
            final_result.get("response_time_ms", 0),
        ),
    )
    await db.commit()
    await db.close()

    # Broadcast to dashboard
    await ws_manager.broadcast({
        "type": "request",
        "timestamp": datetime.utcnow().isoformat(),
        "message": raw_request[:120],
        "classification": classification,
        "confidence": confidence,
        "blocked": blocked,
        "classifier": final_result.get("classifier", "unknown"),
        "attack_type": final_result.get("attack_type", "none"),
    })

    return {
        "classification": classification,
        "confidence": confidence,
        "blocked": blocked,
        "attack_type": final_result.get("attack_type", "none"),
        "classifier": final_result.get("classifier", "unknown"),
        "reason": final_result.get("reason", ""),
        "rules_version": rules["version"],
    }


# --- Site registration ---
@app.post("/api/sites")
async def add_site(req: AddSiteRequest):
    """Register a site to protect. Returns the site_id for the proxy URL."""
    target_url = req.url.rstrip("/")

    # Validate URL
    parsed = urlparse(target_url)
    if not parsed.scheme or not parsed.netloc:
        return JSONResponse(status_code=400, content={"error": "Invalid URL"})

    db = await get_db()

    # Check if already registered
    cursor = await db.execute("SELECT site_id, target_url, created_at FROM sites WHERE target_url = ?", (target_url,))
    existing = await cursor.fetchone()
    if existing:
        await db.close()
        return {"site_id": existing[0], "target_url": existing[1], "created_at": existing[2]}

    site_id = secrets.token_urlsafe(6)
    now = datetime.utcnow().isoformat()

    await db.execute(
        "INSERT INTO sites (site_id, target_url, created_at) VALUES (?, ?, ?)",
        (site_id, target_url, now),
    )
    await db.commit()
    await db.close()

    return {"site_id": site_id, "target_url": target_url, "created_at": now}


@app.get("/api/sites")
async def list_sites():
    """List all registered sites."""
    db = await get_db()
    cursor = await db.execute("SELECT site_id, target_url, created_at FROM sites ORDER BY created_at DESC")
    rows = await cursor.fetchall()
    await db.close()
    return [{"site_id": r[0], "target_url": r[1], "created_at": r[2]} for r in rows]


# --- Reverse proxy ---
@app.api_route("/p/{site_id}/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
async def proxy(site_id: str, path: str, request: Request):
    """Reverse proxy: classifies the request, then forwards to the real backend or blocks."""
    # Look up site
    db = await get_db()
    cursor = await db.execute("SELECT target_url FROM sites WHERE site_id = ?", (site_id,))
    row = await cursor.fetchone()
    await db.close()

    if not row:
        return JSONResponse(status_code=404, content={"error": "Site not found"})

    target_url = row[0]

    # Build raw request string for classification
    query_string = f"?{request.url.query}" if request.url.query else ""
    body = (await request.body()).decode("utf-8", errors="replace")

    raw_lines = [f"{request.method} /{path}{query_string} HTTP/1.1"]
    for key, value in request.headers.items():
        if key.lower() not in ("host", "connection", "transfer-encoding"):
            raw_lines.append(f"{key}: {value}")
    raw_request = "\n".join(raw_lines)
    if body:
        raw_request += f"\n\n{body}"

    # Classify
    result = await classify_request(raw_request)

    if result["blocked"]:
        return JSONResponse(
            status_code=403,
            content={
                "error": "Blocked by Veil",
                "classification": result["classification"],
                "attack_type": result["attack_type"],
                "reason": result["reason"],
            },
        )

    # Forward to real backend
    forward_url = f"{target_url}/{path}"
    if request.url.query:
        forward_url += f"?{request.url.query}"

    # Filter headers for forwarding
    forward_headers = {}
    for key, value in request.headers.items():
        if key.lower() not in ("host", "connection", "transfer-encoding", "content-length"):
            forward_headers[key] = value

    try:
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            resp = await client.request(
                method=request.method,
                url=forward_url,
                headers=forward_headers,
                content=body.encode() if body else None,
            )

        # Return the real response
        excluded_headers = {"transfer-encoding", "connection", "content-encoding", "content-length"}
        response_headers = {
            k: v for k, v in resp.headers.items()
            if k.lower() not in excluded_headers
        }

        return Response(
            content=resp.content,
            status_code=resp.status_code,
            headers=response_headers,
        )

    except httpx.RequestError as e:
        return JSONResponse(
            status_code=502,
            content={"error": f"Could not reach backend: {str(e)}"},
        )


# --- Classification-only endpoint (used by Poke) ---
@app.post("/v1/classify")
async def classify_only(req: ClassifyRequest):
    result = await classify_request(req.message)
    return result


# --- Dashboard API ---
@app.get("/api/stats")
async def get_stats():
    return await get_stats_data()


@app.get("/api/threats")
async def get_threats():
    db = await get_db()
    cursor = await db.execute("SELECT * FROM threats ORDER BY discovered_at DESC")
    rows = await cursor.fetchall()
    await db.close()
    return [
        {
            "id": r[0],
            "technique_name": r[1],
            "category": r[2],
            "source": r[3],
            "raw_payload": r[4][:200],
            "severity": r[5],
            "discovered_at": r[6],
            "tested_at": r[7],
            "blocked": bool(r[8]),
            "patched_at": r[9],
        }
        for r in rows
    ]


@app.get("/api/agents")
async def get_agent_log():
    db = await get_db()
    cursor = await db.execute("SELECT * FROM agent_log ORDER BY timestamp DESC LIMIT 50")
    rows = await cursor.fetchall()
    await db.close()
    return [
        {
            "id": r[0],
            "timestamp": r[1],
            "agent": r[2],
            "action": r[3],
            "detail": r[4],
            "success": bool(r[5]),
        }
        for r in rows
    ]


@app.get("/api/requests")
async def get_requests():
    db = await get_db()
    cursor = await db.execute("SELECT * FROM request_log ORDER BY timestamp DESC LIMIT 100")
    rows = await cursor.fetchall()
    await db.close()
    return [
        {
            "id": r[0],
            "timestamp": r[1],
            "message": r[2][:100],
            "classification": r[3],
            "confidence": r[4],
            "classifier": r[5],
            "blocked": bool(r[6]),
            "attack_type": r[7],
            "response_time_ms": r[8],
        }
        for r in rows
    ]


@app.get("/api/rules")
async def get_rules():
    db = await get_db()
    cursor = await db.execute("SELECT version, updated_at, updated_by FROM rules ORDER BY version DESC")
    rows = await cursor.fetchall()
    await db.close()
    return [{"version": r[0], "updated_at": r[1], "updated_by": r[2]} for r in rows]


# --- Trigger agents manually ---
@app.post("/api/agents/peek/run")
async def trigger_peek():
    discovered = await peek.run()
    return {"discovered": discovered}


@app.post("/api/agents/poke/run")
async def trigger_poke():
    bypasses = await poke.run()
    return {"bypasses": len(bypasses), "details": bypasses}


@app.post("/api/agents/cycle")
async def trigger_full_cycle():
    """Run a full Peek -> Poke -> Patch cycle manually."""
    discovered = await peek.run()
    await ws_manager.broadcast({"type": "agent", "agent": "peek", "status": "done", "detail": f"Found {discovered} new techniques"})

    bypasses = await poke.run()
    await ws_manager.broadcast({"type": "agent", "agent": "poke", "status": "done", "detail": f"Found {len(bypasses)} bypasses"})

    patch_result = {"patched": 0}
    if bypasses:
        patch_result = await patch.run(bypasses)
        await ws_manager.broadcast({"type": "agent", "agent": "patch", "status": "done", "detail": f"Patched {patch_result['patched']}"})

    stats = await get_stats_data()
    await ws_manager.broadcast({"type": "stats", **stats})

    return {
        "discovered": discovered,
        "bypasses": len(bypasses),
        "patched": patch_result["patched"],
        "stats": stats,
    }


# --- WebSocket for live dashboard ---
@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws_manager.connect(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(ws)


# --- Serve static frontend (production) ---
STATIC_DIR = Path(__file__).resolve().parent.parent / "static"
if STATIC_DIR.exists():
    app.mount("/assets", StaticFiles(directory=STATIC_DIR / "assets"), name="assets")

    @app.get("/{path:path}")
    async def serve_spa(path: str):
        file = STATIC_DIR / path
        if file.exists() and file.is_file():
            return FileResponse(file)
        return FileResponse(STATIC_DIR / "index.html")
