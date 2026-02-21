import asyncio
import json
import os
import secrets
import time
from collections import defaultdict
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse, urlencode

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from pydantic import BaseModel

from .db.database import get_db, init_db
from .services import crusoe_classifier, claude_classifier, regex_classifier
from .agents import peek, poke, patch

load_dotenv()


# --- Session helpers ---
GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID", "")
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET", "")
SESSION_SECRET = os.getenv("SESSION_SECRET", "veil-dev-secret-change-me")
SESSION_COOKIE = "veil_session"
SESSION_MAX_AGE = 60 * 60 * 24 * 30  # 30 days

_serializer = URLSafeTimedSerializer(SESSION_SECRET)

# --- Prompt Cache ---
_prompt_cache = {
    "prompt": None,
    "last_fetch": 0
}
PROMPT_CACHE_TTL = 30  # 30 seconds


async def get_cached_crusoe_prompt() -> str:
    """Fetch the Crusoe prompt from DB with a 30s cache."""
    now = time.time()
    if _prompt_cache["prompt"] is None or (now - _prompt_cache["last_fetch"]) > PROMPT_CACHE_TTL:
        rules = await get_current_rules()
        if rules:
            _prompt_cache["prompt"] = rules["crusoe_prompt"]
            _prompt_cache["last_fetch"] = now
    return _prompt_cache["prompt"] or ""


def create_session_cookie(user_id: int) -> str:
    return _serializer.dumps(user_id)


def read_session_cookie(cookie: str) -> int | None:
    try:
        return _serializer.loads(cookie, max_age=SESSION_MAX_AGE)
    except (BadSignature, SignatureExpired):
        return None


async def get_current_user(request: Request) -> dict | None:
    """Return the current user dict from the session cookie, or None."""
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    user_id = read_session_cookie(token)
    if user_id is None:
        return None
    async with get_db() as db:
        cursor = await db.execute(
            "SELECT id, github_id, github_login, avatar_url, name FROM users WHERE id = ?",
            (user_id,),
        )
        row = await cursor.fetchone()
    if not row:
        return None
    return {
        "id": row[0],
        "github_id": row[1],
        "github_login": row[2],
        "avatar_url": row[3],
        "name": row[4],
    }


# --- Rate limiter ---
class RateLimiter:
    """In-memory sliding window rate limiter per IP."""

    def __init__(self):
        self._hits: dict[str, list[float]] = defaultdict(list)

    def is_allowed(self, key: str, max_requests: int, window_seconds: int) -> bool:
        now = time.monotonic()
        cutoff = now - window_seconds
        hits = self._hits[key]
        # Prune old entries
        self._hits[key] = hits = [t for t in hits if t > cutoff]
        if len(hits) >= max_requests:
            return False
        hits.append(now)
        return True


rate_limiter = RateLimiter()

# Limits: (max_requests, window_seconds)
RATE_LIMITS = {
    "classify": (30, 60),    # 30 req/min per IP
    "proxy": (60, 60),       # 60 req/min per IP
    "auth": (10, 60),        # 10 req/min per IP
    "api": (60, 60),         # 60 req/min per IP
    "agents": (3, 300),      # 3 req/5min per IP (expensive LLM calls)
}


def check_rate_limit(request: Request, bucket: str) -> JSONResponse | None:
    """Return a 429 response if rate limited, else None."""
    ip = request.client.host if request.client else "unknown"
    key = f"{bucket}:{ip}"
    limit, window = RATE_LIMITS.get(bucket, (60, 60))
    if not rate_limiter.is_allowed(key, limit, window):
        return JSONResponse(
            status_code=429,
            content={"error": "Rate limited", "retry_after_seconds": window},
            headers={"Retry-After": str(window)},
        )
    return None


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
_last_cycle_hint: dict | None = None
_cycle_counter: int = 0
MAX_PATCH_ROUNDS = 2


def _make_cycle_ctx(hint: dict | None = None) -> dict:
    """Create a fresh cycle context dict."""
    global _cycle_counter
    _cycle_counter += 1
    return {
        "cycle_id": str(_cycle_counter),
        "discovered_count": 0,
        "strategies_used": [],
        "categories_discovered": [],
        "tested_count": 0,
        "blocked_count": 0,
        "bypasses": [],
        "bypass_categories": [],
        "poke_summary": {},
        "patch_rounds": [],
        "hint": hint,
    }


def _build_cycle_hint(cycle_ctx: dict) -> dict | None:
    """Extract cross-cycle hint from a completed cycle context."""

    rounds = cycle_ctx.get("patch_rounds", [])
    if not rounds:
        return None

    last_round = rounds[-1]
    bypass_categories = cycle_ctx.get("bypass_categories", [])

    # Collect still-bypassing IDs from the last patch round's result
    last_bypasses = cycle_ctx.get("_last_still_bypassing", [])

    return {
        "dominant_failure_mode": last_round.get("dominant_failure", "unknown"),
        "weak_categories": bypass_categories,
        "still_bypassing_count": last_round.get("still_bypassing", 0),
        "still_bypassing_ids": [b["threat_id"] for b in last_bypasses],
    }


async def _log_cycle_summary(cycle_ctx: dict):
    """Write a unified cycle summary to agent_log."""

    rounds = cycle_ctx.get("patch_rounds", [])
    total_patched = sum(r.get("patched", 0) for r in rounds)
    total_verified = sum(r.get("verified", 0) for r in rounds)
    hint = cycle_ctx.get("hint")

    detail = (
        f"Cycle #{cycle_ctx['cycle_id']}: "
        f"discovered={cycle_ctx['discovered_count']}, "
        f"tested={cycle_ctx['tested_count']}, "
        f"blocked={cycle_ctx['blocked_count']}, "
        f"bypasses={len(cycle_ctx['bypasses'])}, "
        f"patch_rounds={len(rounds)}, "
        f"patched={total_patched}, verified={total_verified}"
    )
    if hint:
        detail += f" [hint_from_prev: {hint.get('dominant_failure_mode', 'none')}]"
    if cycle_ctx.get("strategies_used"):
        detail += f" [strategies: {','.join(cycle_ctx['strategies_used'])}]"

    if len(detail) > 500:
        detail = detail[:497] + "..."

    async with get_db() as db:
        await db.execute(
            "INSERT INTO agent_log (timestamp, agent, action, detail, success) VALUES (?, ?, ?, ?, ?)",
            (
                datetime.utcnow().isoformat(),
                "system",
                "cycle_summary",
                detail,
                1,
            ),
        )
        await db.commit()


async def _run_closed_loop(cycle_ctx: dict):
    """Execute the closed-loop Peek -> Poke -> Patch(+re-poke) cycle."""

    # 1. Peek: discover new techniques
    await ws_manager.broadcast({"type": "agent", "agent": "peek", "status": "running", "detail": "Scanning for new attack techniques..."})
    discovered = await peek.run(cycle_ctx)
    await ws_manager.broadcast({"type": "agent", "agent": "peek", "status": "done", "detail": f"Found {discovered} new techniques"})

    await asyncio.sleep(2)

    # 2. Poke: test defences
    await ws_manager.broadcast({"type": "agent", "agent": "poke", "status": "running", "detail": "Red-teaming current defences..."})
    bypasses = await poke.run(cycle_ctx)
    await ws_manager.broadcast({"type": "agent", "agent": "poke", "status": "done", "detail": f"Found {len(bypasses)} bypasses"})

    await asyncio.sleep(2)

    # 3. Iterative Patch + verification re-poke
    if not bypasses:
        await ws_manager.broadcast({"type": "agent", "agent": "patch", "status": "idle", "detail": "No bypasses to fix"})
        return

    current_bypasses = bypasses
    for round_num in range(1, MAX_PATCH_ROUNDS + 1):
        await ws_manager.broadcast({
            "type": "agent", "agent": "patch", "status": "running",
            "detail": f"Patching {len(current_bypasses)} bypasses (round {round_num})..."
        })
        result = await patch.run(current_bypasses, cycle_ctx)
        still_bypassing = result.get("still_bypassing", [])
        cycle_ctx["_last_still_bypassing"] = still_bypassing

        await ws_manager.broadcast({
            "type": "agent", "agent": "patch", "status": "done",
            "detail": f"Patched {result['patched']} vulnerabilities, {len(still_bypassing)} still bypassing (round {round_num})"
        })

        if not still_bypassing or round_num >= MAX_PATCH_ROUNDS:
            break

        # Verification re-poke on still-bypassing threats
        repoke_ids = [b["threat_id"] for b in still_bypassing]
        await ws_manager.broadcast({
            "type": "agent", "agent": "poke", "status": "running",
            "detail": f"Re-testing {len(repoke_ids)} still-bypassing threats..."
        })
        repoke_bypasses = await poke.run(target_ids=repoke_ids)
        await ws_manager.broadcast({
            "type": "agent", "agent": "poke", "status": "done",
            "detail": f"Re-poke: {len(repoke_bypasses)} still bypass after patch"
        })

        if not repoke_bypasses:
            break

        current_bypasses = repoke_bypasses


async def agent_loop():
    """Background loop: closed-loop Peek -> Poke -> Patch, repeat."""
    global agent_running, _last_cycle_hint
    agent_running = True

    # Wait for server to be ready before starting agents
    await asyncio.sleep(5)

    while agent_running:
        try:
            cycle_ctx = _make_cycle_ctx(hint=_last_cycle_hint)

            await _run_closed_loop(cycle_ctx)

            # Log cycle summary
            await _log_cycle_summary(cycle_ctx)

            # Broadcast updated stats
            stats = await get_stats_data()
            await ws_manager.broadcast({"type": "stats", **stats})

            # Build hint for next cycle
            _last_cycle_hint = _build_cycle_hint(cycle_ctx)

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


# --- Auth routes ---
@app.get("/auth/github")
async def auth_github(request: Request):
    """Redirect to GitHub OAuth."""
    if r := check_rate_limit(request, "auth"):
        return r
    params = urlencode({
        "client_id": GITHUB_CLIENT_ID,
        "scope": "read:user",
    })
    return RedirectResponse(f"https://github.com/login/oauth/authorize?{params}")


@app.get("/auth/github/callback")
async def auth_github_callback(code: str, request: Request):
    """Exchange code for token, fetch user, set cookie, redirect to /."""
    if r := check_rate_limit(request, "auth"):
        return r
    # Exchange code for access token
    async with httpx.AsyncClient() as client:
        token_resp = await client.post(
            "https://github.com/login/oauth/access_token",
            json={
                "client_id": GITHUB_CLIENT_ID,
                "client_secret": GITHUB_CLIENT_SECRET,
                "code": code,
            },
            headers={"Accept": "application/json"},
        )
    token_data = token_resp.json()
    access_token = token_data.get("access_token")
    if not access_token:
        return JSONResponse(status_code=400, content={"error": "GitHub auth failed"})

    # Fetch user profile
    async with httpx.AsyncClient() as client:
        user_resp = await client.get(
            "https://api.github.com/user",
            headers={"Authorization": f"Bearer {access_token}"},
        )
    gh_user = user_resp.json()
    github_id = gh_user["id"]
    github_login = gh_user["login"]
    avatar_url = gh_user.get("avatar_url", "")
    name = gh_user.get("name", "")

    # Upsert user
    async with get_db() as db:
        cursor = await db.execute("SELECT id FROM users WHERE github_id = ?", (github_id,))
        existing = await cursor.fetchone()
        if existing:
            user_id = existing[0]
            await db.execute(
                "UPDATE users SET github_login = ?, avatar_url = ?, name = ? WHERE id = ?",
                (github_login, avatar_url, name, user_id),
            )
        else:
            cursor = await db.execute(
                "INSERT INTO users (github_id, github_login, avatar_url, name, created_at) VALUES (?, ?, ?, ?, ?)",
                (github_id, github_login, avatar_url, name, datetime.utcnow().isoformat()),
            )
            user_id = cursor.lastrowid
        await db.commit()

    # Set session cookie and redirect to frontend
    response = RedirectResponse("/", status_code=302)
    response.set_cookie(
        SESSION_COOKIE,
        create_session_cookie(user_id),
        max_age=SESSION_MAX_AGE,
        httponly=True,
        samesite="lax",
        path="/",
    )
    return response


@app.get("/auth/me")
async def auth_me(request: Request):
    """Return current user or 401."""
    user = await get_current_user(request)
    if not user:
        return JSONResponse(status_code=401, content={"error": "Not authenticated"})
    return user


@app.post("/auth/logout")
async def auth_logout():
    """Clear session cookie."""
    response = JSONResponse(content={"ok": True})
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response


# --- Models ---
class AddSiteRequest(BaseModel):
    url: str


class ClassifyRequest(BaseModel):
    message: str


# --- Helpers ---
async def get_current_rules():
    async with get_db() as db:
        cursor = await db.execute("SELECT crusoe_prompt, claude_prompt, version FROM rules ORDER BY version DESC LIMIT 1")
        row = await cursor.fetchone()
    if row:
        return {"crusoe_prompt": row[0], "claude_prompt": row[1], "version": row[2]}
    return None


async def get_stats_data():
    async with get_db() as db:
        total = (await (await db.execute("SELECT COUNT(*) FROM request_log")).fetchone())[0]
        blocked = (await (await db.execute("SELECT COUNT(*) FROM request_log WHERE blocked = 1")).fetchone())[0]
        threats = (await (await db.execute("SELECT COUNT(*) FROM threats")).fetchone())[0]
        threats_blocked = (await (await db.execute("SELECT COUNT(*) FROM threats WHERE blocked = 1")).fetchone())[0]
        rules_version = (await (await db.execute("SELECT MAX(version) FROM rules")).fetchone())[0] or 1
    return {
        "total_requests": total,
        "blocked_requests": blocked,
        "total_threats": threats,
        "threats_blocked": threats_blocked,
        "block_rate": round(threats_blocked / max(threats, 1) * 100, 1),
        "rules_version": rules_version,
    }


async def classify_request(raw_request: str):
    """Run classification on a raw HTTP request string.

    Pipeline:
    1. Regex classifier runs first (instant, no API needed)
    2. If API keys are configured, LLM classifiers refine the result
    3. Blocked if any stage says MALICIOUS with confidence > 0.6
    """
    rules = await get_current_rules()
    if not rules:
        return {"classification": "SUSPICIOUS", "confidence": 0.5, "blocked": False, "attack_type": "none", "classifier": "none", "reason": "No rules loaded"}

    # Stage 0: Regex classifier (always runs, instant)
    regex_result = await regex_classifier.classify(raw_request)
    classification = regex_result.get("classification", "SAFE")
    confidence = regex_result.get("confidence", 0.5)
    final_result = regex_result
    blocked = False

    crusoe_key = os.getenv("CRUSOE_API_KEY", "")
    has_crusoe = crusoe_key and crusoe_key != "placeholder"
    has_claude = bool(os.getenv("AWS_ACCESS_KEY_ID") or os.getenv("AWS_PROFILE"))

    # Stage 1: Crusoe fast check (only if API key is real)
    if has_crusoe:
        crusoe_result = await crusoe_classifier.classify(raw_request, rules["crusoe_prompt"])
        crusoe_class = crusoe_result.get("classification", "SUSPICIOUS")
        # If regex said MALICIOUS, keep that. If Crusoe escalates, use that.
        if crusoe_class == "MALICIOUS" or (crusoe_class == "SUSPICIOUS" and classification != "MALICIOUS"):
            classification = crusoe_class
            final_result = crusoe_result
            confidence = crusoe_result.get("confidence", 0.5)

    # Stage 2: Claude deep analysis (only if API key is real and something looks suspicious)
    if has_claude and classification in ("SUSPICIOUS", "MALICIOUS"):
        claude_result = await claude_classifier.classify(raw_request, rules["claude_prompt"])
        claude_class = claude_result.get("classification", "SUSPICIOUS")
        if claude_class == "MALICIOUS":
            classification = claude_class
            final_result = claude_result
            confidence = claude_result.get("confidence", 0.5)
        elif claude_class == "SAFE" and regex_result.get("classification") != "MALICIOUS":
            # Claude overrides Crusoe's SUSPICIOUS to SAFE (but not regex MALICIOUS)
            classification = "SAFE"
            final_result = claude_result
            confidence = claude_result.get("confidence", 0.5)

    if classification == "MALICIOUS" and confidence > 0.6:
        blocked = True

    # Log
    async with get_db() as db:
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
async def add_site(req: AddSiteRequest, request: Request):
    """Register a site to protect. Returns the site_id for the proxy URL."""
    user = await get_current_user(request)
    if not user:
        return JSONResponse(status_code=401, content={"error": "Not authenticated"})

    target_url = req.url.rstrip("/")

    # Validate URL
    parsed = urlparse(target_url)
    if not parsed.scheme or not parsed.netloc:
        return JSONResponse(status_code=400, content={"error": "Invalid URL"})

    async with get_db() as db:
        # Check if already registered by this user
        cursor = await db.execute(
            "SELECT site_id, target_url, created_at FROM sites WHERE target_url = ? AND user_id = ?",
            (target_url, user["id"]),
        )
        existing = await cursor.fetchone()
        if existing:
            return {"site_id": existing[0], "target_url": existing[1], "created_at": existing[2]}

        site_id = secrets.token_urlsafe(6)
        now = datetime.utcnow().isoformat()

        await db.execute(
            "INSERT INTO sites (site_id, target_url, user_id, created_at) VALUES (?, ?, ?, ?)",
            (site_id, target_url, user["id"], now),
        )
        await db.commit()

    return {"site_id": site_id, "target_url": target_url, "created_at": now}


@app.get("/api/sites")
async def list_sites(request: Request):
    """List sites for the current user."""
    user = await get_current_user(request)
    if not user:
        return JSONResponse(status_code=401, content={"error": "Not authenticated"})

    async with get_db() as db:
        cursor = await db.execute(
            "SELECT site_id, target_url, created_at FROM sites WHERE user_id = ? ORDER BY created_at DESC",
            (user["id"],),
        )
        rows = await cursor.fetchall()
    return [{"site_id": r[0], "target_url": r[1], "created_at": r[2]} for r in rows]


# --- Reverse proxy ---
@app.api_route("/p/{site_id}/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
async def proxy(site_id: str, path: str, request: Request):
    """Reverse proxy: classifies the request, then forwards to the real backend or blocks."""
    if r := check_rate_limit(request, "proxy"):
        return r
    # Look up site
    async with get_db() as db:
        cursor = await db.execute("SELECT target_url FROM sites WHERE site_id = ?", (site_id,))
        row = await cursor.fetchone()

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


@app.get("/ping")
async def ping():
    return {"ok": True}


@app.post("/v1/classify")
async def api_classify(req: ClassifyRequest, request: Request):
    """Refined classification using the full pipeline (regex + LLM)."""
    if r := check_rate_limit(request, "classify"):
        return r
    return await classify_request(req.message)


@app.post("/external/crusoe/classify")
async def crusoe_classify(req: ClassifyRequest, request: Request):
    """Direct direct access to Crusoe LLM classification with prompt caching."""
    if r := check_rate_limit(request, "api"):
        return r
    
    prompt = await get_cached_crusoe_prompt()
    if not prompt:
        return JSONResponse(status_code=500, content={"error": "Crusoe prompt not available in database"})
        
    result = await crusoe_classifier.classify(req.message, prompt)
    return result


# --- Auth helper for dashboard API ---
async def require_auth(request: Request) -> dict | JSONResponse:
    user = await get_current_user(request)
    if not user:
        return JSONResponse(status_code=401, content={"error": "Authentication required"})
    return user


# --- Dashboard API (all require auth) ---
@app.get("/api/stats")
async def get_stats(request: Request):
    auth = await require_auth(request)
    if isinstance(auth, JSONResponse):
        return auth
    return await get_stats_data()


@app.get("/api/threats")
async def get_threats(request: Request):
    auth = await require_auth(request)
    if isinstance(auth, JSONResponse):
        return auth
    async with get_db() as db:
        cursor = await db.execute("SELECT * FROM threats ORDER BY discovered_at DESC")
        rows = await cursor.fetchall()
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
async def get_agent_log(request: Request):
    auth = await require_auth(request)
    if isinstance(auth, JSONResponse):
        return auth
    async with get_db() as db:
        cursor = await db.execute("SELECT * FROM agent_log ORDER BY timestamp DESC LIMIT 50")
        rows = await cursor.fetchall()
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
async def get_requests(request: Request):
    auth = await require_auth(request)
    if isinstance(auth, JSONResponse):
        return auth
    async with get_db() as db:
        cursor = await db.execute("SELECT * FROM request_log ORDER BY timestamp DESC LIMIT 100")
        rows = await cursor.fetchall()
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
async def get_rules(request: Request):
    auth = await require_auth(request)
    if isinstance(auth, JSONResponse):
        return auth
    async with get_db() as db:
        cursor = await db.execute("SELECT version, updated_at, updated_by FROM rules ORDER BY version DESC")
        rows = await cursor.fetchall()
    return [{"version": r[0], "updated_at": r[1], "updated_by": r[2]} for r in rows]


@app.get("/api/analytics/threat-distribution")
async def get_threat_distribution(request: Request):
    """Aggregate threats by category for SIG track analytics."""
    auth = await require_auth(request)
    if isinstance(auth, JSONResponse):
        return auth
        
    async with get_db() as db:
        cursor = await db.execute("""
            SELECT category, 
                   COUNT(*) as total, 
                   SUM(CASE WHEN blocked = 1 THEN 1 ELSE 0 END) as patched
            FROM threats 
            GROUP BY category
        """)
        rows = await cursor.fetchall()
        
    return [
        {
            "category": r[0],
            "total": r[1],
            "patched": r[2],
            "exposed": r[1] - r[2]
        }
        for r in rows
    ]


@app.get("/api/compliance/report")
async def get_compliance_report(request: Request):
    """Generate a formal security posture report for BearingPoint track."""
    auth = await require_auth(request)
    if isinstance(auth, JSONResponse):
        return auth

    stats = await get_stats_data()
    
    async with get_db() as db:
        # Get recent critical patches
        cursor = await db.execute("SELECT technique_name, patched_at FROM threats WHERE blocked = 1 ORDER BY patched_at DESC LIMIT 5")
        patches = [{"technique": r[0], "date": r[1]} for r in await cursor.fetchall()]
        
        # Get agent activity summary
        cursor = await db.execute("SELECT COUNT(*), agent FROM agent_log GROUP BY agent")
        agent_stats = {r[1]: r[0] for r in await cursor.fetchall()}

    return {
        "generated_at": datetime.utcnow().isoformat(),
        "security_score": stats["block_rate"],
        "summary": {
            "total_threats_identified": stats["total_threats"],
            "vulnerabilities_remediated": stats["threats_blocked"],
            "rules_version": stats["rules_version"]
        },
        "recent_hardened_assets": patches,
        "agent_activity": agent_stats,
        "compliance_status": "HIGH" if stats["block_rate"] > 80 else "MEDIUM"
    }


# --- Trigger agents manually (auth + rate limited) ---
@app.post("/api/agents/peek/run")
async def trigger_peek(request: Request):
    auth = await require_auth(request)
    if isinstance(auth, JSONResponse):
        return auth
    if r := check_rate_limit(request, "agents"):
        return r
    ctx = _make_cycle_ctx(hint=_last_cycle_hint)
    discovered = await peek.run(ctx)
    return {"discovered": discovered, "strategies_used": ctx.get("strategies_used", [])}


@app.post("/api/agents/poke/run")
async def trigger_poke(request: Request):
    auth = await require_auth(request)
    if isinstance(auth, JSONResponse):
        return auth
    if r := check_rate_limit(request, "agents"):
        return r
    ctx = _make_cycle_ctx()
    bypasses = await poke.run(ctx)
    return {"bypasses": len(bypasses), "details": bypasses}


@app.post("/api/agents/cycle")
async def trigger_full_cycle(request: Request):
    """Run a full closed-loop Peek -> Poke -> Patch cycle manually."""
    global _last_cycle_hint
    auth = await require_auth(request)
    if isinstance(auth, JSONResponse):
        return auth
    if r := check_rate_limit(request, "agents"):
        return r

    cycle_ctx = _make_cycle_ctx(hint=_last_cycle_hint)

    await _run_closed_loop(cycle_ctx)
    await _log_cycle_summary(cycle_ctx)

    stats = await get_stats_data()
    await ws_manager.broadcast({"type": "stats", **stats})

    _last_cycle_hint = _build_cycle_hint(cycle_ctx)

    return {
        "cycle_id": cycle_ctx["cycle_id"],
        "discovered": cycle_ctx["discovered_count"],
        "bypasses": len(cycle_ctx["bypasses"]),
        "patch_rounds": cycle_ctx["patch_rounds"],
        "strategies_used": cycle_ctx["strategies_used"],
        "stats": stats,
    }


# --- WebSocket for live dashboard ---
@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws_manager.connect(ws)

    # Hydrate: send current stats + recent requests + recent agent events
    try:
        stats = await get_stats_data()
        await ws.send_json({"type": "stats", **stats})

        async with get_db() as db:
            cursor = await db.execute("SELECT * FROM request_log ORDER BY timestamp DESC LIMIT 20")
            rows = await cursor.fetchall()
        for r in reversed(rows):
            await ws.send_json({
                "type": "request",
                "timestamp": r[1],
                "message": r[2][:120],
                "classification": r[3],
                "confidence": r[4],
                "blocked": bool(r[6]),
                "classifier": r[5],
                "attack_type": r[7] or "none",
            })

        async with get_db() as db:
            cursor = await db.execute("SELECT * FROM agent_log ORDER BY timestamp DESC LIMIT 10")
            rows = await cursor.fetchall()
        for r in reversed(rows):
            await ws.send_json({
                "type": "agent",
                "agent": r[2],
                "status": "done" if r[5] else "error",
                "detail": r[4] or "",
            })
    except Exception:
        pass

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
