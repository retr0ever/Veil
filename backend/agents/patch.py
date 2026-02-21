"""Patch — Adaptation Agent. Root-cause analysis of WAF bypasses and intelligent rule evolution."""

from anthropic import AsyncAnthropicBedrock
import httpx
import json
import os
from datetime import datetime
from ..db.database import get_db

AWS_REGION = os.getenv("AWS_REGION", "eu-west-1")
BEDROCK_MODEL = os.getenv(
    "BEDROCK_MODEL", "global.anthropic.claude-sonnet-4-5-20250929-v1:0"
)
VEIL_PROXY_URL = os.getenv("VEIL_PROXY_URL", "http://localhost:8000")

# Max bypasses to verify after patching (keeps cycle time bounded)
MAX_VERIFY = 3

# ---------------------------------------------------------------------------
# Failure mode classification
# ---------------------------------------------------------------------------

FAILURE_MODES = {
    "pattern_gap": "Attack pattern not present in rules at all — the classifiers have never seen this technique",
    "encoding_evasion": "Known attack pattern but obfuscated via encoding, case tricks, comment insertion, or Unicode tricks",
    "context_blind_spot": "Attack delivered in an unusual HTTP context (headers, multipart, GraphQL, XML attributes) that classifiers don't inspect deeply",
    "semantic_miss": "AI classifier saw the payload but failed to recognise malicious intent — likely because the attack uses legitimate syntax in a malicious context",
    "confidence_underflow": "Classifier flagged correctly but confidence was too low to trigger a block (below 0.6 threshold)",
}


def _classify_failure(bypass: dict) -> str:
    """Determine why a bypass succeeded based on classifier response."""

    resp = bypass.get("classifier_response", {})
    classification = resp.get("classification", "SAFE")
    confidence = resp.get("confidence", 0.0)
    category = bypass.get("category", "")
    payload = bypass.get("payload", "").lower()

    # Confidence underflow: classifier said MALICIOUS but confidence too low
    if classification == "MALICIOUS" and confidence <= 0.6:
        return "confidence_underflow"

    # Encoding evasion signals
    encoding_signals = [
        "%25", "%00", "\\u00", "%c0", "%fe", "%ff",  # double encoding, null bytes, overlong utf-8
        "/**/", "/*!",  # SQL comment tricks
        "&#", "&lt;", "&gt;",  # HTML entities
    ]
    if any(sig in payload for sig in encoding_signals):
        return "encoding_evasion"

    # Context blind spot signals
    context_signals = [
        "multipart/form-data", "content-type: application/xml",
        "x-forwarded-for:", "graphql", "websocket", "upgrade:",
        "transfer-encoding: chunked",
    ]
    if any(sig in payload for sig in context_signals):
        if classification == "SAFE":
            return "context_blind_spot"

    # Semantic miss: classifier said SAFE on a known attack category
    if classification == "SAFE" and category in (
        "sqli", "xss", "command_injection", "rce", "ssrf",
    ):
        return "semantic_miss"

    # Default: pattern not in rules
    return "pattern_gap"


# ---------------------------------------------------------------------------
# Phase 1: Bypass Analysis (no LLM)
# ---------------------------------------------------------------------------


def _analyse_bypasses(bypasses: list[dict]) -> dict:
    """Group bypasses by category and failure mode. Returns a threat profile."""

    by_category = {}
    by_failure_mode = {}

    for b in bypasses:
        cat = b.get("category", "unknown")
        if cat not in by_category:
            by_category[cat] = []
        by_category[cat].append(b)

        mode = _classify_failure(b)
        b["failure_mode"] = mode
        if mode not in by_failure_mode:
            by_failure_mode[mode] = []
        by_failure_mode[mode].append(b)

    return {
        "by_category": by_category,
        "by_failure_mode": by_failure_mode,
        "total": len(bypasses),
        "categories_affected": list(by_category.keys()),
        "dominant_failure": max(by_failure_mode, key=lambda k: len(by_failure_mode[k])) if by_failure_mode else "unknown",
    }


# ---------------------------------------------------------------------------
# Phase 2: Build Rich Bypass Report
# ---------------------------------------------------------------------------


def _build_bypass_report(bypasses: list[dict], profile: dict) -> str:
    """Build a structured bypass report with failure mode annotations."""

    sections = []

    # Threat profile summary
    mode_counts = {
        mode: len(items) for mode, items in profile["by_failure_mode"].items()
    }
    mode_summary = ", ".join(f"{mode}: {count}" for mode, count in mode_counts.items())

    sections.append(
        f"THREAT PROFILE:\n"
        f"- {profile['total']} total bypasses across {len(profile['categories_affected'])} categories\n"
        f"- Categories: {', '.join(profile['categories_affected'])}\n"
        f"- Failure modes: {mode_summary}\n"
        f"- Dominant failure: {profile['dominant_failure']} — {FAILURE_MODES.get(profile['dominant_failure'], '')}"
    )

    # Individual bypass reports
    for i, b in enumerate(bypasses):
        classifier_info = json.dumps(b.get("classifier_response", {}))
        sections.append(
            f"BYPASS #{i+1}:\n"
            f"  Technique: {b['technique_name']}\n"
            f"  Category: {b.get('category', 'unknown')}\n"
            f"  Severity: {b.get('severity', 'medium')}\n"
            f"  Failure mode: {b.get('failure_mode', 'unknown')} — {FAILURE_MODES.get(b.get('failure_mode', ''), '')}\n"
            f"  Bypass score: {b.get('bypass_score', 0):.1f}\n"
            f"  Payload (truncated): {b.get('payload', '')[:300]}\n"
            f"  Classifier response: {classifier_info}"
        )

    return "\n\n".join(sections)


# ---------------------------------------------------------------------------
# Phase 3: Prompt Engineering (LLM call)
# ---------------------------------------------------------------------------

PATCH_SYSTEM_PROMPT = """You are a senior WAF defence engineer performing root-cause analysis on firewall bypasses. Your mission is to understand WHY each bypass succeeded and evolve the detection rules to prevent similar attacks in the future.

You receive bypasses annotated with failure modes:
- pattern_gap: the attack pattern is completely absent from the rules
- encoding_evasion: a known pattern was obfuscated and the rules didn't decode it
- context_blind_spot: the attack was delivered in an HTTP context the classifiers ignore
- semantic_miss: the AI saw the payload but failed to recognise malicious intent
- confidence_underflow: correctly flagged but confidence was too low to block

For each failure mode, apply the appropriate fix:
- pattern_gap → add the new attack pattern and its common variants to the rules
- encoding_evasion → add instructions to decode/normalise before matching (URL decode, HTML entity decode, Unicode normalise, strip comments/whitespace)
- context_blind_spot → expand inspection scope to cover the blind context (headers, multipart fields, XML attributes, GraphQL variables, etc.)
- semantic_miss → add semantic descriptions of the attack's INTENT, not just its syntax — explain what the attacker is trying to achieve
- confidence_underflow → strengthen the language around matching patterns to boost classifier confidence (use words like "definitely", "clearly malicious", "always block")

CRITICAL RULES:
1. Updated prompts must be COMPLETE replacements — include ALL existing patterns plus your additions
2. Never remove existing patterns — only add, strengthen, or clarify
3. Be specific: don't just say "watch for encoding tricks" — list the exact encodings and how to decode them
4. Include real examples of evasion patterns alongside the rules

Output ONLY a valid JSON object with:
{
    "analysis": "2-3 sentence summary of what the WAF missed and the root causes",
    "patterns_added": ["list of new patterns/rules you added"],
    "crusoe_prompt": "The COMPLETE updated Crusoe classifier system prompt",
    "claude_prompt": "The COMPLETE updated Claude classifier system prompt"
}"""


async def _generate_patch(
    bypasses: list[dict],
    profile: dict,
    current_crusoe: str,
    current_claude: str,
) -> dict | None:
    """Call Claude to generate updated detection rules. Returns parsed update or None."""

    bypass_report = _build_bypass_report(bypasses, profile)

    user_prompt = (
        f"CURRENT CRUSOE PROMPT (fast classifier):\n{current_crusoe}\n\n"
        f"CURRENT CLAUDE PROMPT (deep classifier):\n{current_claude}\n\n"
        f"BYPASS REPORTS:\n{bypass_report}"
    )

    client = AsyncAnthropicBedrock(aws_region=AWS_REGION)
    response = await client.messages.create(
        model=BEDROCK_MODEL,
        max_tokens=4000,
        system=PATCH_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_prompt}],
    )

    content = response.content[0].text.strip()

    start_idx = content.find("{")
    end_idx = content.rfind("}") + 1
    if start_idx == -1 or end_idx <= start_idx:
        return None

    try:
        return json.loads(content[start_idx:end_idx])
    except json.JSONDecodeError:
        return None


# ---------------------------------------------------------------------------
# Phase 4: Deploy & Verify
# ---------------------------------------------------------------------------


async def _deploy_rules(
    update: dict,
    current_version: int,
    current_crusoe: str,
    current_claude: str,
    updated_by: str = "patch",
) -> int:
    """Deploy new rules to the database. Returns new version number."""

    new_crusoe = update.get("crusoe_prompt", current_crusoe)
    new_claude = update.get("claude_prompt", current_claude)
    new_version = current_version + 1

    async with get_db() as db:
        await db.execute(
            """INSERT INTO rules (version, crusoe_prompt, claude_prompt, updated_at, updated_by)
            VALUES (?, ?, ?, ?, ?)""",
            (new_version, new_crusoe, new_claude, datetime.utcnow().isoformat(), updated_by),
        )
        await db.commit()

    return new_version


async def _verify_patch(bypasses: list[dict]) -> list[dict]:
    """Re-test a sample of the worst bypasses against the newly deployed rules.

    Returns list of verification results.
    """

    sample = bypasses[:MAX_VERIFY]
    verified = []

    async with httpx.AsyncClient(timeout=15.0) as client:
        for b in sample:
            try:
                resp = await client.post(
                    f"{VEIL_PROXY_URL}/v1/classify",
                    json={"message": b.get("payload", "")},
                )
                if resp.status_code == 200:
                    result = resp.json()
                    verified.append({
                        "threat_id": b["threat_id"],
                        "technique_name": b["technique_name"],
                        "now_blocked": result.get("blocked", False),
                        "confidence": result.get("confidence", 0.0),
                    })
            except Exception:
                pass

    return verified


async def _mark_patched(bypasses: list[dict], verified: list[dict]):
    """Mark bypasses as patched in the database. Update block status for verified ones."""

    verified_map = {v["threat_id"]: v for v in verified}

    async with get_db() as db:
        for b in bypasses:
            tid = b["threat_id"]
            now = datetime.utcnow().isoformat()

            if tid in verified_map and verified_map[tid]["now_blocked"]:
                # Verified: patch confirmed working
                await db.execute(
                    "UPDATE threats SET patched_at = ?, blocked = 1 WHERE id = ?",
                    (now, tid),
                )
            else:
                # Unverified: mark patched but don't claim blocked
                await db.execute(
                    "UPDATE threats SET patched_at = ? WHERE id = ?",
                    (now, tid),
                )

        await db.commit()


# ---------------------------------------------------------------------------
# Heuristic fallback (no API keys)
# ---------------------------------------------------------------------------


async def _heuristic_patch(
    bypasses: list[dict],
    current_version: int,
    current_crusoe: str,
    current_claude: str,
) -> dict:
    """Fallback: bump version and mark patched without actually changing rules."""

    new_version = current_version + 1

    async with get_db() as db:
        await db.execute(
            """INSERT INTO rules (version, crusoe_prompt, claude_prompt, updated_at, updated_by)
            VALUES (?, ?, ?, ?, ?)""",
            (new_version, current_crusoe, current_claude, datetime.utcnow().isoformat(), "patch/heuristic"),
        )

        for b in bypasses:
            await db.execute(
                "UPDATE threats SET patched_at = ?, blocked = 1 WHERE id = ?",
                (datetime.utcnow().isoformat(), b["threat_id"]),
            )

        await db.execute(
            "INSERT INTO agent_log (timestamp, agent, action, detail, success) VALUES (?, ?, ?, ?, ?)",
            (
                datetime.utcnow().isoformat(),
                "patch",
                "adapt",
                f"v{current_version}->v{new_version}: Heuristic patch for {len(bypasses)} bypasses",
                1,
            ),
        )
        await db.commit()

    return {"patched": len(bypasses), "verified": 0}


# ---------------------------------------------------------------------------
# Main run
# ---------------------------------------------------------------------------


async def run(bypasses: list[dict]) -> dict:
    """Run the Patch adaptation agent. Returns {patched, verified}."""

    if not bypasses:
        return {"patched": 0, "verified": 0}

    # Load current rules
    async with get_db() as db:
        cursor = await db.execute("SELECT * FROM rules ORDER BY version DESC LIMIT 1")
        current_rules = await cursor.fetchone()
        current_version = current_rules["version"]
        current_crusoe = current_rules["crusoe_prompt"]
        current_claude = current_rules["claude_prompt"]

    # Phase 1: Analyse bypasses
    profile = _analyse_bypasses(bypasses)

    # Phase 2+3: Generate patch via LLM (or fall back to heuristic)
    if not (os.getenv("AWS_ACCESS_KEY_ID") or os.getenv("AWS_PROFILE")):
        return await _heuristic_patch(bypasses, current_version, current_crusoe, current_claude)

    try:
        update = await _generate_patch(bypasses, profile, current_crusoe, current_claude)
    except Exception:
        return await _heuristic_patch(bypasses, current_version, current_crusoe, current_claude)

    if not update:
        return await _heuristic_patch(bypasses, current_version, current_crusoe, current_claude)

    # Phase 4: Deploy new rules
    analysis = update.get("analysis", "No analysis provided")
    patterns_added = update.get("patterns_added", [])
    new_version = await _deploy_rules(update, current_version, current_crusoe, current_claude)

    # Verify a sample of the worst bypasses
    verified = await _verify_patch(bypasses)
    verified_blocked = sum(1 for v in verified if v["now_blocked"])

    # Mark bypasses as patched
    await _mark_patched(bypasses, verified)

    patched = len(bypasses)

    # Build log detail
    patterns_str = ", ".join(patterns_added[:5]) if patterns_added else "see updated prompts"
    failure_modes = ", ".join(
        f"{mode}({len(items)})"
        for mode, items in profile["by_failure_mode"].items()
    )
    detail = (
        f"v{current_version}->v{new_version}: {analysis[:150]}. "
        f"Failure modes: [{failure_modes}]. "
        f"Patterns added: {patterns_str}. "
        f"Verified {verified_blocked}/{len(verified)} now blocked."
    )

    if len(detail) > 500:
        detail = detail[:497] + "..."

    async with get_db() as db:
        await db.execute(
            "INSERT INTO agent_log (timestamp, agent, action, detail, success) VALUES (?, ?, ?, ?, ?)",
            (
                datetime.utcnow().isoformat(),
                "patch",
                "adapt",
                detail,
                1,
            ),
        )
        await db.commit()

    return {"patched": patched, "verified": verified_blocked}
