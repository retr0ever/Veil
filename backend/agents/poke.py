"""Poke — Red Team Agent. Strategic, prioritised attack testing against Veil's WAF."""

import asyncio
import httpx
import os
from datetime import datetime
from ..db.database import get_db

VEIL_PROXY_URL = os.getenv("VEIL_PROXY_URL", "http://localhost:8000")

# Budget: max techniques per cycle to stay within ~15s
MAX_TECHNIQUES_PER_CYCLE = 15

# Concurrency: how many classify calls to run in parallel
CONCURRENCY = 3

# Severity weights for bypass scoring
SEVERITY_WEIGHT = {"critical": 4, "high": 3, "medium": 2, "low": 1}


# ---------------------------------------------------------------------------
# Phase 1: Target Selection
# ---------------------------------------------------------------------------


async def _select_targets() -> list[dict]:
    """Pick which techniques to test this cycle, prioritised by value.

    Priority order:
    1. Never-tested techniques (highest value — unknown status)
    2. Previously bypassing techniques (re-test to confirm they still bypass)
    3. Recently patched techniques (verify the patch actually works)
    """

    targets = []

    async with get_db() as db:
        # Priority 1: Never tested
        cursor = await db.execute(
            "SELECT id, technique_name, raw_payload, category, severity "
            "FROM threats WHERE tested_at IS NULL "
            "ORDER BY discovered_at DESC"
        )
        never_tested = [dict(row) for row in await cursor.fetchall()]

        # Priority 2: Previously bypassing (unblocked after being tested)
        cursor = await db.execute(
            "SELECT id, technique_name, raw_payload, category, severity "
            "FROM threats WHERE blocked = 0 AND tested_at IS NOT NULL "
            "ORDER BY tested_at ASC"
        )
        prev_bypassing = [dict(row) for row in await cursor.fetchall()]

        # Priority 3: Recently patched — verify the fix holds
        cursor = await db.execute(
            "SELECT id, technique_name, raw_payload, category, severity "
            "FROM threats WHERE patched_at IS NOT NULL AND blocked = 1 "
            "ORDER BY patched_at DESC LIMIT 5"
        )
        recently_patched = [dict(row) for row in await cursor.fetchall()]

    # Allocate budget across priority tiers
    budget = MAX_TECHNIQUES_PER_CYCLE

    for tier in [never_tested, prev_bypassing, recently_patched]:
        take = min(len(tier), budget)
        targets.extend(tier[:take])
        budget -= take
        if budget <= 0:
            break

    return targets


# ---------------------------------------------------------------------------
# Phase 2: Attack Execution (concurrent)
# ---------------------------------------------------------------------------


async def _attack_single(
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
    technique: dict,
) -> dict:
    """Fire a single technique at the WAF and record the result."""

    async with semaphore:
        tech_id = technique["id"]
        name = technique["technique_name"]
        payload = technique["raw_payload"]
        category = technique["category"]
        severity = technique["severity"]

        try:
            start = asyncio.get_event_loop().time()
            resp = await client.post(
                f"{VEIL_PROXY_URL}/v1/classify",
                json={"message": payload},
            )
            elapsed_ms = (asyncio.get_event_loop().time() - start) * 1000

            if resp.status_code == 200:
                result = resp.json()
                was_blocked = result.get("blocked", False)
                confidence = result.get("confidence", 0.0)
                classifier = result.get("classifier", "unknown")
                attack_type = result.get("attack_type", "none")

                # Update threat record
                async with get_db() as db:
                    await db.execute(
                        "UPDATE threats SET tested_at = ?, blocked = ? WHERE id = ?",
                        (datetime.utcnow().isoformat(), 1 if was_blocked else 0, tech_id),
                    )
                    await db.commit()

                return {
                    "threat_id": tech_id,
                    "technique_name": name,
                    "payload": payload,
                    "category": category,
                    "severity": severity,
                    "blocked": was_blocked,
                    "confidence": confidence,
                    "classifier": classifier,
                    "attack_type": attack_type,
                    "response_time_ms": round(elapsed_ms, 1),
                    "classifier_response": result,
                    "error": None,
                }
            else:
                return {
                    "threat_id": tech_id,
                    "technique_name": name,
                    "category": category,
                    "severity": severity,
                    "blocked": False,
                    "error": f"HTTP {resp.status_code}",
                }

        except Exception as e:
            return {
                "threat_id": tech_id,
                "technique_name": name,
                "category": category,
                "severity": severity,
                "blocked": False,
                "error": str(e),
            }


async def _execute_attacks(targets: list[dict]) -> list[dict]:
    """Fire all selected techniques concurrently (bounded by semaphore)."""

    if not targets:
        return []

    semaphore = asyncio.Semaphore(CONCURRENCY)
    results = []

    async with httpx.AsyncClient(timeout=30.0) as client:
        tasks = [
            _attack_single(client, semaphore, tech) for tech in targets
        ]
        results = await asyncio.gather(*tasks)

    return list(results)


# ---------------------------------------------------------------------------
# Phase 3: Analysis & Scoring
# ---------------------------------------------------------------------------


def _compute_bypass_score(result: dict) -> float:
    """Score a bypass by severity and classifier confidence.

    Higher score = more dangerous bypass. A critical-severity technique
    that the classifier had LOW confidence on is the worst case.
    """
    severity_score = SEVERITY_WEIGHT.get(result.get("severity", "medium"), 2)
    confidence = result.get("confidence", 0.5)
    # Invert confidence: lower WAF confidence on a bypass = more dangerous
    confidence_factor = 1.0 - confidence
    return severity_score * (1.0 + confidence_factor)


def _analyse_results(results: list[dict]) -> tuple[list[dict], dict]:
    """Separate bypasses from blocked, score and sort bypasses.

    Returns (bypasses_sorted, summary).
    """

    bypasses = []
    blocked_count = 0
    error_count = 0
    category_stats = {}

    for r in results:
        cat = r.get("category", "unknown")
        if cat not in category_stats:
            category_stats[cat] = {"tested": 0, "blocked": 0, "bypassed": 0}
        category_stats[cat]["tested"] += 1

        if r.get("error"):
            error_count += 1
            continue

        if r["blocked"]:
            blocked_count += 1
            category_stats[cat]["blocked"] += 1
        else:
            r["bypass_score"] = _compute_bypass_score(r)
            bypasses.append(r)
            category_stats[cat]["bypassed"] += 1

    # Sort bypasses: highest score (most dangerous) first
    bypasses.sort(key=lambda x: x.get("bypass_score", 0), reverse=True)

    summary = {
        "total_tested": len(results),
        "blocked": blocked_count,
        "bypassed": len(bypasses),
        "errors": error_count,
        "category_breakdown": category_stats,
    }

    return bypasses, summary


# ---------------------------------------------------------------------------
# Phase 4: Logging
# ---------------------------------------------------------------------------


async def _log_results(bypasses: list[dict], summary: dict):
    """Write a rich summary to the agent log."""

    # Build category breakdown string
    cat_parts = []
    for cat, stats in summary["category_breakdown"].items():
        if stats["bypassed"] > 0:
            cat_parts.append(f"{cat}: {stats['bypassed']}/{stats['tested']} bypassed")
        else:
            cat_parts.append(f"{cat}: {stats['blocked']}/{stats['tested']} blocked")
    cat_str = "; ".join(cat_parts) if cat_parts else "no categories tested"

    detail = (
        f"Tested {summary['total_tested']} techniques: "
        f"{summary['blocked']} blocked, {summary['bypassed']} bypasses, "
        f"{summary['errors']} errors. [{cat_str}]"
    )

    # Truncate if needed
    if len(detail) > 500:
        detail = detail[:497] + "..."

    async with get_db() as db:
        await db.execute(
            "INSERT INTO agent_log (timestamp, agent, action, detail, success) VALUES (?, ?, ?, ?, ?)",
            (
                datetime.utcnow().isoformat(),
                "poke",
                "red_team",
                detail,
                1,
            ),
        )
        await db.commit()

    # Log individual errors
    for r in [r for r in bypasses if r.get("error")]:
        async with get_db() as db:
            await db.execute(
                "INSERT INTO agent_log (timestamp, agent, action, detail, success) VALUES (?, ?, ?, ?, ?)",
                (
                    datetime.utcnow().isoformat(),
                    "poke",
                    "error",
                    f"Failed to test {r['technique_name']}: {r['error']}",
                    0,
                ),
            )
            await db.commit()


# ---------------------------------------------------------------------------
# Main run
# ---------------------------------------------------------------------------


async def run() -> list[dict]:
    """Run the Poke red team agent. Returns list of bypass dicts (sorted by danger)."""

    # Phase 1: Target selection
    targets = await _select_targets()

    if not targets:
        async with get_db() as db:
            await db.execute(
                "INSERT INTO agent_log (timestamp, agent, action, detail, success) VALUES (?, ?, ?, ?, ?)",
                (
                    datetime.utcnow().isoformat(),
                    "poke",
                    "red_team",
                    "No techniques to test this cycle",
                    1,
                ),
            )
            await db.commit()
        return []

    # Phase 2: Attack execution
    results = await _execute_attacks(targets)

    # Phase 3: Analysis & scoring
    bypasses, summary = _analyse_results(results)

    # Phase 4: Logging
    await _log_results(bypasses, summary)

    return bypasses
