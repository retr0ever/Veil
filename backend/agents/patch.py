"""Patch — Adaptation Agent. Analyses bypasses and updates detection rules."""

import anthropic
import json
import os
from datetime import datetime
from ..db.database import get_db

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")


async def run(bypasses: list[dict]):
    """Run the Patch adaptation agent. Analyses bypasses and strengthens defences."""
    if not bypasses:
        return {"patched": 0, "verified": 0}

    db = await get_db()
    client = anthropic.AsyncAnthropic(api_key=ANTHROPIC_API_KEY)

    # Get current rules
    cursor = await db.execute("SELECT * FROM rules ORDER BY version DESC LIMIT 1")
    current_rules = await cursor.fetchone()
    current_crusoe_prompt = current_rules[2]  # crusoe_prompt
    current_claude_prompt = current_rules[3]  # claude_prompt
    current_version = current_rules[1]  # version

    # Build bypass report for Claude
    bypass_report = "\n\n".join([
        f"BYPASS #{i+1}:\n"
        f"Technique: {b['technique_name']}\n"
        f"Category: {b['category']}\n"
        f"Severity: {b['severity']}\n"
        f"Payload: {b['payload'][:300]}\n"
        f"Classifier said: {json.dumps(b.get('classifier_response', {}))}"
        for i, b in enumerate(bypasses)
    ])

    # Ask Claude to analyse and generate updated rules
    response = await client.messages.create(
        model="claude-sonnet-4-5-20250929",
        max_tokens=3000,
        system="""You are an AI security engineer. You are given bypass reports showing attacks that got past the current firewall rules. Analyse WHY each bypass succeeded and generate UPDATED detection prompts.

You must output ONLY a JSON object with:
{
    "analysis": "Brief explanation of what the current rules missed",
    "crusoe_prompt": "The COMPLETE updated system prompt for the fast Crusoe classifier. Include ALL existing patterns plus new ones to catch these bypasses.",
    "claude_prompt": "The COMPLETE updated system prompt for the deep Claude classifier. Include ALL existing patterns plus new ones."
}

IMPORTANT: The updated prompts must be COMPLETE replacements, not patches. Include everything from the current prompts plus additions.""",
        messages=[
            {
                "role": "user",
                "content": f"CURRENT CRUSOE PROMPT:\n{current_crusoe_prompt}\n\nCURRENT CLAUDE PROMPT:\n{current_claude_prompt}\n\nBYPASS REPORTS:\n{bypass_report}",
            }
        ],
    )

    content = response.content[0].text.strip()
    patched = 0
    verified = 0

    try:
        start_idx = content.find("{")
        end_idx = content.rfind("}") + 1
        if start_idx != -1 and end_idx > start_idx:
            update = json.loads(content[start_idx:end_idx])
            new_crusoe = update.get("crusoe_prompt", current_crusoe_prompt)
            new_claude = update.get("claude_prompt", current_claude_prompt)
            analysis = update.get("analysis", "No analysis provided")

            # Deploy new rules
            new_version = current_version + 1
            await db.execute(
                """INSERT INTO rules (version, crusoe_prompt, claude_prompt, updated_at, updated_by)
                VALUES (?, ?, ?, ?, ?)""",
                (new_version, new_crusoe, new_claude, datetime.utcnow().isoformat(), "patch"),
            )

            # Mark bypasses as patched
            for b in bypasses:
                await db.execute(
                    "UPDATE threats SET patched_at = ?, blocked = 1 WHERE id = ?",
                    (datetime.utcnow().isoformat(), b["threat_id"]),
                )
                patched += 1

            # Log the adaptation
            await db.execute(
                "INSERT INTO agent_log (timestamp, agent, action, detail, success) VALUES (?, ?, ?, ?, ?)",
                (
                    datetime.utcnow().isoformat(),
                    "patch",
                    "adapt",
                    f"v{current_version}→v{new_version}: {analysis[:200]}. Patched {patched} bypasses.",
                    1,
                ),
            )

    except (json.JSONDecodeError, KeyError) as e:
        await db.execute(
            "INSERT INTO agent_log (timestamp, agent, action, detail, success) VALUES (?, ?, ?, ?, ?)",
            (datetime.utcnow().isoformat(), "patch", "error", f"Failed to parse update: {str(e)}", 0),
        )

    await db.commit()
    await db.close()
    return {"patched": patched, "verified": verified}
