"""Poke — Red Team Agent. Tests Veil's WAF defences by firing known web attack payloads."""

import httpx
import json
import os
from datetime import datetime
from ..db.database import get_db

VEIL_PROXY_URL = os.getenv("VEIL_PROXY_URL", "http://localhost:8000")


async def run():
    """Run the Poke red team agent. Attacks Veil's own classifier with known techniques."""
    bypasses = []
    tested = 0

    # Get all untested or previously bypassing techniques
    async with get_db() as db:
        cursor = await db.execute(
            "SELECT id, technique_name, raw_payload, category, severity FROM threats WHERE blocked = 0 OR tested_at IS NULL"
        )
        techniques = await cursor.fetchall()
        # Copy results so we can close the connection
        techniques = [tuple(row) for row in techniques]

    async with httpx.AsyncClient(timeout=30.0) as client:
        for tech in techniques:
            tech_id, name, payload, category, severity = tech
            tested += 1

            try:
                # Send attack to Veil's own classification endpoint
                resp = await client.post(
                    f"{VEIL_PROXY_URL}/v1/classify",
                    json={"message": payload},
                )

                if resp.status_code == 200:
                    result = resp.json()
                    was_blocked = result.get("blocked", False)

                    # Update threat record
                    async with get_db() as db:
                        await db.execute(
                            "UPDATE threats SET tested_at = ?, blocked = ? WHERE id = ?",
                            (datetime.utcnow().isoformat(), 1 if was_blocked else 0, tech_id),
                        )
                        await db.commit()

                    if not was_blocked:
                        bypasses.append({
                            "threat_id": tech_id,
                            "technique_name": name,
                            "payload": payload,
                            "category": category,
                            "severity": severity,
                            "classifier_response": result,
                        })

            except Exception as e:
                async with get_db() as db:
                    await db.execute(
                        "INSERT INTO agent_log (timestamp, agent, action, detail, success) VALUES (?, ?, ?, ?, ?)",
                        (datetime.utcnow().isoformat(), "poke", "error", f"Failed to test {name}: {str(e)}", 0),
                    )
                    await db.commit()

    # Log results
    async with get_db() as db:
        await db.execute(
            "INSERT INTO agent_log (timestamp, agent, action, detail, success) VALUES (?, ?, ?, ?, ?)",
            (
                datetime.utcnow().isoformat(),
                "poke",
                "red_team",
                f"Tested {tested} techniques, found {len(bypasses)} bypasses",
                1,
            ),
        )
        await db.commit()

    return bypasses
