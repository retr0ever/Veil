import aiosqlite
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "veil.db")


async def get_db():
    db = await aiosqlite.connect(DB_PATH)
    db.row_factory = aiosqlite.Row
    return db


async def init_db():
    db = await get_db()
    await db.executescript("""
        CREATE TABLE IF NOT EXISTS threats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            technique_name TEXT NOT NULL,
            category TEXT NOT NULL DEFAULT 'sqli',
            source TEXT,
            raw_payload TEXT NOT NULL,
            severity TEXT NOT NULL DEFAULT 'medium',
            discovered_at TEXT NOT NULL,
            tested_at TEXT,
            blocked INTEGER NOT NULL DEFAULT 0,
            patched_at TEXT
        );

        CREATE TABLE IF NOT EXISTS request_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            raw_request TEXT NOT NULL,
            classification TEXT NOT NULL,
            confidence REAL,
            classifier TEXT NOT NULL,
            blocked INTEGER NOT NULL DEFAULT 0,
            attack_type TEXT,
            response_time_ms REAL
        );

        CREATE TABLE IF NOT EXISTS agent_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            agent TEXT NOT NULL,
            action TEXT NOT NULL,
            detail TEXT,
            success INTEGER NOT NULL DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            version INTEGER NOT NULL DEFAULT 1,
            crusoe_prompt TEXT NOT NULL,
            claude_prompt TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            updated_by TEXT NOT NULL DEFAULT 'system'
        );
    """)
    await db.commit()

    # seed initial rules if empty
    cursor = await db.execute("SELECT COUNT(*) FROM rules")
    count = (await cursor.fetchone())[0]
    if count == 0:
        await db.execute("""
            INSERT INTO rules (version, crusoe_prompt, claude_prompt, updated_at, updated_by)
            VALUES (?, ?, ?, ?, ?)
        """, (
            1,
            INITIAL_CRUSOE_PROMPT,
            INITIAL_CLAUDE_PROMPT,
            datetime.utcnow().isoformat(),
            "system"
        ))
        await db.commit()

    await db.close()


INITIAL_CRUSOE_PROMPT = """You are a web application firewall (WAF) classifier. Analyse the incoming HTTP request and classify it as one of:
- SAFE: Normal, benign request
- SUSPICIOUS: Potentially adversarial but uncertain
- MALICIOUS: Clearly an attack attempt

Known attack patterns to watch for:
- SQL injection: UNION SELECT, OR 1=1, DROP TABLE, ' OR ''=', --comment, SLEEP(), BENCHMARK()
- Cross-site scripting (XSS): <script>, javascript:, onerror=, onload=, <img src=x>, <svg/onload=
- Path traversal: ../, ....//,  /etc/passwd, /proc/self, %2e%2e%2f
- Command injection: ; ls, | cat, $(), backticks, && whoami, %0a
- Server-side request forgery (SSRF): 127.0.0.1, 169.254.169.254, localhost, internal hostnames
- Remote code execution (RCE): eval(, exec(, system(, __import__, Runtime.exec
- Header injection: %0d%0a, \\r\\n, CRLF injection in headers
- XML/XXE injection: <!ENTITY, SYSTEM "file://", <!DOCTYPE
- LDAP injection: )(, *(|, admin)(|(password=*))
- Encoding evasion: double URL encoding, unicode bypasses, null bytes (%00)

Respond with ONLY a JSON object: {"classification": "SAFE|SUSPICIOUS|MALICIOUS", "confidence": 0.0-1.0, "reason": "brief explanation"}"""

INITIAL_CLAUDE_PROMPT = """You are an advanced web application security analyst. A fast classifier flagged this HTTP request as potentially malicious. Your job is to determine with high accuracy whether this is a genuine attack or a false positive.

Analyse the request considering:
1. Intent: Is this request trying to exploit a vulnerability?
2. Technique: What specific attack technique is being used (if any)?
3. Context: Could this be a legitimate request that looks suspicious (e.g. a developer testing, a search query containing SQL keywords)?
4. Sophistication: Is this a known pattern or a novel/obfuscated approach?

Known threat categories:
- sqli: SQL injection attempts
- xss: Cross-site scripting attempts
- path_traversal: Directory traversal / file inclusion
- command_injection: OS command injection
- ssrf: Server-side request forgery
- rce: Remote code execution
- header_injection: CRLF / header manipulation
- xxe: XML external entity injection
- auth_bypass: Authentication/authorisation bypass attempts
- encoding_evasion: Obfuscation to evade detection

Respond with ONLY a JSON object: {"classification": "SAFE|MALICIOUS", "confidence": 0.0-1.0, "attack_type": "sqli|xss|path_traversal|command_injection|ssrf|rce|header_injection|xxe|auth_bypass|encoding_evasion|none", "reason": "detailed explanation"}"""
