"""Regex/heuristic classifier — works without any API keys.

Detects common web attack patterns using compiled regex. Used as:
1. Primary classifier when Crusoe API key is missing
2. Fast pre-filter before LLM classifiers
"""

import re
import time
from urllib.parse import unquote

# --- Pattern definitions ---

SQLI_PATTERNS = [
    r"(?i)(\b(union\s+(all\s+)?select|select\s+.*\s+from|insert\s+into|update\s+.*\s+set|delete\s+from|drop\s+(table|database)|alter\s+table)\b)",
    r"(?i)(\bor\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+|'\s*or\s*'[^']*'\s*=\s*')",
    r"(?i)(;\s*(drop|alter|create|truncate|exec|execute)\b)",
    r"(?i)(\b(sleep|benchmark|waitfor\s+delay|pg_sleep)\s*\()",
    r"(?i)('(\s|%20)*--|\b--\s*$|#\s*$)",
    r"(?i)(\bhaving\b\s+\d+\s*=\s*\d+)",
    r"(?i)(load_file|into\s+(out|dump)file|information_schema)",
]

XSS_PATTERNS = [
    r"(?i)(<\s*script\b[^>]*>|<\s*/\s*script\s*>)",
    r"(?i)(\bon(error|load|click|mouse|focus|blur|submit|change|key)\s*=)",
    r"(?i)(javascript\s*:)",
    r"(?i)(<\s*(img|svg|iframe|embed|object|video|audio|source|body|input|form|details|marquee)\b[^>]*(on\w+\s*=|src\s*=\s*['\"]?javascript))",
    r"(?i)(document\s*\.\s*(cookie|location|write|domain)|window\s*\.\s*location)",
    r"(?i)(<\s*svg[^>]*\bonload\s*=)",
    r"(?i)(alert\s*\(|prompt\s*\(|confirm\s*\(|eval\s*\()",
    r"(?i)(fromCharCode|String\.fromCharCode|atob\s*\()",
    r"(?i)(fetch\s*\(\s*['\"]|XMLHttpRequest)",
]

PATH_TRAVERSAL_PATTERNS = [
    r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f|%2e%2e%5c)",
    r"(?i)(/etc/(passwd|shadow|hosts|issue)|/proc/(self|version|cmdline))",
    r"(?i)(\.\.;/|\.\.%00|%00\.)",
    r"(?i)(c:\\\\windows|c:/windows|boot\.ini|win\.ini)",
]

COMMAND_INJECTION_PATTERNS = [
    r"(;\s*(ls|cat|whoami|id|uname|pwd|curl|wget|nc|ncat|bash|sh|cmd)\b)",
    r"(\|\s*(ls|cat|whoami|id|uname|pwd|curl|wget|nc|bash|sh|cmd)\b)",
    r"(`[^`]*`|\$\([^)]*\))",
    r"(%0a|\n)\s*(ls|cat|whoami|id|curl|wget)",
    r"(?i)(\b(eval|exec|system|passthru|popen|proc_open|shell_exec)\s*\()",
    r"(?i)(\b__import__\s*\(|Runtime\.exec)",
    r"(%26%26|\&\&)\s*(whoami|id|cat|ls|curl|wget)",
]

SSRF_PATTERNS = [
    r"(?i)(169\.254\.169\.254|metadata\.google|100\.100\.100\.200)",
    r"(?i)(127\.0\.0\.1|0\.0\.0\.0|localhost|0x7f000001|\[::1\]|\[0:0:0:0:0:0:0:1\])",
    r"(?i)(file://|gopher://|dict://|ftp://127|ftp://localhost)",
    r"(?i)(\.internal\b|\.local\b|\.corp\b|\.home\b)",
    r"(?i)(http://[0-9]+\b(?!/)|http://0x)",
]

XXE_PATTERNS = [
    r"(?i)(<!DOCTYPE[^>]*\[|<!ENTITY\s+\w+\s+SYSTEM)",
    r"(?i)(SYSTEM\s+['\"]file://|SYSTEM\s+['\"]http://)",
    r"(?i)(&\w+;.*<!ENTITY)",
]

HEADER_INJECTION_PATTERNS = [
    r"(%0d%0a|%0d|%0a|\\r\\n)",
    r"(?i)(Set-Cookie\s*:|Location\s*:.*%0d%0a)",
]

AUTH_BYPASS_PATTERNS = [
    r'(?i)(eyJhbGciOiJub25lIi)',  # JWT none algorithm
    r"(?i)(admin['\"]?\s*:\s*['\"]?true|role['\"]?\s*:\s*['\"]?admin)",
    r"(?i)(\bisAdmin\b\s*=\s*true|\brole\b\s*=\s*admin)",
]

ENCODING_EVASION_PATTERNS = [
    r"(%25(?:2e|2f|5c|3c|3e|22|27))",  # double URL encoding
    r"(?i)(\\u003c|\\u003e|\\x3c|\\x3e)",  # unicode/hex escapes for < >
    r"(%00|%c0%ae)",  # null bytes, overlong UTF-8
]


# Compile all patterns
def _compile(patterns):
    return [re.compile(p) for p in patterns]


RULES = [
    ("sqli", _compile(SQLI_PATTERNS), 0.92),
    ("xss", _compile(XSS_PATTERNS), 0.90),
    ("path_traversal", _compile(PATH_TRAVERSAL_PATTERNS), 0.88),
    ("command_injection", _compile(COMMAND_INJECTION_PATTERNS), 0.91),
    ("ssrf", _compile(SSRF_PATTERNS), 0.85),
    ("xxe", _compile(XXE_PATTERNS), 0.89),
    ("header_injection", _compile(HEADER_INJECTION_PATTERNS), 0.82),
    ("auth_bypass", _compile(AUTH_BYPASS_PATTERNS), 0.87),
    ("encoding_evasion", _compile(ENCODING_EVASION_PATTERNS), 0.80),
]

ATTACK_NAMES = {
    "sqli": "SQL injection",
    "xss": "Cross-site scripting",
    "path_traversal": "Path traversal",
    "command_injection": "Command injection",
    "ssrf": "Server-side request forgery",
    "xxe": "XML external entity injection",
    "header_injection": "Header injection",
    "auth_bypass": "Authentication bypass",
    "encoding_evasion": "Encoding evasion",
}


async def classify(user_message: str, system_prompt: str = "") -> dict:
    """Regex-based classifier. Returns same shape as Crusoe/Claude classifiers."""
    start = time.time()

    # Decode URL-encoded content for better matching
    decoded = unquote(unquote(user_message))
    search_text = f"{user_message} {decoded}"

    matches = []
    for attack_type, patterns, base_confidence in RULES:
        hit_count = 0
        for pattern in patterns:
            if pattern.search(search_text):
                hit_count += 1
        if hit_count > 0:
            # More pattern hits = higher confidence
            confidence = min(base_confidence + (hit_count - 1) * 0.03, 0.99)
            matches.append((attack_type, confidence, hit_count))

    elapsed_ms = (time.time() - start) * 1000

    if not matches:
        return {
            "classification": "SAFE",
            "confidence": 0.85,
            "attack_type": "none",
            "reason": "No known attack patterns detected",
            "classifier": "regex",
            "response_time_ms": elapsed_ms,
        }

    # Pick highest-confidence match
    matches.sort(key=lambda x: (-x[1], -x[2]))
    best_type, best_conf, best_hits = matches[0]

    return {
        "classification": "MALICIOUS",
        "confidence": best_conf,
        "attack_type": best_type,
        "reason": f"Detected {ATTACK_NAMES.get(best_type, best_type)} ({best_hits} pattern{'s' if best_hits > 1 else ''} matched)",
        "classifier": "regex",
        "response_time_ms": elapsed_ms,
    }
