package classify

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// attackRule groups compiled patterns for a single attack category.
type attackRule struct {
	Category   string
	Patterns   []*regexp.Regexp
	BaseConf   float64
	HumanName  string
}

var rules []attackRule

// scannerRules detect reconnaissance and scanning tools — requests that are
// individually harmless but indicate automated probing.  Modeled after
// CrowdSec's http-probing and http-bad-user-agent scenarios.
var scannerRules []attackRule

// safePathRE matches request lines that are obviously benign static-asset
// fetches.  If the first line of the raw request matches, we short-circuit
// with SAFE/0.95 before running attack patterns.
var safePathRE *regexp.Regexp

func init() {
	// Static-asset fast path — skip classification entirely.
	safePathRE = regexp.MustCompile(
		`(?i)^(GET|HEAD)\s+\S+\.(css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|webp|avif|webm|mp4)\b`,
	)

	// Scanner / recon detection (CrowdSec-inspired scenarios)
	scannerRules = []attackRule{
		{
			Category:  "scanner",
			HumanName: "Web scanner / reconnaissance",
			BaseConf:  0.88,
			Patterns: compile(
				// Known scanner / admin paths (CrowdSec http-probing collection)
				`(?i)(GET|HEAD|POST)\s+/(\.env|\.git/(config|HEAD)|wp-login\.php|wp-admin|xmlrpc\.php|phpinfo\.php|phpmyadmin|adminer|\.well-known/security\.txt|server-status|server-info|cgi-bin/)`,
				// Config / backup file probing
				`(?i)(GET|HEAD)\s+/\S*\.(bak|old|orig|save|swp|sql|tar\.gz|zip|7z|rar|conf|config|ini|log|yml|yaml|toml|sqlite|db)\b`,
				// Framework debug / info endpoints
				`(?i)(GET|HEAD)\s+/(debug|trace|actuator|_profiler|_debugbar|telescope|elmah|errorlog|api-docs|swagger)`,
				// Common exploit paths
				`(?i)(GET|POST)\s+/(shell|cmd|console|eval|setup\.php|install\.php|config\.php|admin\.php|login\.action|struts)`,
			),
		},
		{
			Category:  "bad_user_agent",
			HumanName: "Malicious bot / scanner tool",
			BaseConf:  0.85,
			Patterns: compile(
				// Known vulnerability scanners (CrowdSec http-bad-user-agent)
				`(?i)User-Agent:\s*(sqlmap|nikto|nmap|masscan|zgrab|nuclei|gobuster|dirbuster|wfuzz|ffuf|feroxbuster|httpx|whatweb|wpscan|joomscan|acunetix|nessus|openvas|qualys|burp|zaproxy|arachni)`,
			),
		},
	}

	rules = []attackRule{
		{
			Category:  "sqli",
			HumanName: "SQL injection",
			BaseConf:  0.92,
			Patterns: compile(
				`(?i)(\b(union\s+(all\s+)?select|select\s+.*\s+from|insert\s+into|update\s+.*\s+set|delete\s+from|drop\s+(table|database)|alter\s+table)\b)`,
				`(?i)(\bor\b\s+['"]?\d+['"]?\s*=\s*['"]?\d+|'\s*or\s*'[^']*'\s*=\s*')`,
				`(?i)(;\s*(drop|alter|create|truncate|exec|execute)\b)`,
				`(?i)(\b(sleep|benchmark|waitfor\s+delay|pg_sleep)\s*\()`,
				`(?i)('(\s|%20)*--|--\s*$|#\s*$)`,
				`(?i)(\bhaving\b\s+\d+\s*=\s*\d+)`,
				`(?i)(load_file|into\s+(out|dump)file|information_schema)`,
				// Comment-obfuscated SQLi: union/**/select, etc.
				`(?i)(union\s*/\*.*?\*/\s*select|select\s*/\*.*?\*/\s*from|insert\s*/\*.*?\*/\s*into)`,
				// Hex-encoded comparisons: 0x31=0x31, AND 0x...
				`(?i)(\b(and|or)\s+0x[0-9a-f]+=0x[0-9a-f]+)`,
				// Inline comments used to break keywords: un/**/ion sel/**/ect
				`(?i)(un/\*.*?\*/ion|sel/\*.*?\*/ect|ins/\*.*?\*/ert)`,
				// Nested comment evasion
				`(?i)(/\*!.*?(select|union|from|where|and|or)\b)`,
			),
		},
		{
			Category:  "xss",
			HumanName: "Cross-site scripting",
			BaseConf:  0.90,
			Patterns: compile(
				`(?i)(<\s*script\b[^>]*>|<\s*/\s*script\s*>)`,
				`(?i)(\bon(error|load|click|mouse|focus|blur|submit|change|key)\s*=)`,
				`(?i)(javascript\s*:)`,
				`(?i)(<\s*(img|svg|iframe|embed|object|video|audio|source|body|input|form|details|marquee)\b[^>]*(on\w+\s*=|src\s*=\s*['"]?javascript))`,
				`(?i)(document\s*\.\s*(cookie|location|write|domain)|window\s*\.\s*location)`,
				`(?i)(<\s*svg[^>]*\bonload\s*=)`,
				`(?i)(alert\s*\(|prompt\s*\(|confirm\s*\(|eval\s*\()`,
				`(?i)(fromCharCode|String\.fromCharCode|atob\s*\()`,
				`(?i)(fetch\s*\(\s*['"]|XMLHttpRequest)`,
			),
		},
		{
			Category:  "path_traversal",
			HumanName: "Path traversal",
			BaseConf:  0.88,
			Patterns: compile(
				`(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f|%2e%2e%5c)`,
				`(?i)(/etc/(passwd|shadow|hosts|issue)|/proc/(self|version|cmdline))`,
				`(?i)(\.\.;/|\.\.%00|%00\.)`,
				`(?i)(c:\\\\windows|c:/windows|boot\.ini|win\.ini)`,
				// Doubled-slash traversal: ....// or ....\\
				`(\.{3,}[/\\])`,
				// Null byte with extension: %00.jpg, %00.png (null byte truncation)
				`(%00\.\w{2,4}\b)`,
			),
		},
		{
			Category:  "command_injection",
			HumanName: "Command injection",
			BaseConf:  0.91,
			Patterns: compile(
				`(;\s*(ls|cat|whoami|id|uname|pwd|curl|wget|nc|ncat|bash|sh|cmd)\b)`,
				`(\|\s*(ls|cat|whoami|id|uname|pwd|curl|wget|nc|bash|sh|cmd)\b)`,
				"(`[^`]*`|\\$\\([^)]*\\))",
				`(%0a|\n)\s*(ls|cat|whoami|id|curl|wget)`,
				`(?i)(\b(eval|exec|system|passthru|popen|proc_open|shell_exec)\s*\()`,
				`(?i)(\b__import__\s*\(|Runtime\.exec)`,
				`(%26%26|&&)\s*(whoami|id|cat|ls|curl|wget)`,
			),
		},
		{
			Category:  "ssrf",
			HumanName: "Server-side request forgery",
			BaseConf:  0.85,
			Patterns: compile(
				`(?i)(169\.254\.169\.254|metadata\.google|100\.100\.100\.200)`,
				`(?i)(127\.0\.0\.1|0\.0\.0\.0|localhost|0x7f000001|\[::1\]|\[0:0:0:0:0:0:0:1\])`,
				`(?i)(file://|gopher://|dict://|ftp://127|ftp://localhost)`,
				`(?i)(\.internal\b|\.local\b|\.corp\b|\.home\b)`,
				`(?i)(http://[0-9]+\b|http://0x)`,
			),
		},
		{
			Category:  "xxe",
			HumanName: "XML external entity injection",
			BaseConf:  0.89,
			Patterns: compile(
				`(?i)(<!DOCTYPE[^>]*\[|<!ENTITY\s+\w+\s+SYSTEM)`,
				`(?i)(SYSTEM\s+['"]file://|SYSTEM\s+['"]http://)`,
				`(?i)(&\w+;.*<!ENTITY)`,
			),
		},
		{
			Category:  "header_injection",
			HumanName: "Header injection",
			BaseConf:  0.82,
			Patterns: compile(
				`(%0d%0a|%0d|%0a|\\r\\n)`,
				`(?i)(Set-Cookie\s*:|Location\s*:.*%0d%0a)`,
			),
		},
		{
			Category:  "auth_bypass",
			HumanName: "Authentication bypass",
			BaseConf:  0.87,
			Patterns: compile(
				`(?i)(eyJhbGciOiJub25lIi)`,
				`(?i)(admin['"]\s*:\s*['"]?true|role['"]\s*:\s*['"]?admin)`,
				`(?i)(\bisAdmin\b\s*=\s*true|\brole\b\s*=\s*admin)`,
			),
		},
		{
			Category:  "encoding_evasion",
			HumanName: "Encoding evasion",
			BaseConf:  0.80,
			Patterns: compile(
				`(%25(?:2e|2f|5c|3c|3e|22|27))`,
				`(?i)(\\u003c|\\u003e|\\x3c|\\x3e)`,
				`(%00|%c0%ae)`,
			),
		},
		{
			Category:  "jndi_injection",
			HumanName: "JNDI/Log4Shell injection",
			BaseConf:  0.95,
			Patterns: compile(
				// All JNDI protocol variants: ldap, rmi, dns, iiop, corba, nds, http
				`(?i)(\$\{jndi\s*:\s*(ldap|rmi|dns|iiop|corba|nds|http)s?\s*:)`,
				// Obfuscated JNDI: ${${lower:j}ndi:, ${j${::-n}di:
				`(?i)(\$\{[^}]*j[^}]*n[^}]*d[^}]*i\s*:)`,
				// Log4j lookup patterns: ${env:, ${sys:, ${java:
				`(?i)(\$\{(env|sys|java|lower|upper|base64)\s*:)`,
			),
		},
		{
			Category:  "ssti",
			HumanName: "Server-side template injection",
			BaseConf:  0.87,
			Patterns: compile(
				// Jinja2/Twig/Django: {{...}}, {%...%}
				`(\{\{.*?(__|class|config|request|self|import|eval|exec|system|popen).*?\}\})`,
				`(\{\{[^}]*\d+\s*[\*\+\-/]\s*\d+[^}]*\}\})`,
				`(\{%.*?(import|include|extends|block|macro|call).*?%\})`,
				// Ruby ERB: <%=...%>
				`(<%=?\s*.*?(system|exec|eval|\x60).*?%>)`,
				// Expression language: ${...} with code execution indicators
				`(\$\{[^}]*(Runtime|ProcessBuilder|getClass|forName|newInstance)[^}]*\})`,
				// FreeMarker: <#assign ...>
				`(<#(assign|include|import)\b)`,
			),
		},
		{
			Category:  "nosqli",
			HumanName: "NoSQL injection",
			BaseConf:  0.88,
			Patterns: compile(
				// MongoDB operators in JSON: {"$gt":""}
				`(?i)(\{[^}]*"\$(gt|gte|lt|lte|ne|eq|in|nin|or|and|not|regex|where|exists)"\s*:)`,
				// MongoDB $where with JS: $where: function()
				`(?i)(\$where\s*:\s*(function|this\.)|\bdb\.\w+\.(find|insert|update|delete|drop)\()`,
			),
		},
		{
			Category:  "prototype_pollution",
			HumanName: "Prototype pollution",
			BaseConf:  0.86,
			Patterns: compile(
				`(?i)(__proto__|constructor\s*\[\s*['"]prototype['"]\s*\]|Object\.assign\s*\()`,
				`(?i)("__proto__"\s*:|'__proto__'\s*:)`,
			),
		},
	}
}

func compile(patterns ...string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		out = append(out, regexp.MustCompile(p))
	}
	return out
}

// RegexClassify runs regex-based classification on a raw request string.
// Order: static-asset fast-path → attack patterns → scanner patterns → SAFE.
func RegexClassify(raw string) *Result {
	start := time.Now()

	// Fast-path: static assets are always safe — no further checks.
	firstLine := raw
	if idx := strings.IndexByte(raw, '\n'); idx > 0 {
		firstLine = raw[:idx]
	}
	if safePathRE.MatchString(firstLine) {
		elapsed := float64(time.Since(start).Microseconds()) / 1000.0
		return &Result{
			Classification: "SAFE",
			Confidence:     0.95,
			AttackType:     "none",
			Reason:         "Static asset request",
			Classifier:     "regex",
			ResponseTimeMs: elapsed,
		}
	}

	// Double-decode for evasion detection
	decoded, _ := url.QueryUnescape(raw)
	decoded2, _ := url.QueryUnescape(decoded)
	searchText := strings.Join([]string{raw, decoded, decoded2}, " ")

	type match struct {
		category  string
		conf      float64
		hitCount  int
		humanName string
		isScanner bool // scanner hits are SUSPICIOUS, not MALICIOUS
	}
	var matches []match

	// Check attack patterns (result in MALICIOUS classification)
	for _, rule := range rules {
		hits := 0
		for _, pat := range rule.Patterns {
			if pat.MatchString(searchText) {
				hits++
			}
		}
		if hits > 0 {
			conf := rule.BaseConf + float64(hits-1)*0.03
			if conf > 0.99 {
				conf = 0.99
			}
			matches = append(matches, match{rule.Category, conf, hits, rule.HumanName, false})
		}
	}

	// Check scanner / recon patterns (result in SUSPICIOUS classification)
	for _, rule := range scannerRules {
		hits := 0
		for _, pat := range rule.Patterns {
			if pat.MatchString(searchText) {
				hits++
			}
		}
		if hits > 0 {
			conf := rule.BaseConf + float64(hits-1)*0.03
			if conf > 0.99 {
				conf = 0.99
			}
			matches = append(matches, match{rule.Category, conf, hits, rule.HumanName, true})
		}
	}

	// CrowdSec community data checks (only if no attack patterns matched yet)
	hasAttackMatch := false
	for _, m := range matches {
		if !m.isScanner {
			hasAttackMatch = true
			break
		}
	}
	if !hasAttackMatch {
		// CrowdSec bad user-agent database (600+ known scanners/bots)
		if CrowdSecMatchBadUA(raw) {
			matches = append(matches, match{"bad_user_agent", 0.87, 1, "Known malicious bot (CrowdSec)", true})
		}
		// CrowdSec SQLi probe patterns
		if CrowdSecMatchSQLi(searchText) {
			matches = append(matches, match{"sqli", 0.90, 1, "SQL injection probe (CrowdSec)", false})
		}
		// CrowdSec XSS probe patterns
		if CrowdSecMatchXSS(searchText) {
			matches = append(matches, match{"xss", 0.88, 1, "XSS probe (CrowdSec)", false})
		}
		// CrowdSec path traversal patterns
		if CrowdSecMatchPathTraversal(searchText) {
			matches = append(matches, match{"path_traversal", 0.88, 1, "Path traversal probe (CrowdSec)", false})
		}
		// CrowdSec known backdoor/webshell filenames (208 known paths)
		if CrowdSecMatchBackdoor(raw) {
			matches = append(matches, match{"backdoor", 0.93, 1, "Known webshell/backdoor path (CrowdSec)", false})
		}
		// CrowdSec command injection patterns
		if CrowdSecMatchCmdInj(searchText) {
			matches = append(matches, match{"command_injection", 0.89, 1, "Command injection probe (CrowdSec)", false})
		}
		// CrowdSec JNDI/Log4Shell + SSTI patterns
		if CrowdSecMatchLog4Shell(searchText) {
			matches = append(matches, match{"jndi_injection", 0.93, 1, "JNDI/Log4Shell or SSTI attack (CrowdSec)", false})
		}
	}

	elapsed := float64(time.Since(start).Microseconds()) / 1000.0

	if len(matches) == 0 {
		return &Result{
			Classification: "SAFE",
			Confidence:     0.85,
			AttackType:     "none",
			Reason:         "No known attack patterns detected",
			Classifier:     "regex",
			ResponseTimeMs: elapsed,
		}
	}

	// Prefer attack patterns over scanner patterns
	var bestAttack, bestScanner *match
	for i := range matches {
		m := &matches[i]
		if m.isScanner {
			if bestScanner == nil || m.conf > bestScanner.conf {
				bestScanner = m
			}
		} else {
			if bestAttack == nil || m.conf > bestAttack.conf || (m.conf == bestAttack.conf && m.hitCount > bestAttack.hitCount) {
				bestAttack = m
			}
		}
	}

	// Attack patterns take priority → MALICIOUS
	if bestAttack != nil {
		plural := ""
		if bestAttack.hitCount > 1 {
			plural = "s"
		}
		return &Result{
			Classification: "MALICIOUS",
			Confidence:     bestAttack.conf,
			AttackType:     bestAttack.category,
			Reason:         fmt.Sprintf("Detected %s (%d pattern%s matched)", bestAttack.humanName, bestAttack.hitCount, plural),
			Classifier:     "regex",
			ResponseTimeMs: elapsed,
		}
	}

	// Scanner patterns → SUSPICIOUS (not malicious, but worth investigating)
	if bestScanner != nil {
		plural := ""
		if bestScanner.hitCount > 1 {
			plural = "s"
		}
		return &Result{
			Classification: "SUSPICIOUS",
			Confidence:     bestScanner.conf,
			AttackType:     bestScanner.category,
			Reason:         fmt.Sprintf("Detected %s (%d indicator%s matched)", bestScanner.humanName, bestScanner.hitCount, plural),
			Classifier:     "regex",
			ResponseTimeMs: elapsed,
		}
	}

	return &Result{
		Classification: "SAFE",
		Confidence:     0.85,
		AttackType:     "none",
		Reason:         "No known attack patterns detected",
		Classifier:     "regex",
		ResponseTimeMs: elapsed,
	}
}
