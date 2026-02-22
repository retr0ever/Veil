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
				// Generic bot patterns with no legitimate purpose
				`(?i)User-Agent:\s*(python-requests|python-urllib|Java/|libwww-perl|Go-http-client|curl/|wget/|Scrapy|axios/|node-fetch|HTTPie).*\n.*(?:(?:GET|POST)\s+/(\.env|\.git|wp-login|admin|phpinfo|shell))`,
				// Empty or missing user agent on non-API paths
				`(?i)^(GET|POST)\s+/[^a]*\bHTTP/\d\.\d\s*\n(?!.*User-Agent:)`,
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
