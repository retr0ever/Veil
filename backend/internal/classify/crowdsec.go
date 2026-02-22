package classify

import (
	"bufio"
	"embed"
	"regexp"
	"strings"
)

//go:embed crowdsec-data/*.txt
var crowdsecData embed.FS

// Compiled CrowdSec pattern sets — loaded once at init.
var (
	crowdsecBadUAs          []*regexp.Regexp
	crowdsecSQLiPatterns    []string // plain string contains-match (URL-decoded)
	crowdsecXSSPatterns     []string
	crowdsecPathPatterns    []string
	crowdsecBackdoorPaths   []string // known webshell/backdoor filenames
	crowdsecCmdInjPatterns  []string // command injection patterns
	crowdsecLog4ShPatterns  []string // JNDI/Log4Shell + SSTI patterns
)

func init() {
	crowdsecBadUAs = loadRegexFile("crowdsec-data/bad_user_agents.txt")
	crowdsecSQLiPatterns = loadStringFile("crowdsec-data/sqli_patterns.txt")
	crowdsecXSSPatterns = loadStringFile("crowdsec-data/xss_patterns.txt")
	crowdsecPathPatterns = loadStringFile("crowdsec-data/path_traversal.txt")
	crowdsecBackdoorPaths = loadStringFile("crowdsec-data/backdoors.txt")
	crowdsecCmdInjPatterns = loadStringFile("crowdsec-data/command_injection.txt")
	crowdsecLog4ShPatterns = loadStringFile("crowdsec-data/log4shell.txt")
}

// loadRegexFile reads a file of regex patterns (one per line, # comments) and
// compiles them.  Invalid patterns are silently skipped.
func loadRegexFile(name string) []*regexp.Regexp {
	f, err := crowdsecData.Open(name)
	if err != nil {
		return nil
	}
	defer f.Close()

	var out []*regexp.Regexp
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// CrowdSec patterns use (?i) implicitly in their matching;
		// wrap with case-insensitive flag for safety.
		re, err := regexp.Compile("(?i)" + line)
		if err != nil {
			continue // skip unparseable patterns
		}
		out = append(out, re)
	}
	return out
}

// loadStringFile reads a file of plain string patterns (one per line).
func loadStringFile(name string) []string {
	f, err := crowdsecData.Open(name)
	if err != nil {
		return nil
	}
	defer f.Close()

	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}

// CrowdSecMatchBadUA returns true if the User-Agent header matches any known
// bad user agent from the CrowdSec community dataset (600+ patterns).
func CrowdSecMatchBadUA(rawRequest string) bool {
	// Extract User-Agent line from raw request
	for _, line := range strings.Split(rawRequest, "\n") {
		lower := strings.ToLower(strings.TrimSpace(line))
		if !strings.HasPrefix(lower, "user-agent:") {
			continue
		}
		ua := line[len("User-Agent:"):]
		for _, re := range crowdsecBadUAs {
			if re.MatchString(ua) {
				return true
			}
		}
		return false
	}
	return false
}

// CrowdSecMatchSQLi checks URL-decoded query/path against CrowdSec SQLi patterns.
func CrowdSecMatchSQLi(searchText string) bool {
	upper := strings.ToUpper(searchText)
	for _, pat := range crowdsecSQLiPatterns {
		if strings.Contains(upper, strings.ToUpper(pat)) {
			return true
		}
	}
	return false
}

// CrowdSecMatchXSS checks the request against CrowdSec XSS patterns.
func CrowdSecMatchXSS(searchText string) bool {
	upper := strings.ToUpper(searchText)
	for _, pat := range crowdsecXSSPatterns {
		if strings.Contains(upper, strings.ToUpper(pat)) {
			return true
		}
	}
	return false
}

// CrowdSecMatchPathTraversal checks the request path against CrowdSec path
// traversal patterns.
func CrowdSecMatchPathTraversal(searchText string) bool {
	upper := strings.ToUpper(searchText)
	for _, pat := range crowdsecPathPatterns {
		if strings.Contains(upper, strings.ToUpper(pat)) {
			return true
		}
	}
	return false
}

// CrowdSecMatchBackdoor checks whether the request path targets a known
// webshell or backdoor filename (208 known paths from CrowdSec dataset).
func CrowdSecMatchBackdoor(rawRequest string) bool {
	// Extract the path from the first line: "GET /path HTTP/1.1"
	firstLine := rawRequest
	if idx := strings.IndexByte(rawRequest, '\n'); idx > 0 {
		firstLine = rawRequest[:idx]
	}
	lower := strings.ToLower(firstLine)
	for _, backdoor := range crowdsecBackdoorPaths {
		if strings.Contains(lower, "/"+strings.ToLower(backdoor)) {
			return true
		}
	}
	return false
}

// CrowdSecMatchCmdInj checks the request against CrowdSec command injection patterns.
func CrowdSecMatchCmdInj(searchText string) bool {
	lower := strings.ToLower(searchText)
	for _, pat := range crowdsecCmdInjPatterns {
		if strings.Contains(lower, strings.ToLower(pat)) {
			return true
		}
	}
	return false
}

// CrowdSecMatchLog4Shell checks the request against JNDI/Log4Shell and SSTI patterns.
func CrowdSecMatchLog4Shell(searchText string) bool {
	lower := strings.ToLower(searchText)
	for _, pat := range crowdsecLog4ShPatterns {
		if strings.Contains(lower, strings.ToLower(pat)) {
			return true
		}
	}
	return false
}

// CrowdSecPatternCounts returns the number of loaded patterns for logging.
func CrowdSecPatternCounts() map[string]int {
	return map[string]int{
		"bad_user_agents":    len(crowdsecBadUAs),
		"sqli_patterns":      len(crowdsecSQLiPatterns),
		"xss_patterns":       len(crowdsecXSSPatterns),
		"path_traversal":     len(crowdsecPathPatterns),
		"backdoors":          len(crowdsecBackdoorPaths),
		"command_injection":  len(crowdsecCmdInjPatterns),
		"log4shell_ssti":     len(crowdsecLog4ShPatterns),
	}
}
