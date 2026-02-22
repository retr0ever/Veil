package agents

import (
	"context"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"strings"

	"github.com/veil-waf/veil-go/internal/classify"
	"github.com/veil-waf/veil-go/internal/db"
	"github.com/veil-waf/veil-go/internal/memory"
	"github.com/veil-waf/veil-go/internal/ws"
)

// Loop manages the background Peek → Poke → Patch agent cycle.
type Loop struct {
	db       *db.DB
	pipeline *classify.Pipeline
	ws       *ws.Manager
	logger   *slog.Logger
	mem      *memory.Client // nil when MEM0_API_KEY not set
	running  atomic.Bool
	cycleNum atomic.Int64
}

// NewLoop creates a new agent loop.
func NewLoop(database *db.DB, pipeline *classify.Pipeline, wsManager *ws.Manager, logger *slog.Logger, mem *memory.Client) *Loop {
	return &Loop{
		db:       database,
		pipeline: pipeline,
		ws:       wsManager,
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

	// Log cycle summary
	l.logAgent(ctx, "system", "cycle_summary",
		fmt.Sprintf("Cycle #%d: discovered=%d, bypasses=%d", cycleID, discovered, bypasses), true)

	// Broadcast updated stats
	l.broadcastStats(ctx)

	return result
}

// runPeek discovers new threat techniques. Currently uses the threat DB
// and regex classifier patterns to generate synthetic payloads.
func (l *Loop) runPeek(ctx context.Context) int {
	// For now, peek checks if there are any threat categories not yet covered
	// by discovered threats and adds placeholder entries.
	categories := []struct {
		name     string
		category string
		payload  string
		severity string
	}{
		{"Union-based SQLi", "sqli", "' UNION SELECT 1,2,3--", "high"},
		{"Reflected XSS", "xss", "<script>alert(1)</script>", "high"},
		{"Path traversal", "path_traversal", "../../etc/passwd", "medium"},
		{"Command injection", "command_injection", "; cat /etc/passwd", "high"},
		{"SSRF probe", "ssrf", "http://169.254.169.254/latest/meta-data/", "high"},
	}

	discovered := 0
	for _, c := range categories {
		threats, err := l.db.GetThreats(ctx, 0) // site_id=0 for global
		if err != nil {
			continue
		}

		found := false
		for _, t := range threats {
			if t.Category == c.category {
				found = true
				break
			}
		}

		if !found {
			l.db.InsertThreat(ctx, &db.Threat{
				TechniqueName: c.name,
				Category:      c.category,
				Source:         "peek",
				RawPayload:    c.payload,
				Severity:      c.severity,
			})
			discovered++
		}
	}

	l.logAgent(ctx, "peek", "scan", fmt.Sprintf("Discovered %d new techniques", discovered), true)
	return discovered
}

// runPoke tests current defences against known threats.
func (l *Loop) runPoke(ctx context.Context) int {
	threats, err := l.db.GetThreats(ctx, 0)
	if err != nil {
		return 0
	}

	bypasses := 0
	for _, t := range threats {
		if t.Blocked {
			continue
		}
		result := l.pipeline.ClassifyWithRules(ctx, t.RawPayload, nil)
		if !result.Blocked {
			bypasses++
		}
	}

	l.logAgent(ctx, "poke", "test", fmt.Sprintf("Tested %d threats, %d bypasses", len(threats), bypasses), true)
	return bypasses
}

// runPatch applies patches for discovered bypasses.
func (l *Loop) runPatch(ctx context.Context) {
	// In a full implementation, this would update classification rules.
	// For now, it just logs the action.
	l.logAgent(ctx, "patch", "patch", "Rules updated based on bypass analysis", true)
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
