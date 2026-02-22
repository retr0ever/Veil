package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/veil-waf/veil-go/internal/agents"
	"github.com/veil-waf/veil-go/internal/classify"
	"github.com/veil-waf/veil-go/internal/db"
	"github.com/veil-waf/veil-go/internal/proxy"
	"github.com/veil-waf/veil-go/internal/ratelimit"
)

// CompatHandler provides endpoints matching the Python backend's API contract
// so the existing frontend works without modification.
type CompatHandler struct {
	db        *db.DB
	pipeline  *classify.Pipeline
	proxy     *proxy.Handler
	agents    *agents.Loop
	limiter   *ratelimit.Limiter
	logger    *slog.Logger
}

// NewCompatHandler creates a new compatibility handler.
func NewCompatHandler(
	database *db.DB,
	pipeline *classify.Pipeline,
	proxyH *proxy.Handler,
	agentLoop *agents.Loop,
	limiter *ratelimit.Limiter,
	logger *slog.Logger,
) *CompatHandler {
	return &CompatHandler{
		db:       database,
		pipeline: pipeline,
		proxy:    proxyH,
		agents:   agentLoop,
		limiter:  limiter,
		logger:   logger,
	}
}

// GetConfig handles GET /api/config — returns public base URL.
func (ch *CompatHandler) GetConfig(w http.ResponseWriter, r *http.Request) {
	baseURL := os.Getenv("VEIL_PUBLIC_URL")
	if baseURL == "" {
		if domain := os.Getenv("RAILWAY_PUBLIC_DOMAIN"); domain != "" {
			baseURL = "https://" + domain
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"base_url": baseURL})
}

// GetGlobalStats handles GET /api/stats — global stats across all sites.
func (ch *CompatHandler) GetGlobalStats(w http.ResponseWriter, r *http.Request) {
	stats, err := ch.db.GetGlobalStats(r.Context())
	if err != nil {
		jsonError(w, "failed to fetch stats", http.StatusInternalServerError)
		return
	}

	// Match Python backend response format
	threatsBlocked := stats.ThreatCount // approximate
	blockRate := 0.0
	if stats.ThreatCount > 0 {
		blockRate = float64(threatsBlocked) / float64(stats.ThreatCount) * 100
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"total_requests":  stats.TotalRequests,
		"blocked_requests": stats.BlockedCount,
		"total_threats":   stats.ThreatCount,
		"threats_blocked": threatsBlocked,
		"block_rate":      blockRate,
		"rules_version":   1,
	})
}

// GetGlobalThreats handles GET /api/threats — all threats across all sites.
func (ch *CompatHandler) GetGlobalThreats(w http.ResponseWriter, r *http.Request) {
	threats, err := ch.db.GetGlobalThreats(r.Context())
	if err != nil {
		jsonError(w, "failed to fetch threats", http.StatusInternalServerError)
		return
	}

	// Match Python response format
	type threatResp struct {
		ID            int64   `json:"id"`
		TechniqueName string  `json:"technique_name"`
		Category      string  `json:"category"`
		Source        string  `json:"source"`
		RawPayload    string  `json:"raw_payload"`
		Severity      string  `json:"severity"`
		DiscoveredAt  string  `json:"discovered_at"`
		TestedAt      *string `json:"tested_at"`
		Blocked       bool    `json:"blocked"`
		PatchedAt     *string `json:"patched_at"`
	}

	result := make([]threatResp, 0, len(threats))
	for _, t := range threats {
		payload := t.RawPayload
		if len(payload) > 200 {
			payload = payload[:200]
		}
		tr := threatResp{
			ID:            t.ID,
			TechniqueName: t.TechniqueName,
			Category:      t.Category,
			Source:        t.Source,
			RawPayload:    payload,
			Severity:      t.Severity,
			DiscoveredAt:  t.DiscoveredAt.Format(time.RFC3339),
			Blocked:       t.Blocked,
		}
		if t.TestedAt != nil {
			s := t.TestedAt.Format(time.RFC3339)
			tr.TestedAt = &s
		}
		if t.PatchedAt != nil {
			s := t.PatchedAt.Format(time.RFC3339)
			tr.PatchedAt = &s
		}
		result = append(result, tr)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// GetGlobalAgentLogs handles GET /api/agents — recent agent logs.
func (ch *CompatHandler) GetGlobalAgentLogs(w http.ResponseWriter, r *http.Request) {
	logs, err := ch.db.GetGlobalRecentAgentLogs(r.Context(), 50)
	if err != nil {
		jsonError(w, "failed to fetch agent logs", http.StatusInternalServerError)
		return
	}

	type agentResp struct {
		ID        int64  `json:"id"`
		Timestamp string `json:"timestamp"`
		Agent     string `json:"agent"`
		Action    string `json:"action"`
		Detail    string `json:"detail"`
		Success   bool   `json:"success"`
	}

	result := make([]agentResp, 0, len(logs))
	for _, l := range logs {
		result = append(result, agentResp{
			ID:        l.ID,
			Timestamp: l.Timestamp.Format(time.RFC3339),
			Agent:     l.Agent,
			Action:    l.Action,
			Detail:    l.Detail,
			Success:   l.Success,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// GetGlobalRequests handles GET /api/requests — recent request logs.
func (ch *CompatHandler) GetGlobalRequests(w http.ResponseWriter, r *http.Request) {
	requests, err := ch.db.GetGlobalRecentRequests(r.Context(), 100)
	if err != nil {
		jsonError(w, "failed to fetch requests", http.StatusInternalServerError)
		return
	}

	type reqResp struct {
		ID             int64   `json:"id"`
		Timestamp      string  `json:"timestamp"`
		Message        string  `json:"message"`
		Classification string  `json:"classification"`
		Confidence     float32 `json:"confidence"`
		Classifier     string  `json:"classifier"`
		Blocked        bool    `json:"blocked"`
		AttackType     string  `json:"attack_type"`
		ResponseTimeMs float32 `json:"response_time_ms"`
	}

	result := make([]reqResp, 0, len(requests))
	for _, r := range requests {
		msg := r.RawRequest
		if len(msg) > 100 {
			msg = msg[:100]
		}
		result = append(result, reqResp{
			ID:             r.ID,
			Timestamp:      r.Timestamp.Format(time.RFC3339),
			Message:        msg,
			Classification: r.Classification,
			Confidence:     r.Confidence,
			Classifier:     r.Classifier,
			Blocked:        r.Blocked,
			AttackType:     r.AttackType,
			ResponseTimeMs: r.ResponseTimeMs,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// GetGlobalRules handles GET /api/rules — all rule versions.
func (ch *CompatHandler) GetGlobalRules(w http.ResponseWriter, r *http.Request) {
	rules, err := ch.db.GetAllRuleVersions(r.Context())
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]any{})
		return
	}

	type ruleResp struct {
		Version   int    `json:"version"`
		UpdatedAt string `json:"updated_at"`
		UpdatedBy string `json:"updated_by"`
	}

	result := make([]ruleResp, 0, len(rules))
	for _, r := range rules {
		result = append(result, ruleResp{
			Version:   r.Version,
			UpdatedAt: r.UpdatedAt.Format(time.RFC3339),
			UpdatedBy: r.UpdatedBy,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// Classify handles POST /v1/classify — classification-only endpoint.
func (ch *CompatHandler) Classify(w http.ResponseWriter, r *http.Request) {
	if ch.limiter.Check(w, r, "classify") {
		return
	}

	var req struct {
		Message string `json:"message"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Message == "" {
		jsonError(w, "message field is required", http.StatusBadRequest)
		return
	}

	result := ch.pipeline.ClassifyWithRules(r.Context(), req.Message, nil)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// TriggerPeek handles POST /api/agents/peek/run.
func (ch *CompatHandler) TriggerPeek(w http.ResponseWriter, r *http.Request) {
	if ch.limiter.Check(w, r, "agents") {
		return
	}
	result := ch.agents.RunOnce(r.Context())
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"discovered":      result.Discovered,
		"strategies_used": result.StrategiesUsed,
	})
}

// TriggerPoke handles POST /api/agents/poke/run.
func (ch *CompatHandler) TriggerPoke(w http.ResponseWriter, r *http.Request) {
	if ch.limiter.Check(w, r, "agents") {
		return
	}
	result := ch.agents.RunOnce(r.Context())
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"bypasses": result.Bypasses,
	})
}

// TriggerCycle handles POST /api/agents/cycle — full Peek→Poke→Patch cycle.
func (ch *CompatHandler) TriggerCycle(w http.ResponseWriter, r *http.Request) {
	if ch.limiter.Check(w, r, "agents") {
		return
	}
	result := ch.agents.RunOnce(r.Context())

	stats, _ := ch.db.GetGlobalStats(r.Context())

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"cycle_id":        result.CycleID,
		"discovered":      result.Discovered,
		"bypasses":        result.Bypasses,
		"patch_rounds":    result.PatchRounds,
		"strategies_used": result.StrategiesUsed,
		"stats":           stats,
	})
}

// ProxyInfoPage handles GET /p/{siteID} — HTML info page.
func (ch *CompatHandler) ProxyInfoPage(w http.ResponseWriter, r *http.Request) {
	siteIDStr := chi.URLParam(r, "siteID")
	siteID, err := strconv.Atoi(siteIDStr)
	if err != nil {
		jsonError(w, "invalid site ID", http.StatusBadRequest)
		return
	}
	ch.proxy.ProxyInfo(w, r, siteID)
}

// ProxyForward handles /p/{siteID}/{path} — path-based reverse proxy.
func (ch *CompatHandler) ProxyForward(w http.ResponseWriter, r *http.Request) {
	siteIDStr := chi.URLParam(r, "siteID")
	siteID, err := strconv.Atoi(siteIDStr)
	if err != nil {
		jsonError(w, "invalid site ID", http.StatusBadRequest)
		return
	}
	path := chi.URLParam(r, "*")
	ch.proxy.PathProxy(w, r, siteID, path)
}
