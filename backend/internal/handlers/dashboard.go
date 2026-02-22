package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/veil-waf/veil-go/internal/auth"
	"github.com/veil-waf/veil-go/internal/db"
)

type DashboardHandler struct {
	db     *db.DB
	logger *slog.Logger
}

func NewDashboardHandler(database *db.DB, logger *slog.Logger) *DashboardHandler {
	return &DashboardHandler{db: database, logger: logger}
}

// Helper: extract siteID and verify ownership
func (dh *DashboardHandler) getSiteID(w http.ResponseWriter, r *http.Request) (int, bool) {
	user := auth.GetUserFromCtx(r.Context())
	siteID, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, "invalid site ID", http.StatusBadRequest)
		return 0, false
	}
	owns, err := dh.db.UserOwnsSite(r.Context(), user.ID, siteID)
	if err != nil || !owns {
		jsonError(w, "forbidden", http.StatusForbidden)
		return 0, false
	}
	return siteID, true
}

// GetStats handles GET /api/sites/{id}/stats
func (dh *DashboardHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	siteID, ok := dh.getSiteID(w, r)
	if !ok {
		return
	}
	stats, err := dh.db.GetSiteStats(r.Context(), siteID)
	if err != nil {
		jsonError(w, "failed to fetch stats", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// GetThreats handles GET /api/sites/{id}/threats
func (dh *DashboardHandler) GetThreats(w http.ResponseWriter, r *http.Request) {
	siteID, ok := dh.getSiteID(w, r)
	if !ok {
		return
	}
	threats, err := dh.db.GetThreats(r.Context(), siteID)
	if err != nil {
		jsonError(w, "failed to fetch threats", http.StatusInternalServerError)
		return
	}
	if threats == nil {
		threats = []db.Threat{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(threats)
}

// GetAgentLogs handles GET /api/sites/{id}/agents
func (dh *DashboardHandler) GetAgentLogs(w http.ResponseWriter, r *http.Request) {
	siteID, ok := dh.getSiteID(w, r)
	if !ok {
		return
	}
	logs, err := dh.db.GetRecentAgentLogs(r.Context(), siteID, 50)
	if err != nil {
		jsonError(w, "failed to fetch agent logs", http.StatusInternalServerError)
		return
	}
	if logs == nil {
		logs = []db.AgentLogEntry{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(logs)
}

// GetRequests handles GET /api/sites/{id}/requests
func (dh *DashboardHandler) GetRequests(w http.ResponseWriter, r *http.Request) {
	siteID, ok := dh.getSiteID(w, r)
	if !ok {
		return
	}
	requests, err := dh.db.GetRecentRequests(r.Context(), siteID, 200)
	if err != nil {
		jsonError(w, "failed to fetch requests", http.StatusInternalServerError)
		return
	}
	if requests == nil {
		requests = []db.RequestLogEntry{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(requests)
}

// GetRules handles GET /api/sites/{id}/rules
func (dh *DashboardHandler) GetRules(w http.ResponseWriter, r *http.Request) {
	siteID, ok := dh.getSiteID(w, r)
	if !ok {
		return
	}
	rules, err := dh.db.GetCurrentRules(r.Context(), siteID)
	if err != nil {
		// No rules yet is not an error
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"rules": nil, "message": "no rules configured"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rules)
}

// GetPipeline handles GET /api/sites/{id}/pipeline
// Returns a React Flow compatible pipeline graph JSON
func (dh *DashboardHandler) GetPipeline(w http.ResponseWriter, r *http.Request) {
	_, ok := dh.getSiteID(w, r)
	if !ok {
		return
	}

	pipeline := map[string]any{
		"nodes": []map[string]any{
			{"id": "regex", "type": "classifier", "label": "Regex Filter", "position": map[string]int{"x": 0, "y": 0}},
			{"id": "crusoe", "type": "classifier", "label": "Crusoe LLM", "position": map[string]int{"x": 250, "y": 0}},
			{"id": "claude", "type": "classifier", "label": "Claude Deep", "position": map[string]int{"x": 500, "y": 0}},
			{"id": "decision", "type": "decision", "label": "Decision Engine", "position": map[string]int{"x": 750, "y": 0}},
		},
		"edges": []map[string]string{
			{"source": "regex", "target": "crusoe"},
			{"source": "crusoe", "target": "claude"},
			{"source": "claude", "target": "decision"},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(pipeline)
}

// ---------------------------------------------------------------------------
// Analytics + Compliance (Task 54)
// ---------------------------------------------------------------------------

// GetThreatDistribution handles GET /api/analytics/threat-distribution
func (dh *DashboardHandler) GetThreatDistribution(w http.ResponseWriter, r *http.Request) {
	dist, err := dh.db.GetThreatDistribution(r.Context())
	if err != nil {
		jsonError(w, "failed to fetch threat distribution", http.StatusInternalServerError)
		return
	}
	if dist == nil {
		dist = []db.ThreatCategory{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(dist)
}

// GetComplianceReport handles GET /api/compliance/report
func (dh *DashboardHandler) GetComplianceReport(w http.ResponseWriter, r *http.Request) {
	report, err := dh.db.GetComplianceReport(r.Context())
	if err != nil {
		jsonError(w, "failed to generate compliance report", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(report)
}

// GetActiveDecisions handles GET /api/sites/{id}/decisions
func (dh *DashboardHandler) GetActiveDecisions(w http.ResponseWriter, r *http.Request) {
	siteID, ok := dh.getSiteID(w, r)
	if !ok {
		return
	}
	decisions, err := dh.db.ListActiveDecisions(r.Context(), siteID)
	if err != nil {
		jsonError(w, "failed to fetch decisions", http.StatusInternalServerError)
		return
	}
	if decisions == nil {
		decisions = []db.Decision{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(decisions)
}

// GetThreatIPs handles GET /api/sites/{id}/threat-ips
func (dh *DashboardHandler) GetThreatIPs(w http.ResponseWriter, r *http.Request) {
	_, ok := dh.getSiteID(w, r)
	if !ok {
		return
	}
	ips, err := dh.db.ListThreatIPs(r.Context(), 100)
	if err != nil {
		jsonError(w, "failed to fetch threat IPs", http.StatusInternalServerError)
		return
	}
	if ips == nil {
		ips = []db.ThreatIPEntry{}
	}
	count, _ := dh.db.CountThreatIPs(r.Context())
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"entries":    ips,
		"total_count": count,
	})
}
