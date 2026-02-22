package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/veil-waf/veil-go/internal/auth"
	"github.com/veil-waf/veil-go/internal/db"
	"github.com/veil-waf/veil-go/internal/repo"
)

// RepoHandler handles repository linking and code findings endpoints.
type RepoHandler struct {
	db      *db.DB
	scanner *repo.Scanner
	logger  *slog.Logger
}

// NewRepoHandler creates a new RepoHandler.
func NewRepoHandler(database *db.DB, scanner *repo.Scanner, logger *slog.Logger) *RepoHandler {
	return &RepoHandler{db: database, scanner: scanner, logger: logger}
}

// getSiteID extracts and validates site ownership from the request.
func (rh *RepoHandler) getSiteID(w http.ResponseWriter, r *http.Request) (int, bool) {
	user := auth.GetUserFromCtx(r.Context())
	siteID, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, "invalid site ID", http.StatusBadRequest)
		return 0, false
	}
	owns, err := rh.db.UserOwnsSite(r.Context(), user.ID, siteID)
	if err != nil || !owns {
		jsonError(w, "forbidden", http.StatusForbidden)
		return 0, false
	}
	return siteID, true
}

// ListRepos handles GET /api/sites/{id}/repos
func (rh *RepoHandler) ListRepos(w http.ResponseWriter, r *http.Request) {
	_, ok := rh.getSiteID(w, r)
	if !ok {
		return
	}
	user := auth.GetUserFromCtx(r.Context())
	repos, err := rh.scanner.ListRepos(r.Context(), user.ID)
	if err != nil {
		jsonError(w, "failed to list repos — connect GitHub first", http.StatusBadRequest)
		return
	}
	// Return simplified repo list
	type repoSummary struct {
		Owner         string `json:"owner"`
		Name          string `json:"name"`
		FullName      string `json:"full_name"`
		Description   string `json:"description,omitempty"`
		DefaultBranch string `json:"default_branch"`
	}
	var summaries []repoSummary
	for _, r := range repos {
		summaries = append(summaries, repoSummary{
			Owner:         r.GetOwner().GetLogin(),
			Name:          r.GetName(),
			FullName:      r.GetFullName(),
			Description:   r.GetDescription(),
			DefaultBranch: r.GetDefaultBranch(),
		})
	}
	if summaries == nil {
		summaries = []repoSummary{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(summaries)
}

type linkRepoRequest struct {
	Owner  string `json:"owner"`
	Name   string `json:"name"`
	Branch string `json:"branch"`
}

// LinkRepo handles POST /api/sites/{id}/repos
func (rh *RepoHandler) LinkRepo(w http.ResponseWriter, r *http.Request) {
	siteID, ok := rh.getSiteID(w, r)
	if !ok {
		return
	}
	// Require DNS verification before linking repos
	site, err := rh.db.GetSiteByID(r.Context(), siteID)
	if err != nil || site == nil {
		jsonError(w, "site not found", http.StatusNotFound)
		return
	}
	if !site.IsDemo && site.Status != "active" && site.Status != "live" {
		jsonError(w, "DNS must be verified before linking a repository", http.StatusBadRequest)
		return
	}
	var req linkRepoRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Owner == "" || req.Name == "" {
		jsonError(w, "owner and name are required", http.StatusBadRequest)
		return
	}
	branch := req.Branch
	if branch == "" {
		branch = "main"
	}
	if err := rh.db.LinkRepo(r.Context(), siteID, req.Owner, req.Name, branch); err != nil {
		jsonError(w, "failed to link repo", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"status": "linked"})
}

// UnlinkRepo handles DELETE /api/sites/{id}/repos
func (rh *RepoHandler) UnlinkRepo(w http.ResponseWriter, r *http.Request) {
	siteID, ok := rh.getSiteID(w, r)
	if !ok {
		return
	}
	if err := rh.db.UnlinkRepo(r.Context(), siteID); err != nil {
		jsonError(w, "failed to unlink repo", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// GetFindings handles GET /api/sites/{id}/findings
func (rh *RepoHandler) GetFindings(w http.ResponseWriter, r *http.Request) {
	siteID, ok := rh.getSiteID(w, r)
	if !ok {
		return
	}
	findings, err := rh.db.GetCodeFindings(r.Context(), siteID)
	if err != nil {
		jsonError(w, "failed to fetch findings", http.StatusInternalServerError)
		return
	}
	if findings == nil {
		findings = []db.CodeFinding{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(findings)
}

type updateFindingRequest struct {
	Status string `json:"status"`
}

// UpdateFinding handles PATCH /api/sites/{id}/findings/{fid}
func (rh *RepoHandler) UpdateFinding(w http.ResponseWriter, r *http.Request) {
	_, ok := rh.getSiteID(w, r)
	if !ok {
		return
	}
	findingID, err := strconv.ParseInt(chi.URLParam(r, "fid"), 10, 64)
	if err != nil {
		jsonError(w, "invalid finding ID", http.StatusBadRequest)
		return
	}
	var req updateFindingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	validStatuses := map[string]bool{"open": true, "acknowledged": true, "fixed": true, "false_positive": true}
	if !validStatuses[req.Status] {
		jsonError(w, "invalid status (open, acknowledged, fixed, false_positive)", http.StatusBadRequest)
		return
	}
	if err := rh.db.UpdateCodeFindingStatus(r.Context(), findingID, req.Status); err != nil {
		jsonError(w, "failed to update finding", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": req.Status})
}

// TriggerScan handles POST /api/sites/{id}/scan — triggers an immediate code scan.
func (rh *RepoHandler) TriggerScan(w http.ResponseWriter, r *http.Request) {
	siteID, ok := rh.getSiteID(w, r)
	if !ok {
		return
	}
	// Require DNS verification before running scans
	site, err := rh.db.GetSiteByID(r.Context(), siteID)
	if err != nil || site == nil {
		jsonError(w, "site not found", http.StatusNotFound)
		return
	}
	if !site.IsDemo && site.Status != "active" && site.Status != "live" {
		jsonError(w, "DNS must be verified before running scans", http.StatusBadRequest)
		return
	}
	user := auth.GetUserFromCtx(r.Context())

	siteRepo, err := rh.db.GetSiteRepo(r.Context(), siteID)
	if err != nil || siteRepo == nil {
		jsonError(w, "no repository linked to this site", http.StatusBadRequest)
		return
	}

	// Get recent attack types for this site
	attacks, err := rh.db.GetRecentAttackTypes(r.Context(), siteID, 24*time.Hour)
	if err != nil || len(attacks) == 0 {
		// Fall back to global threats
		attacks = []db.AttackSummary{
			{AttackType: "sqli", Payload: "' OR '1'='1", Reason: "SQL injection pattern"},
			{AttackType: "xss", Payload: "<script>alert(1)</script>", Reason: "Cross-site scripting"},
		}
	}

	totalFindings := 0
	for _, attack := range attacks {
		findings, err := rh.scanner.ScanAndAnalyze(r.Context(), siteID, user.ID,
			attack.AttackType, attack.Payload, attack.Reason, nil)
		if err != nil {
			rh.logger.Warn("scan failed", "attack", attack.AttackType, "err", err)
			continue
		}
		totalFindings += len(findings)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"findings_count": totalFindings,
		"attacks_scanned": len(attacks),
	})
}

// GetLinkedRepo handles GET /api/sites/{id}/repo — returns the linked repo info.
func (rh *RepoHandler) GetLinkedRepo(w http.ResponseWriter, r *http.Request) {
	siteID, ok := rh.getSiteID(w, r)
	if !ok {
		return
	}
	siteRepo, err := rh.db.GetSiteRepo(r.Context(), siteID)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"linked": false})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"linked":         true,
		"repo_owner":     siteRepo.RepoOwner,
		"repo_name":      siteRepo.RepoName,
		"default_branch": siteRepo.DefaultBranch,
		"connected_at":   siteRepo.ConnectedAt,
	})
}
