package handlers

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/veil-waf/veil-go/internal/auth"
	"github.com/veil-waf/veil-go/internal/db"
	veildns "github.com/veil-waf/veil-go/internal/dns"
	"github.com/veil-waf/veil-go/internal/netguard"
)

type SiteHandler struct {
	db       *db.DB
	verifier *veildns.Verifier
	logger   *slog.Logger
}

func NewSiteHandler(database *db.DB, verifier *veildns.Verifier, logger *slog.Logger) *SiteHandler {
	return &SiteHandler{db: database, verifier: verifier, logger: logger}
}

// createSiteRequest accepts both Python-style {url} and Go-style {domain, name}.
type createSiteRequest struct {
	URL    string `json:"url"`
	Domain string `json:"domain"`
	Name   string `json:"name,omitempty"`
	Scheme string `json:"scheme,omitempty"` // upstream scheme: "http" or "https" (default "https")
	Port   int    `json:"port,omitempty"`   // upstream port (default 443 for https, 80 for http)
}

type dnsInstructions struct {
	RecordType string `json:"record_type"`
	Name       string `json:"name"`
	Value      string `json:"value"`
	Message    string `json:"message"`
}

// CreateSite handles POST /api/sites
// Accepts {url: "https://example.com"} (Python compat) or {domain: "example.com"} (Go native).
// Returns {site_id, target_url, created_at} for Python frontend compatibility.
func (sh *SiteHandler) CreateSite(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUserFromCtx(r.Context())

	var req createSiteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// Accept either "url" or "domain"
	raw := req.Domain
	if raw == "" {
		raw = req.URL
	}
	if raw == "" {
		jsonError(w, "url or domain is required", http.StatusBadRequest)
		return
	}

	// Store the original URL for target_url (Python compat)
	targetURL := raw
	if !strings.Contains(targetURL, "://") {
		targetURL = "https://" + targetURL
	}
	targetURL = strings.TrimRight(targetURL, "/")

	// Normalize to just domain
	domain := normalizeDomain(raw)
	if domain == "" {
		jsonError(w, "invalid URL", http.StatusBadRequest)
		return
	}

	// Resolve current DNS
	dns, err := veildns.ResolveDomain(domain)
	if err != nil {
		sh.logger.Warn("dns resolution failed", "domain", domain, "err", err)
	}

	// Determine upstream IP from current A records
	upstreamIP := "0.0.0.0"
	if dns != nil && len(dns.A) > 0 {
		upstreamIP = dns.A[0]
	}

	// Strip any CIDR suffix (e.g. /32 from inet conversion)
	if idx := strings.Index(upstreamIP, "/"); idx != -1 {
		upstreamIP = upstreamIP[:idx]
	}

	// Block private/internal IPs to prevent SSRF through the proxy
	if ip := net.ParseIP(upstreamIP); ip != nil && upstreamIP != "0.0.0.0" {
		if netguard.IsBlocked(ip) {
			jsonError(w, "upstream IP resolves to a private/internal address — this is not allowed for security reasons", http.StatusBadRequest)
			return
		}
	}

	// Determine upstream scheme (default https)
	scheme := "https"
	if req.Scheme == "http" {
		scheme = "http"
	}

	// Determine upstream port (default based on scheme)
	port := req.Port
	if port <= 0 || port > 65535 {
		if scheme == "https" {
			port = 443
		} else {
			port = 80
		}
	}

	site := &db.Site{
		UserID:         user.ID,
		Domain:         domain,
		ProjectName:    req.Name,
		UpstreamIP:     upstreamIP,
		UpstreamScheme: scheme,
		UpstreamPort:   port,
		Status:         "pending",
	}
	if dns != nil {
		site.OriginalCNAME = dns.CNAME
	}

	if err := sh.db.CreateSite(r.Context(), site); err != nil {
		sh.logger.Error("create site failed", "err", err)
		jsonError(w, "could not create site — domain may already exist", http.StatusConflict)
		return
	}

	// Return Python-compatible response format
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]any{
		"site_id":    strconv.Itoa(site.ID),
		"target_url": targetURL,
		"created_at": site.CreatedAt.Format("2006-01-02T15:04:05"),
		// Also include Go-specific fields for the enhanced frontend
		"site":         site,
		"dns":          dns,
		"instructions": dnsInstructions{
			RecordType: "CNAME",
			Name:       domain,
			Value:      sh.verifier.ProxyCNAME(),
			Message:    fmt.Sprintf("Point %s to %s via CNAME or ALIAS record. Veil will automatically detect the change.", domain, sh.verifier.ProxyCNAME()),
		},
	})
}

// ListSites handles GET /api/sites
// Returns Python-compatible format: [{site_id, target_url, created_at}]
func (sh *SiteHandler) ListSites(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUserFromCtx(r.Context())
	sites, err := sh.db.GetSitesByUser(r.Context(), user.ID)
	if err != nil {
		jsonError(w, "failed to fetch sites", http.StatusInternalServerError)
		return
	}

	// Build Python-compatible response
	result := make([]map[string]any, 0, len(sites))
	for _, s := range sites {
		// Strip any CIDR suffix from upstream IP
		upIP := s.UpstreamIP
		if idx := strings.Index(upIP, "/"); idx != -1 {
			upIP = upIP[:idx]
		}
		scheme := s.UpstreamScheme
		if scheme == "" {
			scheme = "https"
		}
		port := s.UpstreamPort
		if port <= 0 {
			if scheme == "https" {
				port = 443
			} else {
				port = 80
			}
		}
		targetURL := "https://" + s.Domain
		if upIP != "" && upIP != "0.0.0.0" {
			targetURL = scheme + "://" + upIP + ":" + strconv.Itoa(port)
		}
		result = append(result, map[string]any{
			"site_id":    strconv.Itoa(s.ID),
			"target_url": targetURL,
			"created_at": s.CreatedAt.Format("2006-01-02T15:04:05"),
			// Extra fields for enhanced frontend
			"id":              s.ID,
			"domain":          s.Domain,
			"project_name":    s.ProjectName,
			"status":          s.Status,
			"upstream_ip":     upIP,
			"upstream_scheme": scheme,
			"upstream_port":   port,
			"is_demo":         s.IsDemo,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// GetSite handles GET /api/sites/{id}
func (sh *SiteHandler) GetSite(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUserFromCtx(r.Context())
	siteID, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, "invalid site ID", http.StatusBadRequest)
		return
	}

	site, err := sh.db.GetSiteByID(r.Context(), siteID)
	if err != nil || site == nil {
		jsonError(w, "site not found", http.StatusNotFound)
		return
	}
	if site.UserID != user.ID && !site.IsDemo {
		jsonError(w, "forbidden", http.StatusForbidden)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(site)
}

// GetSiteStatus handles GET /api/sites/{id}/status
func (sh *SiteHandler) GetSiteStatus(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUserFromCtx(r.Context())
	siteID, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, "invalid site ID", http.StatusBadRequest)
		return
	}

	site, err := sh.db.GetSiteByID(r.Context(), siteID)
	if err != nil || site == nil {
		jsonError(w, "site not found", http.StatusNotFound)
		return
	}
	if site.UserID != user.ID && !site.IsDemo {
		jsonError(w, "forbidden", http.StatusForbidden)
		return
	}

	// Check DNS now
	dns, _ := veildns.ResolveDomain(site.Domain)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"site_id":     site.ID,
		"domain":      site.Domain,
		"status":      site.Status,
		"dns":         dns,
		"proxy_cname": sh.verifier.ProxyCNAME(),
		"instructions": dnsInstructions{
			RecordType: "CNAME",
			Name:       site.Domain,
			Value:      sh.verifier.ProxyCNAME(),
			Message:    fmt.Sprintf("Point %s to %s via CNAME or ALIAS record.", site.Domain, sh.verifier.ProxyCNAME()),
		},
	})
}

// VerifySiteNow handles POST /api/sites/{id}/verify
func (sh *SiteHandler) VerifySiteNow(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUserFromCtx(r.Context())
	siteID, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, "invalid site ID", http.StatusBadRequest)
		return
	}

	owns, err := sh.db.UserOwnsSite(r.Context(), user.ID, siteID)
	if err != nil || !owns {
		jsonError(w, "forbidden", http.StatusForbidden)
		return
	}

	if err := sh.verifier.VerifySiteNow(r.Context(), siteID); err != nil {
		jsonError(w, "verification failed: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Return updated site
	site, _ := sh.db.GetSiteByID(r.Context(), siteID)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(site)
}

// DeleteSite handles DELETE /api/sites/{id}
func (sh *SiteHandler) DeleteSite(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUserFromCtx(r.Context())
	siteID, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, "invalid site ID", http.StatusBadRequest)
		return
	}

	// Prevent deletion of demo sites
	site, err := sh.db.GetSiteByID(r.Context(), siteID)
	if err == nil && site != nil && site.IsDemo {
		jsonError(w, "demo site cannot be deleted", http.StatusForbidden)
		return
	}

	if err := sh.db.DeleteSite(r.Context(), siteID, user.ID); err != nil {
		jsonError(w, "site not found or not owned by you", http.StatusNotFound)
		return
	}

	// Return Python-compatible response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

// normalizeDomain strips protocol and path from a URL/domain string
func normalizeDomain(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	// If it looks like a URL, parse it
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil {
			return ""
		}
		return u.Hostname()
	}
	// Remove any path
	if idx := strings.Index(raw, "/"); idx != -1 {
		raw = raw[:idx]
	}
	// Remove any port
	if host, _, err := net.SplitHostPort(raw); err == nil {
		return host
	}
	return raw
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
