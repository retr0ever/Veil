package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/veil-waf/veil-go/internal/classify"
	"github.com/veil-waf/veil-go/internal/db"
	"github.com/veil-waf/veil-go/internal/netguard"
	"github.com/veil-waf/veil-go/internal/ratelimit"
	"github.com/veil-waf/veil-go/internal/sse"
)

// ssrfSafeDialer wraps the default dialer to reject connections to private IPs.
var ssrfSafeDialer = &net.Dialer{Timeout: 10 * time.Second}

func ssrfSafeDial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid address: %w", err)
	}

	// Resolve the host to IPs and check each one BEFORE connecting.
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		// If it's already an IP literal, parse directly.
		ip := net.ParseIP(host)
		if ip == nil {
			return nil, fmt.Errorf("dns lookup failed: %w", err)
		}
		if netguard.IsBlocked(ip) {
			return nil, fmt.Errorf("upstream %s resolves to blocked private IP %s", addr, ip)
		}
		return ssrfSafeDialer.DialContext(ctx, network, addr)
	}

	for _, ipAddr := range ips {
		if netguard.IsBlocked(ipAddr.IP) {
			return nil, fmt.Errorf("upstream %s resolves to blocked private IP %s", addr, ipAddr.IP)
		}
	}

	// All IPs are safe — connect to the first one.
	safeAddr := net.JoinHostPort(ips[0].IP.String(), port)
	return ssrfSafeDialer.DialContext(ctx, network, safeAddr)
}

var proxyClient = &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http.Transport{
		DialContext:         ssrfSafeDial,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     90 * time.Second,
	},
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return fmt.Errorf("too many redirects")
		}
		return nil
	},
}

// Handler implements both host-header routing and path-based proxying.
type Handler struct {
	db       *db.DB
	pipeline *classify.Pipeline
	hub      *sse.Hub
	limiter  *ratelimit.Limiter
	logger   *slog.Logger
}

// NewHandler creates a new proxy handler.
func NewHandler(database *db.DB, pipeline *classify.Pipeline, hub *sse.Hub, limiter *ratelimit.Limiter, logger *slog.Logger) *Handler {
	return &Handler{
		db:       database,
		pipeline: pipeline,
		hub:      hub,
		limiter:  limiter,
		logger:   logger,
	}
}

// HostRoute handles requests routed via Host header (production mode).
// Users CNAME their domain to router.reveil.tech; Veil routes by Host header.
func (h *Handler) HostRoute(w http.ResponseWriter, r *http.Request) {
	if h.limiter.Check(w, r, "proxy") {
		return
	}

	host := r.Host
	if hp, _, err := net.SplitHostPort(host); err == nil {
		host = hp
	}

	site, err := h.db.GetSiteByDomain(r.Context(), host)
	if err != nil {
		http.Error(w, `{"error":"Unknown domain"}`, http.StatusNotFound)
		return
	}

	h.proxyRequest(w, r, site, r.URL.Path)
}

// PathProxy handles GET/POST /p/{siteID}/{path} — path-based proxy for testing/demo.
func (h *Handler) PathProxy(w http.ResponseWriter, r *http.Request, siteID int, path string) {
	if h.limiter.Check(w, r, "proxy") {
		return
	}

	site, err := h.db.GetSiteByID(r.Context(), siteID)
	if err != nil {
		jsonError(w, "Site not found", http.StatusNotFound)
		return
	}

	h.proxyRequest(w, r, site, "/"+path)
}

// ProxyInfo serves the HTML info page at GET /p/{siteID}.
func (h *Handler) ProxyInfo(w http.ResponseWriter, r *http.Request, siteID int) {
	site, err := h.db.GetSiteByID(r.Context(), siteID)
	if err != nil {
		jsonError(w, "Site not found", http.StatusNotFound)
		return
	}

	upstream := "http://" + site.UpstreamIP
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Veil Protected Endpoint</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:system-ui,-apple-system,sans-serif;background:#1a1322;color:#e2dfe8;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:2rem}
.card{max-width:520px;width:100%%;border:1px solid rgba(255,255,255,0.08);border-radius:16px;background:rgba(16,20,31,0.8);padding:2.5rem}
h1{font-size:1.5rem;margin-bottom:.5rem}p{color:#8a8594;line-height:1.6;margin-top:.75rem;font-size:.95rem}
.badge{display:inline-block;background:rgba(99,167,255,0.1);color:#63a7ff;font-size:.75rem;font-weight:600;padding:.25rem .75rem;border-radius:6px;letter-spacing:.05em;margin-bottom:1rem}
.url{background:#0e1219;border:1px solid rgba(255,255,255,0.06);border-radius:8px;padding:.75rem 1rem;font-family:monospace;font-size:.85rem;color:#8fd9a7;margin-top:.75rem;word-break:break-all}
a{color:#63a7ff;text-decoration:none}a:hover{text-decoration:underline}</style></head>
<body><div class="card">
<div class="badge">PROTECTED ENDPOINT</div>
<h1>This is your Veil proxy</h1>
<p>This URL is a reverse-proxy endpoint. Route your API traffic through it to get Veil's WAF protection.</p>
<p style="color:#e2dfe8;font-size:.85rem;margin-top:1.25rem">Domain:</p>
<div class="url">%s</div>
<p style="color:#e2dfe8;font-size:.85rem;margin-top:1.25rem">Upstream target:</p>
<div class="url">%s</div>
<p style="margin-top:1.5rem"><a href="/app/projects/%d">Open dashboard &rarr;</a></p>
</div></body></html>`, site.Domain, upstream, site.ID)
}

func (h *Handler) proxyRequest(w http.ResponseWriter, r *http.Request, site *db.Site, path string) {
	// Build raw request string for classification
	queryString := ""
	if r.URL.RawQuery != "" {
		queryString = "?" + r.URL.RawQuery
	}

	body, _ := io.ReadAll(io.LimitReader(r.Body, 10<<20)) // 10 MB max

	var rawLines []string
	rawLines = append(rawLines, fmt.Sprintf("%s %s%s HTTP/1.1", r.Method, path, queryString))
	for key, values := range r.Header {
		lk := strings.ToLower(key)
		if lk == "host" || lk == "connection" || lk == "transfer-encoding" {
			continue
		}
		for _, v := range values {
			rawLines = append(rawLines, key+": "+v)
		}
	}
	rawRequest := strings.Join(rawLines, "\n")
	if len(body) > 0 {
		rawRequest += "\n\n" + string(body)
	}

	// Truncate for storage
	rawForLog := rawRequest
	if len(rawForLog) > 500 {
		rawForLog = rawForLog[:500]
	}

	// Classify
	result := h.pipeline.Classify(r.Context(), site.ID, rawRequest)

	// Extract source IP
	sourceIP := r.RemoteAddr
	if fwd := r.Header.Get("X-Real-IP"); fwd != "" {
		sourceIP = fwd
	}
	if hp, _, err := net.SplitHostPort(sourceIP); err == nil {
		sourceIP = hp
	}

	// Log to DB
	logEntry := &db.RequestLogEntry{
		SiteID:         site.ID,
		RawRequest:     rawForLog,
		Classification: result.Classification,
		Confidence:     float32(result.Confidence),
		Classifier:     result.Classifier,
		Blocked:        result.Blocked,
		AttackType:     result.AttackType,
		ResponseTimeMs: float32(result.ResponseTimeMs),
		SourceIP:       sourceIP,
	}
	if err := h.db.InsertRequestLog(r.Context(), logEntry); err != nil {
		h.logger.Error("failed to log request", "err", err)
	}

	// Broadcast to SSE
	if h.hub != nil {
		eventData, _ := json.Marshal(map[string]any{
			"type":           "request",
			"timestamp":      time.Now().UTC().Format(time.RFC3339),
			"message":        truncate(rawRequest, 120),
			"classification": result.Classification,
			"confidence":     result.Confidence,
			"blocked":        result.Blocked,
			"classifier":     result.Classifier,
			"attack_type":    result.AttackType,
		})
		h.hub.Publish(strconv.Itoa(site.ID), sse.Event{Type: "request", Data: eventData})
	}

	// Block if malicious
	if result.Blocked {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]any{
			"error":          "Blocked by Veil",
			"classification": result.Classification,
			"attack_type":    result.AttackType,
			"reason":         result.Reason,
		})
		return
	}

	// Forward to upstream
	upstream := "http://" + site.UpstreamIP
	forwardURL := upstream + path
	if r.URL.RawQuery != "" {
		forwardURL += "?" + r.URL.RawQuery
	}

	proxyReq, err := http.NewRequestWithContext(r.Context(), r.Method, forwardURL, strings.NewReader(string(body)))
	if err != nil {
		jsonError(w, "Failed to create upstream request", http.StatusBadGateway)
		return
	}

	// Copy headers
	for key, values := range r.Header {
		lk := strings.ToLower(key)
		if lk == "host" || lk == "connection" || lk == "transfer-encoding" || lk == "content-length" {
			continue
		}
		for _, v := range values {
			proxyReq.Header.Add(key, v)
		}
	}
	proxyReq.Header.Set("Host", site.Domain)
	proxyReq.Header.Set("X-Forwarded-For", sourceIP)
	proxyReq.Header.Set("X-Forwarded-Proto", "https")

	resp, err := proxyClient.Do(proxyReq)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(map[string]string{
			"error": fmt.Sprintf("Could not reach backend: %v", err),
		})
		return
	}
	defer resp.Body.Close()

	// Copy response headers
	excludedHeaders := map[string]bool{
		"transfer-encoding": true,
		"connection":        true,
		"content-encoding":  true,
		"content-length":    true,
	}
	for key, values := range resp.Header {
		if excludedHeaders[strings.ToLower(key)] {
			continue
		}
		for _, v := range values {
			w.Header().Add(key, v)
		}
	}

	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
