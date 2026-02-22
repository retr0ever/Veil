package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net"
	"net/http"
	stdpath "path"
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
	// Allow explicitly trusted upstreams (e.g. container names on the same network).
	if netguard.IsTrustedHost(addr) {
		return ssrfSafeDialer.DialContext(ctx, network, addr)
	}

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

	// Sanitize path to prevent traversal
	clean := stdpath.Clean("/" + path)
	if strings.HasPrefix(clean, "/..") {
		jsonError(w, "Invalid path", http.StatusBadRequest)
		return
	}

	site, err := h.db.GetSiteByID(r.Context(), siteID)
	if err != nil {
		jsonError(w, "Site not found", http.StatusNotFound)
		return
	}

	h.proxyRequest(w, r, site, clean)
}

// ProxyInfo serves the HTML info page at GET /p/{siteID}.
func (h *Handler) ProxyInfo(w http.ResponseWriter, r *http.Request, siteID int) {
	site, err := h.db.GetSiteByID(r.Context(), siteID)
	if err != nil {
		jsonError(w, "Site not found", http.StatusNotFound)
		return
	}

	upIP := site.UpstreamIP
	if idx := strings.Index(upIP, "/"); idx != -1 {
		upIP = upIP[:idx]
	}
	infoScheme := site.UpstreamScheme
	if infoScheme == "" {
		infoScheme = "https"
	}
	upstream := infoScheme + "://" + upIP
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
</div></body></html>`, html.EscapeString(site.Domain), html.EscapeString(upstream), site.ID)
}

func (h *Handler) proxyRequest(w http.ResponseWriter, r *http.Request, site *db.Site, path string) {
	// Re-validate upstream IP at proxy time to prevent SSRF
	upstreamHost := site.UpstreamIP
	if idx := strings.Index(upstreamHost, "/"); idx != -1 {
		upstreamHost = upstreamHost[:idx]
	}
	if host, _, err := net.SplitHostPort(upstreamHost); err == nil {
		upstreamHost = host
	}
	if ip := net.ParseIP(upstreamHost); ip != nil && netguard.IsBlocked(ip) {
		jsonError(w, "upstream resolves to blocked address", http.StatusForbidden)
		return
	}

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

	// Extract source IP
	sourceIP := r.RemoteAddr
	if fwd := r.Header.Get("X-Real-IP"); fwd != "" {
		sourceIP = fwd
	}
	if hp, _, err := net.SplitHostPort(sourceIP); err == nil {
		sourceIP = hp
	}

	// IP blocklist check: threat_ips feed + active decisions
	if blocked, reason := h.checkIPBlock(r.Context(), sourceIP); blocked {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{
			"error":  "Blocked by Veil",
			"reason": reason,
		})
		return
	}

	// Phase 1: Instant regex classification — blocks obvious attacks inline
	regexResult := classify.RegexClassify(rawRequest)

	if regexResult.Classification == "MALICIOUS" && regexResult.Confidence > 0.6 {
		// Regex caught a clear attack — block immediately, run LLM in background for logging
		h.logAndBroadcast(site, rawForLog, rawRequest, sourceIP, regexResult, true)

		// Fire off LLM classification in background for richer logging
		go h.backgroundClassify(site, rawForLog, rawRequest, sourceIP)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]any{
			"error":          "Blocked by Veil",
			"classification": regexResult.Classification,
			"attack_type":    regexResult.AttackType,
			"reason":         html.EscapeString(regexResult.Reason),
		})
		return
	}

	// Phase 2: Proxy immediately. For safe requests, log directly. For suspicious, run LLM in background.
	if regexResult.Classification == "SAFE" {
		// Regex says safe — log it and move on, no LLM needed
		go h.logAndBroadcast(site, rawForLog, rawRequest, sourceIP, regexResult, false)
	} else {
		// Suspicious or low-confidence malicious — run full LLM pipeline in background
		go h.backgroundClassify(site, rawForLog, rawRequest, sourceIP)
	}

	// Forward to upstream — strip any CIDR suffix (e.g. /32 from inet conversion)
	upstreamIP := site.UpstreamIP
	if idx := strings.Index(upstreamIP, "/"); idx != -1 {
		upstreamIP = upstreamIP[:idx]
	}
	scheme := site.UpstreamScheme
	if scheme == "" {
		scheme = "https"
	}
	upstream := scheme + "://" + upstreamIP
	forwardURL := upstream + path
	if r.URL.RawQuery != "" {
		forwardURL += "?" + r.URL.RawQuery
	}

	proxyReq, err := http.NewRequestWithContext(r.Context(), r.Method, forwardURL, strings.NewReader(string(body)))
	if err != nil {
		jsonError(w, "Failed to create upstream request", http.StatusBadGateway)
		return
	}

	// Copy headers — strip hop-by-hop and spoofable forwarded headers
	strippedHeaders := map[string]bool{
		"host": true, "connection": true, "transfer-encoding": true,
		"content-length": true, "x-forwarded-host": true, "x-forwarded-proto": true,
		"x-forwarded-for": true, "x-real-ip": true, "via": true,
	}
	for key, values := range r.Header {
		if strippedHeaders[strings.ToLower(key)] {
			continue
		}
		for _, v := range values {
			proxyReq.Header.Add(key, v)
		}
	}
	// Set trusted forwarded headers from our own knowledge
	proxyReq.Header.Set("Host", site.Domain)
	proxyReq.Header.Set("X-Forwarded-For", sourceIP)
	proxyReq.Header.Set("X-Forwarded-Proto", "https")
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

// checkIPBlock checks the source IP against the threat_ips feed and active
// decisions table. Returns (true, reason) if the IP should be blocked.
func (h *Handler) checkIPBlock(ctx context.Context, ip string) (bool, string) {
	// Check threat intelligence feed (ban/block tiers)
	if tip, err := h.db.LookupThreatIP(ctx, ip); err == nil {
		if tip.Tier == "ban" || tip.Tier == "block" {
			h.logger.Warn("blocked by threat feed", "ip", ip, "tier", tip.Tier)
			return true, fmt.Sprintf("IP blocked by threat intelligence (%s)", tip.Tier)
		}
		// "scrutinize" tier — don't block, just let classification handle it
	}

	// Check active decisions (ban/captcha/throttle)
	if dec, err := h.db.CheckIPDecision(ctx, ip); err == nil {
		switch dec.DecisionType {
		case "ban":
			h.logger.Warn("blocked by decision", "ip", ip, "reason", dec.Reason)
			return true, fmt.Sprintf("IP banned: %s", dec.Reason)
		case "captcha":
			// For now, treat captcha as a soft block (no captcha UI yet)
			h.logger.Info("captcha decision for IP (passing through)", "ip", ip)
		case "throttle":
			// Throttle decisions are handled by the rate limiter already
			h.logger.Info("throttle decision for IP", "ip", ip)
		}
	}

	return false, ""
}

// backgroundClassify runs the full LLM classification pipeline in a background goroutine.
// It logs the result to DB and broadcasts via SSE.
func (h *Handler) backgroundClassify(site *db.Site, rawForLog, rawRequest, sourceIP string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result := h.pipeline.Classify(ctx, site.ID, rawRequest)
	h.logAndBroadcast(site, rawForLog, rawRequest, sourceIP, result, result.Blocked)
}

// logAndBroadcast writes a request log entry and publishes an SSE event.
func (h *Handler) logAndBroadcast(site *db.Site, rawForLog, rawRequest, sourceIP string, result *classify.Result, blocked bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	logEntry := &db.RequestLogEntry{
		SiteID:         site.ID,
		RawRequest:     rawForLog,
		Classification: result.Classification,
		Confidence:     float32(result.Confidence),
		Classifier:     result.Classifier,
		Blocked:        blocked,
		AttackType:     result.AttackType,
		ResponseTimeMs: float32(result.ResponseTimeMs),
		SourceIP:       sourceIP,
	}
	if err := h.db.InsertRequestLog(ctx, logEntry); err != nil {
		h.logger.Error("failed to log request", "err", err)
	}

	if h.hub != nil {
		eventData, _ := json.Marshal(map[string]any{
			"type":           "request",
			"timestamp":      time.Now().UTC().Format(time.RFC3339),
			"message":        truncate(rawRequest, 120),
			"classification": result.Classification,
			"confidence":     result.Confidence,
			"blocked":        blocked,
			"classifier":     result.Classifier,
			"attack_type":    result.AttackType,
		})
		h.hub.Publish(strconv.Itoa(site.ID), sse.Event{Type: "request", Data: eventData})
	}
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
