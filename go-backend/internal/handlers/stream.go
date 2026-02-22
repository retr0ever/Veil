package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/veil-waf/veil-go/internal/auth"
	"github.com/veil-waf/veil-go/internal/db"
	"github.com/veil-waf/veil-go/internal/sse"
)

// StreamHandler serves SSE streams for real-time site event monitoring.
type StreamHandler struct {
	hub *sse.Hub
	db  *db.DB
}

// NewStreamHandler creates a new StreamHandler.
func NewStreamHandler(hub *sse.Hub, database *db.DB) *StreamHandler {
	return &StreamHandler{hub: hub, db: database}
}

// HandleSSE handles GET /api/stream/events?site_id=X
// It sends an initial hydration payload of recent requests, agent logs, and stats,
// then streams live events via SSE with periodic keepalives.
func (sh *StreamHandler) HandleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	siteIDStr := r.URL.Query().Get("site_id")
	if siteIDStr == "" {
		jsonError(w, "site_id required", http.StatusBadRequest)
		return
	}

	siteID, err := strconv.Atoi(siteIDStr)
	if err != nil {
		jsonError(w, "invalid site_id", http.StatusBadRequest)
		return
	}

	user := auth.GetUserFromCtx(r.Context())
	owns, err := sh.db.UserOwnsSite(r.Context(), user.ID, siteID)
	if err != nil || !owns {
		jsonError(w, "forbidden", http.StatusForbidden)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	// Hydrate with recent data
	recent, _ := sh.db.GetRecentRequests(r.Context(), siteID, 20)
	for _, req := range recent {
		data, _ := json.Marshal(req)
		fmt.Fprintf(w, "event: request\ndata: %s\n\n", data)
	}

	agents, _ := sh.db.GetRecentAgentLogs(r.Context(), siteID, 10)
	for _, a := range agents {
		data, _ := json.Marshal(a)
		fmt.Fprintf(w, "event: agent\ndata: %s\n\n", data)
	}

	stats, _ := sh.db.GetSiteStats(r.Context(), siteID)
	if stats != nil {
		data, _ := json.Marshal(stats)
		fmt.Fprintf(w, "event: stats\ndata: %s\n\n", data)
	}
	flusher.Flush()

	// Subscribe to live events
	ch, cancel := sh.hub.Subscribe(siteIDStr)
	defer cancel()

	keepalive := time.NewTicker(30 * time.Second)
	defer keepalive.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case event, ok := <-ch:
			if !ok {
				return
			}
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event.Type, event.Data)
			flusher.Flush()
		case <-keepalive.C:
			fmt.Fprintf(w, ": keepalive\n\n")
			flusher.Flush()
		}
	}
}
