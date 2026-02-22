package sse

import (
	"log/slog"
	"sync"
)

// Event represents a server-sent event to be published to subscribers.
type Event struct {
	Type string // "request", "agent", "stats"
	Data []byte // JSON payload
}

// Hub is a fan-out hub that manages per-site SSE subscriptions.
// Subscribers receive events published for the site IDs they are subscribed to.
type Hub struct {
	mu          sync.RWMutex
	subscribers map[string]map[chan Event]struct{} // siteID -> set of channels
	logger      *slog.Logger
}

// NewHub creates a new SSE hub.
func NewHub(logger *slog.Logger) *Hub {
	return &Hub{
		subscribers: make(map[string]map[chan Event]struct{}),
		logger:      logger,
	}
}

// Subscribe registers a new subscriber for the given site ID.
// It returns a channel that will receive events and a cancel function that
// must be called when the subscriber disconnects.
func (h *Hub) Subscribe(siteID string) (chan Event, func()) {
	ch := make(chan Event, 64)
	h.mu.Lock()
	if h.subscribers[siteID] == nil {
		h.subscribers[siteID] = make(map[chan Event]struct{})
	}
	h.subscribers[siteID][ch] = struct{}{}
	h.mu.Unlock()

	cancel := func() {
		h.mu.Lock()
		delete(h.subscribers[siteID], ch)
		if len(h.subscribers[siteID]) == 0 {
			delete(h.subscribers, siteID)
		}
		close(ch)
		h.mu.Unlock()
	}
	return ch, cancel
}

// Publish sends an event to all subscribers of the given site ID.
// If a subscriber's channel is full, the event is dropped and a warning is logged.
func (h *Hub) Publish(siteID string, event Event) {
	h.mu.RLock()
	subs := h.subscribers[siteID]
	h.mu.RUnlock()

	for ch := range subs {
		select {
		case ch <- event:
		default:
			h.logger.Warn("sse: dropped event for slow client", "site_id", siteID)
		}
	}
}

// SubscriberCount returns the number of active subscribers for the given site ID.
func (h *Hub) SubscriberCount(siteID string) int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.subscribers[siteID])
}
