package ws

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/veil-waf/veil-go/internal/db"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin:     func(r *http.Request) bool { return true },
}

// Manager tracks active WebSocket connections and broadcasts events.
type Manager struct {
	mu          sync.RWMutex
	connections []*websocket.Conn
	logger      *slog.Logger
	db          *db.DB
}

// NewManager creates a new WebSocket manager.
func NewManager(database *db.DB, logger *slog.Logger) *Manager {
	return &Manager{db: database, logger: logger}
}

// HandleWS upgrades an HTTP connection to WebSocket and registers it.
func (m *Manager) HandleWS(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		m.logger.Error("websocket upgrade failed", "err", err)
		return
	}

	m.mu.Lock()
	m.connections = append(m.connections, conn)
	m.mu.Unlock()

	// Hydrate: send current stats and recent data
	m.hydrate(conn)

	// Keep connection alive, read messages (we ignore them)
	defer func() {
		m.mu.Lock()
		for i, c := range m.connections {
			if c == conn {
				m.connections = append(m.connections[:i], m.connections[i+1:]...)
				break
			}
		}
		m.mu.Unlock()
		conn.Close()
	}()

	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			break
		}
	}
}

func (m *Manager) hydrate(conn *websocket.Conn) {
	ctx := conn.NetConn().LocalAddr().Network() // dummy context
	_ = ctx

	// Send global stats
	stats, err := m.db.GetGlobalStats(nil)
	if err == nil {
		m.sendJSON(conn, map[string]any{
			"type":              "stats",
			"total_requests":    stats.TotalRequests,
			"blocked_requests":  stats.BlockedCount,
			"total_threats":     stats.ThreatCount,
			"threats_blocked":   stats.ThreatCount, // approximate
			"block_rate":        blockRate(stats.TotalRequests, stats.BlockedCount),
			"rules_version":     1,
		})
	}

	// Send recent requests
	requests, err := m.db.GetGlobalRecentRequests(nil, 20)
	if err == nil {
		for i := len(requests) - 1; i >= 0; i-- {
			r := requests[i]
			m.sendJSON(conn, map[string]any{
				"type":           "request",
				"timestamp":      r.Timestamp.Format(time.RFC3339),
				"message":        truncate(r.RawRequest, 120),
				"classification": r.Classification,
				"confidence":     r.Confidence,
				"blocked":        r.Blocked,
				"classifier":     r.Classifier,
				"attack_type":    r.AttackType,
			})
		}
	}

	// Send recent agent logs
	logs, err := m.db.GetGlobalRecentAgentLogs(nil, 10)
	if err == nil {
		for i := len(logs) - 1; i >= 0; i-- {
			l := logs[i]
			status := "done"
			if !l.Success {
				status = "error"
			}
			m.sendJSON(conn, map[string]any{
				"type":   "agent",
				"agent":  l.Agent,
				"status": status,
				"detail": l.Detail,
			})
		}
	}
}

// Broadcast sends a message to all connected WebSocket clients.
func (m *Manager) Broadcast(data map[string]any) {
	m.mu.RLock()
	conns := make([]*websocket.Conn, len(m.connections))
	copy(conns, m.connections)
	m.mu.RUnlock()

	var dead []*websocket.Conn
	for _, conn := range conns {
		if err := m.sendJSON(conn, data); err != nil {
			dead = append(dead, conn)
		}
	}

	if len(dead) > 0 {
		m.mu.Lock()
		for _, d := range dead {
			for i, c := range m.connections {
				if c == d {
					m.connections = append(m.connections[:i], m.connections[i+1:]...)
					d.Close()
					break
				}
			}
		}
		m.mu.Unlock()
	}
}

func (m *Manager) sendJSON(conn *websocket.Conn, data map[string]any) error {
	msg, err := json.Marshal(data)
	if err != nil {
		return err
	}
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	return conn.WriteMessage(websocket.TextMessage, msg)
}

func blockRate(total, blocked int64) float64 {
	if total == 0 {
		return 0
	}
	return float64(blocked) / float64(total) * 100
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}
