package sse

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PGListener subscribes to PostgreSQL NOTIFY channels and fans out
// notifications to the SSE hub.
type PGListener struct {
	pool   *pgxpool.Pool
	hub    *Hub
	logger *slog.Logger
}

// NewPGListener creates a new PGListener that bridges PostgreSQL notifications to SSE.
func NewPGListener(pool *pgxpool.Pool, hub *Hub, logger *slog.Logger) *PGListener {
	return &PGListener{pool: pool, hub: hub, logger: logger}
}

// Listen subscribes to PostgreSQL NOTIFY channels and fans out to the SSE hub.
// It blocks until ctx is cancelled or an error occurs.
// It should be run inside RunWithRecovery so it auto-restarts on failure.
func (pl *PGListener) Listen(ctx context.Context) {
	conn, err := pl.pool.Acquire(ctx)
	if err != nil {
		pl.logger.Error("pg-listen: acquire connection failed", "err", err)
		return
	}
	defer conn.Release()

	for _, ch := range []string{"request_stream", "agent_stream"} {
		if _, err := conn.Exec(ctx, fmt.Sprintf("LISTEN %s", ch)); err != nil {
			pl.logger.Error("pg-listen: LISTEN failed", "channel", ch, "err", err)
			return
		}
	}
	pl.logger.Info("pg-listen: subscribed to notification channels")

	for {
		notification, err := conn.Conn().WaitForNotification(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return // graceful shutdown
			}
			pl.logger.Error("pg-listen: notification error", "err", err)
			return // RunWithRecovery will reconnect
		}

		event := Event{Data: []byte(notification.Payload)}
		switch notification.Channel {
		case "request_stream":
			event.Type = "request"
		case "agent_stream":
			event.Type = "agent"
		}

		var payload struct {
			SiteID int `json:"site_id"`
		}
		if err := json.Unmarshal([]byte(notification.Payload), &payload); err != nil {
			pl.logger.Warn("pg-listen: unmarshal payload failed", "err", err)
			continue
		}

		pl.hub.Publish(strconv.Itoa(payload.SiteID), event)
	}
}
