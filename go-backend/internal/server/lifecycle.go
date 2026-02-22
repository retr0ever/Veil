package server

import (
	"context"
	"log/slog"
	"math"
	"os"
	"runtime/debug"
	"time"
)

// RunWithRecovery runs fn in a loop, recovering from panics with exponential backoff.
// It stops when ctx is cancelled.
func RunWithRecovery(ctx context.Context, logger *slog.Logger, name string, fn func(ctx context.Context)) {
	attempt := 0
	for {
		select {
		case <-ctx.Done():
			logger.Info("goroutine stopped", "name", name, "reason", "context cancelled")
			return
		default:
		}

		func() {
			defer func() {
				if r := recover(); r != nil {
					logger.Error("goroutine panicked",
						"name", name,
						"panic", r,
						"stack", string(debug.Stack()),
						"attempt", attempt,
					)
				}
			}()
			fn(ctx)
		}()

		// If fn returned normally (not panic), check if context is done
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Exponential backoff: 1s, 2s, 4s, 8s, ... max 5min
		attempt++
		backoff := time.Duration(math.Min(
			float64(time.Second)*math.Pow(2, float64(attempt-1)),
			float64(5*time.Minute),
		))
		logger.Warn("goroutine restarting",
			"name", name,
			"attempt", attempt,
			"backoff", backoff,
		)

		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
	}
}

// SetupLogger creates a structured slog.Logger with JSON output to stdout.
func SetupLogger(level string) *slog.Logger {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}

	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: lvl,
	})
	return slog.New(handler)
}
