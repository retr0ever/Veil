package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/veil-waf/veil-go/internal/db"
)

const (
	SessionCookie = "veil_sid"
	SessionMaxAge = 30 * 24 * time.Hour // 30 days
)

type SessionManager struct {
	db     *db.DB
	logger *slog.Logger
	secure bool // true in production (Secure cookie flag)
}

func NewSessionManager(database *db.DB, logger *slog.Logger, production bool) *SessionManager {
	return &SessionManager{db: database, logger: logger, secure: production}
}

// Create inserts a session row and sets the cookie.
func (sm *SessionManager) Create(ctx context.Context, w http.ResponseWriter, userID int, r *http.Request) error {
	// Strip port from RemoteAddr before storing as inet
	ip := r.RemoteAddr
	if host, _, err := net.SplitHostPort(ip); err == nil {
		ip = host
	}
	ua := r.UserAgent()

	sessionID, err := sm.db.CreateSession(ctx, userID, ip, ua)
	if err != nil {
		return err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookie,
		Value:    sessionID,
		Path:     "/",
		MaxAge:   int(SessionMaxAge.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   sm.secure,
	})
	return nil
}

// Validate reads the cookie and returns the user, or nil.
func (sm *SessionManager) Validate(ctx context.Context, r *http.Request) (*db.User, error) {
	cookie, err := r.Cookie(SessionCookie)
	if err != nil {
		return nil, nil // no cookie = not logged in
	}

	session, err := sm.db.GetSession(ctx, cookie.Value)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil // session not found = not logged in
		}
		return nil, fmt.Errorf("get session: %w", err)
	}
	if session == nil || session.ExpiresAt.Before(time.Now()) {
		return nil, nil // expired or not found
	}

	return sm.db.GetUserByID(ctx, session.UserID)
}

// Destroy deletes the session and clears the cookie.
func (sm *SessionManager) Destroy(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(SessionCookie)
	if err == nil {
		sm.db.DeleteSession(ctx, cookie.Value)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   sm.secure,
	})
}

// CleanupLoop purges expired sessions every 24 hours.
func (sm *SessionManager) CleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			deleted, err := sm.db.CleanExpiredSessions(ctx)
			if err != nil {
				sm.logger.Error("session cleanup failed", "err", err)
				continue
			}
			if deleted > 0 {
				sm.logger.Info("cleaned expired sessions", "count", deleted)
			}
		}
	}
}
