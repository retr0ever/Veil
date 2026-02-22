package auth

import (
	"context"
	"net/http"

	"github.com/veil-waf/veil-go/internal/db"
)

type ctxKey string

const userCtxKey ctxKey = "user"

// RequireAuth is chi middleware that validates the session.
func RequireAuth(sm *SessionManager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, err := sm.Validate(r.Context(), r)
			if err != nil || user == nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(`{"error":"authentication required"}`))
				return
			}
			ctx := context.WithValue(r.Context(), userCtxKey, user)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetUserFromCtx extracts user from request context.
func GetUserFromCtx(ctx context.Context) *db.User {
	u, _ := ctx.Value(userCtxKey).(*db.User)
	return u
}
