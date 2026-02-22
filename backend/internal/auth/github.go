package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/veil-waf/veil-go/internal/db"
)

var githubHTTPClient = &http.Client{
	Timeout: 10 * time.Second,
}

type OAuthConfig struct {
	ClientID     string
	ClientSecret string
	BaseURL      string // e.g. "https://app.reveil.tech"
}

type OAuthHandler struct {
	cfg       OAuthConfig
	sessions  *SessionManager
	db        *db.DB
	logger    *slog.Logger
	encryptor *TokenEncryptor // may be nil if TOKEN_ENCRYPTION_KEY not set

	// In-memory state store (pending OAuth states, TTL 10 min)
	mu     sync.Mutex
	states map[string]*oauthState
}

type oauthState struct {
	UserID    int    // 0 for login, >0 for repo-connect
	Purpose   string // "login" or "repo-connect"
	SiteID    string // only for repo-connect
	CreatedAt time.Time
}

func NewOAuthHandler(cfg OAuthConfig, sm *SessionManager, database *db.DB, logger *slog.Logger, enc *TokenEncryptor) *OAuthHandler {
	h := &OAuthHandler{
		cfg:       cfg,
		sessions:  sm,
		db:        database,
		logger:    logger,
		encryptor: enc,
		states:    make(map[string]*oauthState),
	}
	return h
}

func (h *OAuthHandler) generateState(purpose string, userID int, siteID string) string {
	b := make([]byte, 16)
	rand.Read(b)
	state := hex.EncodeToString(b)

	h.mu.Lock()
	h.states[state] = &oauthState{
		UserID: userID, Purpose: purpose, SiteID: siteID, CreatedAt: time.Now(),
	}
	h.mu.Unlock()
	return state
}

func (h *OAuthHandler) validateState(state string) (*oauthState, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	s, ok := h.states[state]
	if !ok {
		return nil, false
	}
	delete(h.states, state)
	if time.Since(s.CreatedAt) > 10*time.Minute {
		return nil, false
	}
	return s, true
}

// StateCleanupLoop removes expired states every 5 minutes.
func (h *OAuthHandler) StateCleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			h.mu.Lock()
			for k, s := range h.states {
				if time.Since(s.CreatedAt) > 10*time.Minute {
					delete(h.states, k)
				}
			}
			h.mu.Unlock()
		}
	}
}

// BeginLogin redirects to GitHub OAuth (read:user scope).
func (h *OAuthHandler) BeginLogin(w http.ResponseWriter, r *http.Request) {
	state := h.generateState("login", 0, "")
	params := url.Values{
		"client_id":    {h.cfg.ClientID},
		"scope":        {"read:user"},
		"state":        {state},
		"redirect_uri": {h.cfg.BaseURL + "/auth/github/callback"},
	}
	http.Redirect(w, r, "https://github.com/login/oauth/authorize?"+params.Encode(), http.StatusFound)
}

// BeginRepoConnect redirects to GitHub OAuth with repo scope.
func (h *OAuthHandler) BeginRepoConnect(w http.ResponseWriter, r *http.Request) {
	user := GetUserFromCtx(r.Context())
	if user == nil {
		http.Error(w, `{"error":"authentication required"}`, http.StatusUnauthorized)
		return
	}
	siteID := r.URL.Query().Get("site_id")
	if siteID == "" {
		http.Error(w, `{"error":"site_id required"}`, http.StatusBadRequest)
		return
	}
	state := h.generateState("repo-connect", user.ID, siteID)
	params := url.Values{
		"client_id":    {h.cfg.ClientID},
		"scope":        {"read:user repo"},
		"state":        {state},
		"redirect_uri": {h.cfg.BaseURL + "/auth/github/callback"},
	}
	http.Redirect(w, r, "https://github.com/login/oauth/authorize?"+params.Encode(), http.StatusFound)
}

// Callback handles the OAuth callback.
func (h *OAuthHandler) Callback(w http.ResponseWriter, r *http.Request) {
	if errParam := r.URL.Query().Get("error"); errParam != "" {
		h.logger.Info("oauth denied by user", "error", errParam)
		http.Redirect(w, r, "/?error=denied", http.StatusFound)
		return
	}

	code := r.URL.Query().Get("code")
	stateStr := r.URL.Query().Get("state")

	if code == "" {
		http.Error(w, `{"error":"missing code parameter"}`, http.StatusBadRequest)
		return
	}

	state, valid := h.validateState(stateStr)
	if !valid {
		http.Error(w, `{"error":"invalid or expired state"}`, http.StatusBadRequest)
		return
	}

	// Exchange code for token
	token, err := h.exchangeCode(r.Context(), code)
	if err != nil {
		h.logger.Error("oauth exchange failed", "err", err)
		http.Error(w, `{"error":"github auth failed"}`, http.StatusBadRequest)
		return
	}

	// Fetch GitHub profile
	ghUser, err := h.fetchGitHubUser(r.Context(), token)
	if err != nil {
		h.logger.Error("github user fetch failed", "err", err)
		http.Error(w, `{"error":"github user fetch failed"}`, http.StatusInternalServerError)
		return
	}

	// Upsert user
	user := &db.User{
		GitHubID:    ghUser.ID,
		GitHubLogin: ghUser.Login,
		AvatarURL:   ghUser.AvatarURL,
		Name:        ghUser.Name,
	}
	userID, err := h.db.UpsertUser(r.Context(), user)
	if err != nil {
		h.logger.Error("user upsert failed", "err", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	switch state.Purpose {
	case "login":
		if err := h.sessions.Create(r.Context(), w, userID, r); err != nil {
			http.Error(w, `{"error":"session creation failed"}`, http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/app/projects", http.StatusFound)

	case "repo-connect":
		if h.encryptor == nil {
			h.logger.Error("repo connect: no token encryptor configured")
			http.Error(w, `{"error":"token encryption not configured"}`, http.StatusInternalServerError)
			return
		}
		encToken, err := h.encryptor.Encrypt(token)
		if err != nil {
			h.logger.Error("repo connect: encrypt token failed", "err", err)
			http.Error(w, `{"error":"token encryption failed"}`, http.StatusInternalServerError)
			return
		}
		if err := h.db.StoreGitHubToken(r.Context(), userID, encToken, "read:user repo"); err != nil {
			h.logger.Error("repo connect: store token failed", "err", err)
			http.Error(w, `{"error":"token storage failed"}`, http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r,
			fmt.Sprintf("/app/projects/%s#setup", state.SiteID), http.StatusFound)
	}
}

// Me returns the current user as JSON.
func (h *OAuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	user, err := h.sessions.Validate(r.Context(), r)
	if err != nil {
		h.logger.Error("session validate failed", "err", err)
	}
	if user == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "not authenticated"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

// Logout destroys the session (POST only).
func (h *OAuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	h.sessions.Destroy(r.Context(), w, r)
	http.Redirect(w, r, "/", http.StatusFound)
}

type ghUser struct {
	ID        int64  `json:"id"`
	Login     string `json:"login"`
	AvatarURL string `json:"avatar_url"`
	Name      string `json:"name"`
}

// exchangeCode exchanges the OAuth code for an access token.
func (h *OAuthHandler) exchangeCode(ctx context.Context, code string) (string, error) {
	data := url.Values{
		"client_id":     {h.cfg.ClientID},
		"client_secret": {h.cfg.ClientSecret},
		"code":          {code},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://github.com/login/oauth/access_token",
		strings.NewReader(data.Encode()))
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := githubHTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("exchange request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github token exchange returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MB max
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}

	var result struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
		ErrorDesc   string `json:"error_description"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("parse response: %w", err)
	}
	if result.Error != "" {
		return "", fmt.Errorf("github oauth error: %s - %s", result.Error, result.ErrorDesc)
	}
	if result.AccessToken == "" {
		return "", fmt.Errorf("empty access token in response")
	}
	return result.AccessToken, nil
}

// fetchGitHubUser fetches the authenticated user's profile from GitHub.
func (h *OAuthHandler) fetchGitHubUser(ctx context.Context, token string) (*ghUser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user", nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := githubHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch user: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github user API returned %d", resp.StatusCode)
	}

	var user ghUser
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, fmt.Errorf("decode user: %w", err)
	}
	return &user, nil
}
