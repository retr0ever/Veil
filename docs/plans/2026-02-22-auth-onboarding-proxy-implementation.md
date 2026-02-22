# Auth, Onboarding, Proxy & Dashboard Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Extend the Go backend with PostgreSQL 18, server-side sessions, Cloudflare-style DNS onboarding, certmagic auto-TLS, SSE log streaming, dashboard REST API, GitHub repo code scanning, and intelligence/compliance analytics.

**Architecture:** This plan supplements `docs/plans/2026-02-21-go-backend-implementation.md` (Phases 1-9, Tasks 1-36). It replaces SQLite with PostgreSQL, WebSocket with SSE, and signed cookies with server-side sessions. All new phases can be developed after Phase 1 foundation is laid.

**Tech Stack:** Go 1.23+, PostgreSQL 18 (pgx/v5, pgxpool), certmagic, chi/v5, google/go-github/v60, slog, EventSource/SSE

**Worktree:** `.worktrees/go-merged` (branch: `go-merged`)

**Design doc:** `docs/plans/2026-02-21-go-backend-design.md` (Sections 13-19)

---

## Superseded Tasks from Original Plan

These tasks from the original plan are **replaced** by tasks in this plan:

| Original Task | Replaced By | Reason |
|---------------|-------------|--------|
| Task 1 (go.mod) | Task 37 | Different dependencies (pgx, certmagic, chi) |
| Task 2 (SQLite DB) | Tasks 38-39 | PostgreSQL with migrations, extensions, triggers |
| Task 6 (WebSocket hub) | Tasks 50-52 | SSE via LISTEN/NOTIFY replaces WebSocket |
| Task 7 (GitHub OAuth) | Tasks 41-42 | Server-side sessions, state param, repo scope |

Tasks 3-5, 8-36 from the original plan remain valid but should reference PostgreSQL instead of SQLite for any DB operations.

---

## Phase 10: PostgreSQL Foundation

### Task 37: Update Go module dependencies

**Files:**
- Modify: `go-backend/go.mod`

**Step 1: Replace SQLite deps with PostgreSQL + new deps**

```bash
cd .worktrees/go-merged/go-backend

# Remove SQLite
go get -u github.com/mattn/go-sqlite3@none 2>/dev/null || true

# Add PostgreSQL driver
go get github.com/jackc/pgx/v5@latest

# Replace gorilla/mux with chi (stdlib-compatible, lighter)
go get github.com/go-chi/chi/v5@latest
go get -u github.com/gorilla/mux@none 2>/dev/null || true

# Add certmagic for auto-TLS
go get github.com/caddyserver/certmagic@latest

# Add GitHub API client
go get github.com/google/go-github/v60@latest

# Keep existing deps
go mod tidy
```

**Step 2: Verify module resolves**

Run: `go mod verify`
Expected: `all modules verified`

**Step 3: Commit**

```bash
git add go-backend/go.mod go-backend/go.sum
git commit -m "feat: update deps — pgx, chi, certmagic, go-github replace sqlite/mux"
```

---

### Task 38: PostgreSQL database layer with migrations

**Files:**
- Create: `go-backend/internal/db/database.go`
- Create: `go-backend/internal/db/migrations/001_init.sql`

**Step 1: Write the migration SQL file**

`001_init.sql` contains ALL table definitions from Design Section 3 — core tables, behavioral tables, CrowdSec hub table, threat intel tables, GitHub repo tables, SSE triggers. Complete SQL:

```sql
-- Extensions
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS btree_gist;
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- Core tables
CREATE TABLE IF NOT EXISTS users (
    id              SERIAL PRIMARY KEY,
    github_id       BIGINT NOT NULL UNIQUE,
    github_login    TEXT NOT NULL,
    avatar_url      TEXT,
    name            TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS sessions (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '30 days',
    ip_address  inet,
    user_agent  TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS sites (
    id              SERIAL PRIMARY KEY,
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    domain          TEXT NOT NULL UNIQUE,
    project_name    TEXT,
    upstream_ip     inet NOT NULL,
    original_cname  TEXT,
    status          TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending','verifying','active',
                                      'ssl_provisioning','live','error')),
    verified_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_sites_domain ON sites(domain);
CREATE INDEX IF NOT EXISTS idx_sites_user ON sites(user_id);

CREATE TABLE IF NOT EXISTS threats (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    site_id         INTEGER REFERENCES sites(id) ON DELETE CASCADE,
    technique_name  TEXT NOT NULL,
    category        TEXT NOT NULL DEFAULT 'sqli',
    source          TEXT,
    raw_payload     TEXT NOT NULL,
    severity        TEXT NOT NULL DEFAULT 'medium',
    discovered_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    tested_at       TIMESTAMPTZ,
    blocked         BOOLEAN NOT NULL DEFAULT FALSE,
    patched_at      TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS request_log (
    id              BIGINT GENERATED ALWAYS AS IDENTITY,
    site_id         INTEGER NOT NULL,
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    raw_request     TEXT NOT NULL,
    classification  TEXT NOT NULL,
    confidence      REAL,
    classifier      TEXT NOT NULL,
    blocked         BOOLEAN NOT NULL DEFAULT FALSE,
    attack_type     TEXT,
    response_time_ms REAL,
    source_ip       inet,
    PRIMARY KEY (id, timestamp)
) PARTITION BY RANGE (timestamp);

CREATE TABLE IF NOT EXISTS agent_log (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    site_id     INTEGER REFERENCES sites(id) ON DELETE CASCADE,
    timestamp   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    agent       TEXT NOT NULL,
    action      TEXT NOT NULL,
    detail      TEXT,
    success     BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS rules (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    site_id     INTEGER REFERENCES sites(id) ON DELETE CASCADE,
    version     INTEGER NOT NULL DEFAULT 1,
    crusoe_prompt TEXT NOT NULL,
    claude_prompt TEXT NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by  TEXT NOT NULL DEFAULT 'system'
);

-- Behavioral tables
CREATE TABLE IF NOT EXISTS decisions (
    id                BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ip                inet NOT NULL,
    decision_type     TEXT NOT NULL CHECK (decision_type IN ('ban','captcha','throttle','log_only')),
    scope             TEXT NOT NULL,
    duration_seconds  INTEGER,
    reason            TEXT,
    source            TEXT,
    confidence        REAL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at        TIMESTAMPTZ,
    site_id           INTEGER REFERENCES sites(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_decisions_ip ON decisions USING gist (ip inet_ops);
CREATE INDEX IF NOT EXISTS idx_decisions_expires ON decisions(expires_at);

CREATE TABLE IF NOT EXISTS ip_reputation (
    ip              inet PRIMARY KEY,
    score           REAL DEFAULT 0.0,
    attack_count    INTEGER DEFAULT 0,
    tenant_count    INTEGER DEFAULT 0,
    attack_types    JSONB DEFAULT '[]',
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    geo_country     TEXT,
    asn             TEXT,
    is_tor          BOOLEAN DEFAULT FALSE,
    is_vpn          BOOLEAN DEFAULT FALSE
);
CREATE INDEX IF NOT EXISTS idx_ip_reputation_score ON ip_reputation(score);

CREATE TABLE IF NOT EXISTS behavioral_sessions (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ip              inet NOT NULL,
    site_id         INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    window_start    TIMESTAMPTZ,
    request_count   INTEGER DEFAULT 0,
    error_count     INTEGER DEFAULT 0,
    unique_paths    INTEGER DEFAULT 0,
    auth_failures   INTEGER DEFAULT 0,
    avg_interval_ms REAL,
    flags           JSONB DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_behavioral_ip_site ON behavioral_sessions(ip, site_id);

CREATE TABLE IF NOT EXISTS endpoint_profiles (
    id                   BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    site_id              INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    path_pattern         TEXT NOT NULL,
    sensitivity          TEXT DEFAULT 'MEDIUM',
    attack_frequency     REAL,
    false_positive_rate  REAL,
    skip_classification  BOOLEAN DEFAULT FALSE,
    force_deep_analysis  BOOLEAN DEFAULT FALSE,
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Threat intelligence tables
CREATE TABLE IF NOT EXISTS threat_ips (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ip          inet NOT NULL,
    tier        TEXT NOT NULL CHECK (tier IN ('ban', 'block', 'scrutinize')),
    source      TEXT NOT NULL,
    fetched_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_threat_ips_containment ON threat_ips USING gist (ip inet_ops);
CREATE INDEX IF NOT EXISTS idx_threat_ips_source ON threat_ips(source);

CREATE TABLE IF NOT EXISTS threat_feeds (
    id          SERIAL PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    url         TEXT NOT NULL,
    tier        INTEGER NOT NULL,
    last_fetch  TIMESTAMPTZ,
    last_success TIMESTAMPTZ,
    entry_count INTEGER DEFAULT 0,
    error       TEXT,
    enabled     BOOLEAN DEFAULT TRUE
);

-- CrowdSec Hub table
CREATE TABLE IF NOT EXISTS hub_rules (
    id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    hub_name      TEXT NOT NULL UNIQUE,
    hub_type      TEXT NOT NULL,
    version       TEXT,
    yaml_content  TEXT,
    imported_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    site_id       INTEGER REFERENCES sites(id) ON DELETE CASCADE,
    active        BOOLEAN DEFAULT TRUE
);

-- GitHub repo connection tables
CREATE TABLE IF NOT EXISTS github_tokens (
    user_id         INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    encrypted_token TEXT NOT NULL,
    scopes          TEXT NOT NULL DEFAULT 'read:user',
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS site_repos (
    site_id         INTEGER PRIMARY KEY REFERENCES sites(id) ON DELETE CASCADE,
    repo_owner      TEXT NOT NULL,
    repo_name       TEXT NOT NULL,
    default_branch  TEXT NOT NULL DEFAULT 'main',
    connected_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS code_findings (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    site_id         INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    threat_id       BIGINT REFERENCES threats(id),
    file_path       TEXT NOT NULL,
    line_start      INTEGER,
    line_end        INTEGER,
    snippet         TEXT,
    finding_type    TEXT NOT NULL,
    confidence      REAL NOT NULL,
    description     TEXT NOT NULL,
    suggested_fix   TEXT,
    status          TEXT NOT NULL DEFAULT 'open'
                    CHECK (status IN ('open','acknowledged','fixed','false_positive')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_code_findings_site ON code_findings(site_id);
CREATE INDEX IF NOT EXISTS idx_code_findings_threat ON code_findings(threat_id);

-- SSE notification triggers
CREATE OR REPLACE FUNCTION notify_request_log() RETURNS trigger AS $$
BEGIN
    PERFORM pg_notify('request_stream', json_build_object(
        'id', NEW.id, 'site_id', NEW.site_id, 'timestamp', NEW.timestamp,
        'raw_request', left(NEW.raw_request, 120), 'classification', NEW.classification,
        'confidence', NEW.confidence, 'classifier', NEW.classifier,
        'blocked', NEW.blocked, 'attack_type', NEW.attack_type,
        'response_time_ms', NEW.response_time_ms, 'source_ip', NEW.source_ip
    )::text);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_request_log_notify
    AFTER INSERT ON request_log FOR EACH ROW EXECUTE FUNCTION notify_request_log();

CREATE OR REPLACE FUNCTION notify_agent_log() RETURNS trigger AS $$
BEGIN
    PERFORM pg_notify('agent_stream', json_build_object(
        'id', NEW.id, 'site_id', NEW.site_id, 'timestamp', NEW.timestamp,
        'agent', NEW.agent, 'action', NEW.action,
        'detail', left(NEW.detail, 200), 'success', NEW.success
    )::text);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_agent_log_notify
    AFTER INSERT ON agent_log FOR EACH ROW EXECUTE FUNCTION notify_agent_log();
```

**Step 2: Write database.go**

```go
package db

import (
    "context"
    "embed"
    "fmt"
    "log/slog"
    "os"
    "time"

    "github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrations embed.FS

type DB struct {
    Pool   *pgxpool.Pool
    logger *slog.Logger
}

func Connect(ctx context.Context, logger *slog.Logger) (*DB, error) {
    dsn := os.Getenv("DATABASE_URL")
    if dsn == "" {
        dsn = "postgres://veil:veil@localhost:5432/veil?sslmode=disable"
    }

    config, err := pgxpool.ParseConfig(dsn)
    if err != nil {
        return nil, fmt.Errorf("parse dsn: %w", err)
    }
    config.MaxConns = 20
    config.MinConns = 2
    config.MaxConnLifetime = 30 * time.Minute
    config.MaxConnIdleTime = 5 * time.Minute

    pool, err := pgxpool.NewWithConfig(ctx, config)
    if err != nil {
        return nil, fmt.Errorf("connect: %w", err)
    }

    if err := pool.Ping(ctx); err != nil {
        return nil, fmt.Errorf("ping: %w", err)
    }

    db := &DB{Pool: pool, logger: logger}
    if err := db.Migrate(ctx); err != nil {
        return nil, fmt.Errorf("migrate: %w", err)
    }

    return db, nil
}

func (db *DB) Migrate(ctx context.Context) error {
    sql, err := migrations.ReadFile("migrations/001_init.sql")
    if err != nil {
        return fmt.Errorf("read migration: %w", err)
    }
    if _, err := db.Pool.Exec(ctx, string(sql)); err != nil {
        return fmt.Errorf("exec migration: %w", err)
    }
    db.logger.Info("database migrated")
    return nil
}

func (db *DB) Close() {
    db.Pool.Close()
}

func (db *DB) PingContext(ctx context.Context) error {
    return db.Pool.Ping(ctx)
}
```

Then add CRUD methods for each table. Key methods:

```go
// Sessions
func (db *DB) CreateSession(ctx context.Context, userID int, ip, ua string) (string, error)
func (db *DB) GetSession(ctx context.Context, sessionID string) (*Session, error)
func (db *DB) DeleteSession(ctx context.Context, sessionID string) error
func (db *DB) CleanExpiredSessions(ctx context.Context) (int64, error)

// Users
func (db *DB) UpsertUser(ctx context.Context, u *User) (int, error)
func (db *DB) GetUserByID(ctx context.Context, id int) (*User, error)

// Sites
func (db *DB) CreateSite(ctx context.Context, s *Site) error
func (db *DB) GetSiteByDomain(ctx context.Context, domain string) (*Site, error)
func (db *DB) GetSitesByUser(ctx context.Context, userID int) ([]Site, error)
func (db *DB) GetUnverifiedSites(ctx context.Context) ([]Site, error)
func (db *DB) UpdateSiteStatus(ctx context.Context, siteID int, status string) error
func (db *DB) DeleteSite(ctx context.Context, siteID, userID int) error
func (db *DB) UserOwnsSite(ctx context.Context, userID int, siteID string) bool

// Request log (partitioned)
func (db *DB) InsertRequestLog(ctx context.Context, r *RequestLogEntry) error
func (db *DB) GetRecentRequests(ctx context.Context, siteID string, limit int) ([]RequestLogEntry, error)
func (db *DB) EnsurePartition(ctx context.Context, t time.Time) error

// Agent log
func (db *DB) InsertAgentLog(ctx context.Context, a *AgentLogEntry) error
func (db *DB) GetRecentAgentLogs(ctx context.Context, siteID string, limit int) ([]AgentLogEntry, error)

// Rules
func (db *DB) GetCurrentRules(ctx context.Context, siteID int) (*Rules, error)
func (db *DB) InsertRules(ctx context.Context, r *Rules) error

// Threats
func (db *DB) InsertThreat(ctx context.Context, t *Threat) error
func (db *DB) GetThreats(ctx context.Context, siteID int) ([]Threat, error)
func (db *DB) GetThreatDistribution(ctx context.Context) ([]ThreatCategory, error)

// Stats
func (db *DB) GetSiteStats(ctx context.Context, siteID string) (*Stats, error)
func (db *DB) GetComplianceReport(ctx context.Context) (*ComplianceReport, error)

// Threat intelligence (native inet queries)
func (db *DB) LookupThreatIP(ctx context.Context, ip string) (*ThreatIPResult, error)
func (db *DB) BulkInsertThreatIPs(ctx context.Context, entries []ThreatIPEntry) error
func (db *DB) ClearThreatIPsBySource(ctx context.Context, source string) error

// GitHub repos
func (db *DB) StoreGitHubToken(ctx context.Context, userID int, encToken, scopes string) error
func (db *DB) GetGitHubToken(ctx context.Context, userID int) (string, error)
func (db *DB) LinkRepo(ctx context.Context, siteID int, owner, name, branch string) error
func (db *DB) GetSiteRepo(ctx context.Context, siteID int) (*SiteRepo, error)
func (db *DB) UnlinkRepo(ctx context.Context, siteID int) error
func (db *DB) InsertCodeFinding(ctx context.Context, f *CodeFinding) error
func (db *DB) GetCodeFindings(ctx context.Context, siteID int) ([]CodeFinding, error)
func (db *DB) UpdateCodeFindingStatus(ctx context.Context, findingID int64, status string) error
```

**Step 3: Build check**

```bash
cd .worktrees/go-merged/go-backend && go build ./internal/db/
```

**Step 4: Commit**

```bash
git add go-backend/internal/db/
git commit -m "feat: add PostgreSQL database layer with migrations, extensions, and full CRUD"
```

---

### Task 39: Request log partition management

**Files:**
- Modify: `go-backend/internal/db/database.go`

**Step 1: Add partition management**

```go
// EnsurePartition creates a monthly partition for request_log if it doesn't exist
func (db *DB) EnsurePartition(ctx context.Context, t time.Time) error {
    year, month, _ := t.Date()
    name := fmt.Sprintf("request_log_%d_%02d", year, month)
    start := time.Date(year, month, 1, 0, 0, 0, 0, time.UTC)
    end := start.AddDate(0, 1, 0)

    sql := fmt.Sprintf(
        `CREATE TABLE IF NOT EXISTS %s PARTITION OF request_log
         FOR VALUES FROM ('%s') TO ('%s')`,
        name, start.Format("2006-01-02"), end.Format("2006-01-02"),
    )
    _, err := db.Pool.Exec(ctx, sql)
    if err != nil {
        return fmt.Errorf("create partition %s: %w", name, err)
    }
    db.logger.Info("partition ensured", "table", name)
    return nil
}

// EnsureCurrentAndNextPartitions creates partitions for current and next month
func (db *DB) EnsureCurrentAndNextPartitions(ctx context.Context) error {
    now := time.Now().UTC()
    if err := db.EnsurePartition(ctx, now); err != nil {
        return err
    }
    return db.EnsurePartition(ctx, now.AddDate(0, 1, 0))
}
```

**Step 2: Call from Migrate()**

Add `db.EnsureCurrentAndNextPartitions(ctx)` at the end of `Migrate()`.

**Step 3: Build check**

```bash
go build ./internal/db/
```

**Step 4: Commit**

```bash
git add go-backend/internal/db/database.go
git commit -m "feat: add request_log monthly partition management"
```

---

## Phase 11: Auth + Server-Side Sessions

### Task 40: Session management

**Files:**
- Create: `go-backend/internal/auth/sessions.go`

**Step 1: Write sessions.go**

```go
package auth

import (
    "context"
    "net/http"
    "time"

    "github.com/veil-waf/veil-go/internal/db"
)

const (
    SessionCookie  = "veil_sid"
    SessionMaxAge  = 30 * 24 * time.Hour // 30 days
)

type SessionManager struct {
    db     *db.DB
    secure bool // true in production (Secure cookie flag)
}

func NewSessionManager(database *db.DB, production bool) *SessionManager {
    return &SessionManager{db: database, secure: production}
}

// Create inserts a session row and sets the cookie
func (sm *SessionManager) Create(ctx context.Context, w http.ResponseWriter, userID int, r *http.Request) error {
    ip := r.RemoteAddr
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

// Validate reads the cookie and returns the user, or nil
func (sm *SessionManager) Validate(ctx context.Context, r *http.Request) (*db.User, error) {
    cookie, err := r.Cookie(SessionCookie)
    if err != nil {
        return nil, nil // no cookie = not logged in
    }

    session, err := sm.db.GetSession(ctx, cookie.Value)
    if err != nil {
        return nil, err
    }
    if session == nil || session.ExpiresAt.Before(time.Now()) {
        return nil, nil // expired or not found
    }

    return sm.db.GetUserByID(ctx, session.UserID)
}

// Destroy deletes the session and clears the cookie
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

// CleanupLoop purges expired sessions every 24 hours
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
                continue
            }
            _ = deleted // logged by caller via slog
        }
    }
}
```

**Step 2: Build check**

```bash
go build ./internal/auth/
```

**Step 3: Commit**

```bash
git add go-backend/internal/auth/sessions.go
git commit -m "feat: add server-side session management with PostgreSQL"
```

---

### Task 41: GitHub OAuth with state parameter

**Files:**
- Create: `go-backend/internal/auth/github.go`

**Step 1: Write github.go**

```go
package auth

import (
    "context"
    "crypto/rand"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "log/slog"
    "net/http"
    "net/url"
    "os"
    "sync"
    "time"

    "github.com/veil-waf/veil-go/internal/db"
)

type OAuthConfig struct {
    ClientID     string
    ClientSecret string
    BaseURL      string // e.g. "https://app.reveil.tech"
}

type OAuthHandler struct {
    cfg      OAuthConfig
    sessions *SessionManager
    db       *db.DB
    logger   *slog.Logger

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

func NewOAuthHandler(cfg OAuthConfig, sm *SessionManager, database *db.DB, logger *slog.Logger) *OAuthHandler {
    h := &OAuthHandler{
        cfg:      cfg,
        sessions: sm,
        db:       database,
        logger:   logger,
        states:   make(map[string]*oauthState),
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

// BeginLogin redirects to GitHub OAuth (read:user scope)
func (h *OAuthHandler) BeginLogin(w http.ResponseWriter, r *http.Request) {
    state := h.generateState("login", 0, "")
    params := url.Values{
        "client_id":    {h.cfg.ClientID},
        "scope":        {"read:user"},
        "state":        {state},
        "redirect_uri": {h.cfg.BaseURL + "/auth/github/callback"},
    }
    http.Redirect(w, r, "https://github.com/login/oauth/authorize?"+params.Encode(), 302)
}

// Callback handles the OAuth callback
func (h *OAuthHandler) Callback(w http.ResponseWriter, r *http.Request) {
    code := r.URL.Query().Get("code")
    stateStr := r.URL.Query().Get("state")

    state, valid := h.validateState(stateStr)
    if !valid {
        http.Error(w, `{"error":"invalid or expired state"}`, 400)
        return
    }

    // Exchange code for token
    token, err := h.exchangeCode(r.Context(), code)
    if err != nil {
        h.logger.Error("oauth exchange failed", "err", err)
        http.Error(w, `{"error":"github auth failed"}`, 400)
        return
    }

    // Fetch GitHub profile
    ghUser, err := h.fetchGitHubUser(r.Context(), token)
    if err != nil {
        h.logger.Error("github user fetch failed", "err", err)
        http.Error(w, `{"error":"github user fetch failed"}`, 500)
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
        http.Error(w, `{"error":"internal error"}`, 500)
        return
    }

    switch state.Purpose {
    case "login":
        // Create session and redirect
        if err := h.sessions.Create(r.Context(), w, userID, r); err != nil {
            http.Error(w, `{"error":"session creation failed"}`, 500)
            return
        }
        http.Redirect(w, r, "/app/projects", 302)

    case "repo-connect":
        // Store encrypted repo token
        // (handled in Task 59)
        http.Redirect(w, r,
            fmt.Sprintf("/app/projects/%s#setup", state.SiteID), 302)
    }
}

// Me returns the current user
func (h *OAuthHandler) Me(w http.ResponseWriter, r *http.Request) {
    user, _ := h.sessions.Validate(r.Context(), r)
    if user == nil {
        w.WriteHeader(401)
        json.NewEncoder(w).Encode(map[string]string{"error": "not authenticated"})
        return
    }
    json.NewEncoder(w).Encode(user)
}

// Logout destroys the session
func (h *OAuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
    h.sessions.Destroy(r.Context(), w, r)
    http.Redirect(w, r, "/", 302)
}

type ghUser struct {
    ID        int64  `json:"id"`
    Login     string `json:"login"`
    AvatarURL string `json:"avatar_url"`
    Name      string `json:"name"`
}

func (h *OAuthHandler) exchangeCode(ctx context.Context, code string) (string, error) {
    // POST to https://github.com/login/oauth/access_token
    // Return access_token string
    // (standard OAuth code exchange)
    return "", nil // placeholder — full impl in execution
}

func (h *OAuthHandler) fetchGitHubUser(ctx context.Context, token string) (*ghUser, error) {
    // GET https://api.github.com/user with Bearer token
    return nil, nil // placeholder — full impl in execution
}
```

**Step 2: Build check**

```bash
go build ./internal/auth/
```

**Step 3: Commit**

```bash
git add go-backend/internal/auth/github.go
git commit -m "feat: add GitHub OAuth with state parameter and server-side sessions"
```

---

### Task 42: Auth middleware

**Files:**
- Create: `go-backend/internal/auth/middleware.go`

**Step 1: Write middleware.go**

```go
package auth

import (
    "context"
    "net/http"

    "github.com/veil-waf/veil-go/internal/db"
)

type ctxKey string
const userCtxKey ctxKey = "user"

// RequireAuth is chi middleware that validates the session
func RequireAuth(sm *SessionManager) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            user, err := sm.Validate(r.Context(), r)
            if err != nil || user == nil {
                w.Header().Set("Content-Type", "application/json")
                w.WriteHeader(401)
                w.Write([]byte(`{"error":"authentication required"}`))
                return
            }
            ctx := context.WithValue(r.Context(), userCtxKey, user)
            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }
}

// GetUserFromCtx extracts user from request context
func GetUserFromCtx(ctx context.Context) *db.User {
    u, _ := ctx.Value(userCtxKey).(*db.User)
    return u
}
```

**Step 2: Build check**

```bash
go build ./internal/auth/
```

**Step 3: Commit**

```bash
git add go-backend/internal/auth/middleware.go
git commit -m "feat: add auth middleware for chi router"
```

---

## Phase 12: DNS Onboarding

### Task 43: DNS resolver

**Files:**
- Create: `go-backend/internal/dns/verifier.go`

**Step 1: Write verifier.go**

```go
package dns

import (
    "context"
    "fmt"
    "log/slog"
    "net"
    "os"
    "strings"
    "time"

    "github.com/veil-waf/veil-go/internal/db"
)

type DNSRecords struct {
    Domain string   `json:"domain"`
    A      []string `json:"a,omitempty"`
    AAAA   []string `json:"aaaa,omitempty"`
    CNAME  string   `json:"cname,omitempty"`
}

type Verifier struct {
    db         *db.DB
    logger     *slog.Logger
    proxyCNAME string // e.g. "router.reveil.tech"
}

func NewVerifier(database *db.DB, logger *slog.Logger) *Verifier {
    return &Verifier{
        db:         database,
        logger:     logger,
        proxyCNAME: envOr("VEIL_PROXY_CNAME", "router.reveil.tech"),
    }
}

func envOr(key, fallback string) string {
    if v := os.Getenv(key); v != "" {
        return v
    }
    return fallback
}

// ResolveDomain fetches current DNS records for a domain
func ResolveDomain(domain string) (*DNSRecords, error) {
    result := &DNSRecords{Domain: domain}

    cname, err := net.LookupCNAME(domain)
    if err == nil && cname != domain+"." {
        result.CNAME = strings.TrimSuffix(cname, ".")
    }

    ips, err := net.LookupHost(domain)
    if err != nil {
        return nil, fmt.Errorf("cannot resolve %s: %w", domain, err)
    }
    for _, ip := range ips {
        if parsed := net.ParseIP(ip); parsed != nil {
            if parsed.To4() != nil {
                result.A = append(result.A, ip)
            } else {
                result.AAAA = append(result.AAAA, ip)
            }
        }
    }
    return result, nil
}

// VerificationLoop polls unverified sites every 60 seconds
func (v *Verifier) VerificationLoop(ctx context.Context) {
    ticker := time.NewTicker(60 * time.Second)
    defer ticker.Stop()

    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            sites, err := v.db.GetUnverifiedSites(ctx)
            if err != nil {
                v.logger.Error("dns: query unverified sites failed", "err", err)
                continue
            }
            for _, site := range sites {
                select {
                case <-ctx.Done():
                    return
                default:
                }
                if err := v.verifySite(ctx, site); err != nil {
                    v.logger.Warn("dns: verification failed",
                        "domain", site.Domain, "err", err)
                }
            }
        }
    }
}

func (v *Verifier) verifySite(ctx context.Context, site db.Site) error {
    cname, err := net.LookupCNAME(site.Domain)
    if err != nil {
        return fmt.Errorf("lookup CNAME: %w", err)
    }
    resolved := strings.TrimSuffix(cname, ".")
    if resolved == v.proxyCNAME {
        v.logger.Info("dns: site verified", "domain", site.Domain)
        return v.db.UpdateSiteStatus(ctx, site.ID, "active")
    }
    return nil
}

// VerifySiteNow is the manual "Check Now" trigger
func (v *Verifier) VerifySiteNow(ctx context.Context, siteID int) error {
    site, err := v.db.GetSiteByID(ctx, siteID)
    if err != nil || site == nil {
        return fmt.Errorf("site not found")
    }
    return v.verifySite(ctx, *site)
}
```

**Step 2: Build check**

```bash
go build ./internal/dns/
```

**Step 3: Commit**

```bash
git add go-backend/internal/dns/
git commit -m "feat: add DNS resolver and background verification loop"
```

---

### Task 44: Site creation endpoint with DNS instructions

**Files:**
- Create: `go-backend/internal/handlers/sites.go`

**Step 1: Write sites.go**

Handles `POST /api/sites`, `GET /api/sites`, `GET /api/sites/{id}`, `GET /api/sites/{id}/status`, `POST /api/sites/{id}/verify`, `DELETE /api/sites/{id}`.

The `POST /api/sites` handler:
1. Validates the domain
2. Calls `dns.ResolveDomain()` to get current A/CNAME records
3. Stores the site with `upstream_ip` set to the resolved IP
4. Returns the site + DNS instructions (CNAME to `router.reveil.tech`)

**Step 2: Build check**

```bash
go build ./internal/handlers/
```

**Step 3: Commit**

```bash
git add go-backend/internal/handlers/sites.go
git commit -m "feat: add site creation with DNS resolution and Cloudflare-style instructions"
```

---

## Phase 13: Reverse Proxy + TLS

### Task 45: Host-header routing reverse proxy

**Files:**
- Modify: `go-backend/internal/proxy/proxy.go`

**Step 1: Update proxy.go for host-header routing**

Replace the `/p/{site_id}/` path-prefix routing with host-header routing. The proxy handler:
1. Reads `r.Host` to determine the target site
2. If host matches a registered domain → classify → proxy to upstream
3. If host doesn't match → serve the Veil API (apiRouter fallback)
4. If site status is not `live` → serve setup page
5. If browser hits root path with `Accept: text/html` → serve info page

```go
func (s *Server) proxyHandler(w http.ResponseWriter, r *http.Request) {
    host := r.Host
    if h, _, err := net.SplitHostPort(host); err == nil {
        host = h
    }

    site, err := s.db.GetSiteByDomain(r.Context(), host)
    if err != nil || site == nil {
        s.apiRouter.ServeHTTP(w, r)
        return
    }

    if site.Status != "live" {
        s.serveSetupPage(w, r, site)
        return
    }

    if r.URL.Path == "/" && strings.Contains(r.Header.Get("Accept"), "text/html") {
        s.serveProxyInfoPage(w, r, site)
        return
    }

    // Classify and proxy (existing pipeline from original Task 20)
    result := s.pipeline.Classify(r.Context(), classifier.ClassifyInput{
        RawRequest: buildRawRequest(r),
        SourceIP:   r.RemoteAddr,
        Path:       r.URL.Path,
        Method:     r.Method,
        SiteID:     fmt.Sprintf("%d", site.ID),
    })

    if result.Blocked {
        s.writeBlockResponse(w, result)
        return
    }

    proxy := &httputil.ReverseProxy{
        Director: func(req *http.Request) {
            req.URL.Scheme = "https"
            req.URL.Host = site.UpstreamIP.String()
            req.Host = site.Domain
            req.Header.Set("X-Forwarded-For", r.RemoteAddr)
            req.Header.Set("X-Forwarded-Proto", "https")
            req.Header.Set("X-Real-IP", r.RemoteAddr)
        },
        ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
            s.logger.Error("proxy upstream error", "domain", site.Domain, "err", err)
            http.Error(w, `{"error":"upstream unreachable"}`, 502)
        },
    }
    proxy.ServeHTTP(w, r)
}
```

**Step 2: Build check**

```bash
go build ./internal/proxy/
```

**Step 3: Commit**

```bash
git add go-backend/internal/proxy/proxy.go
git commit -m "feat: add host-header routing reverse proxy"
```

---

### Task 46: certmagic auto-TLS

**Files:**
- Create: `go-backend/internal/tls/certmanager.go`

**Step 1: Write certmanager.go**

```go
package tls

import (
    "context"
    "fmt"
    "log/slog"
    "net/http"
    "os"

    "github.com/caddyserver/certmagic"
    "github.com/veil-waf/veil-go/internal/db"
)

type CertManager struct {
    db     *db.DB
    logger *slog.Logger
    cfg    *certmagic.Config
}

func NewCertManager(database *db.DB, logger *slog.Logger) *CertManager {
    certmagic.DefaultACME.Email = os.Getenv("ACME_EMAIL")
    certmagic.DefaultACME.Agreed = true

    if os.Getenv("VEIL_ENV") != "production" {
        certmagic.DefaultACME.CA = certmagic.LetsEncryptStagingCA
    }

    cfg := certmagic.NewDefault()
    cm := &CertManager{db: database, logger: logger, cfg: cfg}

    cfg.OnDemand = &certmagic.OnDemandConfig{
        DecisionFunc: cm.allowCert,
    }

    return cm
}

func (cm *CertManager) allowCert(ctx context.Context, name string) error {
    site, err := cm.db.GetSiteByDomain(ctx, name)
    if err != nil || site == nil {
        return fmt.Errorf("unknown domain: %s", name)
    }
    if site.Status != "active" && site.Status != "ssl_provisioning" && site.Status != "live" {
        return fmt.Errorf("site not verified: %s (status=%s)", name, site.Status)
    }
    return nil
}

func (cm *CertManager) ListenAndServe(handler http.Handler) error {
    proxyCNAME := os.Getenv("VEIL_PROXY_CNAME")
    dashDomain := os.Getenv("VEIL_DASHBOARD_DOMAIN")

    domains := []string{}
    if proxyCNAME != "" {
        domains = append(domains, proxyCNAME)
    }
    if dashDomain != "" {
        domains = append(domains, dashDomain)
    }

    cm.logger.Info("starting TLS server", "domains", domains)
    return cm.cfg.HTTPS(domains, handler)
}
```

**Step 2: Build check**

```bash
go build ./internal/tls/
```

**Step 3: Commit**

```bash
git add go-backend/internal/tls/
git commit -m "feat: add certmagic auto-TLS with on-demand certificate provisioning"
```

---

## Phase 14: SSE Log Stream

### Task 47: SSE hub

**Files:**
- Create: `go-backend/internal/sse/hub.go`

**Step 1: Write hub.go**

```go
package sse

import (
    "log/slog"
    "sync"
)

type Event struct {
    Type string // "request", "agent", "stats"
    Data []byte // JSON payload
}

type Hub struct {
    mu          sync.RWMutex
    subscribers map[string]map[chan Event]struct{} // siteID -> set of channels
    logger      *slog.Logger
}

func NewHub(logger *slog.Logger) *Hub {
    return &Hub{
        subscribers: make(map[string]map[chan Event]struct{}),
        logger:      logger,
    }
}

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

func (h *Hub) SubscriberCount(siteID string) int {
    h.mu.RLock()
    defer h.mu.RUnlock()
    return len(h.subscribers[siteID])
}
```

**Step 2: Build check**

```bash
go build ./internal/sse/
```

**Step 3: Commit**

```bash
git add go-backend/internal/sse/
git commit -m "feat: add SSE fan-out hub with per-site subscriptions"
```

---

### Task 48: PostgreSQL listener goroutine

**Files:**
- Create: `go-backend/internal/sse/pglistener.go`

**Step 1: Write pglistener.go**

```go
package sse

import (
    "context"
    "encoding/json"
    "fmt"
    "log/slog"
    "strconv"

    "github.com/jackc/pgx/v5/pgxpool"
)

type PGListener struct {
    pool   *pgxpool.Pool
    hub    *Hub
    logger *slog.Logger
}

func NewPGListener(pool *pgxpool.Pool, hub *Hub, logger *slog.Logger) *PGListener {
    return &PGListener{pool: pool, hub: hub, logger: logger}
}

// Listen subscribes to PostgreSQL NOTIFY channels and fans out to SSE hub.
// This function blocks until ctx is cancelled or an error occurs.
// It should be run inside runWithRecovery so it auto-restarts on failure.
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
            return // runWithRecovery will reconnect
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
        json.Unmarshal([]byte(notification.Payload), &payload)

        pl.hub.Publish(strconv.Itoa(payload.SiteID), event)
    }
}
```

**Step 2: Build check**

```bash
go build ./internal/sse/
```

**Step 3: Commit**

```bash
git add go-backend/internal/sse/pglistener.go
git commit -m "feat: add PostgreSQL LISTEN/NOTIFY to SSE bridge"
```

---

### Task 49: SSE HTTP handler with hydration

**Files:**
- Create: `go-backend/internal/handlers/stream.go`

**Step 1: Write stream.go**

```go
package handlers

import (
    "encoding/json"
    "fmt"
    "net/http"
    "time"

    "github.com/go-chi/chi/v5"
    "github.com/veil-waf/veil-go/internal/auth"
    "github.com/veil-waf/veil-go/internal/db"
    "github.com/veil-waf/veil-go/internal/sse"
)

type StreamHandler struct {
    hub *sse.Hub
    db  *db.DB
}

func NewStreamHandler(hub *sse.Hub, database *db.DB) *StreamHandler {
    return &StreamHandler{hub: hub, db: database}
}

// HandleSSE handles GET /api/stream/events?site_id=X
func (sh *StreamHandler) HandleSSE(w http.ResponseWriter, r *http.Request) {
    flusher, ok := w.(http.Flusher)
    if !ok {
        http.Error(w, "streaming not supported", 500)
        return
    }

    siteID := r.URL.Query().Get("site_id")
    if siteID == "" {
        http.Error(w, `{"error":"site_id required"}`, 400)
        return
    }

    user := auth.GetUserFromCtx(r.Context())
    if !sh.db.UserOwnsSite(r.Context(), user.ID, siteID) {
        http.Error(w, `{"error":"forbidden"}`, 403)
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
    ch, cancel := sh.hub.Subscribe(siteID)
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
```

**Step 2: Build check**

```bash
go build ./internal/handlers/
```

**Step 3: Commit**

```bash
git add go-backend/internal/handlers/stream.go
git commit -m "feat: add SSE stream handler with hydration and keepalive"
```

---

## Phase 15: Graceful Lifecycle

### Task 50: runWithRecovery + structured logging

**Files:**
- Create: `go-backend/internal/server/lifecycle.go`

**Step 1: Write lifecycle.go**

Contains `runWithRecovery` (panic catching, exponential backoff restart, context cancellation), structured `slog` setup, and signal handling.

**Step 2: Build check**

```bash
go build ./internal/server/
```

**Step 3: Commit**

```bash
git add go-backend/internal/server/
git commit -m "feat: add goroutine recovery wrapper and structured logging"
```

---

### Task 51: Main server with all goroutines

**Files:**
- Modify: `go-backend/main.go`

**Step 1: Write main.go**

The main function:
1. Parse env vars, init `slog` JSON logger
2. Connect to PostgreSQL via `db.Connect()`
3. Init all components: session manager, OAuth handler, DNS verifier, SSE hub, PG listener, pipeline, behavioral engine, aggregator
4. Mount chi routes (auth, API, SSE, static)
5. Start 5 background goroutines via `runWithRecovery`:
   - `dns-verifier`
   - `agent-loop`
   - `intel-refresher`
   - `session-cleanup`
   - `pg-listener`
6. Start certmagic TLS server (or plain HTTP in dev)
7. Wait for signal, graceful shutdown (10s drain)

**Step 2: Build full project**

```bash
cd .worktrees/go-merged/go-backend && go build -o veil-go .
```

**Step 3: Commit**

```bash
git add go-backend/main.go
git commit -m "feat: add main server with graceful lifecycle and all background goroutines"
```

---

### Task 52: Docker Compose configuration

**Files:**
- Create: `go-backend/Dockerfile`
- Create: `go-backend/docker-compose.yml`

**Step 1: Write Dockerfile**

```dockerfile
FROM golang:1.23-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /veil-go .

FROM alpine:3.21
RUN apk add --no-cache ca-certificates curl
COPY --from=builder /veil-go /usr/local/bin/veil-go
COPY prompts/ /app/prompts/
WORKDIR /app
EXPOSE 443 80
CMD ["veil-go"]
```

**Step 2: Write docker-compose.yml**

```yaml
services:
  veil:
    build: .
    ports:
      - "443:443"
      - "80:80"
    volumes:
      - certs:/root/.local/share/certmagic
    environment:
      - DATABASE_URL=postgres://veil:${DB_PASSWORD}@db:5432/veil?sslmode=disable
      - VEIL_PROXY_CNAME=${VEIL_PROXY_CNAME:-router.reveil.tech}
      - VEIL_DASHBOARD_DOMAIN=${VEIL_DASHBOARD_DOMAIN:-app.reveil.tech}
      - VEIL_ENV=${VEIL_ENV:-production}
      - ACME_EMAIL=${ACME_EMAIL}
      - GITHUB_CLIENT_ID=${GITHUB_CLIENT_ID}
      - GITHUB_CLIENT_SECRET=${GITHUB_CLIENT_SECRET}
      - TOKEN_ENCRYPTION_KEY=${TOKEN_ENCRYPTION_KEY}
      - OLLAMA_HOST=${OLLAMA_HOST:-http://ollama:11434}
      - CRUSOE_API_KEY=${CRUSOE_API_KEY}
      - AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}
      - AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}
      - AWS_REGION=${AWS_REGION:-eu-west-1}
    depends_on:
      db:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/ping"]
      interval: 30s
      timeout: 5s
      retries: 3

  db:
    image: postgres:18-alpine
    volumes:
      - pgdata:/var/lib/postgresql/data
    environment:
      - POSTGRES_DB=veil
      - POSTGRES_USER=veil
      - POSTGRES_PASSWORD=${DB_PASSWORD}
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U veil"]
      interval: 10s
      timeout: 5s
      retries: 5

volumes:
  pgdata:
  certs:
```

**Step 3: Commit**

```bash
git add go-backend/Dockerfile go-backend/docker-compose.yml
git commit -m "feat: add Dockerfile and docker-compose.yml (veil + postgres)"
```

---

## Phase 16: Dashboard REST API

### Task 53: Site-scoped REST endpoints

**Files:**
- Create: `go-backend/internal/handlers/dashboard.go`

**Step 1: Write dashboard.go**

Endpoints (all require auth, all scoped to site):
- `GET /api/sites/{id}/stats` — request counts, block rate, rules version
- `GET /api/sites/{id}/threats` — threat library
- `GET /api/sites/{id}/agents` — agent log (last 50)
- `GET /api/sites/{id}/requests` — request log (last 100)
- `GET /api/sites/{id}/rules` — rule versions
- `GET /api/sites/{id}/pipeline` — pipeline graph JSON (nodes + edges for React Flow)

**Step 2: Build check**

```bash
go build ./internal/handlers/
```

**Step 3: Commit**

```bash
git add go-backend/internal/handlers/dashboard.go
git commit -m "feat: add site-scoped dashboard REST endpoints"
```

---

### Task 54: Analytics + compliance endpoints

**Files:**
- Modify: `go-backend/internal/handlers/dashboard.go`

**Step 1: Add intelligence endpoints**

From `feat/intelligence-compliance` branch:
- `GET /api/analytics/threat-distribution` — threats by category (total/patched/exposed)
- `GET /api/compliance/report` — security score, remediation history, agent activity, compliance status

**Step 2: Build check**

```bash
go build ./internal/handlers/
```

**Step 3: Commit**

```bash
git add go-backend/internal/handlers/dashboard.go
git commit -m "feat: add analytics and compliance endpoints"
```

---

## Phase 17: GitHub Repo Connection

### Task 55: Token encryption (AES-256-GCM)

**Files:**
- Create: `go-backend/internal/auth/crypto.go`

**Step 1: Write crypto.go**

```go
package auth

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/base64"
    "encoding/hex"
    "fmt"
    "io"
    "os"
)

type TokenEncryptor struct {
    key []byte // 32 bytes for AES-256
}

func NewTokenEncryptor() (*TokenEncryptor, error) {
    keyHex := os.Getenv("TOKEN_ENCRYPTION_KEY")
    if keyHex == "" {
        return nil, fmt.Errorf("TOKEN_ENCRYPTION_KEY not set")
    }
    key, err := hex.DecodeString(keyHex)
    if err != nil || len(key) != 32 {
        return nil, fmt.Errorf("TOKEN_ENCRYPTION_KEY must be 64 hex chars (32 bytes)")
    }
    return &TokenEncryptor{key: key}, nil
}

func (te *TokenEncryptor) Encrypt(plaintext string) (string, error) {
    block, err := aes.NewCipher(te.key)
    if err != nil {
        return "", err
    }
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }
    nonce := make([]byte, gcm.NonceSize())
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return "", err
    }
    ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
    return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func (te *TokenEncryptor) Decrypt(encoded string) (string, error) {
    ciphertext, err := base64.StdEncoding.DecodeString(encoded)
    if err != nil {
        return "", err
    }
    block, err := aes.NewCipher(te.key)
    if err != nil {
        return "", err
    }
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }
    nonceSize := gcm.NonceSize()
    if len(ciphertext) < nonceSize {
        return "", fmt.Errorf("ciphertext too short")
    }
    nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
    plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return "", err
    }
    return string(plaintext), nil
}
```

**Step 2: Build check**

```bash
go build ./internal/auth/
```

**Step 3: Commit**

```bash
git add go-backend/internal/auth/crypto.go
git commit -m "feat: add AES-256-GCM token encryption for GitHub repo tokens"
```

---

### Task 56: Incremental OAuth for repo scope

**Files:**
- Modify: `go-backend/internal/auth/github.go`

**Step 1: Add repo-connect OAuth flow**

Add `BeginRepoConnect(w, r)` handler:
- Reads `site_id` from query param
- Generates state with `purpose="repo-connect"` and the user's ID
- Redirects to GitHub with `scope: "read:user repo"`

Update `Callback` to handle `repo-connect` purpose:
- Exchange code for token
- Encrypt token with `TokenEncryptor`
- Store in `github_tokens` table
- Redirect back to project setup page

**Step 2: Build check**

```bash
go build ./internal/auth/
```

**Step 3: Commit**

```bash
git add go-backend/internal/auth/github.go
git commit -m "feat: add incremental OAuth for GitHub repo scope"
```

---

### Task 57: Repo linking + code scanning

**Files:**
- Create: `go-backend/internal/repo/scanner.go`

**Step 1: Write scanner.go**

```go
package repo

import (
    "context"
    "log/slog"

    "github.com/google/go-github/v60/github"
    "golang.org/x/oauth2"
    "github.com/veil-waf/veil-go/internal/auth"
    "github.com/veil-waf/veil-go/internal/db"
)

type Scanner struct {
    db        *db.DB
    encryptor *auth.TokenEncryptor
    logger    *slog.Logger
}

func NewScanner(database *db.DB, enc *auth.TokenEncryptor, logger *slog.Logger) *Scanner {
    return &Scanner{db: database, encryptor: enc, logger: logger}
}

func (s *Scanner) getClient(ctx context.Context, userID int) (*github.Client, error) {
    encToken, err := s.db.GetGitHubToken(ctx, userID)
    if err != nil {
        return nil, err
    }
    token, err := s.encryptor.Decrypt(encToken)
    if err != nil {
        return nil, err
    }
    ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
    return github.NewClient(oauth2.NewClient(ctx, ts)), nil
}

// ListRepos returns repos the user has access to
func (s *Scanner) ListRepos(ctx context.Context, userID int) ([]*github.Repository, error) {
    client, err := s.getClient(ctx, userID)
    if err != nil {
        return nil, err
    }
    repos, _, err := client.Repositories.List(ctx, "", &github.RepositoryListOptions{
        Sort:        "updated",
        ListOptions: github.ListOptions{PerPage: 30},
    })
    return repos, err
}

// ScanForVulnerability searches the connected repo for code related to a threat
func (s *Scanner) ScanForVulnerability(ctx context.Context, site db.Site, threat db.Threat) error {
    repo, err := s.db.GetSiteRepo(ctx, site.ID)
    if err != nil || repo == nil {
        return nil // no repo connected, skip
    }

    client, err := s.getClient(ctx, site.UserID)
    if err != nil {
        return err
    }

    query := buildSearchQuery(threat, repo.RepoOwner, repo.RepoName)
    results, _, err := client.Search.Code(ctx, query, &github.SearchOptions{
        ListOptions: github.ListOptions{PerPage: 10},
    })
    if err != nil {
        return err
    }

    for _, result := range results.CodeResults {
        content, _, _, err := client.Repositories.GetContents(ctx,
            repo.RepoOwner, repo.RepoName, result.GetPath(),
            &github.RepositoryContentGetOptions{Ref: repo.DefaultBranch})
        if err != nil {
            continue
        }

        decoded, _ := content.GetContent()
        // LLM analysis of the code would happen here (Task in original plan)
        // For now, store a basic finding
        _ = decoded
    }
    return nil
}

func buildSearchQuery(threat db.Threat, owner, repo string) string {
    // Build GitHub code search query based on attack type
    // e.g. for sqli: "sql query execute" in the repo
    return fmt.Sprintf("repo:%s/%s %s", owner, repo, threat.Category)
}
```

**Step 2: Build check**

```bash
go build ./internal/repo/
```

**Step 3: Commit**

```bash
git add go-backend/internal/repo/
git commit -m "feat: add GitHub repo code scanner for vulnerability tracing"
```

---

### Task 58: Repo + findings API endpoints

**Files:**
- Create: `go-backend/internal/handlers/repos.go`

**Step 1: Write repos.go**

Endpoints:
- `GET /api/sites/{id}/repos` — list available repos (from GitHub API)
- `POST /api/sites/{id}/repos` — link repo `{"owner":"...", "name":"...", "branch":"main"}`
- `DELETE /api/sites/{id}/repos` — unlink repo
- `GET /api/sites/{id}/findings` — list code findings
- `PATCH /api/sites/{id}/findings/{fid}` — update finding status

**Step 2: Build check**

```bash
go build ./internal/handlers/
```

**Step 3: Commit**

```bash
git add go-backend/internal/handlers/repos.go
git commit -m "feat: add repo linking and code findings API endpoints"
```

---

## Phase 18: Integration + Verification

### Task 59: Full build + vet

**Step 1: Build**

```bash
cd .worktrees/go-merged/go-backend && go build -o veil-go .
```

Expected: clean build.

**Step 2: Vet**

```bash
go vet ./...
```

Expected: no warnings.

**Step 3: Test startup**

```bash
# Start PostgreSQL first
docker compose up db -d
sleep 3
DATABASE_URL="postgres://veil:veil@localhost:5432/veil?sslmode=disable" \
  VEIL_ENV=development \
  timeout 5 ./veil-go 2>&1 || true
```

Expected: logs show migration, goroutine starts, then timeout kills it. No panics.

**Step 4: Commit any fixes**

---

## Task Dependency Graph (Phases 10-18)

```
Phase 10 (PG foundation):  [37] → [38] → [39]
Phase 11 (auth):           [38] → [40] → [41] → [42]
Phase 12 (DNS):            [38] → [43] → [44]
Phase 13 (proxy):          [38,43] → [45] → [46]
Phase 14 (SSE):            [38,39] → [47] → [48] → [49]
Phase 15 (lifecycle):      [40,43,47,48] → [50] → [51] → [52]
Phase 16 (dashboard):      [38,47] → [53] → [54]
Phase 17 (repo):           [42] → [55] → [56] → [57] → [58]
Phase 18 (integration):    [all above] → [59]
```

**Critical path:** 37 → 38 → 39 → 48 → 49 → 51 → 59

**Parallelizable after Task 38:**
- Tasks 40-42 (auth) and Tasks 43-44 (DNS) can run in parallel
- Tasks 47-49 (SSE) can run in parallel with auth/DNS
- Task 55-58 (repo) depends only on auth (Task 42)

---

## Key Reference Files

| File | Purpose |
|------|---------|
| `docs/plans/2026-02-21-go-backend-design.md` (Sections 13-19) | Approved design for all features in this plan |
| `docs/plans/2026-02-21-go-backend-implementation.md` | Original plan (Tasks 1-36) — classifier, agents, behavioral engine |
| `backend/main.py` | Current Python backend — reference for API behavior |
| `backend/db/database.py` | Current SQLite schema — reference for table structure |
| `frontend/src/pages/OnboardingPage.jsx` | Current onboarding UI — will need DNS step added |
| `frontend/src/components/Dashboard.jsx` | Current dashboard — will switch from WS to SSE |
