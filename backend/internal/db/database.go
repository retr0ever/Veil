package db

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNotFound is returned when a queried entity does not exist.
var ErrNotFound = errors.New("not found")

//go:embed migrations/*.sql
var migrations embed.FS

// DB wraps a pgx connection pool and provides CRUD methods for the Veil WAF.
type DB struct {
	Pool   *pgxpool.Pool
	logger *slog.Logger
}

// Connect creates a new DB instance, connects to PostgreSQL, and runs migrations.
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

// Migrate reads and executes the embedded SQL migration files.
func (db *DB) Migrate(ctx context.Context) error {
	sql, err := migrations.ReadFile("migrations/001_init.sql")
	if err != nil {
		return fmt.Errorf("read migration: %w", err)
	}
	if _, err := db.Pool.Exec(ctx, string(sql)); err != nil {
		return fmt.Errorf("exec migration: %w", err)
	}
	db.logger.Info("database migrated")

	if err := db.EnsureCurrentAndNextPartitions(ctx); err != nil {
		return fmt.Errorf("ensure partitions: %w", err)
	}

	return nil
}

// Close shuts down the connection pool.
func (db *DB) Close() {
	db.Pool.Close()
}

// PingContext checks the database connection.
func (db *DB) PingContext(ctx context.Context) error {
	return db.Pool.Ping(ctx)
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

// CreateSession inserts a new session and returns its UUID.
func (db *DB) CreateSession(ctx context.Context, userID int, ip, ua string) (string, error) {
	var id string
	err := db.Pool.QueryRow(ctx,
		`INSERT INTO sessions (user_id, ip_address, user_agent) VALUES ($1, $2::inet, $3) RETURNING id`,
		userID, ip, ua).Scan(&id)
	return id, err
}

// GetSession retrieves a session by its UUID.
func (db *DB) GetSession(ctx context.Context, sessionID string) (*Session, error) {
	var s Session
	var ipAddr *string
	var userAgent *string
	err := db.Pool.QueryRow(ctx,
		`SELECT id, user_id, created_at, expires_at, ip_address::text, user_agent
		 FROM sessions WHERE id = $1`,
		sessionID).Scan(&s.ID, &s.UserID, &s.CreatedAt, &s.ExpiresAt, &ipAddr, &userAgent)
	if err != nil {
		return nil, err
	}
	if ipAddr != nil {
		s.IPAddress = *ipAddr
	}
	if userAgent != nil {
		s.UserAgent = *userAgent
	}
	return &s, nil
}

// DeleteSession removes a session by its UUID.
func (db *DB) DeleteSession(ctx context.Context, sessionID string) error {
	_, err := db.Pool.Exec(ctx, `DELETE FROM sessions WHERE id = $1`, sessionID)
	return err
}

// CleanExpiredSessions removes all sessions past their expiry time.
func (db *DB) CleanExpiredSessions(ctx context.Context) (int64, error) {
	tag, err := db.Pool.Exec(ctx, `DELETE FROM sessions WHERE expires_at < NOW()`)
	return tag.RowsAffected(), err
}

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

// UpsertUser inserts or updates a user based on their GitHub ID.
func (db *DB) UpsertUser(ctx context.Context, u *User) (int, error) {
	var id int
	err := db.Pool.QueryRow(ctx,
		`INSERT INTO users (github_id, github_login, avatar_url, name)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT (github_id) DO UPDATE SET
		    github_login = EXCLUDED.github_login,
		    avatar_url = EXCLUDED.avatar_url,
		    name = EXCLUDED.name
		 RETURNING id`,
		u.GitHubID, u.GitHubLogin, u.AvatarURL, u.Name).Scan(&id)
	return id, err
}

// GetUserByID retrieves a user by their primary key.
func (db *DB) GetUserByID(ctx context.Context, id int) (*User, error) {
	var u User
	var avatarURL, name *string
	err := db.Pool.QueryRow(ctx,
		`SELECT id, github_id, github_login, avatar_url, name, created_at
		 FROM users WHERE id = $1`,
		id).Scan(&u.ID, &u.GitHubID, &u.GitHubLogin, &avatarURL, &name, &u.CreatedAt)
	if err != nil {
		return nil, err
	}
	if avatarURL != nil {
		u.AvatarURL = *avatarURL
	}
	if name != nil {
		u.Name = *name
	}
	return &u, nil
}

// ---------------------------------------------------------------------------
// Sites
// ---------------------------------------------------------------------------

// CreateSite inserts a new site and populates its ID and CreatedAt.
func (db *DB) CreateSite(ctx context.Context, s *Site) error {
	return db.Pool.QueryRow(ctx,
		`INSERT INTO sites (user_id, domain, project_name, upstream_ip, upstream_scheme, upstream_port, original_cname, status)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id, created_at`,
		s.UserID, s.Domain, s.ProjectName, s.UpstreamIP, s.UpstreamScheme, s.UpstreamPort, s.OriginalCNAME, s.Status,
	).Scan(&s.ID, &s.CreatedAt)
}

// GetSiteByDomain retrieves a site by its domain name.
func (db *DB) GetSiteByDomain(ctx context.Context, domain string) (*Site, error) {
	var s Site
	var projectName, originalCNAME *string
	err := db.Pool.QueryRow(ctx,
		`SELECT id, user_id, domain, project_name, upstream_ip, upstream_scheme, upstream_port, original_cname, status, verified_at, created_at, is_demo
		 FROM sites WHERE domain = $1`, domain,
	).Scan(&s.ID, &s.UserID, &s.Domain, &projectName, &s.UpstreamIP, &s.UpstreamScheme, &s.UpstreamPort, &originalCNAME, &s.Status, &s.VerifiedAt, &s.CreatedAt, &s.IsDemo)
	if err != nil {
		return nil, err
	}
	if projectName != nil {
		s.ProjectName = *projectName
	}
	if originalCNAME != nil {
		s.OriginalCNAME = *originalCNAME
	}
	return &s, nil
}

// GetSiteByID retrieves a site by its primary key.
func (db *DB) GetSiteByID(ctx context.Context, id int) (*Site, error) {
	var s Site
	var projectName, originalCNAME *string
	err := db.Pool.QueryRow(ctx,
		`SELECT id, user_id, domain, project_name, upstream_ip, upstream_scheme, upstream_port, original_cname, status, verified_at, created_at, is_demo
		 FROM sites WHERE id = $1`, id,
	).Scan(&s.ID, &s.UserID, &s.Domain, &projectName, &s.UpstreamIP, &s.UpstreamScheme, &s.UpstreamPort, &originalCNAME, &s.Status, &s.VerifiedAt, &s.CreatedAt, &s.IsDemo)
	if err != nil {
		return nil, err
	}
	if projectName != nil {
		s.ProjectName = *projectName
	}
	if originalCNAME != nil {
		s.OriginalCNAME = *originalCNAME
	}
	return &s, nil
}

// GetSitesByUser retrieves all sites belonging to a user PLUS any demo sites, ordered by creation time (newest first).
func (db *DB) GetSitesByUser(ctx context.Context, userID int) ([]Site, error) {
	rows, err := db.Pool.Query(ctx,
		`SELECT id, user_id, domain, project_name, upstream_ip, upstream_scheme, upstream_port, original_cname, status, verified_at, created_at, is_demo
		 FROM sites WHERE user_id = $1 OR is_demo = TRUE ORDER BY is_demo ASC, created_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var sites []Site
	for rows.Next() {
		var s Site
		var projectName, originalCNAME *string
		if err := rows.Scan(&s.ID, &s.UserID, &s.Domain, &projectName, &s.UpstreamIP, &s.UpstreamScheme, &s.UpstreamPort, &originalCNAME, &s.Status, &s.VerifiedAt, &s.CreatedAt, &s.IsDemo); err != nil {
			return nil, err
		}
		if projectName != nil {
			s.ProjectName = *projectName
		}
		if originalCNAME != nil {
			s.OriginalCNAME = *originalCNAME
		}
		sites = append(sites, s)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return sites, nil
}

// GetUnverifiedSites retrieves all sites with status 'pending' or 'verifying'.
func (db *DB) GetUnverifiedSites(ctx context.Context) ([]Site, error) {
	rows, err := db.Pool.Query(ctx,
		`SELECT id, user_id, domain, project_name, upstream_ip, upstream_scheme, upstream_port, original_cname, status, verified_at, created_at, is_demo
		 FROM sites WHERE status IN ('pending', 'verifying') ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var sites []Site
	for rows.Next() {
		var s Site
		var projectName, originalCNAME *string
		if err := rows.Scan(&s.ID, &s.UserID, &s.Domain, &projectName, &s.UpstreamIP, &s.UpstreamScheme, &s.UpstreamPort, &originalCNAME, &s.Status, &s.VerifiedAt, &s.CreatedAt, &s.IsDemo); err != nil {
			return nil, err
		}
		if projectName != nil {
			s.ProjectName = *projectName
		}
		if originalCNAME != nil {
			s.OriginalCNAME = *originalCNAME
		}
		sites = append(sites, s)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return sites, nil
}

// UpdateSiteStatus changes a site's status.
func (db *DB) UpdateSiteStatus(ctx context.Context, siteID int, status string) error {
	_, err := db.Pool.Exec(ctx, `UPDATE sites SET status = $1 WHERE id = $2`, status, siteID)
	return err
}

// DeleteSite removes a site, verifying ownership.
func (db *DB) DeleteSite(ctx context.Context, siteID, userID int) error {
	tag, err := db.Pool.Exec(ctx, `DELETE FROM sites WHERE id = $1 AND user_id = $2`, siteID, userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// UserOwnsSite checks whether the given user owns the given site.
func (db *DB) UserOwnsSite(ctx context.Context, userID int, siteID int) (bool, error) {
	var exists bool
	err := db.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM sites WHERE id = $1 AND (user_id = $2 OR is_demo = TRUE))`, siteID, userID).Scan(&exists)
	return exists, err
}

// ---------------------------------------------------------------------------
// Request log
// ---------------------------------------------------------------------------

// InsertRequestLog inserts a new request log entry.
func (db *DB) InsertRequestLog(ctx context.Context, r *RequestLogEntry) error {
	_, err := db.Pool.Exec(ctx,
		`INSERT INTO request_log (site_id, raw_request, classification, confidence, classifier, blocked, attack_type, response_time_ms, source_ip)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::inet)`,
		r.SiteID, r.RawRequest, r.Classification, r.Confidence, r.Classifier, r.Blocked, r.AttackType, r.ResponseTimeMs, r.SourceIP)
	return err
}

// GetRecentRequests retrieves the most recent request log entries for a site.
func (db *DB) GetRecentRequests(ctx context.Context, siteID int, limit int) ([]RequestLogEntry, error) {
	rows, err := db.Pool.Query(ctx,
		`SELECT id, site_id, timestamp, raw_request, classification, confidence, classifier, blocked, attack_type, response_time_ms, source_ip
		 FROM request_log WHERE site_id = $1 ORDER BY timestamp DESC LIMIT $2`, siteID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var entries []RequestLogEntry
	for rows.Next() {
		var e RequestLogEntry
		var attackType, sourceIP *string
		var confidence, responseTimeMs *float32
		if err := rows.Scan(&e.ID, &e.SiteID, &e.Timestamp, &e.RawRequest, &e.Classification, &confidence, &e.Classifier, &e.Blocked, &attackType, &responseTimeMs, &sourceIP); err != nil {
			return nil, err
		}
		if attackType != nil {
			e.AttackType = *attackType
		}
		if sourceIP != nil {
			e.SourceIP = *sourceIP
		}
		if confidence != nil {
			e.Confidence = *confidence
		}
		if responseTimeMs != nil {
			e.ResponseTimeMs = *responseTimeMs
		}
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

// ---------------------------------------------------------------------------
// Agent log
// ---------------------------------------------------------------------------

// InsertAgentLog inserts a new agent log entry.
func (db *DB) InsertAgentLog(ctx context.Context, a *AgentLogEntry) error {
	_, err := db.Pool.Exec(ctx,
		`INSERT INTO agent_log (site_id, agent, action, detail, success) VALUES ($1, $2, $3, $4, $5)`,
		a.SiteID, a.Agent, a.Action, a.Detail, a.Success)
	return err
}

// GetRecentAgentLogs retrieves the most recent agent log entries for a site.
// If siteID is 0, it queries for entries where site_id IS NULL (global/system entries).
func (db *DB) GetRecentAgentLogs(ctx context.Context, siteID int, limit int) ([]AgentLogEntry, error) {
	var rows pgx.Rows
	var err error
	if siteID == 0 {
		rows, err = db.Pool.Query(ctx,
			`SELECT id, site_id, timestamp, agent, action, detail, success
			 FROM agent_log WHERE site_id IS NULL ORDER BY timestamp DESC LIMIT $1`, limit)
	} else {
		rows, err = db.Pool.Query(ctx,
			`SELECT id, site_id, timestamp, agent, action, detail, success
			 FROM agent_log WHERE (site_id = $1 OR site_id IS NULL) ORDER BY timestamp DESC LIMIT $2`, siteID, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var entries []AgentLogEntry
	for rows.Next() {
		var e AgentLogEntry
		var detail *string
		if err := rows.Scan(&e.ID, &e.SiteID, &e.Timestamp, &e.Agent, &e.Action, &detail, &e.Success); err != nil {
			return nil, err
		}
		if detail != nil {
			e.Detail = *detail
		}
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

// GetCurrentRules retrieves the latest rule version for a site.
func (db *DB) GetCurrentRules(ctx context.Context, siteID int) (*Rules, error) {
	var r Rules
	err := db.Pool.QueryRow(ctx,
		`SELECT id, site_id, version, crusoe_prompt, claude_prompt, updated_at, updated_by
		 FROM rules WHERE (site_id = $1 OR site_id IS NULL) ORDER BY version DESC LIMIT 1`, siteID,
	).Scan(&r.ID, &r.SiteID, &r.Version, &r.CrusoePrompt, &r.ClaudePrompt, &r.UpdatedAt, &r.UpdatedBy)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// InsertRules inserts a new rule version for a site.
func (db *DB) InsertRules(ctx context.Context, r *Rules) error {
	_, err := db.Pool.Exec(ctx,
		`INSERT INTO rules (site_id, version, crusoe_prompt, claude_prompt, updated_by)
		 VALUES ($1, $2, $3, $4, $5)`,
		r.SiteID, r.Version, r.CrusoePrompt, r.ClaudePrompt, r.UpdatedBy)
	return err
}

// ---------------------------------------------------------------------------
// Threats
// ---------------------------------------------------------------------------

// InsertThreat inserts a new threat record.
func (db *DB) InsertThreat(ctx context.Context, t *Threat) error {
	_, err := db.Pool.Exec(ctx,
		`INSERT INTO threats (site_id, technique_name, category, source, raw_payload, severity, blocked)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		t.SiteID, t.TechniqueName, t.Category, t.Source, t.RawPayload, t.Severity, t.Blocked)
	return err
}

// GetThreats retrieves all threats for a site, ordered by discovery time (newest first).
// If siteID is 0, it queries for threats where site_id IS NULL (global/system threats).
func (db *DB) GetThreats(ctx context.Context, siteID int) ([]Threat, error) {
	var rows pgx.Rows
	var err error
	if siteID == 0 {
		rows, err = db.Pool.Query(ctx,
			`SELECT id, site_id, technique_name, category, source, raw_payload, severity, discovered_at, tested_at, blocked, patched_at
			 FROM threats WHERE site_id IS NULL ORDER BY discovered_at DESC`)
	} else {
		rows, err = db.Pool.Query(ctx,
			`SELECT id, site_id, technique_name, category, source, raw_payload, severity, discovered_at, tested_at, blocked, patched_at
			 FROM threats WHERE (site_id = $1 OR site_id IS NULL) ORDER BY discovered_at DESC`, siteID)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var threats []Threat
	for rows.Next() {
		var t Threat
		var source *string
		if err := rows.Scan(&t.ID, &t.SiteID, &t.TechniqueName, &t.Category, &source, &t.RawPayload, &t.Severity, &t.DiscoveredAt, &t.TestedAt, &t.Blocked, &t.PatchedAt); err != nil {
			return nil, err
		}
		if source != nil {
			t.Source = *source
		}
		threats = append(threats, t)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return threats, nil
}

// MarkThreatTested updates a threat's tested_at timestamp and blocked status.
func (db *DB) MarkThreatTested(ctx context.Context, threatID int64, blocked bool) error {
	_, err := db.Pool.Exec(ctx,
		`UPDATE threats SET tested_at = NOW(), blocked = $1 WHERE id = $2`,
		blocked, threatID)
	return err
}

// GetThreatDistribution returns threat counts grouped by category.
func (db *DB) GetThreatDistribution(ctx context.Context) ([]ThreatCategory, error) {
	rows, err := db.Pool.Query(ctx,
		`SELECT category, COUNT(*) as count FROM threats GROUP BY category ORDER BY count DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var cats []ThreatCategory
	for rows.Next() {
		var c ThreatCategory
		if err := rows.Scan(&c.Category, &c.Count); err != nil {
			return nil, err
		}
		cats = append(cats, c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return cats, nil
}

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

// GetSiteStats returns aggregate stats for a site.
func (db *DB) GetSiteStats(ctx context.Context, siteID int) (*Stats, error) {
	var s Stats
	err := db.Pool.QueryRow(ctx,
		`SELECT
		    COUNT(*),
		    COUNT(*) FILTER (WHERE blocked),
		    COALESCE((SELECT COUNT(*) FROM threats WHERE site_id = $1), 0),
		    COALESCE(AVG(response_time_ms), 0)
		 FROM request_log WHERE site_id = $1`, siteID,
	).Scan(&s.TotalRequests, &s.BlockedCount, &s.ThreatCount, &s.AvgResponseMs)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// GetComplianceReport returns a summary compliance report across all sites.
func (db *DB) GetComplianceReport(ctx context.Context) (*ComplianceReport, error) {
	var r ComplianceReport
	err := db.Pool.QueryRow(ctx,
		`SELECT
		    (SELECT COUNT(*) FROM sites),
		    (SELECT COUNT(*) FROM sites WHERE status IN ('active','live')),
		    (SELECT COUNT(*) FROM threats),
		    (SELECT COUNT(*) FROM threats WHERE blocked),
		    COALESCE((SELECT AVG(confidence) FROM request_log WHERE confidence IS NOT NULL), 0)`,
	).Scan(&r.TotalSites, &r.ActiveSites, &r.TotalThreats, &r.BlockedThreats, &r.AvgConfidence)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// ---------------------------------------------------------------------------
// Threat intelligence
// ---------------------------------------------------------------------------

// LookupThreatIP checks if an IP is in the threat intelligence feed.
func (db *DB) LookupThreatIP(ctx context.Context, ip string) (*ThreatIPResult, error) {
	var r ThreatIPResult
	err := db.Pool.QueryRow(ctx,
		`SELECT ip, tier FROM threat_ips WHERE ip >>= $1::inet ORDER BY
		    CASE tier WHEN 'ban' THEN 0 WHEN 'block' THEN 1 ELSE 2 END
		 LIMIT 1`, ip,
	).Scan(&r.IP, &r.Tier)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// CheckIPDecision returns the most severe active (non-expired) decision for an IP.
func (db *DB) CheckIPDecision(ctx context.Context, ip string) (*Decision, error) {
	var d Decision
	var reason, source *string
	var expiresAt *time.Time
	var siteID *int
	err := db.Pool.QueryRow(ctx,
		`SELECT id, ip, decision_type, scope, duration_seconds, reason, source, confidence, created_at, expires_at, site_id
		 FROM decisions
		 WHERE ip >>= $1::inet
		   AND (expires_at IS NULL OR expires_at > NOW())
		 ORDER BY CASE decision_type WHEN 'ban' THEN 0 WHEN 'captcha' THEN 1 WHEN 'throttle' THEN 2 ELSE 3 END
		 LIMIT 1`, ip,
	).Scan(&d.ID, &d.IP, &d.DecisionType, &d.Scope, &d.DurationSeconds, &reason, &source, &d.Confidence, &d.CreatedAt, &expiresAt, &siteID)
	if err != nil {
		return nil, err
	}
	if reason != nil {
		d.Reason = *reason
	}
	if source != nil {
		d.Source = *source
	}
	if siteID != nil {
		d.SiteID = *siteID
	}
	d.ExpiresAt = expiresAt
	return &d, nil
}

// InsertDecision creates a new IP decision (ban, captcha, throttle, or log_only).
func (db *DB) InsertDecision(ctx context.Context, d *Decision) error {
	var siteID any = d.SiteID
	if d.SiteID == 0 {
		siteID = nil // NULL for global decisions (no FK violation)
	}
	_, err := db.Pool.Exec(ctx,
		`INSERT INTO decisions (ip, decision_type, scope, duration_seconds, reason, source, confidence, expires_at, site_id)
		 VALUES ($1::inet, $2, $3, $4, $5, $6, $7, $8, $9)`,
		d.IP, d.DecisionType, d.Scope, d.DurationSeconds, d.Reason, d.Source, d.Confidence, d.ExpiresAt, siteID)
	return err
}

// BulkInsertThreatIPs inserts multiple threat IP entries in a transaction.
func (db *DB) BulkInsertThreatIPs(ctx context.Context, entries []ThreatIPEntry) error {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	for _, e := range entries {
		_, err := tx.Exec(ctx,
			`INSERT INTO threat_ips (ip, tier, source) VALUES ($1::inet, $2, $3)
			 ON CONFLICT DO NOTHING`,
			e.IP, e.Tier, e.Source)
		if err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// ClearThreatIPsBySource removes all threat IPs from a given source.
func (db *DB) ClearThreatIPsBySource(ctx context.Context, source string) error {
	_, err := db.Pool.Exec(ctx, `DELETE FROM threat_ips WHERE source = $1`, source)
	return err
}

// ListActiveDecisions returns all non-expired decisions, optionally filtered by site.
func (db *DB) ListActiveDecisions(ctx context.Context, siteID int) ([]Decision, error) {
	query := `SELECT id, ip, decision_type, scope, duration_seconds, reason, source, confidence, created_at, expires_at, site_id
		FROM decisions
		WHERE (expires_at IS NULL OR expires_at > NOW())`
	args := []any{}
	if siteID > 0 {
		query += ` AND (site_id = $1 OR site_id = 0 OR site_id IS NULL)`
		args = append(args, siteID)
	}
	query += ` ORDER BY created_at DESC LIMIT 200`

	rows, err := db.Pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Decision
	for rows.Next() {
		var d Decision
		var reason, source *string
		var expiresAt *time.Time
		var siteID *int
		if err := rows.Scan(&d.ID, &d.IP, &d.DecisionType, &d.Scope, &d.DurationSeconds, &reason, &source, &d.Confidence, &d.CreatedAt, &expiresAt, &siteID); err != nil {
			return nil, err
		}
		if reason != nil {
			d.Reason = *reason
		}
		if source != nil {
			d.Source = *source
		}
		if siteID != nil {
			d.SiteID = *siteID
		}
		d.ExpiresAt = expiresAt
		out = append(out, d)
	}
	return out, nil
}

// ListThreatIPs returns recent threat IP entries, optionally filtered by tier.
func (db *DB) ListThreatIPs(ctx context.Context, limit int) ([]ThreatIPEntry, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := db.Pool.Query(ctx,
		`SELECT id, ip, tier, source, fetched_at FROM threat_ips ORDER BY fetched_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []ThreatIPEntry
	for rows.Next() {
		var e ThreatIPEntry
		if err := rows.Scan(&e.ID, &e.IP, &e.Tier, &e.Source, &e.FetchedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}

// CountThreatIPs returns the total number of IPs in the threat_ips table.
func (db *DB) CountThreatIPs(ctx context.Context) (int64, error) {
	var count int64
	err := db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM threat_ips`).Scan(&count)
	return count, err
}

// SeedThreatIPsFromBlockedRequests extracts distinct IPs from blocked
// malicious requests and inserts them into threat_ips with appropriate tiers.
func (db *DB) SeedThreatIPsFromBlockedRequests(ctx context.Context) (int64, error) {
	tag, err := db.Pool.Exec(ctx,
		`INSERT INTO threat_ips (ip, tier, source)
		 SELECT DISTINCT source_ip::inet,
		        CASE WHEN block_count >= 5 THEN 'ban'
		             WHEN block_count >= 3 THEN 'block'
		             ELSE 'scrutinize'
		        END,
		        'waf-observed'
		 FROM (
		     SELECT source_ip, COUNT(*) AS block_count
		     FROM request_log
		     WHERE blocked = true AND classification = 'MALICIOUS'
		       AND source_ip IS NOT NULL AND source_ip != ''
		       AND source_ip ~ '^[0-9a-fA-F:.]+$'
		     GROUP BY source_ip
		 ) sub
		 ON CONFLICT DO NOTHING`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// SeedThreatFeeds populates the threat_feeds table with well-known threat
// intelligence sources for the dashboard to display.
func (db *DB) SeedThreatFeeds(ctx context.Context) error {
	feeds := []struct {
		Name string
		URL  string
		Tier int
	}{
		{"CrowdSec Community Blocklist", "https://cti.api.crowdsec.net/v2/smoke", 1},
		{"Emerging Threats Open", "https://rules.emergingthreats.net/blockrules/compromised-ips.txt", 2},
		{"AbuseIPDB Confidence 90+", "https://api.abuseipdb.com/api/v2/blacklist", 1},
		{"Spamhaus DROP", "https://www.spamhaus.org/drop/drop.txt", 1},
		{"Spamhaus EDROP", "https://www.spamhaus.org/drop/edrop.txt", 1},
		{"Tor Exit Nodes", "https://check.torproject.org/torbulkexitlist", 3},
		{"Firehol Level 1", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset", 2},
		{"Blocklist.de All", "https://lists.blocklist.de/lists/all.txt", 2},
		{"WAF Observed Attackers", "internal://waf-observed", 1},
	}
	for _, f := range feeds {
		_, err := db.Pool.Exec(ctx,
			`INSERT INTO threat_feeds (name, url, tier, enabled)
			 VALUES ($1, $2, $3, true)
			 ON CONFLICT (name) DO NOTHING`,
			f.Name, f.URL, f.Tier)
		if err != nil {
			return err
		}
	}
	return nil
}

// InsertSingleThreatIP inserts a single threat IP entry (e.g. from live WAF blocking).
func (db *DB) InsertSingleThreatIP(ctx context.Context, ip, tier, source string) error {
	_, err := db.Pool.Exec(ctx,
		`INSERT INTO threat_ips (ip, tier, source) VALUES ($1::inet, $2, $3)
		 ON CONFLICT DO NOTHING`, ip, tier, source)
	return err
}

// ---------------------------------------------------------------------------
// GitHub repos
// ---------------------------------------------------------------------------

// StoreGitHubToken stores or updates a user's encrypted GitHub token.
func (db *DB) StoreGitHubToken(ctx context.Context, userID int, encToken, scopes string) error {
	_, err := db.Pool.Exec(ctx,
		`INSERT INTO github_tokens (user_id, encrypted_token, scopes)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (user_id) DO UPDATE SET encrypted_token = $2, scopes = $3, updated_at = NOW()`,
		userID, encToken, scopes)
	return err
}

// GetGitHubToken retrieves the encrypted token for a user.
func (db *DB) GetGitHubToken(ctx context.Context, userID int) (string, error) {
	var token string
	err := db.Pool.QueryRow(ctx,
		`SELECT encrypted_token FROM github_tokens WHERE user_id = $1`, userID).Scan(&token)
	return token, err
}

// LinkRepo connects a site to a GitHub repository.
func (db *DB) LinkRepo(ctx context.Context, siteID int, owner, name, branch string) error {
	_, err := db.Pool.Exec(ctx,
		`INSERT INTO site_repos (site_id, repo_owner, repo_name, default_branch)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT (site_id) DO UPDATE SET repo_owner = $2, repo_name = $3, default_branch = $4, connected_at = NOW()`,
		siteID, owner, name, branch)
	return err
}

// GetSiteRepo retrieves the GitHub repo linked to a site.
func (db *DB) GetSiteRepo(ctx context.Context, siteID int) (*SiteRepo, error) {
	var r SiteRepo
	err := db.Pool.QueryRow(ctx,
		`SELECT site_id, repo_owner, repo_name, default_branch, connected_at
		 FROM site_repos WHERE site_id = $1`, siteID,
	).Scan(&r.SiteID, &r.RepoOwner, &r.RepoName, &r.DefaultBranch, &r.ConnectedAt)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// UnlinkRepo disconnects a site from its GitHub repository.
func (db *DB) UnlinkRepo(ctx context.Context, siteID int) error {
	_, err := db.Pool.Exec(ctx, `DELETE FROM site_repos WHERE site_id = $1`, siteID)
	return err
}

// InsertCodeFinding inserts a new code finding for a site.
func (db *DB) InsertCodeFinding(ctx context.Context, f *CodeFinding) error {
	_, err := db.Pool.Exec(ctx,
		`INSERT INTO code_findings (site_id, threat_id, file_path, line_start, line_end, snippet, finding_type, confidence, description, suggested_fix)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		f.SiteID, f.ThreatID, f.FilePath, f.LineStart, f.LineEnd, f.Snippet, f.FindingType, f.Confidence, f.Description, f.SuggestedFix)
	return err
}

// GetCodeFindings retrieves all code findings for a site, newest first.
func (db *DB) GetCodeFindings(ctx context.Context, siteID int) ([]CodeFinding, error) {
	rows, err := db.Pool.Query(ctx,
		`SELECT id, site_id, threat_id, file_path, line_start, line_end, snippet, finding_type, confidence, description, suggested_fix, status, created_at
		 FROM code_findings WHERE (site_id = $1 OR site_id IS NULL OR site_id = 0) ORDER BY created_at DESC`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var findings []CodeFinding
	for rows.Next() {
		var f CodeFinding
		var snippet, suggestedFix *string
		if err := rows.Scan(&f.ID, &f.SiteID, &f.ThreatID, &f.FilePath, &f.LineStart, &f.LineEnd, &snippet, &f.FindingType, &f.Confidence, &f.Description, &suggestedFix, &f.Status, &f.CreatedAt); err != nil {
			return nil, err
		}
		if snippet != nil {
			f.Snippet = *snippet
		}
		if suggestedFix != nil {
			f.SuggestedFix = *suggestedFix
		}
		findings = append(findings, f)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return findings, nil
}

// UpdateCodeFindingStatus changes the status of a code finding.
func (db *DB) UpdateCodeFindingStatus(ctx context.Context, findingID int64, status string) error {
	_, err := db.Pool.Exec(ctx, `UPDATE code_findings SET status = $1 WHERE id = $2`, status, findingID)
	return err
}

// GetSitesWithRepos returns all sites that have a linked GitHub repo.
func (db *DB) GetSitesWithRepos(ctx context.Context) ([]Site, error) {
	rows, err := db.Pool.Query(ctx,
		`SELECT s.id, s.user_id, s.domain, s.project_name, s.upstream_ip, s.upstream_scheme, s.upstream_port, s.original_cname, s.status, s.verified_at, s.created_at, s.is_demo
		 FROM sites s INNER JOIN site_repos sr ON s.id = sr.site_id
		 ORDER BY s.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var sites []Site
	for rows.Next() {
		var s Site
		var projectName, originalCNAME *string
		if err := rows.Scan(&s.ID, &s.UserID, &s.Domain, &projectName, &s.UpstreamIP, &s.UpstreamScheme, &s.UpstreamPort, &originalCNAME, &s.Status, &s.VerifiedAt, &s.CreatedAt, &s.IsDemo); err != nil {
			return nil, err
		}
		if projectName != nil {
			s.ProjectName = *projectName
		}
		if originalCNAME != nil {
			s.OriginalCNAME = *originalCNAME
		}
		sites = append(sites, s)
	}
	return sites, rows.Err()
}

// AttackSummary represents a distinct attack type from recent blocked requests.
type AttackSummary struct {
	AttackType string
	Payload    string
	Reason     string
}

// GetRecentAttackTypes returns distinct attack types from recent blocked requests for a site.
func (db *DB) GetRecentAttackTypes(ctx context.Context, siteID int, window time.Duration) ([]AttackSummary, error) {
	rows, err := db.Pool.Query(ctx,
		`SELECT DISTINCT ON (attack_type)
		    attack_type, raw_request,
		    COALESCE(classification, '') as reason
		 FROM request_log
		 WHERE site_id = $1
		   AND blocked = true
		   AND attack_type IS NOT NULL
		   AND attack_type != ''
		   AND timestamp > NOW() - $2::interval
		 ORDER BY attack_type, timestamp DESC`,
		siteID, fmt.Sprintf("%d seconds", int(window.Seconds())))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var summaries []AttackSummary
	for rows.Next() {
		var s AttackSummary
		if err := rows.Scan(&s.AttackType, &s.Payload, &s.Reason); err != nil {
			return nil, err
		}
		summaries = append(summaries, s)
	}
	return summaries, rows.Err()
}

// ---------------------------------------------------------------------------
// Partition management
// ---------------------------------------------------------------------------

// EnsurePartition creates a monthly partition for the request_log table if it
// does not already exist.
func (db *DB) EnsurePartition(ctx context.Context, t time.Time) error {
	year, month, _ := t.Date()
	name := fmt.Sprintf("request_log_%d_%02d", year, month)
	start := time.Date(year, month, 1, 0, 0, 0, 0, time.UTC)
	end := start.AddDate(0, 1, 0)
	quotedName := pgx.Identifier{name}.Sanitize()
	sql := fmt.Sprintf(
		`CREATE TABLE IF NOT EXISTS %s PARTITION OF request_log FOR VALUES FROM ('%s') TO ('%s')`,
		quotedName, start.Format("2006-01-02"), end.Format("2006-01-02"),
	)
	_, err := db.Pool.Exec(ctx, sql)
	if err != nil {
		return fmt.Errorf("create partition %s: %w", name, err)
	}
	db.logger.Info("partition ensured", "table", name)
	return nil
}

// EnsureCurrentAndNextPartitions creates partitions for the current and next month.
func (db *DB) EnsureCurrentAndNextPartitions(ctx context.Context) error {
	now := time.Now().UTC()
	if err := db.EnsurePartition(ctx, now); err != nil {
		return err
	}
	return db.EnsurePartition(ctx, now.AddDate(0, 1, 0))
}

// ---------------------------------------------------------------------------
// Global queries (cross-site, for frontend compatibility)
// ---------------------------------------------------------------------------

// GetGlobalStats returns aggregate stats across all sites.
func (db *DB) GetGlobalStats(ctx context.Context) (*Stats, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	var s Stats
	err := db.Pool.QueryRow(ctx,
		`SELECT
		    COUNT(*),
		    COUNT(*) FILTER (WHERE blocked),
		    COALESCE((SELECT COUNT(*) FROM threats WHERE site_id IS NOT NULL), 0),
		    COALESCE(AVG(response_time_ms), 0)
		 FROM request_log`,
	).Scan(&s.TotalRequests, &s.BlockedCount, &s.ThreatCount, &s.AvgResponseMs)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// GetGlobalRecentRequests retrieves the most recent request log entries across all sites.
func (db *DB) GetGlobalRecentRequests(ctx context.Context, limit int) ([]RequestLogEntry, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	rows, err := db.Pool.Query(ctx,
		`SELECT id, site_id, timestamp, raw_request, classification, confidence, classifier, blocked, attack_type, response_time_ms, source_ip
		 FROM request_log ORDER BY timestamp DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var entries []RequestLogEntry
	for rows.Next() {
		var e RequestLogEntry
		var attackType, sourceIP *string
		var confidence, responseTimeMs *float32
		if err := rows.Scan(&e.ID, &e.SiteID, &e.Timestamp, &e.RawRequest, &e.Classification, &confidence, &e.Classifier, &e.Blocked, &attackType, &responseTimeMs, &sourceIP); err != nil {
			return nil, err
		}
		if attackType != nil {
			e.AttackType = *attackType
		}
		if sourceIP != nil {
			e.SourceIP = *sourceIP
		}
		if confidence != nil {
			e.Confidence = *confidence
		}
		if responseTimeMs != nil {
			e.ResponseTimeMs = *responseTimeMs
		}
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

// GetGlobalRecentAgentLogs retrieves the most recent agent log entries across all real sites
// (excludes synthetic agent-loop entries with no site).
func (db *DB) GetGlobalRecentAgentLogs(ctx context.Context, limit int) ([]AgentLogEntry, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	rows, err := db.Pool.Query(ctx,
		`SELECT id, site_id, timestamp, agent, action, detail, success
		 FROM agent_log WHERE site_id IS NOT NULL ORDER BY timestamp DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var entries []AgentLogEntry
	for rows.Next() {
		var e AgentLogEntry
		var detail *string
		if err := rows.Scan(&e.ID, &e.SiteID, &e.Timestamp, &e.Agent, &e.Action, &detail, &e.Success); err != nil {
			return nil, err
		}
		if detail != nil {
			e.Detail = *detail
		}
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

// GetGlobalThreats retrieves threats across all real sites (excludes agent-generated synthetic data).
func (db *DB) GetGlobalThreats(ctx context.Context) ([]Threat, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	rows, err := db.Pool.Query(ctx,
		`SELECT id, site_id, technique_name, category, source, raw_payload, severity, discovered_at, tested_at, blocked, patched_at
		 FROM threats WHERE site_id IS NOT NULL ORDER BY discovered_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var threats []Threat
	for rows.Next() {
		var t Threat
		var source *string
		if err := rows.Scan(&t.ID, &t.SiteID, &t.TechniqueName, &t.Category, &source, &t.RawPayload, &t.Severity, &t.DiscoveredAt, &t.TestedAt, &t.Blocked, &t.PatchedAt); err != nil {
			return nil, err
		}
		if source != nil {
			t.Source = *source
		}
		threats = append(threats, t)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return threats, nil
}

// RepeatOffender represents an IP with multiple blocked requests.
type RepeatOffender struct {
	IP          string
	BlockCount  int
	AttackTypes []string
	FirstSeen   time.Time
	LastSeen    time.Time
}

// GetRepeatOffenderIPs returns IPs with multiple blocked requests in the given window.
func (db *DB) GetRepeatOffenderIPs(ctx context.Context, window time.Duration, minBlocks int) ([]RepeatOffender, error) {
	rows, err := db.Pool.Query(ctx,
		`SELECT source_ip::text, COUNT(*) as block_count,
		    array_agg(DISTINCT attack_type) FILTER (WHERE attack_type IS NOT NULL AND attack_type != '') as attack_types,
		    MIN(timestamp) as first_seen,
		    MAX(timestamp) as last_seen
		 FROM request_log
		 WHERE blocked = true
		   AND source_ip IS NOT NULL
		   AND timestamp > NOW() - $1::interval
		 GROUP BY source_ip
		 HAVING COUNT(*) >= $2
		 ORDER BY block_count DESC
		 LIMIT 50`,
		fmt.Sprintf("%d seconds", int(window.Seconds())), minBlocks)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var offenders []RepeatOffender
	for rows.Next() {
		var o RepeatOffender
		var attackTypes []string
		if err := rows.Scan(&o.IP, &o.BlockCount, &attackTypes, &o.FirstSeen, &o.LastSeen); err != nil {
			return nil, err
		}
		o.AttackTypes = attackTypes
		offenders = append(offenders, o)
	}
	return offenders, rows.Err()
}

// ClassifierBreakdown represents classification stats for a time window.
type ClassifierBreakdown struct {
	Classifier     string
	Classification string
	Count          int64
}

// GetClassifierBreakdown returns classification counts grouped by classifier and result.
func (db *DB) GetClassifierBreakdown(ctx context.Context, window time.Duration) ([]ClassifierBreakdown, error) {
	rows, err := db.Pool.Query(ctx,
		`SELECT classifier, classification, COUNT(*) as cnt
		 FROM request_log
		 WHERE timestamp > NOW() - $1::interval
		 GROUP BY classifier, classification
		 ORDER BY cnt DESC`,
		fmt.Sprintf("%d seconds", int(window.Seconds())))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var results []ClassifierBreakdown
	for rows.Next() {
		var b ClassifierBreakdown
		if err := rows.Scan(&b.Classifier, &b.Classification, &b.Count); err != nil {
			return nil, err
		}
		results = append(results, b)
	}
	return results, rows.Err()
}

// AttackTrend represents attack frequency for a specific type.
type AttackTrend struct {
	AttackType string
	Count      int64
	AvgConf    float64
}

// GetAttackTrends returns attack type frequency over the given window.
func (db *DB) GetAttackTrends(ctx context.Context, window time.Duration) ([]AttackTrend, error) {
	rows, err := db.Pool.Query(ctx,
		`SELECT attack_type, COUNT(*) as cnt, AVG(confidence) as avg_conf
		 FROM request_log
		 WHERE attack_type IS NOT NULL AND attack_type != '' AND attack_type != 'none'
		   AND timestamp > NOW() - $1::interval
		 GROUP BY attack_type
		 ORDER BY cnt DESC`,
		fmt.Sprintf("%d seconds", int(window.Seconds())))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var trends []AttackTrend
	for rows.Next() {
		var t AttackTrend
		if err := rows.Scan(&t.AttackType, &t.Count, &t.AvgConf); err != nil {
			return nil, err
		}
		trends = append(trends, t)
	}
	return trends, rows.Err()
}

// RegexBypassEntry represents a request that the LLM caught but regex missed.
type RegexBypassEntry struct {
	RawRequest string
	AttackType string
	Classifier string
	Confidence float32
}

// GetRegexBypasses returns recent requests where the LLM classifier caught an
// attack that the regex classifier missed (classifier != 'regex' AND blocked).
func (db *DB) GetRegexBypasses(ctx context.Context, window time.Duration, limit int) ([]RegexBypassEntry, error) {
	rows, err := db.Pool.Query(ctx,
		`SELECT raw_request, attack_type, classifier, confidence
		 FROM request_log
		 WHERE classifier IN ('crusoe', 'claude')
		   AND classification = 'MALICIOUS'
		   AND blocked = true
		   AND attack_type IS NOT NULL AND attack_type != 'none'
		   AND timestamp > NOW() - $1::interval
		 ORDER BY timestamp DESC
		 LIMIT $2`,
		fmt.Sprintf("%d seconds", int(window.Seconds())), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var entries []RegexBypassEntry
	for rows.Next() {
		var e RegexBypassEntry
		if err := rows.Scan(&e.RawRequest, &e.AttackType, &e.Classifier, &e.Confidence); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// GetAllRuleVersions retrieves all rule versions, newest first.
func (db *DB) GetAllRuleVersions(ctx context.Context) ([]Rules, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	rows, err := db.Pool.Query(ctx,
		`SELECT id, site_id, version, crusoe_prompt, claude_prompt, updated_at, updated_by
		 FROM rules ORDER BY version DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var rules []Rules
	for rows.Next() {
		var r Rules
		if err := rows.Scan(&r.ID, &r.SiteID, &r.Version, &r.CrusoePrompt, &r.ClaudePrompt, &r.UpdatedAt, &r.UpdatedBy); err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return rules, nil
}
