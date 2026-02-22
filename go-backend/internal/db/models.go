package db

import (
	"encoding/json"
	"time"
)

type User struct {
	ID          int       `json:"id"`
	GitHubID    int64     `json:"github_id"`
	GitHubLogin string    `json:"github_login"`
	AvatarURL   string    `json:"avatar_url,omitempty"`
	Name        string    `json:"name,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

type Session struct {
	ID        string    `json:"id"`
	UserID    int       `json:"user_id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	IPAddress string    `json:"ip_address,omitempty"`
	UserAgent string    `json:"user_agent,omitempty"`
}

type Site struct {
	ID            int        `json:"id"`
	UserID        int        `json:"user_id"`
	Domain        string     `json:"domain"`
	ProjectName   string     `json:"project_name,omitempty"`
	UpstreamIP    string     `json:"upstream_ip"`
	OriginalCNAME string     `json:"original_cname,omitempty"`
	Status        string     `json:"status"`
	VerifiedAt    *time.Time `json:"verified_at,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
}

type Threat struct {
	ID            int64      `json:"id"`
	SiteID        *int       `json:"site_id"`
	TechniqueName string     `json:"technique_name"`
	Category      string     `json:"category"`
	Source        string     `json:"source,omitempty"`
	RawPayload    string     `json:"raw_payload"`
	Severity      string     `json:"severity"`
	DiscoveredAt  time.Time  `json:"discovered_at"`
	TestedAt      *time.Time `json:"tested_at,omitempty"`
	Blocked       bool       `json:"blocked"`
	PatchedAt     *time.Time `json:"patched_at,omitempty"`
}

type RequestLogEntry struct {
	ID             int64     `json:"id"`
	SiteID         int       `json:"site_id"`
	Timestamp      time.Time `json:"timestamp"`
	RawRequest     string    `json:"raw_request"`
	Classification string    `json:"classification"`
	Confidence     float32   `json:"confidence"`
	Classifier     string    `json:"classifier"`
	Blocked        bool      `json:"blocked"`
	AttackType     string    `json:"attack_type,omitempty"`
	ResponseTimeMs float32   `json:"response_time_ms"`
	SourceIP       string    `json:"source_ip,omitempty"`
}

type AgentLogEntry struct {
	ID        int64     `json:"id"`
	SiteID    *int      `json:"site_id"`
	Timestamp time.Time `json:"timestamp"`
	Agent     string    `json:"agent"`
	Action    string    `json:"action"`
	Detail    string    `json:"detail,omitempty"`
	Success   bool      `json:"success"`
}

type Rules struct {
	ID           int64     `json:"id"`
	SiteID       int       `json:"site_id"`
	Version      int       `json:"version"`
	CrusoePrompt string    `json:"crusoe_prompt"`
	ClaudePrompt string    `json:"claude_prompt"`
	UpdatedAt    time.Time `json:"updated_at"`
	UpdatedBy    string    `json:"updated_by"`
}

type Decision struct {
	ID              int64      `json:"id"`
	IP              string     `json:"ip"`
	DecisionType    string     `json:"decision_type"`
	Scope           string     `json:"scope"`
	DurationSeconds int        `json:"duration_seconds,omitempty"`
	Reason          string     `json:"reason,omitempty"`
	Source          string     `json:"source,omitempty"`
	Confidence      float32    `json:"confidence"`
	CreatedAt       time.Time  `json:"created_at"`
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`
	SiteID          int        `json:"site_id"`
}

type IPReputation struct {
	IP          string          `json:"ip"`
	Score       float32         `json:"score"`
	AttackCount int             `json:"attack_count"`
	TenantCount int             `json:"tenant_count"`
	AttackTypes json.RawMessage `json:"attack_types"`
	FirstSeen   time.Time       `json:"first_seen"`
	LastSeen    time.Time       `json:"last_seen"`
	GeoCountry  string          `json:"geo_country,omitempty"`
	ASN         string          `json:"asn,omitempty"`
	IsTor       bool            `json:"is_tor"`
	IsVPN       bool            `json:"is_vpn"`
}

type BehavioralSession struct {
	ID            int64           `json:"id"`
	IP            string          `json:"ip"`
	SiteID        int             `json:"site_id"`
	WindowStart   *time.Time      `json:"window_start,omitempty"`
	RequestCount  int             `json:"request_count"`
	ErrorCount    int             `json:"error_count"`
	UniquePaths   int             `json:"unique_paths"`
	AuthFailures  int             `json:"auth_failures"`
	AvgIntervalMs float32         `json:"avg_interval_ms"`
	Flags         json.RawMessage `json:"flags"`
}

type EndpointProfile struct {
	ID                 int64     `json:"id"`
	SiteID             int       `json:"site_id"`
	PathPattern        string    `json:"path_pattern"`
	Sensitivity        string    `json:"sensitivity"`
	AttackFrequency    float32   `json:"attack_frequency"`
	FalsePositiveRate  float32   `json:"false_positive_rate"`
	SkipClassification bool      `json:"skip_classification"`
	ForceDeepAnalysis  bool      `json:"force_deep_analysis"`
	UpdatedAt          time.Time `json:"updated_at"`
}

type ThreatIPEntry struct {
	ID        int64     `json:"id"`
	IP        string    `json:"ip"`
	Tier      string    `json:"tier"`
	Source    string    `json:"source"`
	FetchedAt time.Time `json:"fetched_at"`
}

type ThreatFeed struct {
	ID          int        `json:"id"`
	Name        string     `json:"name"`
	URL         string     `json:"url"`
	Tier        int        `json:"tier"`
	LastFetch   *time.Time `json:"last_fetch,omitempty"`
	LastSuccess *time.Time `json:"last_success,omitempty"`
	EntryCount  int        `json:"entry_count"`
	Error       string     `json:"error,omitempty"`
	Enabled     bool       `json:"enabled"`
}

type HubRule struct {
	ID          int64     `json:"id"`
	HubName     string    `json:"hub_name"`
	HubType     string    `json:"hub_type"`
	Version     string    `json:"version,omitempty"`
	YAMLContent string    `json:"yaml_content,omitempty"`
	ImportedAt  time.Time `json:"imported_at"`
	SiteID      int       `json:"site_id"`
	Active      bool      `json:"active"`
}

type GitHubToken struct {
	UserID         int       `json:"user_id"`
	EncryptedToken string    `json:"-"`
	Scopes         string    `json:"scopes"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type SiteRepo struct {
	SiteID        int       `json:"site_id"`
	RepoOwner     string    `json:"repo_owner"`
	RepoName      string    `json:"repo_name"`
	DefaultBranch string    `json:"default_branch"`
	ConnectedAt   time.Time `json:"connected_at"`
}

type CodeFinding struct {
	ID           int64     `json:"id"`
	SiteID       int       `json:"site_id"`
	ThreatID     *int64    `json:"threat_id,omitempty"`
	FilePath     string    `json:"file_path"`
	LineStart    *int      `json:"line_start,omitempty"`
	LineEnd      *int      `json:"line_end,omitempty"`
	Snippet      string    `json:"snippet,omitempty"`
	FindingType  string    `json:"finding_type"`
	Confidence   float32   `json:"confidence"`
	Description  string    `json:"description"`
	SuggestedFix string    `json:"suggested_fix,omitempty"`
	Status       string    `json:"status"`
	CreatedAt    time.Time `json:"created_at"`
}

// Stats aggregation types
type Stats struct {
	TotalRequests int64   `json:"total_requests"`
	BlockedCount  int64   `json:"blocked_count"`
	ThreatCount   int64   `json:"threat_count"`
	AvgResponseMs float64 `json:"avg_response_ms"`
}

type ThreatCategory struct {
	Category string `json:"category"`
	Count    int64  `json:"count"`
}

type ThreatIPResult struct {
	IP   string `json:"ip"`
	Tier string `json:"tier"`
}

type ComplianceReport struct {
	TotalSites     int64   `json:"total_sites"`
	ActiveSites    int64   `json:"active_sites"`
	TotalThreats   int64   `json:"total_threats"`
	BlockedThreats int64   `json:"blocked_threats"`
	AvgConfidence  float64 `json:"avg_confidence"`
}
