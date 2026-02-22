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
    upstream_ip     TEXT NOT NULL DEFAULT '0.0.0.0',
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
CREATE INDEX IF NOT EXISTS idx_request_log_site ON request_log(site_id);

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
CREATE UNIQUE INDEX IF NOT EXISTS idx_threat_ips_unique ON threat_ips(ip, source);

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

DROP TRIGGER IF EXISTS trg_request_log_notify ON request_log;
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

DROP TRIGGER IF EXISTS trg_agent_log_notify ON agent_log;
CREATE TRIGGER trg_agent_log_notify
    AFTER INSERT ON agent_log FOR EACH ROW EXECUTE FUNCTION notify_agent_log();

-- Code findings notification trigger
CREATE OR REPLACE FUNCTION notify_code_finding() RETURNS trigger AS $$
BEGIN
    PERFORM pg_notify('finding_stream', json_build_object(
        'id', NEW.id, 'site_id', NEW.site_id, 'file_path', NEW.file_path,
        'line_start', NEW.line_start, 'line_end', NEW.line_end,
        'snippet', left(COALESCE(NEW.snippet, ''), 300),
        'finding_type', NEW.finding_type, 'confidence', NEW.confidence,
        'description', left(NEW.description, 300),
        'suggested_fix', left(COALESCE(NEW.suggested_fix, ''), 300),
        'status', NEW.status, 'created_at', NEW.created_at
    )::text);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_code_finding_notify ON code_findings;
CREATE TRIGGER trg_code_finding_notify
    AFTER INSERT ON code_findings FOR EACH ROW EXECUTE FUNCTION notify_code_finding();
