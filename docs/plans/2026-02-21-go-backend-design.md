# Veil Go Backend Design — Merged Genkit + Fabric-Hybrid

**Status:** Approved
**Date:** 2026-02-21
**Approach:** Merge `go-fabric-hybrid` (behavioral engine, CrowdSec features, Fabric prompts, graduated decisions) with `go-genkit` (Genkit Flows for agent orchestration, OpenTelemetry, Ollama plugin)

---

## 1. Architecture

The Go backend is a separate codebase from the Python backend (`go-backend/` directory). It shares the same frontend and database schema (extended with 4 behavioral tables). The Python backend remains untouched.

```
┌─────────────────────────────────────────────────────────────────┐
│                    Veil Go Backend                                │
│                                                                  │
│  HTTP Server (gorilla/mux, :8080)                                │
│  Routes: /auth/* /api/* /p/{site_id}/* /ws /v1/classify          │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  Enhanced Reverse Proxy                                    │   │
│  │  1. IP Reputation check        (in-memory, ~0ms)          │   │
│  │  2. Behavioral Analysis         (leaky bucket, ~1ms)      │   │
│  │  3. Regex Classifier            (compiled patterns, ~1ms) │   │
│  │  4. Fast LLM (Ollama local)     (Qwen3-0.6B, ~15-40ms)  │   │
│  │  5. Crusoe API (Llama 3.1 8B)   (hosted, ~50-150ms)      │   │
│  │  6. Claude via Bedrock           (deep, no reasoning,     │   │
│  │                                   ~500ms-1s)              │   │
│  │  7. Decision Engine              (Ban/Captcha/Throttle/   │   │
│  │                                   LogOnly/Allow)          │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  Genkit Flows (agent orchestration)                        │   │
│  │  peek-discover  → discover new attack techniques           │   │
│  │  poke-redteam   → test classifier with known payloads     │   │
│  │  patch-update   → update detection prompts from bypasses  │   │
│  │  behavioral-update → aggregate cross-tenant signals        │   │
│  │  + OpenTelemetry tracing on every flow                     │   │
│  │  + Genkit Dev UI at localhost:3100 (GENKIT_ENV=dev)        │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  Behavioral Engine (CrowdSec-inspired)                     │   │
│  │  - IP Reputation (cross-tenant scoring, time decay)        │   │
│  │  - Session Tracking (per-IP request patterns)              │   │
│  │  - Leaky Bucket Scenarios:                                 │   │
│  │    * Credential stuffing (N auth failures / T seconds)     │   │
│  │    * Path enumeration (rapid sequential similar paths)     │   │
│  │    * Scanner fingerprint (/wp-admin, /.env, /phpinfo.php)  │   │
│  │    * Rate anomaly (sudden spike from single IP)            │   │
│  │    * Path fuzzing (high 404 ratio from single IP)          │   │
│  │    * Error storm (high 4xx/5xx ratio)                      │   │
│  │  - Graduated Decisions (5-level response system)           │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  Fabric-Style Prompt Patterns (prompts/*.md)               │   │
│  │  Format: IDENTITY → STEPS → OUTPUT INSTRUCTIONS → INPUT   │   │
│  │  - classify_request.md    (fast classification)            │   │
│  │  - deep_analysis.md       (Claude deep analysis)           │   │
│  │  - peek_discover.md       (attack discovery)               │   │
│  │  - patch_update.md        (prompt self-improvement)        │   │
│  │  - analyze_bypass.md      (bypass root cause analysis)     │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│  Database: SQLite WAL, 10 tables (6 core + 4 behavioral)        │
│  WebSocket: Real-time dashboard via /ws                          │
│  Auth: GitHub OAuth with HMAC-signed session cookies             │
└─────────────────────────────────────────────────────────────────┘
```

## 2. Four-Stage LLM Classification Cascade

Each stage only fires if the previous returned SUSPICIOUS. SAFE or MALICIOUS at any stage triggers an immediate decision.

| Stage | Engine | Latency | Handles | Cost |
|-------|--------|---------|---------|------|
| 0 (pre-filter) | IP Reputation + Behavioral | ~1ms | ~8% preemptive blocks | $0 |
| 1 | Regex (9 categories, compiled) | ~1ms | ~80% of remaining | $0 |
| 2 | Ollama local (Qwen3-0.6B / Gemma 270M) | ~15-40ms (GPU) | ~10% of remaining | $0 |
| 3 | Crusoe API (Llama 3.1 8B) | ~50-150ms | ~1.5% of remaining | Low |
| 4 | Claude via Bedrock (no reasoning) | ~500ms-1s | ~0.5% of remaining | ~$0.003/req |

**Expected latency distribution:**
- p50: ~2ms (regex handles it)
- p90: ~5ms (behavioral + regex)
- p95: ~25ms (fast local LLM)
- p99: ~100ms (Crusoe)
- p99.9: ~700ms (Claude deep)

### Crusoe Integration

Crusoe serves an OpenAI-compatible API at `https://inference.crusoe.ai/v1/chat/completions`. In Go, this is a standard HTTP POST:

```go
type CrusoeEngine struct {
    apiKey  string
    apiURL  string
    model   string
    client  *http.Client
}

// POST to Crusoe with the same system prompt as Python backend
func (c *CrusoeEngine) Classify(ctx context.Context, raw, systemPrompt string) (*Classification, error) {
    // OpenAI-compatible request body
    body := map[string]any{
        "model": c.model,  // "meta-llama/Meta-Llama-3.1-8B-Instruct"
        "messages": []map[string]string{
            {"role": "system", "content": systemPrompt},
            {"role": "user", "content": raw},
        },
        "temperature": 0.0,
        "max_tokens":  200,
    }
    // ... HTTP POST, parse JSON response
}
```

### Claude Configuration (No Reasoning)

Claude is called with `temperature: 0.0`, no extended thinking, no tools — pure classification:

```go
msg, err := client.Messages.New(ctx, anthropic.MessageNewParams{
    Model:     anthropic.Model("global.anthropic.claude-sonnet-4-5-20250929-v1:0"),
    MaxTokens: 300,
    Temperature: anthropic.Float(0.0),
    System:    []anthropic.TextBlockParam{{Text: systemPrompt}},
    Messages:  []anthropic.MessageParam{
        anthropic.NewUserMessage(anthropic.NewTextBlock(truncatedRequest)),
    },
})
```

## 3. Database Schema (10 Tables)

### Core tables (matching Python backend):

```sql
users (id, github_id UNIQUE, github_login, avatar_url, name, created_at)
sites (id, site_id UNIQUE, target_url, user_id FK, created_at)
threats (id, technique_name, category, source, raw_payload, severity,
         discovered_at, tested_at, blocked, patched_at)
request_log (id, timestamp, raw_request, classification, confidence,
             classifier, blocked, attack_type, response_time_ms)
agent_log (id, timestamp, agent, action, detail, success)
rules (id, version, crusoe_prompt, claude_prompt, updated_at, updated_by)
```

### New behavioral tables (from CrowdSec spec):

```sql
-- Graduated decisions (replaces binary block/allow)
decisions (
    id INTEGER PRIMARY KEY,
    ip TEXT NOT NULL,
    decision_type TEXT NOT NULL,  -- ban, captcha, throttle, log_only
    scope TEXT NOT NULL,          -- ip, session, fingerprint
    duration_seconds INTEGER,
    reason TEXT,
    source TEXT,                  -- regex, model, behavioral, community
    confidence REAL,
    created_at TEXT,
    expires_at TEXT,
    site_id TEXT
)

-- Cross-tenant IP reputation
ip_reputation (
    ip TEXT PRIMARY KEY,
    score REAL DEFAULT 0.0,      -- 0=trusted, 1=malicious
    attack_count INTEGER DEFAULT 0,
    tenant_count INTEGER DEFAULT 0,
    attack_types TEXT,            -- JSON array
    first_seen TEXT,
    last_seen TEXT,
    geo_country TEXT,
    asn TEXT,
    is_tor BOOLEAN DEFAULT 0,
    is_vpn BOOLEAN DEFAULT 0
)

-- Per-IP behavioral tracking
behavioral_sessions (
    id INTEGER PRIMARY KEY,
    ip TEXT NOT NULL,
    site_id TEXT NOT NULL,
    window_start TEXT,
    request_count INTEGER DEFAULT 0,
    error_count INTEGER DEFAULT 0,
    unique_paths INTEGER DEFAULT 0,
    auth_failures INTEGER DEFAULT 0,
    avg_interval_ms REAL,
    flags TEXT                    -- JSON array of detected behaviors
)

-- Auto-learned endpoint sensitivity
endpoint_profiles (
    id INTEGER PRIMARY KEY,
    site_id TEXT NOT NULL,
    path_pattern TEXT NOT NULL,
    sensitivity TEXT DEFAULT 'MEDIUM',
    attack_frequency REAL,
    false_positive_rate REAL,
    skip_classification BOOLEAN DEFAULT 0,
    force_deep_analysis BOOLEAN DEFAULT 0,
    updated_at TEXT
)
```

## 4. Genkit Flow Definitions

Each agent is a typed Genkit Flow with OpenTelemetry tracing:

```go
// Classification Flow
classifyFlow := genkit.DefineFlow(g, "classify-request",
    func(ctx context.Context, input ClassifyInput) (*Classification, error) {
        // Stage pipeline: regex → fast LLM → Crusoe → Claude
    })

// Peek: discover new attack techniques
peekFlow := genkit.DefineFlow(g, "peek-discover",
    func(ctx context.Context, input PeekInput) (*PeekOutput, error) {
        // Read Fabric prompt from prompts/peek_discover.md
        // Call Claude to generate novel attack variations
        // Insert new threats into DB
    })

// Poke: red-team the classifier
pokeFlow := genkit.DefineFlow(g, "poke-redteam",
    func(ctx context.Context, input PokeInput) (*PokeOutput, error) {
        // Query untested threats
        // Send each to /v1/classify
        // Record bypasses
    })

// Patch: update detection prompts
patchFlow := genkit.DefineFlow(g, "patch-update",
    func(ctx context.Context, input PatchInput) (*PatchOutput, error) {
        // Read Fabric prompt from prompts/patch_update.md
        // Call Claude to analyze bypasses and generate updated prompts
        // Create new rule version in DB
    })

// BehavioralUpdate: aggregate cross-tenant signals
behavioralFlow := genkit.DefineFlow(g, "behavioral-update",
    func(ctx context.Context, input struct{}) (*BehavioralOutput, error) {
        // Update IP reputation scores
        // Persist behavioral sessions to DB
        // Clean up expired decisions
    })
```

### Agent Loop

```go
func RunLoop(ctx context.Context, flows *Flows, hub *ws.Hub) {
    ticker := time.NewTicker(30 * time.Second)
    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            peekResult, _ := flows.Peek.Run(ctx, PeekInput{})
            time.Sleep(2 * time.Second)
            pokeResult, _ := flows.Poke.Run(ctx, PokeInput{})
            time.Sleep(2 * time.Second)
            patchResult, _ := flows.Patch.Run(ctx, PatchInput{Bypasses: pokeResult.Bypasses})
            flows.Behavioral.Run(ctx, struct{}{})
            hub.BroadcastStats(...)
        }
    }
}
```

## 5. Behavioral Engine

### IP Reputation

In-memory map with periodic SQLite persistence:

```go
type IPReputation struct {
    Score       float64   // 0.0 = trusted, 1.0 = malicious
    AttackCount int
    TenantCount int
    AttackTypes []string
    FirstSeen   time.Time
    LastSeen    time.Time
    IsTor       bool
    IsVPN       bool
}

// Decision thresholds:
// score > 0.9 → preemptive BAN (skip all classification)
// score > 0.7 → force deep classification (skip to Crusoe/Claude)
// score > 0.5 → force fast classification (skip regex shortcut)
// score < 0.2 → trusted (skip classification entirely)
```

### Leaky Bucket Scenarios

| Scenario | Trigger | Decision |
|----------|---------|----------|
| Credential stuffing | >10 auth failures / 60s from same IP | CAPTCHA, then BAN |
| Path enumeration | >20 sequential similar paths / 30s | THROTTLE |
| Scanner fingerprint | Request to /wp-admin, /.env, /phpinfo.php | BAN 24h |
| Rate anomaly | >100 requests / 60s from single IP | THROTTLE |
| Path fuzzing | >80% 404 ratio over 20+ requests | BAN 1h |
| Error storm | >50% 4xx/5xx ratio over 30+ requests | THROTTLE |

### Graduated Decision System

```go
type DecisionType int
const (
    DecisionAllow DecisionType = iota
    DecisionLogOnly
    DecisionThrottle   // Slow down responses (add delay)
    DecisionCaptcha    // Show challenge page
    DecisionBan        // Hard block (403)
)

type Decision struct {
    Type       DecisionType
    Scope      string        // ip, session, fingerprint
    Duration   time.Duration
    Reason     string
    Source     string        // regex, model, behavioral, community
    Confidence float64
}
```

## 6. Fabric Prompt Patterns

Prompts stored as markdown files in `prompts/`, loaded at startup and cacheable. Follows Fabric's community-proven format:

```markdown
# prompts/classify_request.md

# IDENTITY and PURPOSE
You are a web application firewall classifier. You analyze HTTP requests
to determine if they contain attack payloads.

# STEPS
1. Examine the HTTP method, path, query parameters, headers, and body
2. Check for SQL injection patterns (UNION, OR 1=1, comments, etc.)
3. Check for XSS patterns (script tags, event handlers, DOM manipulation)
4. Check for command injection, path traversal, SSRF, XXE
5. Consider encoding evasion (double URL encode, unicode, null bytes)
6. Assess confidence based on number and severity of indicators

# OUTPUT INSTRUCTIONS
- Respond with a single JSON object, no markdown, no explanation
- Fields: classification (SAFE|SUSPICIOUS|MALICIOUS), confidence (0.0-1.0),
  attack_type (sqli|xss|path_traversal|command_injection|ssrf|xxe|
  header_injection|auth_bypass|encoding_evasion|none), reason (brief)

# INPUT
```

The Patch agent updates these prompts when it closes bypasses. New prompt versions are stored in the `rules` table and loaded at the next classification cycle.

## 7. Directory Structure

```
go-backend/
├── main.go                           -- Genkit init, HTTP server, routes
├── handlers.go                       -- API endpoint handlers
├── go.mod / go.sum
├── prompts/
│   ├── classify_request.md           -- Fast classification prompt
│   ├── deep_analysis.md              -- Claude deep analysis prompt
│   ├── peek_discover.md              -- Attack discovery prompt
│   ├── patch_update.md               -- Prompt self-improvement
│   └── analyze_bypass.md             -- Bypass root cause analysis
├── internal/
│   ├── classifier/
│   │   ├── pipeline.go               -- Four-stage cascade orchestration
│   │   ├── regex.go                  -- 9 attack categories, compiled patterns
│   │   ├── fast_model.go             -- Genkit + Ollama (Qwen3-0.6B)
│   │   ├── crusoe.go                 -- Crusoe API (Llama 3.1 8B)
│   │   ├── deep_model.go             -- Anthropic SDK + Bedrock (Claude)
│   │   └── types.go                  -- Classification, ClassifyInput structs
│   ├── behavioral/
│   │   ├── engine.go                 -- IP reputation, session tracking, scenarios
│   │   └── decisions.go              -- Graduated decision system (5 levels)
│   ├── agents/
│   │   ├── peek.go                   -- Genkit Flow: discover attacks
│   │   ├── poke.go                   -- Genkit Flow: red-team classifier
│   │   ├── patch.go                  -- Genkit Flow: update rules
│   │   ├── loop.go                   -- Background orchestration
│   │   └── types.go                  -- Flow input/output types
│   ├── proxy/
│   │   └── proxy.go                  -- Enhanced reverse proxy
│   ├── db/
│   │   └── database.go               -- SQLite, 10 tables, CRUD
│   ├── auth/
│   │   └── github.go                 -- GitHub OAuth
│   ├── ws/
│   │   └── hub.go                    -- WebSocket hub
│   └── ratelimit/
│       └── limiter.go                -- Per-IP sliding window
```

## 8. Dependencies

| Package | Purpose |
|---------|---------|
| `github.com/firebase/genkit/go` | Flow orchestration, Ollama plugin, OTel tracing |
| `github.com/firebase/genkit/go/plugins/ollama` | Local model inference |
| `github.com/anthropics/anthropic-sdk-go` | Claude via Bedrock |
| `github.com/mattn/go-sqlite3` | Database |
| `github.com/gorilla/mux` | HTTP routing |
| `github.com/gorilla/websocket` | Real-time dashboard |
| `golang.org/x/oauth2` | GitHub OAuth |
| `net/http` (stdlib) | Crusoe API calls |

## 9. Environment Variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `PORT` / `LISTEN_ADDR` | HTTP server address | `:8080` |
| `OLLAMA_HOST` | Ollama sidecar URL | `http://localhost:11434` |
| `OLLAMA_MODEL` | Fast model name | `qwen3:0.6b` |
| `CRUSOE_API_KEY` | Crusoe inference auth | (required for Stage 3) |
| `CRUSOE_API_URL` | Crusoe endpoint | `https://inference.crusoe.ai/v1` |
| `CRUSOE_MODEL` | Crusoe model | `meta-llama/Meta-Llama-3.1-8B-Instruct` |
| `AWS_ACCESS_KEY_ID` | Bedrock auth | (required for Stage 4) |
| `AWS_SECRET_ACCESS_KEY` | Bedrock auth | (required for Stage 4) |
| `AWS_REGION` | AWS region | `eu-west-1` |
| `BEDROCK_MODEL` | Claude model ID | `global.anthropic.claude-sonnet-4-5-20250929-v1:0` |
| `GITHUB_CLIENT_ID` | OAuth app ID | (required) |
| `GITHUB_CLIENT_SECRET` | OAuth app secret | (required) |
| `SESSION_SECRET` | Cookie signing key | (required) |
| `VEIL_PROXY_URL` | Poke agent target | `http://localhost:8080` |
| `GENKIT_ENV` | Genkit mode | (set to `dev` for Dev UI) |

## 10. What's Novel / Differentiators

1. **Four-stage LLM cascade**: Regex → local 0.6B → Crusoe 8B → Claude. p50 latency ~2ms.
2. **CrowdSec-inspired behavioral analysis**: IP reputation, leaky bucket scenarios, cross-tenant intelligence — features that CrowdSec has but no AI WAF does.
3. **Graduated decisions**: Not just block/allow. Ban, captcha, throttle, log-only, and allow — with configurable durations and scopes.
4. **Genkit Flows**: Each agent is a typed, observable, independently testable function with OpenTelemetry tracing.
5. **Fabric prompt patterns**: Battle-tested prompt structure (39k stars) adapted for security classification.
6. **Self-improving prompts**: The Patch flow updates prompts stored as markdown files and rule versions in the DB.
7. **Go performance**: The reverse proxy, behavioral engine, and regex classifier all run in pure Go with zero network calls for the fast path.

## 11. Existing Worktrees (Reference)

The four prototype worktrees remain available for reference:
- `.worktrees/go-langchaingo` — LangChainGo approach
- `.worktrees/go-genkit` — Genkit approach (Flows, OTel)
- `.worktrees/go-gollm` — GoLLM approach (prompt engineering)
- `.worktrees/go-fabric-hybrid` — Fabric + CrowdSec approach (behavioral engine)

The implementation will create a new worktree merging the best of go-genkit and go-fabric-hybrid.
