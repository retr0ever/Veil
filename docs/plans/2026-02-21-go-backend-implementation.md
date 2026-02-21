# Go Backend Implementation Plan (Merged Genkit + Fabric-Hybrid)

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a Go reverse proxy WAF with four-stage LLM classification, CrowdSec-inspired behavioral analysis, Genkit Flow-based agents, and Fabric-style prompt patterns.

**Architecture:** Merge the `go-fabric-hybrid` scaffold (behavioral engine, CrowdSec features, graduated decisions, Fabric prompts) with `go-genkit` scaffold (Genkit Flows, OpenTelemetry, Ollama plugin). The Go backend lives in `go-backend/` alongside the existing Python backend. Both share the same frontend.

**Tech Stack:** Go 1.23+, Firebase Genkit (Go) v1.4+, Anthropic SDK Go, gorilla/mux, gorilla/websocket, go-sqlite3, Ollama (sidecar), Crusoe Inference API

**Worktree:** `.worktrees/go-merged` (branch: `go-merged`)

**Reference scaffolds:**
- `.worktrees/go-genkit/go-backend/` — Genkit Flow patterns, correct API signatures
- `.worktrees/go-fabric-hybrid/go-backend/` — Behavioral engine, decisions, prompts

---

## Phase 1: Foundation (Database + Config + HTTP Server)

### Task 1: Initialize Go module and dependencies

**Files:**
- Create: `go-backend/go.mod`
- Create: `go-backend/go.sum` (via `go mod tidy`)

**Step 1: Create go.mod**

```
cd .worktrees/go-merged && mkdir -p go-backend && cd go-backend
go mod init github.com/veil-waf/veil-go
```

**Step 2: Add dependencies**

```
go get github.com/firebase/genkit/go@v1.4.0
go get github.com/firebase/genkit/go/plugins/ollama
go get github.com/anthropics/anthropic-sdk-go@latest
go get github.com/gorilla/mux@v1.8.1
go get github.com/gorilla/websocket@v1.5.3
go get github.com/mattn/go-sqlite3@v1.14.24
go get golang.org/x/oauth2@latest
go get gopkg.in/yaml.v3@latest
go mod tidy
```

**Step 3: Commit**

```
git add go-backend/go.mod go-backend/go.sum
git commit -m "feat: initialize Go module with Genkit, Anthropic SDK, and deps"
```

---

### Task 2: Database layer (10 tables)

**Files:**
- Create: `go-backend/internal/db/database.go`

**Reference:** Copy from `.worktrees/go-fabric-hybrid/go-backend/internal/db/database.go` (10-table schema) but update Anthropic SDK types to match `.worktrees/go-genkit/go-backend/internal/db/database.go` (correct v1.19+ SDK).

**What it must have:**
- `Init()` — create all 10 tables (users, sites, threats, request_log, agent_log, rules, decisions, ip_reputation, behavioral_sessions, endpoint_profiles)
- `Close()` — close DB
- PRAGMA: `journal_mode=WAL`, `busy_timeout=15000`
- CRUD functions for all tables (see fabric-hybrid scaffold for complete list)
- Seed initial rules with default prompts
- `MaxOpenConns(1)` for SQLite safety

**Step 1: Write database.go**

Copy the database.go from go-fabric-hybrid, which has all 10 tables and full CRUD. Verify it compiles standalone.

**Step 2: Build check**

```
cd .worktrees/go-merged/go-backend && go build ./internal/db/
```

**Step 3: Commit**

```
git add go-backend/internal/db/
git commit -m "feat: add SQLite database layer with 10 tables (6 core + 4 behavioral)"
```

---

### Task 3: Shared types

**Files:**
- Create: `go-backend/internal/classifier/types.go`

**Step 1: Write types.go**

```go
package classifier

type ClassifyInput struct {
    RawRequest string `json:"raw_request"`
    SourceIP   string `json:"source_ip"`
    Path       string `json:"path"`
    Method     string `json:"method"`
    SiteID     string `json:"site_id"`
}

type Classification struct {
    ClassificationLabel string  `json:"classification"` // SAFE, SUSPICIOUS, MALICIOUS
    Confidence          float64 `json:"confidence"`
    AttackType          string  `json:"attack_type"`
    Reason              string  `json:"reason"`
    Classifier          string  `json:"classifier"` // regex, llm_fast, crusoe, claude
    ResponseTimeMs      float64 `json:"response_time_ms"`
    Blocked             bool    `json:"blocked"`
}
```

**Step 2: Commit**

```
git add go-backend/internal/classifier/types.go
git commit -m "feat: add shared classification types"
```

---

### Task 4: Regex classifier (Stage 1)

**Files:**
- Create: `go-backend/internal/classifier/regex.go`

**Reference:** `.worktrees/go-genkit/go-backend/internal/classifier/regex.go` (all 9 categories, compiled patterns)

**What it must have:**
- 9 attack categories: sqli, xss, path_traversal, command_injection, ssrf, xxe, header_injection, auth_bypass, encoding_evasion
- Patterns compiled at `init()` via `regexp.MustCompile`
- Double URL-decode input before matching
- Multiple matches increase confidence (+3% per additional hit)
- Return SAFE (0.85 confidence) if no matches
- `Classify(rawRequest string) *Classification`

**Step 1: Write regex.go**

Copy from go-genkit scaffold — it has the exact same patterns as the Python backend.

**Step 2: Build check**

```
go build ./internal/classifier/
```

**Step 3: Commit**

```
git add go-backend/internal/classifier/regex.go
git commit -m "feat: add regex classifier with 9 attack categories"
```

---

### Task 5: Rate limiter

**Files:**
- Create: `go-backend/internal/ratelimit/limiter.go`

**Reference:** `.worktrees/go-genkit/go-backend/internal/ratelimit/limiter.go`

**What it must have:**
- Per-IP sliding window
- 4 buckets: classify (30/min), proxy (60/min), auth (10/min), api (60/min)
- `Wrap(bucket string, handler http.HandlerFunc) http.HandlerFunc` middleware
- Background cleanup goroutine (every 5 min)
- Return 429 with `Retry-After` header when exceeded

**Step 1: Write limiter.go**

Copy from go-genkit scaffold.

**Step 2: Commit**

```
git add go-backend/internal/ratelimit/
git commit -m "feat: add per-IP sliding window rate limiter"
```

---

### Task 6: WebSocket hub

**Files:**
- Create: `go-backend/internal/ws/hub.go`

**Reference:** `.worktrees/go-genkit/go-backend/internal/ws/hub.go`

**What it must have:**
- `Hub` struct with clients map, broadcast channel, register/unregister channels
- `Run()` goroutine for event loop
- `Broadcast(msgType string, data any)` — sends `{"type": "request"|"agent"|"stats", ...}` to all clients
- `HandleWebSocket(w, r)` — upgrade connection, register, read pump
- Hydration on connect: send recent stats, requests, agent logs
- Thread-safe with `sync.RWMutex`

**Step 1: Write hub.go**

Copy from go-genkit scaffold.

**Step 2: Commit**

```
git add go-backend/internal/ws/
git commit -m "feat: add WebSocket hub for real-time dashboard"
```

---

### Task 7: GitHub OAuth

**Files:**
- Create: `go-backend/internal/auth/github.go`

**Reference:** `.worktrees/go-genkit/go-backend/internal/auth/github.go`

**What it must have:**
- `BeginGitHubOAuth(w, r)` — redirect to GitHub authorize
- `GitHubCallback(w, r)` — exchange code for token, fetch profile, upsert user, set cookie
- `Me(w, r)` — return current user from session cookie
- `Logout(w, r)` — clear cookie
- `RequireAuth(handler) http.HandlerFunc` — middleware
- HMAC-SHA256 signed session cookies with expiry

**Step 1: Write github.go**

Copy from go-genkit scaffold.

**Step 2: Commit**

```
git add go-backend/internal/auth/
git commit -m "feat: add GitHub OAuth with signed session cookies"
```

---

## Phase 2: Behavioral Engine (CrowdSec-inspired)

### Task 8: Behavioral analysis engine

**Files:**
- Create: `go-backend/internal/behavioral/engine.go`

**Reference:** `.worktrees/go-fabric-hybrid/go-backend/internal/behavioral/engine.go`

**What it must have:**
- `BehavioralEngine` struct with:
  - `ipReputation map[string]*IPReputation` (in-memory, synced to DB)
  - `sessions map[string]*SessionTracker` (per-IP behavioral tracking)
  - `scannerPaths map[string]bool` (known scanner paths)
- `IPReputation` struct: Score, AttackCount, TenantCount, AttackTypes, FirstSeen, LastSeen, IsTor, IsVPN
- `SessionTracker` struct: RequestCount, ErrorCount, UniquePaths, AuthFailures, AvgIntervalMs, Flags
- `CheckIP(ip string) *IPReputation` — lookup reputation
- `RecordRequest(ip, path, siteID string)` — update session tracking
- `RecordAttack(ip, attackType, siteID string)` — update reputation score
- `RecordResponseFeedback(ip string, statusCode int)` — update error counts
- 6 leaky bucket scenarios (credential stuffing, enumeration, scanner fingerprint, rate anomaly, path fuzzing, error storm)
- Time-decay on reputation scores
- `PersistToDB()` / `LoadFromDB()` for durability

**Step 1: Write engine.go**

Copy from go-fabric-hybrid scaffold.

**Step 2: Build check**

```
go build ./internal/behavioral/
```

**Step 3: Commit**

```
git add go-backend/internal/behavioral/engine.go
git commit -m "feat: add CrowdSec-inspired behavioral analysis engine"
```

---

### Task 9: Graduated decision system

**Files:**
- Create: `go-backend/internal/behavioral/decisions.go`

**Reference:** `.worktrees/go-fabric-hybrid/go-backend/internal/behavioral/decisions.go`

**What it must have:**
- `DecisionType` enum: Allow, LogOnly, Throttle, Captcha, Ban
- `Decision` struct: Type, Scope (ip/session/fingerprint), Duration, Reason, Source, Confidence
- `MakeDecision(classification *Classification, behavioral *BehavioralContext) *Decision` — combine AI classification with behavioral signals into a graduated response
- `Escalate(current Decision) Decision` — escalate a decision
- `MergeDecisions(decisions []Decision) Decision` — take the most severe
- Integration with DB decisions table (active decisions, expiry checking)

**Step 1: Write decisions.go**

Copy from go-fabric-hybrid scaffold.

**Step 2: Commit**

```
git add go-backend/internal/behavioral/decisions.go
git commit -m "feat: add graduated decision system (5-level responses)"
```

---

## Phase 3: LLM Classification (Stages 2-4)

### Task 10: Fast model classifier (Genkit + Ollama)

**Files:**
- Create: `go-backend/internal/classifier/fast_model.go`

**Reference:** `.worktrees/go-genkit/go-backend/internal/classifier/fast_model.go` (correct Genkit API)

**What it must have:**
- Use Genkit's Ollama plugin: `ollamaPlugin.DefineModel(g, ...)`
- `genkit.Generate(ctx, g, ai.WithModel(model), ai.WithSystem(systemPrompt), ai.WithPrompt(rawRequest))`
- Load system prompt from `prompts/classify_request.md` at startup
- Parse JSON response, fallback to extracting JSON from markdown
- Return SUSPICIOUS (0.5) if Ollama unavailable
- Model configurable via `OLLAMA_MODEL` env var (default: `qwen3:0.6b`)

**Step 1: Write fast_model.go**

Adapt from go-genkit scaffold, adding prompt file loading.

**Step 2: Commit**

```
git add go-backend/internal/classifier/fast_model.go
git commit -m "feat: add Genkit + Ollama fast model classifier (Stage 2)"
```

---

### Task 11: Crusoe API classifier (Stage 3)

**Files:**
- Create: `go-backend/internal/classifier/crusoe.go`

**This is new code — not in any existing scaffold.** Port from `backend/services/crusoe_classifier.py`.

**What it must have:**
- `CrusoeClassifier` struct with apiKey, apiURL, model, http.Client (15s timeout)
- OpenAI-compatible POST to `https://inference.crusoe.ai/v1/chat/completions`
- Request body: `{"model": "meta-llama/Meta-Llama-3.1-8B-Instruct", "messages": [...], "temperature": 0.0, "max_tokens": 200}`
- Load system prompt from `prompts/classify_request.md` (same as fast model but Crusoe is smarter)
- Parse JSON response, fallback to SUSPICIOUS
- Auth: `Authorization: Bearer <CRUSOE_API_KEY>`

```go
type CrusoeClassifier struct {
    apiKey string
    apiURL string
    model  string
    client *http.Client
}

func NewCrusoeClassifier() *CrusoeClassifier {
    return &CrusoeClassifier{
        apiKey: os.Getenv("CRUSOE_API_KEY"),
        apiURL: envOr("CRUSOE_API_URL", "https://inference.crusoe.ai/v1"),
        model:  envOr("CRUSOE_MODEL", "meta-llama/Meta-Llama-3.1-8B-Instruct"),
        client: &http.Client{Timeout: 15 * time.Second},
    }
}

func (c *CrusoeClassifier) Classify(ctx context.Context, rawRequest, systemPrompt string) *Classification {
    // POST to c.apiURL + "/chat/completions"
    // Parse response.choices[0].message.content as JSON
}
```

**Step 1: Write crusoe.go**

**Step 2: Build check**

```
go build ./internal/classifier/
```

**Step 3: Commit**

```
git add go-backend/internal/classifier/crusoe.go
git commit -m "feat: add Crusoe API classifier for Llama 3.1 8B (Stage 3)"
```

---

### Task 12: Claude deep classifier (Stage 4)

**Files:**
- Create: `go-backend/internal/classifier/deep_model.go`

**Reference:** `.worktrees/go-genkit/go-backend/internal/classifier/deep_model.go` (correct Anthropic SDK v1.19+ API)

**What it must have:**
- `ClaudeClassifier` struct with `*anthropic.Client` and model string
- Init with `bedrock.WithLoadDefaultConfig(ctx, config.WithRegion(region))`
- `Classify(ctx, rawRequest, systemPrompt string) *Classification`
- Load system prompt from `prompts/deep_analysis.md`
- temperature: 0.0, no extended thinking, max_tokens: 300
- Parse `message.Content` blocks, extract text, parse JSON

**Step 1: Write deep_model.go**

Adapt from go-genkit scaffold (it has the correct API signatures already verified).

**Step 2: Commit**

```
git add go-backend/internal/classifier/deep_model.go
git commit -m "feat: add Claude via Bedrock deep classifier (Stage 4)"
```

---

### Task 13: Four-stage classification pipeline

**Files:**
- Create: `go-backend/internal/classifier/pipeline.go`

**This combines behavioral pre-filtering + four LLM stages:**

```go
func (p *Pipeline) Classify(ctx context.Context, input ClassifyInput) *Classification {
    // Pre-filter: check active decisions (bans, throttles)
    // Pre-filter: IP reputation (score > 0.9 → immediate block)

    // Stage 1: Regex (~1ms)
    result := p.regex.Classify(input.RawRequest)
    if result.ClassificationLabel != "SUSPICIOUS" {
        return result // SAFE or MALICIOUS — done
    }

    // Stage 2: Fast LLM via Ollama (~15-40ms)
    if p.fastModel != nil {
        result = p.fastModel.Classify(ctx, input.RawRequest, p.fastPrompt)
        if result.ClassificationLabel != "SUSPICIOUS" {
            return result
        }
    }

    // Stage 3: Crusoe API (~50-150ms)
    if p.crusoe != nil && p.crusoe.Available() {
        result = p.crusoe.Classify(ctx, input.RawRequest, p.fastPrompt)
        if result.ClassificationLabel != "SUSPICIOUS" {
            return result
        }
    }

    // Stage 4: Claude via Bedrock (~500ms-1s)
    if p.claude != nil {
        result = p.claude.Classify(ctx, input.RawRequest, p.deepPrompt)
    }

    return result
}
```

**Step 1: Write pipeline.go**

**Step 2: Build check**

```
go build ./internal/classifier/
```

**Step 3: Commit**

```
git add go-backend/internal/classifier/pipeline.go
git commit -m "feat: add four-stage classification pipeline"
```

---

## Phase 4: Fabric Prompt Patterns

### Task 14: Create prompt files

**Files:**
- Create: `go-backend/prompts/classify_request.md`
- Create: `go-backend/prompts/deep_analysis.md`
- Create: `go-backend/prompts/peek_discover.md`
- Create: `go-backend/prompts/patch_update.md`
- Create: `go-backend/prompts/analyze_bypass.md`

**Reference:** `.worktrees/go-fabric-hybrid/go-backend/prompts/` (all 5 files exist)

**Step 1: Copy all 5 prompt files from go-fabric-hybrid**

**Step 2: Commit**

```
git add go-backend/prompts/
git commit -m "feat: add Fabric-style prompt patterns for classification and agents"
```

---

## Phase 5: Agent Flows (Genkit)

### Task 15: Agent types and flow registration

**Files:**
- Create: `go-backend/internal/agents/types.go`

**Reference:** `.worktrees/go-genkit/go-backend/internal/agents/types.go`

**What it must have:**
- `PeekInput`, `PeekOutput` — input/output for discovery flow
- `PokeInput`, `PokeOutput`, `BypassResult` — for red-team flow
- `PatchInput`, `PatchOutput` — for rule update flow
- `BehavioralOutput` — for behavioral update flow
- `Flows` struct holding all `*core.Flow` references

**Step 1: Write types.go**

**Step 2: Commit**

```
git add go-backend/internal/agents/types.go
git commit -m "feat: add agent flow types"
```

---

### Task 16: Peek agent (Genkit Flow)

**Files:**
- Create: `go-backend/internal/agents/peek.go`

**Reference:** `.worktrees/go-genkit/go-backend/internal/agents/peek.go` (Genkit Flow pattern) + `.worktrees/go-fabric-hybrid/go-backend/internal/agents/peek.go` (Fabric prompt loading)

**What it must have:**
- `genkit.DefineFlow(g, "peek-discover", func(ctx, input) (*PeekOutput, error) { ... })`
- Seed 16 attack techniques on first run
- Load prompt from `prompts/peek_discover.md`
- Call Claude via Bedrock to generate 3 novel attack variations
- Fallback: call Ollama via Genkit if Claude unavailable
- Insert new threats into DB
- Log activity to agent_log

**Step 1: Write peek.go**

Merge the Genkit Flow structure from go-genkit with the Fabric prompt loading from go-fabric-hybrid.

**Step 2: Commit**

```
git add go-backend/internal/agents/peek.go
git commit -m "feat: add Peek agent as Genkit Flow with Fabric prompts"
```

---

### Task 17: Poke agent (Genkit Flow)

**Files:**
- Create: `go-backend/internal/agents/poke.go`

**Reference:** `.worktrees/go-genkit/go-backend/internal/agents/poke.go`

**What it must have:**
- `genkit.DefineFlow(g, "poke-redteam", ...)`
- Query untested/unblocked threats from DB
- POST each payload to `http://localhost:8080/v1/classify`
- Record blocked/bypassed status
- Return `[]BypassResult` for Patch

**Step 1: Write poke.go**

**Step 2: Commit**

```
git add go-backend/internal/agents/poke.go
git commit -m "feat: add Poke red-team agent as Genkit Flow"
```

---

### Task 18: Patch agent (Genkit Flow)

**Files:**
- Create: `go-backend/internal/agents/patch.go`

**Reference:** `.worktrees/go-genkit/go-backend/internal/agents/patch.go` + `.worktrees/go-fabric-hybrid/go-backend/internal/agents/patch.go` (Fabric prompt)

**What it must have:**
- `genkit.DefineFlow(g, "patch-update", ...)`
- Load prompt from `prompts/patch_update.md`
- If bypasses exist: call Claude to analyze and generate updated prompts
- Heuristic fallback if no API key (same as Python backend)
- Create new rule version in DB
- Mark bypasses as patched

**Step 1: Write patch.go**

**Step 2: Commit**

```
git add go-backend/internal/agents/patch.go
git commit -m "feat: add Patch agent as Genkit Flow with Fabric prompts"
```

---

### Task 19: Agent loop orchestration

**Files:**
- Create: `go-backend/internal/agents/loop.go`

**Reference:** `.worktrees/go-genkit/go-backend/internal/agents/loop.go`

**What it must have:**
- `RegisterFlows(g *genkit.Genkit) *Flows` — register all flows, return struct
- `RunLoop(ctx, flows, hub, behavioral)` — background goroutine
- Peek → 2s pause → Poke → 2s pause → Patch → BehavioralUpdate → 30s pause
- Broadcast status updates via WebSocket
- Panic recovery
- Context cancellation support

**Step 1: Write loop.go**

**Step 2: Commit**

```
git add go-backend/internal/agents/loop.go
git commit -m "feat: add agent loop orchestration with behavioral update"
```

---

## Phase 6: Reverse Proxy + HTTP Server

### Task 20: Enhanced reverse proxy

**Files:**
- Create: `go-backend/internal/proxy/proxy.go`

**Reference:** `.worktrees/go-fabric-hybrid/go-backend/internal/proxy/proxy.go` (six-step pipeline) adapted to use Genkit classify flow

**What it must have:**
- `NewHandler(classifyFlow, hub, behavioral, db)` constructor
- `Handle(w, r)` — the six-step pipeline:
  1. Rate limit check
  2. IP reputation check → preemptive block if score > 0.9
  3. Behavioral analysis → check leaky bucket scenarios
  4. Run classification flow (regex → fast LLM → Crusoe → Claude)
  5. Decision engine (combine classification + behavioral into graduated response)
  6. Block (403) or forward (reverse proxy to origin)
- Record response feedback to behavioral engine (status code)
- Log to request_log table
- Broadcast via WebSocket
- Header filtering (same as Python: exclude host, connection, transfer-encoding)
- 30s timeout on origin requests

**Step 1: Write proxy.go**

**Step 2: Commit**

```
git add go-backend/internal/proxy/proxy.go
git commit -m "feat: add enhanced reverse proxy with six-step classification pipeline"
```

---

### Task 21: Main server + API handlers

**Files:**
- Create: `go-backend/main.go`
- Create: `go-backend/handlers.go`

**Reference:** `.worktrees/go-genkit/go-backend/main.go` + `.worktrees/go-genkit/go-backend/handlers.go`

**What main.go must have:**
- Initialize Genkit with Ollama plugin: `genkit.Init(ctx, genkit.WithPlugins(&ollama.Ollama{...}))`
- Initialize DB, behavioral engine, WebSocket hub, rate limiter
- Register Genkit Flows (classify, peek, poke, patch, behavioral)
- Create classification pipeline (regex + fast + crusoe + claude)
- Mount all routes on gorilla/mux
- Start background agent loop
- Graceful shutdown via signal handling
- CORS middleware

**What handlers.go must have:**
- `/api/stats` — global statistics
- `/api/threats` — list discovered techniques
- `/api/agents` — recent agent activity
- `/api/requests` — recent classified requests
- `/api/rules` — rule version history
- `/api/sites` POST/GET — create/list sites (auth required)
- `/api/agents/peek/run` — manual trigger
- `/api/agents/poke/run` — manual trigger
- `/api/agents/cycle` — full cycle trigger
- `/v1/classify` POST — classification endpoint (used by Poke + external)
- `/api/intelligence/ip/{ip}` — IP reputation lookup (new, from CrowdSec)
- `/api/decisions/active` — active graduated decisions (new)

**Step 1: Write main.go and handlers.go**

Merge patterns from go-genkit (correct Genkit init) and go-fabric-hybrid (extra API endpoints).

**Step 2: Build full project**

```
cd .worktrees/go-merged/go-backend && go build ./...
```

**Step 3: Run go vet**

```
go vet ./...
```

**Step 4: Commit**

```
git add go-backend/main.go go-backend/handlers.go
git commit -m "feat: add HTTP server with all API endpoints and Genkit initialization"
```

---

## Phase 7: Integration Testing

### Task 22: Verify full build

**Step 1: Full build**

```
cd .worktrees/go-merged/go-backend && go build -o veil-go ./...
```

Expected: clean build, binary produced.

**Step 2: Go vet**

```
go vet ./...
```

Expected: no warnings.

**Step 3: Test startup (will fail without env vars but should not panic)**

```
LISTEN_ADDR=:0 timeout 3 ./veil-go 2>&1 || true
```

Expected: should log initialization messages, may fail on DB init or missing env vars but no panics.

**Step 4: Commit any fixes**

---

### Task 23: Add APPROACH.md

**Files:**
- Create: `go-backend/APPROACH.md`

Document the merged approach: Genkit Flows + Fabric prompts + CrowdSec behavioral + four-stage cascade. Reference both source scaffolds.

**Step 1: Write APPROACH.md**

**Step 2: Final commit**

```
git add go-backend/APPROACH.md
git commit -m "docs: add approach documentation for merged Go backend"
```

---

## Phase 8: CrowdSec Hub Integration

### Task 24: CrowdSec Hub types

**Files:**
- Create: `go-backend/internal/crowdsec/types.go`

**What it must have:**

```go
package crowdsec

import "time"

// Scenario represents a CrowdSec leaky bucket scenario
type Scenario struct {
    Type        string            `yaml:"type"`        // leaky, trigger, conditional
    Name        string            `yaml:"name"`        // author/name
    Description string            `yaml:"description"`
    Filter      string            `yaml:"filter"`      // CrowdSec expr (we extract hints from this)
    GroupBy     string            `yaml:"groupby"`
    Capacity    int               `yaml:"capacity"`
    LeakSpeed   string            `yaml:"leakspeed"`   // "10s", "0.5s"
    Blackhole   string            `yaml:"blackhole"`   // "5m", "1m"
    Distinct    string            `yaml:"distinct"`
    CacheSize   int               `yaml:"cache_size"`
    Reprocess   bool              `yaml:"reprocess"`
    Debug       bool              `yaml:"debug"`
    Format      string            `yaml:"format"`
    Labels      Labels            `yaml:"labels"`
    Data        []DataSource      `yaml:"data"`
    References  []string          `yaml:"references"`
}

// AppSecRule represents a CrowdSec WAF-style rule
type AppSecRule struct {
    Name        string   `yaml:"name"`
    Description string   `yaml:"description"`
    Rules       []Rule   `yaml:"rules"`
    Labels      Labels   `yaml:"labels"`
}

// Rule is a single matching block (may contain AND conditions)
type Rule struct {
    And       []Condition `yaml:"and"`       // compound AND conditions
    Zones     []string    `yaml:"zones"`     // simple single condition
    Transform []string    `yaml:"transform"`
    Match     *Match      `yaml:"match"`
    Variables []string    `yaml:"variables"`
}

// Condition is a single zone/match/transform condition within an AND block
type Condition struct {
    Zones     []string `yaml:"zones"`
    Transform []string `yaml:"transform"`
    Match     Match    `yaml:"match"`
    Variables []string `yaml:"variables"`
}

type Match struct {
    Type  string `yaml:"type"`  // equals, contains, endsWith, startsWith, regex
    Value string `yaml:"value"`
}

// Collection bundles scenarios, appsec-rules, and other collections
type Collection struct {
    Name          string   `yaml:"name"`
    Description   string   `yaml:"description"`
    Author        string   `yaml:"author"`
    Tags          []string `yaml:"tags"`
    Parsers       []string `yaml:"parsers"`
    Scenarios     []string `yaml:"scenarios"`
    Collections   []string `yaml:"collections"`
    AppSecRules   []string `yaml:"appsec-rules"`
    AppSecConfigs []string `yaml:"appsec-configs"`
    Contexts      []string `yaml:"contexts"`
}

// AppSecConfig ties AppSec rules together with remediation policy
type AppSecConfig struct {
    Name               string   `yaml:"name"`
    DefaultRemediation string   `yaml:"default_remediation"` // ban, captcha, log
    InbandRules        []string `yaml:"inband_rules"`        // glob patterns
    OutofbandRules     []string `yaml:"outofband_rules"`
}

type Labels struct {
    Remediation    bool     `yaml:"remediation"`
    Confidence     int      `yaml:"confidence"`
    Spoofable      int      `yaml:"spoofable"`
    Classification []string `yaml:"classification"` // MITRE ATT&CK, CVE, CWE
    Behavior       string   `yaml:"behavior"`       // http:crawl, http:exploit, etc.
    Service        string   `yaml:"service"`
    Label          string   `yaml:"label"`
    Type           string   `yaml:"type"`           // exploit, scan, bruteforce
}

type DataSource struct {
    SourceURL string `yaml:"source_url"`
    DestFile  string `yaml:"dest_file"`
    Type      string `yaml:"type"` // string, regex
}

// HubIndex represents the .index.json top-level structure
type HubIndex struct {
    AppSecConfigs map[string]HubItem `json:"appsec-configs"`
    AppSecRules   map[string]HubItem `json:"appsec-rules"`
    Collections   map[string]HubItem `json:"collections"`
    Contexts      map[string]HubItem `json:"contexts"`
    Parsers       map[string]HubItem `json:"parsers"`
    Postoverflows map[string]HubItem `json:"postoverflows"`
    Scenarios     map[string]HubItem `json:"scenarios"`
}

type HubItem struct {
    Author      string            `json:"author"`
    Content     string            `json:"content"` // base64-encoded YAML
    Description string            `json:"description"`
    Labels      map[string]any    `json:"labels"`
    Path        string            `json:"path"`
    Version     string            `json:"version"`
    Versions    map[string]HubVer `json:"versions"`
}

type HubVer struct {
    Deprecated bool   `json:"deprecated"`
    Digest     string `json:"digest"`
}

// VeilMatcher is the converted form used by Veil's classification pipeline
type VeilMatcher struct {
    HubName   string   // source CrowdSec rule name
    Zone      string   // uri, uri_full, headers, args, body, method, filenames
    Variable  string   // specific header/arg name (empty for whole zone)
    Transform []string // lowercase, urldecode, b64decode
    MatchType string   // equals, contains, endsWith, startsWith, regex
    Value     string
}

// VeilScenarioConfig is the converted behavioral scenario config
type VeilScenarioConfig struct {
    HubName     string
    Description string
    Capacity    int
    LeakSpeed   time.Duration
    Blackhole   time.Duration
    Behavior    string
    Service     string
    Remediation bool
    Confidence  int
}
```

**Step 1: Write types.go**

**Step 2: Build check**

```
go build ./internal/crowdsec/
```

**Step 3: Commit**

```
git add go-backend/internal/crowdsec/types.go
git commit -m "feat: add CrowdSec Hub YAML type definitions"
```

---

### Task 25: Hub client (fetch and cache .index.json)

**Files:**
- Create: `go-backend/internal/crowdsec/hub.go`

**What it must have:**

- `HubClient` struct with `http.Client`, index cache, cache TTL (1 hour default)
- `NewHubClient()` — constructor, configurable index URL via `CROWDSEC_HUB_URL` env var (default: `https://raw.githubusercontent.com/crowdsecurity/hub/master/.index.json`)
- `FetchIndex(ctx) (*HubIndex, error)` — download and parse .index.json, cache in memory
- `GetAppSecRule(name string) (*AppSecRule, error)` — decode base64 content, parse YAML
- `GetScenario(name string) (*Scenario, error)` — decode base64 content, parse YAML (handle multi-document YAML with `---` separators)
- `GetCollection(name string) (*Collection, error)` — decode base64 content, parse YAML
- `ResolveCollection(name string) (rules []AppSecRule, scenarios []Scenario, error)` — recursively resolve a collection, following nested collection references, returning all leaf AppSec rules and scenarios
- `ListCollections() []string` — list all available collection names
- `SearchCollections(tags []string) []Collection` — find collections by tag (http, wordpress, nginx, etc.)
- Thread-safe with `sync.RWMutex` on the cache

```go
type HubClient struct {
    indexURL   string
    client     *http.Client
    mu         sync.RWMutex
    index      *HubIndex
    lastFetch  time.Time
    cacheTTL   time.Duration
}

func NewHubClient() *HubClient {
    return &HubClient{
        indexURL: envOr("CROWDSEC_HUB_URL",
            "https://raw.githubusercontent.com/crowdsecurity/hub/master/.index.json"),
        client:   &http.Client{Timeout: 30 * time.Second},
        cacheTTL: 1 * time.Hour,
    }
}
```

**Step 1: Write hub.go**

**Step 2: Build check**

```
go build ./internal/crowdsec/
```

**Step 3: Commit**

```
git add go-backend/internal/crowdsec/hub.go
git commit -m "feat: add CrowdSec Hub client with .index.json caching"
```

---

### Task 26: Rule converter (CrowdSec → Veil matchers)

**Files:**
- Create: `go-backend/internal/crowdsec/converter.go`
- Create: `go-backend/internal/crowdsec/matcher.go`

**converter.go must have:**

- `ConvertAppSecRule(rule *AppSecRule) []VeilMatcher` — convert a CrowdSec AppSec rule into Veil matchers
  - Each condition becomes a `VeilMatcher`
  - AND conditions are grouped (returned as a slice that must all match)
  - Map zones: URI→uri, URI_FULL→uri_full, HEADERS→headers, ARGS→args, BODY→body, METHOD→method, FILENAMES→filenames
  - Map transforms: lowercase, uppercase, urldecode, b64decode
  - Map match types: equals, contains, endsWith, startsWith, regex
- `ConvertScenario(scenario *Scenario) (*VeilScenarioConfig, error)` — convert CrowdSec scenario to behavioral config
  - Parse `leakspeed` duration string ("10s", "0.5s")
  - Parse `blackhole` duration string ("5m", "1m")
  - Extract behavior and service from labels

**matcher.go must have:**

- `EvalMatcher(m *VeilMatcher, req *http.Request) bool` — evaluate a single matcher against an HTTP request
  - Extract the target zone from the request (path, headers, query, body, method)
  - Apply transforms in order
  - Apply match type comparison
- `EvalMatcherGroup(matchers []VeilMatcher, req *http.Request) bool` — evaluate AND group (all must match)
- `EvalAppSecRule(matchers [][]VeilMatcher, req *http.Request) bool` — evaluate full rule (OR of AND groups)

```go
func EvalMatcher(m *VeilMatcher, req *http.Request) bool {
    value := extractZone(m.Zone, m.Variable, req)
    for _, t := range m.Transform {
        value = applyTransform(t, value)
    }
    switch m.MatchType {
    case "equals":
        return value == m.Value
    case "contains":
        return strings.Contains(value, m.Value)
    case "endsWith":
        return strings.HasSuffix(value, m.Value)
    case "startsWith":
        return strings.HasPrefix(value, m.Value)
    case "regex":
        // pre-compiled regex stored elsewhere
    }
    return false
}

func extractZone(zone, variable string, req *http.Request) string {
    switch zone {
    case "uri":
        return req.URL.Path
    case "uri_full":
        return req.URL.RequestURI()
    case "method":
        return req.Method
    case "headers":
        return req.Header.Get(variable)
    case "args":
        return req.URL.Query().Get(variable)
    case "body":
        // read and cache body
    }
    return ""
}
```

**Step 1: Write converter.go and matcher.go**

**Step 2: Build check**

```
go build ./internal/crowdsec/
```

**Step 3: Commit**

```
git add go-backend/internal/crowdsec/converter.go go-backend/internal/crowdsec/matcher.go
git commit -m "feat: add CrowdSec-to-Veil rule converter and matcher engine"
```

---

### Task 27: Hub rules database table + CRUD

**Files:**
- Modify: `go-backend/internal/db/database.go`

**What to add:**

New table `hub_rules` in the `Init()` function:

```sql
CREATE TABLE IF NOT EXISTS hub_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hub_name TEXT NOT NULL UNIQUE,
    hub_type TEXT NOT NULL,
    version TEXT,
    yaml_content TEXT,
    imported_at TEXT DEFAULT (datetime('now')),
    site_id TEXT,
    active BOOLEAN DEFAULT 1
)
```

New CRUD functions:
- `InsertHubRule(hubName, hubType, version, yamlContent, siteID string) error`
- `GetActiveHubRules(hubType string) ([]HubRuleRow, error)` — get all active rules of a type
- `GetHubRule(hubName string) (*HubRuleRow, error)` — get by name
- `DeactivateHubRule(hubName string) error`
- `IsHubRuleImported(hubName string) bool` — check if already imported (avoid re-importing)

```go
type HubRuleRow struct {
    ID          int
    HubName     string
    HubType     string
    Version     string
    YAMLContent string
    ImportedAt  string
    SiteID      string
    Active      bool
}
```

**Step 1: Add table creation to Init()**

**Step 2: Add CRUD functions**

**Step 3: Build check**

```
go build ./internal/db/
```

**Step 4: Commit**

```
git add go-backend/internal/db/database.go
git commit -m "feat: add hub_rules table for CrowdSec Hub imports"
```

---

### Task 28: Learn agent (Genkit Flow)

**Files:**
- Create: `go-backend/internal/agents/learn.go`

**What it must have:**

- `genkit.DefineFlow(g, "learn-hub", func(ctx, input LearnInput) (*LearnOutput, error) { ... })`
- `LearnInput` struct: SiteID, RecentPaths []string (paths seen in last 5 min)
- `LearnOutput` struct: ImportedRules int, ImportedScenarios int, DetectedAppType string

**Flow logic:**

1. **Detect app type** from recent request paths:
   - `/wp-admin`, `/wp-login.php`, `/wp-content` → WordPress
   - `/administrator`, `/components/com_` → Joomla
   - `/vendor/`, `/artisan` → Laravel
   - `/admin/`, `/static/admin/` → Django
   - `/confluence/`, `/jira/` → Atlassian
   - Generic fallback: use `crowdsecurity/appsec-virtual-patching` (covers CVE vpatches)
2. **Select collections** from Hub index based on detected type + always include base HTTP scenarios
3. **Resolve collections** recursively to get leaf AppSec rules and scenarios
4. **Skip already-imported rules** (check `hub_rules` table)
5. **Convert and store** new rules:
   - AppSec rules → `VeilMatcher` groups, stored in DB as `hub_rules`
   - Scenarios → `VeilScenarioConfig`, stored in DB as `hub_rules`
6. **Hot-reload** — call `pipeline.ReloadHubRules()` to inject new matchers into the running regex classifier
7. **Log** to agent_log table and broadcast via WebSocket

```go
type LearnInput struct {
    SiteID      string   `json:"site_id"`
    RecentPaths []string `json:"recent_paths"`
}

type LearnOutput struct {
    ImportedRules     int    `json:"imported_rules"`
    ImportedScenarios int    `json:"imported_scenarios"`
    DetectedAppType   string `json:"detected_app_type"`
    CollectionsUsed   []string `json:"collections_used"`
}
```

**Step 1: Write learn.go**

**Step 2: Build check**

```
go build ./internal/agents/
```

**Step 3: Commit**

```
git add go-backend/internal/agents/learn.go
git commit -m "feat: add Learn agent for dynamic CrowdSec Hub rule import"
```

---

### Task 29: Integrate Hub matchers into classification pipeline

**Files:**
- Modify: `go-backend/internal/classifier/pipeline.go`
- Modify: `go-backend/internal/agents/loop.go`

**pipeline.go changes:**

- Add `hubMatchers [][]VeilMatcher` field to Pipeline struct
- Add `hubScenarios []VeilScenarioConfig` field
- Add `ReloadHubRules(matchers [][]VeilMatcher, scenarios []VeilScenarioConfig)` method (thread-safe with `sync.RWMutex`)
- In `Classify()`, after regex Stage 1 returns SAFE, also check Hub matchers:

```go
// After regex check
if result.ClassificationLabel == "SAFE" {
    // Check CrowdSec Hub matchers (AppSec rules converted to Go matchers)
    if hubResult := p.checkHubMatchers(req); hubResult != nil {
        return hubResult // MALICIOUS with attack_type from Hub rule
    }
}
```

**loop.go changes:**

- Add Learn flow to the agent loop on a slower cadence:
  - Every 5 minutes (vs 30 seconds for Peek/Poke/Patch)
  - Or: every 10th iteration of the main loop
- Pass recent request paths from the request log to the Learn agent
- After Learn completes, call `pipeline.ReloadHubRules()`

**Step 1: Update pipeline.go**

**Step 2: Update loop.go**

**Step 3: Build full project**

```
go build ./...
```

**Step 4: Commit**

```
git add go-backend/internal/classifier/pipeline.go go-backend/internal/agents/loop.go
git commit -m "feat: integrate CrowdSec Hub matchers into classification pipeline"
```

---

### Task 30: Add Hub API endpoints

**Files:**
- Modify: `go-backend/handlers.go`

**New endpoints:**

- `GET /api/hub/collections` — list available CrowdSec Hub collections (from cached index)
- `GET /api/hub/imported` — list imported Hub rules from DB (active rules)
- `POST /api/hub/import` — manually trigger import of a specific collection `{"collection": "crowdsecurity/appsec-wordpress", "site_id": "..."}`
- `DELETE /api/hub/rules/{name}` — deactivate an imported rule
- `POST /api/agents/learn/run` — manually trigger the Learn agent

**Step 1: Add endpoint handlers**

**Step 2: Mount routes in main.go**

**Step 3: Build check**

```
go build ./...
```

**Step 4: Commit**

```
git add go-backend/handlers.go go-backend/main.go
git commit -m "feat: add Hub API endpoints for CrowdSec rule management"
```

---

## Task Dependency Graph

```
Phase 1 (foundation):  [1] → [2] → [3,4,5,6,7] (parallel)
Phase 2 (behavioral):  [8] → [9]
Phase 3 (classifiers): [3] → [10,11,12] (parallel) → [13]
Phase 4 (prompts):     [14] (independent)
Phase 5 (agents):      [2,13,14] → [15] → [16,17,18] (parallel) → [19]
Phase 6 (server):      [all above] → [20] → [21]
Phase 7 (integration): [21] → [22] → [23]
Phase 8 (hub):         [24] → [25] → [26] → [27] → [28] → [29] → [30]
                       [24,25,26] can start after Phase 1 (need only go.mod)
                       [27] depends on Task 2 (database layer)
                       [28] depends on [15] (agent types) + [24,25,26]
                       [29] depends on [13] (pipeline) + [26] (converter)
                       [30] depends on [21] (handlers) + [28] (learn agent)
```

**Parallelizable tasks:**
- Tasks 3,4,5,6,7 can all run in parallel
- Tasks 10,11,12 can all run in parallel
- Tasks 16,17,18 can all run in parallel
- Tasks 24,25,26 can start in parallel with Phase 2-4
- Task 14 (prompts) is fully independent

**Critical path:** 1 → 2 → 3 → 13 → 15 → 19 → 20 → 21 → 22

**Hub integration can be developed in parallel with Phases 2-5**, merging at Phase 6 (server) and Phase 7 (integration).

---

## Key Files to Reference

| File | Where | What |
|------|-------|------|
| `backend/main.py` | Main repo | Python backend (744 lines) — reference for all API behavior |
| `backend/services/regex_classifier.py` | Main repo | Regex patterns to port |
| `backend/services/crusoe_classifier.py` | Main repo | Crusoe API integration to port |
| `backend/services/claude_classifier.py` | Main repo | Claude/Bedrock integration to port |
| `backend/agents/peek.py` | Main repo | Peek agent logic + seed techniques |
| `backend/agents/poke.py` | Main repo | Poke agent logic |
| `backend/agents/patch.py` | Main repo | Patch agent logic |
| `backend/db/database.py` | Main repo | SQLite schema |
| `.worktrees/go-genkit/go-backend/` | Worktree | Correct Genkit API usage |
| `.worktrees/go-fabric-hybrid/go-backend/` | Worktree | Behavioral engine, decisions, prompts |
| `docs/plans/2026-02-21-go-backend-design.md` | Main repo | Approved design doc |
| `SPEC-veil-next.md` | Main repo | Full v2 spec with CrowdSec analysis |
| CrowdSec Hub `.index.json` | [GitHub](https://raw.githubusercontent.com/crowdsecurity/hub/master/.index.json) | Hub index with base64-encoded YAML rules |
| CrowdSec Hub repo | [GitHub](https://github.com/crowdsecurity/hub) | MIT-licensed detection rules, scenarios, AppSec rules |
