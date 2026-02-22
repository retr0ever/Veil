# Real Data Dashboard Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Wire the dashboard pages (Overview, Agents, Threats) to use site-scoped real data from the backend, while keeping the Demo page unchanged with its existing global data behaviour.

**Architecture:** The Go backend already has site-scoped REST endpoints (`/api/sites/{id}/stats`, `/api/sites/{id}/threats`, `/api/sites/{id}/agents`, `/api/sites/{id}/requests`, `/api/sites/{id}/rules`) and a site-scoped SSE streaming endpoint (`/api/stream/events?site_id=X`). The frontend currently uses a global WebSocket (`/ws`) and global REST endpoints (`/api/threats`, `/api/rules`). We will create a new `useSiteData` hook that connects to the SSE endpoint for real-time site-scoped data, and pass `siteId` down to components that currently fetch global data. The Demo page continues to use `useVeilSocket` (global WebSocket) untouched.

**Tech Stack:** React 19, Vite, EventSource API (SSE), Go backend (Chi router, PostgreSQL)

**Design constraint:** Justyna's UI must remain pixel-identical. Zero changes to component markup, CSS classes, colours, layout, or visual behaviour. Only data source wiring changes.

---

## Data Format Mapping

The site-scoped endpoints return DB model structs directly (via `json.Encoder`), while the global WebSocket sends a slightly different format. Key differences the new hook must normalise:

| Field | WebSocket (`useVeilSocket`) | Site-scoped REST/SSE (DB model) |
|-------|----------------------------|----------------------------------|
| Request payload | `message` (truncated) | `raw_request` (full) |
| Request type marker | `type: "request"` | SSE event name `request` |
| Agent status | `status` ("running"/"done"/"error") | `success` (bool) + `action` |
| Stats fields | `total_requests`, `blocked_requests`, `total_threats`, `threats_blocked`, `block_rate`, `rules_version` | `total_requests`, `blocked_count`, `threat_count`, `avg_response_ms` |
| Threat fields | Same as global `/api/threats` compat format | DB struct: `discovered_at` is RFC3339 from Go time.Time JSON |

---

## Task 1: Create `useSiteData` hook

**Files:**
- Create: `frontend/src/hooks/useSiteData.js`

This hook replaces `useVeilSocket` for dashboard pages. It:
1. Fetches initial data from site-scoped REST endpoints
2. Opens an SSE connection to `/api/stream/events?site_id=X` for live updates
3. Normalises data to match the same shape `useVeilSocket` returns so all downstream components work unchanged

**Step 1: Create the hook file**

```javascript
import { useState, useEffect, useRef, useCallback } from 'react'

/**
 * useSiteData — site-scoped real-time data hook.
 *
 * Returns the same { requests, agentEvents, stats } shape as useVeilSocket
 * but scoped to a single site via REST + SSE instead of the global WebSocket.
 */
export function useSiteData(siteId) {
  const [requests, setRequests] = useState([])
  const [agentEvents, setAgentEvents] = useState([])
  const [stats, setStats] = useState({
    total_requests: 0,
    blocked_requests: 0,
    total_threats: 0,
    threats_blocked: 0,
    block_rate: 0,
    rules_version: 1,
  })
  const esRef = useRef(null)

  // Normalise a DB RequestLogEntry to the shape components expect
  const normaliseRequest = useCallback((r) => ({
    timestamp: r.timestamp,
    message: r.raw_request || r.message || '',
    classification: r.classification,
    confidence: r.confidence,
    blocked: r.blocked,
    classifier: r.classifier,
    attack_type: r.attack_type,
  }), [])

  // Normalise a DB AgentLogEntry to the shape components expect
  const normaliseAgent = useCallback((a) => ({
    timestamp: a.timestamp,
    agent: a.agent,
    status: a.action === 'error' ? 'error' : a.success ? 'done' : (a.action || 'done'),
    detail: a.detail || '',
  }), [])

  // Normalise DB Stats to the shape StatsBar expects
  const normaliseStats = useCallback((s) => {
    const total = s.total_requests ?? 0
    const blocked = s.blocked_count ?? s.blocked_requests ?? 0
    const threats = s.threat_count ?? s.total_threats ?? 0
    const blockRate = total > 0 ? (blocked / total) * 100 : 0
    return {
      total_requests: total,
      blocked_requests: blocked,
      total_threats: threats,
      threats_blocked: threats, // approximate: all known threats count as "blocked" threats
      block_rate: Math.round(blockRate * 10) / 10,
      rules_version: s.rules_version ?? 1,
    }
  }, [])

  useEffect(() => {
    if (!siteId) return

    let cancelled = false

    // 1. Fetch initial data from REST endpoints
    const hydrate = async () => {
      try {
        const [reqRes, agentRes, statsRes] = await Promise.all([
          fetch(`/api/sites/${siteId}/requests`),
          fetch(`/api/sites/${siteId}/agents`),
          fetch(`/api/sites/${siteId}/stats`),
        ])

        if (cancelled) return

        if (reqRes.ok) {
          const data = await reqRes.json()
          setRequests(Array.isArray(data) ? data.map(normaliseRequest) : [])
        }
        if (agentRes.ok) {
          const data = await agentRes.json()
          setAgentEvents(Array.isArray(data) ? data.map(normaliseAgent) : [])
        }
        if (statsRes.ok) {
          const data = await statsRes.json()
          setStats(normaliseStats(data))
        }
      } catch {
        // Silently handle — components show empty states
      }
    }

    hydrate()

    // 2. Open SSE connection for live updates
    const protocol = window.location.protocol
    const host = window.location.host
    const sseUrl = `${protocol}//${host}/api/stream/events?site_id=${siteId}`

    const es = new EventSource(sseUrl)
    esRef.current = es

    es.addEventListener('request', (e) => {
      if (cancelled) return
      try {
        const data = JSON.parse(e.data)
        setRequests((prev) => [normaliseRequest(data), ...prev].slice(0, 200))
      } catch {}
    })

    es.addEventListener('agent', (e) => {
      if (cancelled) return
      try {
        const data = JSON.parse(e.data)
        setAgentEvents((prev) => [normaliseAgent(data), ...prev].slice(0, 100))
      } catch {}
    })

    es.addEventListener('stats', (e) => {
      if (cancelled) return
      try {
        const data = JSON.parse(e.data)
        setStats(normaliseStats(data))
      } catch {}
    })

    es.onerror = () => {
      // EventSource auto-reconnects; nothing to do
    }

    return () => {
      cancelled = true
      es.close()
      esRef.current = null
    }
  }, [siteId, normaliseRequest, normaliseAgent, normaliseStats])

  return { requests, agentEvents, stats }
}
```

**Step 2: Commit**

```bash
git add frontend/src/hooks/useSiteData.js
git commit -m "feat: add useSiteData hook for site-scoped real-time data via REST+SSE"
```

---

## Task 2: Wire Dashboard to use `useSiteData` instead of `useVeilSocket`

**Files:**
- Modify: `frontend/src/components/Dashboard.jsx` (lines 1-2, line 418)

The Dashboard component currently calls `useVeilSocket()` on line 418. We need to:
1. Import `useSiteData` instead of `useVeilSocket`
2. Pass the `site.site_id` to the hook
3. Everything else stays identical — same props, same rendering

**Step 1: Update imports**

In `frontend/src/components/Dashboard.jsx`, replace line 2:
```javascript
// OLD:
import { useVeilSocket } from '../hooks/useVeilSocket'
// NEW:
import { useSiteData } from '../hooks/useSiteData'
```

**Step 2: Update hook call**

In `frontend/src/components/Dashboard.jsx`, line 418:
```javascript
// OLD:
export function Dashboard({ site, activeSection = 'site' }) {
  const { requests, agentEvents, stats } = useVeilSocket()

// NEW:
export function Dashboard({ site, activeSection = 'site' }) {
  const { requests, agentEvents, stats } = useSiteData(site.site_id)
```

**That's it.** No other changes. The rest of the component uses `requests`, `agentEvents`, and `stats` exactly the same way. The `StatsBar`, `AgentPipeline`, `AgentLog`, activity feed, and `ConnectionBanner` all consume the same data shapes.

**Step 3: Verify no other Dashboard imports of useVeilSocket exist**

Search the file to confirm `useVeilSocket` is not used anywhere else in Dashboard.jsx.

**Step 4: Commit**

```bash
git add frontend/src/components/Dashboard.jsx
git commit -m "feat: switch Dashboard from global WebSocket to site-scoped useSiteData"
```

---

## Task 3: Wire ThreatTable to use site-scoped endpoint

**Files:**
- Modify: `frontend/src/components/ThreatTable.jsx` (lines 12, 21)
- Modify: `frontend/src/components/Dashboard.jsx` (line 734)

ThreatTable currently fetches from the global `/api/threats` endpoint (line 21). We need it to fetch from `/api/sites/{siteId}/threats` instead.

**Step 1: Add siteId prop to ThreatTable**

In `frontend/src/components/ThreatTable.jsx`, change line 12:
```javascript
// OLD:
export function ThreatTable() {

// NEW:
export function ThreatTable({ siteId }) {
```

**Step 2: Update the fetch URL**

In `frontend/src/components/ThreatTable.jsx`, change line 21:
```javascript
// OLD:
        const res = await fetch('/api/threats')

// NEW:
        const res = await fetch(siteId ? `/api/sites/${siteId}/threats` : '/api/threats')
```

**Step 3: Add siteId to the useEffect dependency array**

In `frontend/src/components/ThreatTable.jsx`, change line 32:
```javascript
// OLD:
  }, [])

// NEW:
  }, [siteId])
```

**Step 4: Pass siteId from Dashboard**

In `frontend/src/components/Dashboard.jsx`, change line 734:
```javascript
// OLD:
            <ThreatTable />

// NEW:
            <ThreatTable siteId={site.site_id} />
```

**Step 5: Commit**

```bash
git add frontend/src/components/ThreatTable.jsx frontend/src/components/Dashboard.jsx
git commit -m "feat: scope ThreatTable to current site via siteId prop"
```

---

## Task 4: Wire BlockRateChart to use site-scoped endpoint

**Files:**
- Modify: `frontend/src/components/BlockRateChart.jsx` (lines 4, 10, 20)
- Modify: `frontend/src/components/Dashboard.jsx` (line 718)

BlockRateChart currently fetches from the global `/api/rules` endpoint (line 10). We need it to fetch from `/api/sites/{siteId}/rules` instead.

**Important note:** The global `/api/rules` endpoint (`GetGlobalRules` in compat.go) returns an array of `{ version, updated_at, updated_by }` objects. The site-scoped `/api/sites/{id}/rules` endpoint (`GetRules` in dashboard.go) returns a single `Rules` object (current rules only). So we can't just swap the URL — the site-scoped endpoint returns a different shape.

**Approach:** Since the site-scoped rules endpoint returns only the *current* rules (not history), and the BlockRateChart needs a timeline of rule versions, the simplest approach is to keep using the global `/api/rules` endpoint but also fallback correctly. Alternatively, we can have the BlockRateChart still use `/api/rules` (which already returns real data from the database) — this is already "real data", not mock data.

Actually, looking at this more carefully: `/api/rules` in `GetGlobalRules` calls `db.GetAllRuleVersions()` which returns real rule versions from the database. **This is already real data.** The BlockRateChart is already showing real protection timeline data. No change needed for correctness.

However, if we want site-scoping, we would need to add a new backend endpoint like `GET /api/sites/{id}/rules/history`. For now, the global rules endpoint is sufficient since rules are typically the same across a single-user deployment.

**Decision: No changes needed for BlockRateChart.** It already fetches real data from `/api/rules`. If site-scoped rule history is desired in the future, a new backend endpoint would be needed.

**Step 1: (Optional) Pass siteId for future use**

If you want to future-proof, you can add the prop plumbing now without changing the fetch:

In `frontend/src/components/BlockRateChart.jsx`, change line 4:
```javascript
// OLD:
export function BlockRateChart() {

// NEW:
export function BlockRateChart({ siteId }) {
```

In `frontend/src/components/Dashboard.jsx`, change line 718:
```javascript
// OLD:
                <BlockRateChart />

// NEW:
                <BlockRateChart siteId={site.site_id} />
```

The fetch URL stays as `/api/rules` for now since it already returns real data.

**Step 2: Commit**

```bash
git add frontend/src/components/BlockRateChart.jsx frontend/src/components/Dashboard.jsx
git commit -m "feat: pass siteId to BlockRateChart for future site-scoped rule history"
```

---

## Task 5: Wire agent cycle trigger to site-scoped context

**Files:**
- Modify: `frontend/src/components/Dashboard.jsx` (line 480)

The "Run Improvement Cycle" button currently calls the global `/api/agents/cycle` endpoint. This is the correct endpoint — agent cycles are a global operation in the current architecture. The cycle discovers threats, tests them, and patches rules globally. **No change needed** since agent cycles are inherently global operations.

**Decision: No changes.** The `/api/agents/cycle` endpoint triggers a real AI agent cycle — it's already calling real backend logic, not mock data.

---

## Task 6: Confirm DemoPage is untouched

**Files:**
- Verify only: `frontend/src/pages/DemoPage.jsx`

The DemoPage must continue using `useVeilSocket()` (the global WebSocket hook). Since we only changed `Dashboard.jsx` to use `useSiteData`, and DemoPage imports `useVeilSocket` independently, it is automatically untouched.

**Step 1: Verify DemoPage still imports useVeilSocket**

Confirm `frontend/src/pages/DemoPage.jsx` line 2 still reads:
```javascript
import { useVeilSocket } from '../hooks/useVeilSocket'
```

**Step 2: Verify useVeilSocket.js is NOT deleted**

The `frontend/src/hooks/useVeilSocket.js` file must remain since DemoPage depends on it.

---

## Task 7: Handle SSE auth — ensure session cookies are sent

**Files:**
- Verify: `frontend/src/hooks/useSiteData.js`

The SSE endpoint (`/api/stream/events`) requires authentication (it's behind `api.Use(auth.RequireAuth(sm))`). The `EventSource` API automatically sends cookies for same-origin requests, so session cookies will be included. No special configuration needed.

However, the `fetch()` calls also need to include credentials. Since these are same-origin requests, `fetch` sends cookies by default. **No changes needed.**

**Step 1: Verify by testing**

After all changes are made, test by:
1. Log in via GitHub OAuth
2. Navigate to a project dashboard
3. Check browser DevTools Network tab — confirm requests to `/api/sites/{id}/requests`, `/api/sites/{id}/agents`, `/api/sites/{id}/stats` return 200 (not 401/403)
4. Confirm SSE connection to `/api/stream/events?site_id=X` is established (shows as pending/streaming in Network tab)

---

## Task 8: Handle normalisation edge cases in useSiteData

**Files:**
- Modify: `frontend/src/hooks/useSiteData.js`

The `humaniseAgentEvent` function in `humanise.js` expects agent events to have a `status` field with values `"running"`, `"done"`, or `"error"`. The DB model has `success` (bool) and `action` (string) instead.

Looking at how the global WebSocket sets `status`:
```go
status := "done"
if !l.Success {
    status = "error"
}
```

And the SSE hydration sends the raw DB model, which has `action` and `success` fields. We need the `normaliseAgent` function to correctly map these.

**Step 1: Refine the normaliseAgent function**

The `normaliseAgent` function in the hook should be:
```javascript
const normaliseAgent = useCallback((a) => {
  // The SSE/REST sends raw DB AgentLogEntry which has:
  //   agent, action, detail, success, timestamp
  // The frontend expects:
  //   agent, status ("running"/"done"/"error"), detail, timestamp
  let status = 'done'
  if (a.status) {
    // If the event already has a status field (e.g. from SSE live broadcast), use it
    status = a.status
  } else if (a.action === 'running' || a.action === 'start') {
    status = 'running'
  } else if (!a.success && a.success !== undefined) {
    status = 'error'
  }

  return {
    timestamp: a.timestamp,
    agent: a.agent,
    status,
    detail: a.detail || '',
  }
}, [])
```

This covers:
- Hydration data (REST/SSE initial load): has `success` bool + `action` string
- Live SSE events: may already have `status` field if the SSE hub publishes in that format

**Step 2: Commit**

```bash
git add frontend/src/hooks/useSiteData.js
git commit -m "fix: refine agent event normalisation for DB model format"
```

---

## Summary of Changes

| File | Change | Justyna's UI affected? |
|------|--------|----------------------|
| `frontend/src/hooks/useSiteData.js` | **New file** — SSE + REST hook | No — internal logic only |
| `frontend/src/components/Dashboard.jsx` | Import + hook swap (2 lines), pass props (2 lines) | **No** — zero markup/style changes |
| `frontend/src/components/ThreatTable.jsx` | Accept `siteId` prop, use in fetch URL (3 lines) | **No** — zero markup/style changes |
| `frontend/src/components/BlockRateChart.jsx` | Accept `siteId` prop (1 line) | **No** — zero markup/style changes |
| `frontend/src/hooks/useVeilSocket.js` | **Untouched** — still used by DemoPage | N/A |
| `frontend/src/pages/DemoPage.jsx` | **Untouched** | N/A |

**Total lines changed in existing files: ~10 lines.** All changes are data-source wiring. Zero visual changes.
