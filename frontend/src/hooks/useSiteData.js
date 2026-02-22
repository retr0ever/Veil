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
  const normaliseAgent = useCallback((a) => {
    let status = 'done'
    if (a.status) {
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
      threats_blocked: threats,
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
