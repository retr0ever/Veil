import { useState, useEffect, useRef, useCallback } from 'react'

export function useVeilSocket() {
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
  const wsRef = useRef(null)

  useEffect(() => {
    const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws'
    const host = window.location.hostname
    const port = 8000
    const url = `${protocol}://${host}:${port}/ws`

    function connect() {
      const ws = new WebSocket(url)
      wsRef.current = ws

      ws.onmessage = (event) => {
        const data = JSON.parse(event.data)

        if (data.type === 'request') {
          setRequests((prev) => [data, ...prev].slice(0, 200))
        } else if (data.type === 'agent') {
          setAgentEvents((prev) => [data, ...prev].slice(0, 100))
        } else if (data.type === 'stats') {
          setStats(data)
        }
      }

      ws.onclose = () => {
        setTimeout(connect, 2000)
      }
    }

    connect()
    return () => wsRef.current?.close()
  }, [])

  return { requests, agentEvents, stats }
}
