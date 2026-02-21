import { useState } from 'react'
import { useVeilSocket } from '../hooks/useVeilSocket'
import { StatsBar } from '../components/StatsBar'
import { RequestFeed } from '../components/RequestFeed'
import { AgentLog } from '../components/AgentLog'
import { ThreatTable } from '../components/ThreatTable'

const replayScenarios = [
  {
    id: 'sqli',
    label: 'Replay SQL injection',
    payload: "GET /users?id=1' OR '1'='1 HTTP/1.1\nHost: demo.internal",
  },
  {
    id: 'xss',
    label: 'Replay XSS payload',
    payload: 'POST /comment HTTP/1.1\nHost: demo.internal\n\n<script>alert(1)</script>',
  },
  {
    id: 'ssrf',
    label: 'Replay SSRF probe',
    payload: 'GET /proxy?url=http://169.254.169.254/latest/meta-data HTTP/1.1\nHost: demo.internal',
  },
]

export function DemoPage() {
  const { requests, agentEvents, stats } = useVeilSocket()
  const [running, setRunning] = useState('')
  const [results, setResults] = useState([])

  const replayScenario = async (scenario) => {
    setRunning(scenario.id)
    try {
      const res = await fetch('/v1/classify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: scenario.payload }),
      })

      if (!res.ok) throw new Error('Request failed')
      const data = await res.json()
      setResults((prev) => [
        {
          id: `${scenario.id}-${Date.now()}`,
          label: scenario.label,
          classification: data.classification,
          attackType: data.attack_type,
          blocked: data.blocked,
        },
        ...prev,
      ].slice(0, 8))
    } catch {
      setResults((prev) => [
        {
          id: `err-${scenario.id}-${Date.now()}`,
          label: scenario.label,
          classification: 'ERROR',
          attackType: 'network',
          blocked: false,
        },
        ...prev,
      ].slice(0, 8))
    }
    setRunning('')
  }

  return (
    <div className="min-h-screen bg-bg text-text">
      <header className="border-b border-border bg-bg/85 backdrop-blur">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-5 py-3">
          <div className="flex items-center gap-3">
            <span className="font-logo text-[22px] leading-none text-dim">VEIL DEMO</span>
            <span className="rounded-full border border-safe/40 px-2 py-0.5 text-[11px] text-safe">READ ONLY</span>
          </div>
          <div className="flex items-center gap-3 text-[13px]">
            <a href="/" className="text-dim hover:text-text">Landing</a>
            <a href="/app/projects" className="text-dim hover:text-text">Projects</a>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-7xl px-5 pb-6 pt-5">
        <section className="mb-4 rounded-2xl border border-border bg-surface p-4">
          <h1 className="text-xl font-semibold tracking-tight">Control Room Demo</h1>
          <p className="mt-1 text-[13px] text-dim">
            Replay known bypass payloads without forwarding to a real backend. Useful for judge walkthroughs.
          </p>
          <div className="mt-4 flex flex-wrap gap-2">
            {replayScenarios.map((scenario) => (
              <button
                key={scenario.id}
                type="button"
                onClick={() => replayScenario(scenario)}
                disabled={running === scenario.id}
                className="rounded-lg border border-border bg-bg px-3 py-2 text-[12px] text-dim transition hover:text-text disabled:opacity-50"
              >
                {running === scenario.id ? 'Replaying...' : scenario.label}
              </button>
            ))}
          </div>
          {results.length > 0 && (
            <div className="mt-4 overflow-hidden rounded-lg border border-border">
              {results.map((result) => (
                <div key={result.id} className="flex flex-wrap items-center gap-3 border-b border-border/60 bg-bg/65 px-3 py-2 text-[12px] last:border-b-0">
                  <span className="font-medium text-dim">{result.label}</span>
                  <span className={`font-mono ${result.classification === 'MALICIOUS' ? 'text-blocked' : result.classification === 'SAFE' ? 'text-safe' : 'text-suspicious'}`}>
                    {result.classification}
                  </span>
                  <span className="text-muted">{result.attackType}</span>
                  {result.blocked && (
                    <span className="rounded bg-blocked/10 px-1.5 py-0.5 text-[11px] font-semibold text-blocked">BLOCKED</span>
                  )}
                </div>
              ))}
            </div>
          )}
        </section>

        <section className="overflow-hidden rounded-2xl border border-border bg-surface">
          <StatsBar stats={stats} />
          <div className="grid min-h-[500px] grid-cols-1 lg:grid-cols-[1fr_350px]">
            <div className="min-h-0 border-b border-border lg:border-b-0 lg:border-r">
              <RequestFeed requests={requests} />
            </div>
            <div className="min-h-0">
              <AgentLog events={agentEvents} />
            </div>
          </div>
          <div className="h-[220px] border-t border-border">
            <ThreatTable />
          </div>
        </section>
      </main>
    </div>
  )
}
