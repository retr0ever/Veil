import { useState } from 'react'
import { useVeilSocket } from '../hooks/useVeilSocket'
import { StatsBar } from '../components/StatsBar'
import { RequestFeed } from '../components/RequestFeed'

const testScenarios = [
  {
    id: 'sqli',
    label: 'SQL injection',
    payload: "GET /users?id=1' OR '1'='1 HTTP/1.1\nHost: demo.internal",
  },
  {
    id: 'xss',
    label: 'Cross-site scripting',
    payload: 'POST /comment HTTP/1.1\nHost: demo.internal\n\n<script>alert(1)</script>',
  },
  {
    id: 'ssrf',
    label: 'Server-side request forgery',
    payload: 'GET /proxy?url=http://169.254.169.254/latest/meta-data HTTP/1.1\nHost: demo.internal',
  },
]

export function DemoPage() {
  const { requests, agentEvents, stats } = useVeilSocket()
  const [running, setRunning] = useState(false)
  const [results, setResults] = useState(null)

  const runAllTests = async () => {
    setRunning(true)
    const outcomes = []
    for (const scenario of testScenarios) {
      try {
        const res = await fetch('/v1/classify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ message: scenario.payload }),
        })
        if (!res.ok) throw new Error('Request failed')
        const data = await res.json()
        outcomes.push({
          id: scenario.id,
          label: scenario.label,
          blocked: data.blocked,
          classification: data.classification,
        })
      } catch {
        outcomes.push({
          id: scenario.id,
          label: scenario.label,
          blocked: false,
          classification: 'ERROR',
        })
      }
    }
    setResults(outcomes)
    setRunning(false)
  }

  const blockedCount = results ? results.filter((r) => r.blocked).length : 0

  return (
    <div className="min-h-screen bg-bg text-text">
      <main className="mx-auto max-w-7xl px-6 pb-8 pt-6">
        <section className="mb-6 rounded-2xl border border-border bg-surface p-8">
          <h1 className="text-[32px] font-semibold tracking-tight">Try Veil</h1>
          <p className="mt-3 text-[18px] text-dim">
            Run simulated attack payloads against Veil's detection engine and see how they are classified in real time.
          </p>

          <button
            onClick={runAllTests}
            disabled={running}
            className="mt-5 rounded-lg bg-agent px-6 py-3 text-[18px] font-medium text-[#1a1322] transition-all disabled:opacity-50 hover:brightness-110"
            style={{ color: '#1a1322' }}
          >
            {running ? 'Running tests...' : 'Run Simulated Tests'}
          </button>

          {results && (
            <div className="mt-6">
              <p className="text-[20px] font-semibold">
                <span className={blockedCount === results.length ? 'text-safe' : blockedCount > 0 ? 'text-suspicious' : 'text-blocked'}>
                  {blockedCount}/{results.length}
                </span>
                <span className="ml-2 text-dim font-normal">simulated attacks blocked</span>
              </p>

              <div className="mt-4 grid gap-3 sm:grid-cols-3">
                {results.map((r) => (
                  <div
                    key={r.id}
                    className={`rounded-lg border p-5 ${
                      r.blocked
                        ? 'border-safe/40 bg-safe/5'
                        : 'border-blocked/40 bg-blocked/5'
                    }`}
                  >
                    <div className="flex items-center gap-2">
                      {r.blocked ? (
                        <svg width="18" height="18" viewBox="0 0 16 16" className="text-safe shrink-0">
                          <path d="M6.5 12L2 7.5l1.4-1.4L6.5 9.2l6.1-6.1L14 4.5z" fill="currentColor" />
                        </svg>
                      ) : (
                        <svg width="18" height="18" viewBox="0 0 16 16" className="text-blocked shrink-0">
                          <path d="M4.5 3L8 6.5 11.5 3 13 4.5 9.5 8 13 11.5 11.5 13 8 9.5 4.5 13 3 11.5 6.5 8 3 4.5z" fill="currentColor" />
                        </svg>
                      )}
                      <span className={`text-[18px] font-medium ${r.blocked ? 'text-safe' : 'text-blocked'}`}>
                        {r.blocked ? 'Blocked' : 'Missed'}
                      </span>
                    </div>
                    <p className="mt-2 text-[16px] text-dim">{r.label}</p>
                  </div>
                ))}
              </div>
            </div>
          )}

          <div className="mt-8 border-t border-border pt-5">
            <a
              href="/auth"
              className="inline-flex rounded-lg bg-agent px-5 py-2.5 text-[18px] font-medium text-[#1a1322] transition-all hover:brightness-110"
              style={{ color: '#1a1322' }}
            >
              Protect your own site
            </a>
          </div>
        </section>

        <section className="overflow-hidden rounded-2xl border border-border bg-surface">
          <StatsBar stats={stats} />
          <div className="min-h-[400px]">
            <RequestFeed requests={requests} />
          </div>
        </section>
      </main>
    </div>
  )
}
