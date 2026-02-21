import { useState, useMemo } from 'react'
import { useVeilSocket } from '../hooks/useVeilSocket'
import { StatsBar } from './StatsBar'
import { RequestFeed } from './RequestFeed'
import { AgentLog, AgentPipeline } from './AgentLog'
import { ThreatTable } from './ThreatTable'
import { BlockRateChart } from './BlockRateChart'
import { NavBar } from './NavBar'
import { APP_NAV_LINKS } from '../lib/navLinks'
import { humaniseRequest, humaniseAgentEvent, relativeTime } from '../lib/humanise'

const tabs = [
  { key: 'site', label: 'Your Site' },
  { key: 'agents', label: 'Agents' },
  { key: 'threats', label: 'Threat Library' },
  { key: 'setup', label: 'Setup' },
]

const TEST_SCENARIOS = [
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

export function Dashboard({ site, projectName, user, logout }) {
  const { requests, agentEvents, stats } = useVeilSocket()
  const [copied, setCopied] = useState(false)
  const [activeTab, setActiveTab] = useState('site')
  const [testRunning, setTestRunning] = useState(false)
  const [testResults, setTestResults] = useState(null)

  const proxyUrl = `${window.location.origin}/p/${site.site_id}`
  const title = projectName || site.target_url
  const hasTraffic = requests.length > 0

  const copyUrl = () => {
    navigator.clipboard.writeText(proxyUrl)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const triggerCycle = async () => {
    await fetch('/api/agents/cycle', { method: 'POST' })
  }

  const runTests = async () => {
    setTestRunning(true)
    const results = []
    for (const scenario of TEST_SCENARIOS) {
      try {
        const res = await fetch('/v1/classify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ message: scenario.payload }),
        })
        if (!res.ok) throw new Error('Request failed')
        const data = await res.json()
        results.push({
          id: scenario.id,
          label: scenario.label,
          blocked: data.blocked,
          classification: data.classification,
        })
      } catch {
        results.push({
          id: scenario.id,
          label: scenario.label,
          blocked: false,
          classification: 'ERROR',
        })
      }
    }
    setTestResults(results)
    setTestRunning(false)
  }

  const mergedFeed = useMemo(() => {
    const items = []

    requests
      .filter((r) => r.classification !== 'SAFE')
      .forEach((r) => {
        const { summary, color } = humaniseRequest(r)
        items.push({
          time: r.timestamp ? new Date(r.timestamp).getTime() : 0,
          timestamp: r.timestamp,
          summary,
          color,
          blocked: r.blocked,
          kind: 'request',
        })
      })

    agentEvents.forEach((evt) => {
      const { summary, color } = humaniseAgentEvent(evt)
      items.push({
        time: evt.timestamp ? new Date(evt.timestamp).getTime() : 0,
        timestamp: evt.timestamp,
        summary,
        color,
        kind: 'agent',
      })
    })

    items.sort((a, b) => b.time - a.time)
    return items.slice(0, 50)
  }, [requests, agentEvents])

  const safeCount = requests.filter((r) => r.classification === 'SAFE').length

  return (
    <div className="flex h-screen flex-col overflow-hidden bg-bg">
      <div className="px-5 pt-3">
        <NavBar links={APP_NAV_LINKS} activeHref="/app/projects" size="compact" showDivider />
      </div>

      <div className="flex items-center justify-between border-b border-border px-5 py-3">
        <div className="flex min-w-0 items-center gap-4">
          <span className="rounded-full border border-safe/40 px-2 py-0.5 text-[11px] text-safe">PROJECT</span>
          <div className="min-w-0">
            <p className="truncate text-[14px] font-semibold text-text">{title}</p>
            <p className="truncate text-[12px] text-dim">{site.target_url}</p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          {user && (
            <div className="flex items-center gap-2">
              {user.avatar_url && (
                <img src={user.avatar_url} alt={user.github_login} className="h-6 w-6 rounded-full" />
              )}
              <span className="text-[12px] text-dim">{user.name || user.github_login}</span>
              <button
                onClick={logout}
                className="border-none bg-transparent text-[11px] text-muted transition-colors hover:text-text"
              >
                Sign out
              </button>
            </div>
          )}
        </div>
      </div>

      <div className="flex gap-2 border-b border-border bg-surface px-5 py-2">
        {tabs.map((tab) => (
          <button
            key={tab.key}
            type="button"
            onClick={() => setActiveTab(tab.key)}
            className={`rounded-md px-3 py-1.5 text-[12px] font-medium transition-colors ${
              activeTab === tab.key
                ? 'bg-bg text-text'
                : 'bg-transparent text-muted hover:text-text'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      <div className="flex-1 min-h-0 overflow-y-auto">
        {/* ── Tab: Your Site ── */}
        {activeTab === 'site' && (
          <div>
            {!hasTraffic ? (
              <div className="border-b border-border bg-surface px-5 py-5">
                <div className="flex items-center gap-3 mb-3">
                  <svg width="20" height="20" viewBox="0 0 20 20" className="text-agent shrink-0" fill="none">
                    <circle cx="10" cy="10" r="9" stroke="currentColor" strokeWidth="1.5" />
                    <path d="M10 6v5M10 13v1" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
                  </svg>
                  <h3 className="text-[14px] font-semibold text-text">Connect your site</h3>
                </div>
                <p className="text-[13px] text-dim mb-3">
                  Point your application at the protected proxy URL to start monitoring traffic.
                </p>
                <div className="flex items-center gap-2 rounded-md border border-border bg-bg px-3 py-2">
                  <code className="flex-1 truncate font-mono text-[13px] text-text">{proxyUrl}</code>
                  <button
                    onClick={copyUrl}
                    className="shrink-0 border-none bg-transparent text-[11px] text-muted transition-colors hover:text-text"
                  >
                    {copied ? 'Copied' : 'Copy'}
                  </button>
                </div>
                <p className="mt-2 text-[11px] text-muted">
                  Replace your backend URL with this proxy URL. See the Setup tab for full instructions.
                </p>
              </div>
            ) : (
              <div className="flex items-center gap-2 border-b border-border bg-safe/5 px-5 py-2.5">
                <div className="h-1.5 w-1.5 animate-pulse rounded-full bg-safe" />
                <span className="text-[12px] font-medium text-safe">Protected</span>
                <span className="text-[12px] text-dim">Proxy active</span>
              </div>
            )}

            <StatsBar stats={stats} />

            <div className="flex-1 min-h-0">
              <div className="flex items-center justify-between px-4 py-2.5 border-b border-border">
                <span className="text-muted text-[12px] font-medium">Recent activity</span>
                {safeCount > 0 && (
                  <span className="text-[11px] text-safe">{safeCount} safe request{safeCount !== 1 ? 's' : ''} passed</span>
                )}
              </div>
              <div className="px-4 py-2 border-b border-border/40 bg-surface">
                <p className="text-[11px] text-dim leading-relaxed">
                  All classifications shown, including agent self-testing.
                </p>
              </div>
              {mergedFeed.length === 0 && (
                <div className="px-4 py-8 text-muted text-center text-[13px]">
                  No classifications yet. Connect your site or check the Agents tab.
                </div>
              )}
              {mergedFeed.map((item, i) => (
                <div key={i} className="px-4 py-2.5 border-b border-border/40 flex items-center gap-3">
                  <div className={`w-1.5 h-1.5 rounded-full shrink-0 ${
                    item.kind === 'agent' ? 'bg-agent' : item.blocked ? 'bg-blocked' : 'bg-suspicious'
                  }`} />
                  <span className={`flex-1 text-[13px] ${item.color}`}>{item.summary}</span>
                  <span className="text-[11px] text-muted shrink-0">{relativeTime(item.timestamp)}</span>
                  {item.blocked && (
                    <span className="text-blocked text-[10px] font-semibold shrink-0 bg-blocked/10 px-2 py-0.5 rounded">
                      BLOCKED
                    </span>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ── Tab: Agents ── */}
        {activeTab === 'agents' && (
          <div>
            <AgentPipeline events={agentEvents} />

            <div className="flex items-center justify-between border-b border-border px-5 py-3">
              <p className="text-[13px] text-dim">
                Veil's agents continuously discover, test, and patch attack techniques.
              </p>
              <button
                onClick={triggerCycle}
                className="shrink-0 rounded-md border border-border bg-transparent px-3 py-1.5 text-[12px] text-muted transition-colors hover:border-dim hover:text-text"
              >
                Run Improvement Cycle
              </button>
            </div>

            <div className="grid min-h-[500px] grid-cols-1 lg:grid-cols-[1fr_340px]">
              <div className="min-h-0 border-b border-border lg:border-b-0 lg:border-r">
                <AgentLog events={agentEvents} />
              </div>
              <div className="min-h-0 flex flex-col">
                <BlockRateChart />
              </div>
            </div>
          </div>
        )}

        {/* ── Tab: Threat Library ── */}
        {activeTab === 'threats' && (
          <div className="h-full min-h-0">
            <ThreatTable />
          </div>
        )}

        {/* ── Tab: Setup ── */}
        {activeTab === 'setup' && (
          <div>
            <div className="border-b border-border px-5 py-5">
              <h3 className="text-[14px] font-semibold text-text mb-3">Proxy connection</h3>
              <p className="text-[13px] text-dim mb-3">
                Replace your backend URL with the protected proxy URL below. All traffic routed through Veil is
                classified and filtered in real time.
              </p>
              <div className="flex items-center gap-2 rounded-md border border-border bg-surface px-3 py-2 mb-3">
                <code className="flex-1 truncate font-mono text-[13px] text-text">{proxyUrl}</code>
                <button
                  onClick={copyUrl}
                  className="shrink-0 border-none bg-transparent text-[11px] text-muted transition-colors hover:text-text"
                >
                  {copied ? 'Copied' : 'Copy'}
                </button>
              </div>
              <div className="rounded-md border border-border bg-bg p-3 font-mono text-[12px]">
                <div className="text-muted">
                  <span className="text-blocked">- </span>API_URL={site.target_url}
                </div>
                <div className="mt-1">
                  <span className="text-safe">+ </span>API_URL={proxyUrl}
                </div>
              </div>
            </div>

            <div className="border-b border-border px-5 py-5">
              <div className="flex items-center justify-between mb-1">
                <h3 className="text-[14px] font-semibold text-text">Test My Defences</h3>
                <button
                  onClick={runTests}
                  disabled={testRunning}
                  className="rounded-lg bg-text px-4 py-2 text-[13px] font-medium text-bg disabled:opacity-50"
                >
                  {testRunning ? 'Testing...' : 'Run Tests'}
                </button>
              </div>
              <p className="text-[12px] text-dim mb-3">
                Simulated tests against the detection engine — not attacks on your site.
              </p>

              {testResults && (
                <div className="grid gap-2 sm:grid-cols-3">
                  {testResults.map((r) => (
                    <div
                      key={r.id}
                      className={`rounded-lg border p-3 ${
                        r.blocked
                          ? 'border-safe/40 bg-safe/5'
                          : 'border-blocked/40 bg-blocked/5'
                      }`}
                    >
                      <div className="flex items-center gap-2">
                        {r.blocked ? (
                          <svg width="16" height="16" viewBox="0 0 16 16" className="text-safe shrink-0">
                            <path d="M6.5 12L2 7.5l1.4-1.4L6.5 9.2l6.1-6.1L14 4.5z" fill="currentColor" />
                          </svg>
                        ) : (
                          <svg width="16" height="16" viewBox="0 0 16 16" className="text-blocked shrink-0">
                            <path d="M4.5 3L8 6.5 11.5 3 13 4.5 9.5 8 13 11.5 11.5 13 8 9.5 4.5 13 3 11.5 6.5 8 3 4.5z" fill="currentColor" />
                          </svg>
                        )}
                        <span className={`text-[13px] font-medium ${r.blocked ? 'text-safe' : 'text-blocked'}`}>
                          {r.blocked ? 'Blocked' : 'Missed'}
                        </span>
                      </div>
                      <p className="mt-1 text-[12px] text-dim">{r.label}</p>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
