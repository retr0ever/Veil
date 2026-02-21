import { useState, useMemo } from 'react'
import { useVeilSocket } from '../hooks/useVeilSocket'
import { StatsBar } from './StatsBar'
import { RequestFeed } from './RequestFeed'
import { AgentLog, AgentPipeline } from './AgentLog'
import { ThreatTable } from './ThreatTable'
import { BlockRateChart } from './BlockRateChart'
import { humaniseRequest, humaniseAgentEvent, humaniseAttackType, relativeTime } from '../lib/humanise'

const TEST_SCENARIOS = [
  {
    id: 'sqli',
    label: 'SQL injection',
    description: 'Attempts to manipulate database queries',
    payload: "GET /users?id=1' OR '1'='1 HTTP/1.1\nHost: demo.internal",
  },
  {
    id: 'xss',
    label: 'Cross-site scripting',
    description: 'Injects malicious scripts into pages',
    payload: 'POST /comment HTTP/1.1\nHost: demo.internal\n\n<script>alert(1)</script>',
  },
  {
    id: 'ssrf',
    label: 'Server-side request forgery',
    description: 'Tricks server into accessing internal resources',
    payload: 'GET /proxy?url=http://169.254.169.254/latest/meta-data HTTP/1.1\nHost: demo.internal',
  },
]

const SECTION_META = {
  site: {
    title: 'Overview',
    description: 'Real-time traffic monitoring and protection status',
  },
  agents: {
    title: 'Agents',
    description: 'AI-powered attack discovery and patching',
  },
  threats: {
    title: 'Threats',
    description: 'Discovered attack techniques',
  },
  setup: {
    title: 'Setup',
    description: 'Configuration and testing',
  },
}

/* ------------------------------------------------------------ */
/*  Section header (sticky)                                      */
/* ------------------------------------------------------------ */
function SectionHeader({ title, description, action }) {
  return (
    <div className="sticky top-0 z-10 flex items-start justify-between gap-4 border-b border-border bg-bg px-6 py-4">
      <div className="min-w-0">
        <h3 className="text-[18px] font-semibold text-text">{title}</h3>
        {description && (
          <p className="mt-1 text-[15px] leading-relaxed text-dim">{description}</p>
        )}
      </div>
      {action && <div className="shrink-0">{action}</div>}
    </div>
  )
}

/* ------------------------------------------------------------ */
/*  Activity feed item                                           */
/* ------------------------------------------------------------ */
function ActivityItem({ item, isLast }) {
  const dotColor =
    item.kind === 'agent'
      ? 'bg-agent'
      : item.blocked
        ? 'bg-blocked'
        : 'bg-suspicious'

  const dotGlow =
    item.kind === 'agent'
      ? 'shadow-[0_0_6px_rgba(212,167,218,0.3)]'
      : item.blocked
        ? 'shadow-[0_0_6px_rgba(240,138,149,0.3)]'
        : 'shadow-[0_0_6px_rgba(242,199,122,0.3)]'

  return (
    <div
      className={`flex items-center gap-3 px-6 py-3 transition-colors hover:bg-surface/30 ${
        !isLast ? 'border-b border-border/30' : ''
      }`}
    >
      <div className={`h-2 w-2 shrink-0 rounded-full ${dotColor} ${dotGlow}`} />
      <span className={`flex-1 min-w-0 truncate text-[15px] ${item.color}`}>
        {item.summary}
      </span>
      <span className="shrink-0 text-[13px] text-muted tabular-nums">
        {relativeTime(item.timestamp)}
      </span>
      {item.blocked && (
        <span className="shrink-0 rounded-md bg-blocked/10 px-2 py-0.5 text-[12px] font-semibold tracking-wide text-blocked">
          BLOCKED
        </span>
      )}
    </div>
  )
}

/* ------------------------------------------------------------ */
/*  Connection status banner                                     */
/* ------------------------------------------------------------ */
function ConnectionBanner({ hasTraffic, proxyUrl, copied, onCopy }) {
  if (hasTraffic) {
    return (
      <div className="flex items-center gap-3 border-b border-safe/10 bg-safe/[0.04] px-6 py-3">
        <div className="relative flex h-4 w-4 items-center justify-center">
          <span
            className="absolute inline-flex h-3 w-3 rounded-full bg-safe/30"
            style={{ animation: 'ping 2s cubic-bezier(0,0,0.2,1) infinite' }}
          />
          <span className="relative inline-flex h-2 w-2 rounded-full bg-safe" />
        </div>
        <span className="text-[15px] font-medium text-safe">Protected</span>
        <span className="text-[14px] text-dim">-- Proxy active and monitoring traffic</span>
      </div>
    )
  }

  return (
    <div className="border-b border-agent/10 bg-agent/[0.03] px-6 py-5">
      {/* Step indicator */}
      <div className="mb-3 flex items-center gap-3">
        <div className="flex h-7 w-7 items-center justify-center rounded-full border border-agent/30 bg-agent/10">
          <span className="text-[14px] font-semibold text-agent">1</span>
        </div>
        <div>
          <h3 className="text-[16px] font-semibold text-text">Connect your site</h3>
          <p className="text-[14px] text-dim">Point your application at the proxy URL to start monitoring</p>
        </div>
      </div>

      {/* Copy box */}
      <div className="flex items-center gap-2 rounded-lg border border-border bg-bg/80 px-3.5 py-2.5">
        <svg width="14" height="14" viewBox="0 0 16 16" fill="none" className="shrink-0 text-muted">
          <path d="M6.5 10.5L4.5 12.5a2.12 2.12 0 01-3-3L3.5 7.5a2.12 2.12 0 013 0" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
          <path d="M9.5 5.5l2-2a2.12 2.12 0 013 3l-2 2a2.12 2.12 0 01-3 0" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
          <path d="M6 10L10 6" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
        </svg>
        <code className="flex-1 truncate text-[15px] text-text">{proxyUrl}</code>
        <button
          onClick={onCopy}
          className="shrink-0 rounded-md border border-border bg-surface px-2.5 py-1 text-[13px] font-medium text-muted transition-all hover:border-dim hover:text-text"
        >
          {copied ? 'Copied' : 'Copy'}
        </button>
      </div>

      <p className="mt-2.5 text-[13px] text-muted">
        Replace your backend URL with this proxy URL. See the Setup tab for detailed instructions.
      </p>
    </div>
  )
}

/* ------------------------------------------------------------ */
/*  Empty feed state                                             */
/* ------------------------------------------------------------ */
function EmptyFeed() {
  return (
    <div className="flex min-h-[280px] flex-col items-center justify-center px-6 py-16 text-center">
      <div className="mb-4 flex h-12 w-12 items-center justify-center rounded-xl border border-border bg-surface">
        <svg width="20" height="20" viewBox="0 0 20 20" fill="none" className="text-muted">
          <circle cx="10" cy="10" r="7" stroke="currentColor" strokeWidth="1.5" />
          <path d="M10 6v4.5l3 1.5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      </div>
      <p className="text-[15px] font-medium text-text">No activity yet</p>
      <p className="mt-1 max-w-xs text-[14px] text-dim">
        Connect your site to start seeing classifications, or run an improvement cycle from the Agents tab.
      </p>
    </div>
  )
}

/* ------------------------------------------------------------ */
/*  Test results summary + cards                                 */
/* ------------------------------------------------------------ */
function TestResultsSummary({ results }) {
  const blockedCount = results.filter((r) => r.blocked).length
  const total = results.length
  const allBlocked = blockedCount === total

  return (
    <div className="space-y-4">
      {/* Summary line */}
      <div className="flex items-center gap-3">
        <div
          className={`flex h-10 w-10 items-center justify-center rounded-xl ${
            allBlocked ? 'bg-safe/10 border border-safe/20' : 'bg-suspicious/10 border border-suspicious/20'
          }`}
        >
          {allBlocked ? (
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="text-safe">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              <path d="M9 12l2 2 4-4" />
            </svg>
          ) : (
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="text-suspicious">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              <path d="M12 8v4M12 16h.01" />
            </svg>
          )}
        </div>
        <div>
          <p className={`text-[18px] font-semibold ${allBlocked ? 'text-safe' : 'text-suspicious'}`}>
            {blockedCount}/{total} blocked
          </p>
          <p className="text-[14px] text-dim">
            {allBlocked
              ? 'All attack vectors successfully intercepted'
              : `${total - blockedCount} attack vector${total - blockedCount !== 1 ? 's' : ''} bypassed defences`}
          </p>
        </div>
      </div>

      {/* Result cards */}
      <div className="grid gap-3 sm:grid-cols-3">
        {results.map((r) => (
          <div
            key={r.id}
            className={`rounded-xl border p-5 transition-colors ${
              r.blocked
                ? 'border-safe/20 bg-safe/[0.04]'
                : 'border-blocked/20 bg-blocked/[0.04]'
            }`}
          >
            <div className="flex items-center gap-2.5 mb-2">
              {r.blocked ? (
                <div className="flex h-8 w-8 items-center justify-center rounded-full bg-safe/15">
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" className="text-safe">
                    <path d="M9 12.5L11.5 15L15.5 9.5" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                  </svg>
                </div>
              ) : (
                <div className="flex h-8 w-8 items-center justify-center rounded-full bg-blocked/15">
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" className="text-blocked">
                    <path d="M8 8l8 8M16 8l-8 8" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
                  </svg>
                </div>
              )}
              <span className={`text-[18px] font-semibold ${r.blocked ? 'text-safe' : 'text-blocked'}`}>
                {r.blocked ? 'Blocked' : 'Missed'}
              </span>
            </div>
            <p className="text-[16px] font-medium text-text">{r.label}</p>
            <p className="mt-1 text-[14px] leading-relaxed text-muted">{r.description}</p>
          </div>
        ))}
      </div>
    </div>
  )
}

/* ------------------------------------------------------------ */
/*  Main Dashboard                                               */
/* ------------------------------------------------------------ */
export function Dashboard({ site, activeSection = 'site' }) {
  const { requests, agentEvents, stats } = useVeilSocket()
  const [copied, setCopied] = useState(false)
  const [testRunning, setTestRunning] = useState(false)
  const [testResults, setTestResults] = useState(null)
  const [cycleRunning, setCycleRunning] = useState(false)
  const [lastCycle, setLastCycle] = useState(null)

  const proxyUrl = `${window.location.origin}/p/${site.site_id}`
  const hasTraffic = requests.length > 0

  const copyUrl = () => {
    navigator.clipboard.writeText(proxyUrl)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const triggerCycle = async () => {
    setCycleRunning(true)
    setLastCycle(null)
    try {
      const res = await fetch('/api/agents/cycle', { method: 'POST' })
      if (res.ok) {
        const data = await res.json()
        setLastCycle(data)
      }
    } catch {}
    setCycleRunning(false)
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
          description: scenario.description,
          blocked: data.blocked,
          classification: data.classification,
        })
      } catch {
        results.push({
          id: scenario.id,
          label: scenario.label,
          description: scenario.description,
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
  const sectionMeta = SECTION_META[activeSection] || SECTION_META.site

  return (
    <div className="flex h-full flex-col overflow-hidden">
      <div className="flex-1 min-h-0 overflow-y-auto">

        {/* ================================================================ */}
        {/*  OVERVIEW SECTION                                                */}
        {/* ================================================================ */}
        {activeSection === 'site' && (
          <div className="mx-auto max-w-5xl">
            <SectionHeader
              title={SECTION_META.site.title}
              description={SECTION_META.site.description}
            />

            {/* Connection status */}
            <ConnectionBanner
              hasTraffic={hasTraffic}
              proxyUrl={proxyUrl}
              copied={copied}
              onCopy={copyUrl}
            />

            {/* Stats bar */}
            <StatsBar stats={stats} />

            {/* Activity feed */}
            <div className="border-b border-border">
              <div className="flex items-center justify-between px-6 py-4 border-b border-border/50">
                <div className="flex items-center gap-2.5">
                  <h4 className="text-[15px] font-semibold text-text">Recent activity</h4>
                  {mergedFeed.length > 0 && (
                    <span className="rounded-full bg-surface px-2 py-0.5 text-[12px] font-medium text-muted">
                      {mergedFeed.length}
                    </span>
                  )}
                </div>
                {safeCount > 0 && (
                  <span className="flex items-center gap-1.5 text-[13px] text-safe">
                    <span className="inline-block h-1.5 w-1.5 rounded-full bg-safe" />
                    {safeCount} safe request{safeCount !== 1 ? 's' : ''} passed
                  </span>
                )}
              </div>

              {mergedFeed.length === 0 ? (
                <EmptyFeed />
              ) : (
                <div>
                  {mergedFeed.map((item, i) => (
                    <ActivityItem
                      key={i}
                      item={item}
                      isLast={i === mergedFeed.length - 1}
                    />
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {/* ================================================================ */}
        {/*  AGENTS SECTION                                                  */}
        {/* ================================================================ */}
        {activeSection === 'agents' && (
          <div className="mx-auto max-w-5xl">
            <SectionHeader
              title={SECTION_META.agents.title}
              description={SECTION_META.agents.description}
            />

            <AgentPipeline events={agentEvents} />

            {/* Agent control bar */}
            <div className="flex items-center justify-between border-b border-border px-6 py-4">
              <p className="text-[15px] text-dim leading-relaxed">
                Veil's agents continuously discover, test, and patch attack techniques.
              </p>
              <button
                onClick={triggerCycle}
                disabled={cycleRunning}
                className="shrink-0 rounded-lg border border-border bg-transparent px-4 py-2 text-[14px] font-medium text-muted transition-all hover:border-dim hover:text-text disabled:opacity-40"
              >
                {cycleRunning ? (
                  <span className="flex items-center gap-2">
                    <span className="relative flex h-2 w-2">
                      <span className="absolute inline-flex h-full w-full rounded-full bg-agent opacity-75" style={{ animation: 'ping 1.5s cubic-bezier(0,0,0.2,1) infinite' }} />
                      <span className="relative inline-flex h-2 w-2 rounded-full bg-agent" />
                    </span>
                    Cycle running...
                  </span>
                ) : 'Run Improvement Cycle'}
              </button>
            </div>

            {/* Last cycle result */}
            {lastCycle && (
              <div className="border-b border-border bg-safe/[0.03] px-6 py-4">
                <div className="flex items-center gap-2.5 mb-2.5">
                  <div className="flex h-5 w-5 items-center justify-center rounded-full bg-safe/10">
                    <svg width="12" height="12" viewBox="0 0 16 16" className="text-safe">
                      <path d="M6.5 12L2 7.5l1.4-1.4L6.5 9.2l6.1-6.1L14 4.5z" fill="currentColor" />
                    </svg>
                  </div>
                  <span className="text-[15px] font-semibold text-text">Cycle #{lastCycle.cycle_id} complete</span>
                </div>
                <div className="flex flex-wrap gap-4 text-[14px]">
                  <span className="text-muted">Discovered: <span className="font-semibold text-agent">{lastCycle.discovered}</span></span>
                  <span className="text-muted">Bypasses: <span className="font-semibold text-suspicious">{lastCycle.bypasses}</span></span>
                  {lastCycle.patch_rounds?.map((r, i) => (
                    <span key={i} className="text-muted">
                      Round {r.round}: <span className="font-semibold text-safe">{r.patched} patched</span>
                      {r.still_bypassing > 0 && <span className="font-semibold text-blocked">, {r.still_bypassing} still evading</span>}
                    </span>
                  ))}
                  {lastCycle.strategies_used?.length > 0 && (
                    <span className="text-muted flex items-center gap-1.5 flex-wrap">
                      Strategies:
                      {lastCycle.strategies_used.map(s => (
                        <span key={s} className="inline-block rounded-md bg-agent/10 px-2 py-0.5 text-[12px] font-medium text-agent">{s.replace(/_/g, ' ')}</span>
                      ))}
                    </span>
                  )}
                </div>
              </div>
            )}

            {/* Agent log + chart */}
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

        {/* ================================================================ */}
        {/*  THREATS SECTION                                                 */}
        {/* ================================================================ */}
        {activeSection === 'threats' && (
          <div className="h-full min-h-0 mx-auto max-w-5xl">
            <SectionHeader
              title={SECTION_META.threats.title}
              description={SECTION_META.threats.description}
            />
            <ThreatTable />
          </div>
        )}

        {/* ================================================================ */}
        {/*  SETUP SECTION                                                   */}
        {/* ================================================================ */}
        {activeSection === 'setup' && (
          <div className="mx-auto max-w-3xl">
            <SectionHeader
              title={SECTION_META.setup.title}
              description={SECTION_META.setup.description}
            />

            {/* Proxy connection */}
            <div className="border-b border-border px-6 py-4">
              <div className="flex items-center gap-3 mb-3">
                <div className="flex h-8 w-8 items-center justify-center rounded-lg border border-border bg-surface">
                  <svg width="16" height="16" viewBox="0 0 16 16" fill="none" className="text-agent">
                    <path d="M6.5 10.5L4.5 12.5a2.12 2.12 0 01-3-3L3.5 7.5a2.12 2.12 0 013 0" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
                    <path d="M9.5 5.5l2-2a2.12 2.12 0 013 3l-2 2a2.12 2.12 0 01-3 0" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
                    <path d="M6 10L10 6" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
                  </svg>
                </div>
                <div>
                  <h3 className="text-[18px] font-semibold text-text">Proxy connection</h3>
                  <p className="text-[14px] text-dim">
                    Route traffic through Veil for real-time classification and filtering
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-2 rounded-lg border border-border bg-bg/80 px-3.5 py-2.5 mb-4">
                <code className="flex-1 truncate text-[15px] text-text">{proxyUrl}</code>
                <button
                  onClick={copyUrl}
                  className="shrink-0 rounded-md border border-border bg-surface px-2.5 py-1 text-[13px] font-medium text-muted transition-all hover:border-dim hover:text-text"
                >
                  {copied ? 'Copied' : 'Copy'}
                </button>
              </div>

              {/* Diff-style code snippet */}
              <div className="overflow-hidden rounded-lg border border-border bg-bg">
                <div className="border-b border-border/50 px-3 py-1.5">
                  <span className="text-[12px] font-medium tracking-wide text-muted">.env</span>
                </div>
                <div className="p-3 text-[14px]">
                  <div className="flex items-center gap-2 text-blocked/80">
                    <span className="w-4 text-right text-[12px] text-muted/50">1</span>
                    <span className="font-semibold text-blocked">-</span>
                    <span>API_URL={site.target_url}</span>
                  </div>
                  <div className="flex items-center gap-2 text-safe/80 mt-0.5">
                    <span className="w-4 text-right text-[12px] text-muted/50">1</span>
                    <span className="font-semibold text-safe">+</span>
                    <span>API_URL={proxyUrl}</span>
                  </div>
                </div>
              </div>
            </div>

            {/* Test my defences */}
            <div className="border-b border-border px-6 py-4">
              <div className="flex items-start justify-between gap-4 mb-4">
                <div className="flex items-center gap-3">
                  <div className="flex h-8 w-8 items-center justify-center rounded-lg border border-border bg-surface">
                    <svg width="16" height="16" viewBox="0 0 18 18" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" className="text-suspicious">
                      <path d="M9 1.5L2.5 4.5v4.5c0 4 3 6.5 6.5 7.5 3.5-1 6.5-3.5 6.5-7.5V4.5L9 1.5z" />
                    </svg>
                  </div>
                  <div>
                    <h3 className="text-[18px] font-semibold text-text">Test my defences</h3>
                    <p className="text-[14px] text-dim">
                      Simulated tests against the detection engine -- not attacks on your site
                    </p>
                  </div>
                </div>
                <button
                  onClick={runTests}
                  disabled={testRunning}
                  className="shrink-0 rounded-lg bg-text px-4 py-2 text-[15px] font-semibold text-bg transition-opacity hover:opacity-90 disabled:opacity-40"
                >
                  {testRunning ? (
                    <span className="flex items-center gap-2">
                      <span className="h-3 w-3 animate-spin rounded-full border-2 border-bg/30 border-t-bg" />
                      Testing...
                    </span>
                  ) : 'Run tests'}
                </button>
              </div>

              {testResults && <TestResultsSummary results={testResults} />}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
