import { useState, useEffect, useMemo, useCallback } from 'react'
import { useSiteData } from '../hooks/useSiteData'
import { StatsBar } from './StatsBar'
import { AgentLog, AgentPipeline } from './AgentLog'
import { ThreatTable } from './ThreatTable'
import { BlockRateChart } from './BlockRateChart'
import { ComplianceView } from './ComplianceView'
import { FindingsPanel } from './FindingsPanel'
import {
  humaniseRequest,
  humaniseAgentEvent,
  humaniseAttackType,
  relativeTime,
  attackCategory,
  attackExplanation,
} from '../lib/humanise'

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
    helpText: 'Veil sits between your app and the internet, checking every request for attacks. This page shows what it\'s finding and how well it\'s blocking threats.',
  },
  agents: {
    title: 'Agents',
    description: 'AI-powered attack discovery and patching',
    helpText: 'Veil\'s AI agents continuously invent new attacks, test them against your defences, and patch any gaps they find -- so your protection improves on its own.',
  },
  threats: {
    title: 'Threats',
    description: 'Discovered attack techniques',
    helpText: 'Every attack technique Veil has discovered or generated. Shows whether each one is now blocked or still needs patching.',
  },
  findings: {
    title: 'Code Findings',
    description: 'Vulnerabilities discovered in your source code',
    helpText: 'When Veil detects attacks in your traffic, it scans your linked GitHub repository to find the exact vulnerable code. Each finding shows the file, line numbers, and a suggested fix.',
  },
  setup: {
    title: 'Setup',
    description: 'Configuration and testing',
    helpText: 'Connect your app to Veil\'s proxy and test your defences with simulated attacks.',
  },
}

/* ------------------------------------------------------------ */
/*  Section header (sticky)                                      */
/* ------------------------------------------------------------ */
function SectionHeader({ title, description, helpText, action }) {
  const [helpOpen, setHelpOpen] = useState(false)

  return (
    <div className="sticky top-0 z-10 border-b border-border bg-bg px-6 py-4">
      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <h3 className="text-[18px] font-semibold text-text">{title}</h3>
            {helpText && (
              <button
                onClick={() => setHelpOpen((v) => !v)}
                className="flex h-5 w-5 items-center justify-center rounded-full border border-border bg-surface text-[12px] font-medium text-muted transition-colors hover:border-dim hover:text-text"
                aria-label={`What is ${title}?`}
              >
                ?
              </button>
            )}
          </div>
          {description && (
            <p className="mt-1 text-[15px] leading-relaxed text-dim">{description}</p>
          )}
        </div>
        {action && <div className="shrink-0">{action}</div>}
      </div>
      {helpOpen && helpText && (
        <div className="mt-3 rounded-lg border border-border bg-surface px-4 py-3 text-[14px] leading-relaxed text-dim">
          {helpText}
        </div>
      )}
    </div>
  )
}

/* ------------------------------------------------------------ */
/*  Category icon for feed items                                 */
/* ------------------------------------------------------------ */
const CATEGORY_ICONS = {
  sqli: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <ellipse cx="12" cy="5" rx="9" ry="3" /><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3" /><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5" />
    </svg>
  ),
  xss: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="16 18 22 12 16 6" /><polyline points="8 6 2 12 8 18" />
    </svg>
  ),
  ssrf: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10" /><line x1="2" y1="12" x2="22" y2="12" /><path d="M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z" />
    </svg>
  ),
  rce: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="4 17 10 11 4 5" /><line x1="12" y1="19" x2="20" y2="19" />
    </svg>
  ),
  file: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z" /><polyline points="14 2 14 8 20 8" />
    </svg>
  ),
  auth: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <rect x="3" y="11" width="18" height="11" rx="2" ry="2" /><path d="M7 11V7a5 5 0 0110 0v4" />
    </svg>
  ),
  web: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10" /><line x1="2" y1="12" x2="22" y2="12" /><path d="M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z" />
    </svg>
  ),
  xxe: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="16 18 22 12 16 6" /><polyline points="8 6 2 12 8 18" />
    </svg>
  ),
  agent: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="3" /><path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z" />
    </svg>
  ),
  unknown: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    </svg>
  ),
}

/* ------------------------------------------------------------ */
/*  Activity feed item (expandable)                              */
/* ------------------------------------------------------------ */
function ActivityItem({ item, isLast }) {
  const [expanded, setExpanded] = useState(false)

  const icon = CATEGORY_ICONS[item.category] || CATEGORY_ICONS.unknown

  const iconBg =
    item.kind === 'agent'
      ? 'bg-agent/15 text-agent'
      : item.blocked
        ? 'bg-blocked/15 text-blocked'
        : 'bg-suspicious/15 text-suspicious'

  // Truncate path for display
  const shortPath = item.path
    ? item.path.length > 48 ? item.path.slice(0, 45) + '...' : item.path
    : null

  return (
    <div
      className={`${!isLast ? 'border-b border-border/30' : ''}`}
    >
      <button
        onClick={() => setExpanded((v) => !v)}
        className="flex w-full items-start gap-3 bg-transparent border-none px-6 py-3.5 text-left transition-colors hover:bg-surface/30"
      >
        {/* Category icon */}
        <div className={`flex h-7 w-7 shrink-0 items-center justify-center rounded-lg mt-0.5 ${iconBg}`}>
          {icon}
        </div>

        {/* Summary + metadata */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className={`truncate text-[15px] ${item.color}`}>
              {item.summary}
            </span>
          </div>
          {/* Inline metadata row for requests */}
          {item.kind === 'request' && (
            <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-[12px] text-muted">
              {item.method && shortPath && (
                <span className="font-mono text-text/70">
                  <span className="font-semibold">{item.method}</span> {shortPath}
                </span>
              )}
              {item.confidence != null && (
                <span>
                  <span className={`font-mono font-medium ${item.confidence >= 80 ? 'text-blocked' : item.confidence >= 50 ? 'text-suspicious' : 'text-muted'}`}>{item.confidence}%</span> confidence
                </span>
              )}
              {item.classifier && (
                <span>via <span className="font-medium text-text/70">{item.classifier}</span></span>
              )}
              {item.sourceIp && (
                <span className="font-mono">{item.sourceIp}</span>
              )}
            </div>
          )}
        </div>

        {/* Timestamp */}
        <span className="shrink-0 text-[13px] text-muted tabular-nums mt-0.5">
          {relativeTime(item.timestamp)}
        </span>

        {/* Severity badge */}
        {item.blocked && (
          <span className="shrink-0 rounded-md bg-blocked/10 px-2 py-0.5 text-[11px] font-semibold tracking-wide uppercase text-blocked mt-0.5">
            Blocked
          </span>
        )}
        {!item.blocked && item.kind === 'request' && (
          <span className="shrink-0 rounded-md bg-suspicious/10 px-2 py-0.5 text-[11px] font-semibold tracking-wide uppercase text-suspicious mt-0.5">
            Flagged
          </span>
        )}
        {item.kind === 'agent' && item.agentName && (
          <span className="shrink-0 rounded-md bg-agent/10 px-2 py-0.5 text-[11px] font-semibold tracking-wide text-agent mt-0.5">
            {item.agentName}
          </span>
        )}

        {/* Expand chevron */}
        <svg
          width="14"
          height="14"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
          className={`shrink-0 text-muted transition-transform duration-200 mt-1 ${expanded ? 'rotate-90' : ''}`}
        >
          <polyline points="9 18 15 12 9 6" />
        </svg>
      </button>

      {/* Expanded details */}
      <div
        className={`overflow-hidden transition-all duration-200 ease-out ${expanded ? 'max-h-[300px] opacity-100' : 'max-h-0 opacity-0'
          }`}
      >
        <div className="mx-6 mb-3 space-y-3 rounded-lg border border-border/40 bg-bg px-4 py-3 text-[13px]">
          {/* Metadata chips */}
          <div className="flex flex-wrap gap-x-5 gap-y-2">
            {item.attackType && (
              <span className="text-muted">
                Type: <span className="font-medium text-text">{humaniseAttackType(item.attackType)}</span>
              </span>
            )}
            {item.classification && (
              <span className="text-muted">
                Classification: <span className={`font-semibold ${item.classification === 'MALICIOUS' ? 'text-blocked' : 'text-suspicious'}`}>{item.classification}</span>
              </span>
            )}
            {item.confidence != null && (
              <span className="text-muted">
                Confidence: <span className="font-mono font-medium text-text">{item.confidence}%</span>
              </span>
            )}
            {item.classifier && (
              <span className="text-muted">
                Classifier: <span className="font-medium text-text">{item.classifier}</span>
              </span>
            )}
            {item.sourceIp && (
              <span className="text-muted">
                Source: <span className="font-mono font-medium text-text">{item.sourceIp}</span>
              </span>
            )}
            {item.responseTimeMs != null && (
              <span className="text-muted">
                Response: <span className="font-mono font-medium text-text">{Math.round(item.responseTimeMs)}ms</span>
              </span>
            )}
          </div>

          {/* Explanation */}
          <p className="text-dim leading-relaxed">
            {item.explanation}
          </p>

          {/* Raw request preview */}
          {item.rawRequest && (
            <div className="rounded-md border border-border/30 bg-surface/50 px-3 py-2">
              <p className="mb-1 text-[11px] font-medium uppercase tracking-wide text-muted">Raw request</p>
              <pre className="whitespace-pre-wrap break-all font-mono text-[12px] leading-relaxed text-text/80 max-h-[120px] overflow-y-auto">
                {item.rawRequest.slice(0, 500)}{item.rawRequest.length > 500 ? '...' : ''}
              </pre>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

/* ------------------------------------------------------------ */
/*  Connection status banner (DNS-based)                         */
/* ------------------------------------------------------------ */
function ConnectionBanner({ hasTraffic, site, dnsStatus }) {
  const isActive = site.status === 'active' || hasTraffic

  if (isActive) {
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
        <span className="text-[14px] text-dim">
          {site.domain} is routing through Veil
        </span>
      </div>
    )
  }

  return (
    <div className="border-b border-agent/10 bg-agent/[0.03] px-6 py-5">
      <div className="mb-3 flex items-center gap-3">
        <div className="flex h-7 w-7 items-center justify-center rounded-full border border-agent/30 bg-agent/10">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="text-agent">
            <circle cx="12" cy="12" r="10" />
            <line x1="2" y1="12" x2="22" y2="12" />
            <path d="M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z" />
          </svg>
        </div>
        <div>
          <h3 className="text-[16px] font-semibold text-text">Waiting for DNS</h3>
          <p className="text-[14px] text-dim">
            Point <span className="font-mono text-text">{site.domain}</span> to Veil via CNAME.
            See the Setup tab for instructions.
          </p>
        </div>
      </div>
    </div>
  )
}

/* ------------------------------------------------------------ */
/*  Empty feed state                                             */
/* ------------------------------------------------------------ */
function EmptyFeed({ hasTraffic }) {
  if (hasTraffic) {
    /* Traffic exists but no flagged/blocked items */
    return (
      <div className="flex min-h-[240px] flex-col items-center justify-center px-6 py-14 text-center">
        <div className="mb-4 flex h-12 w-12 items-center justify-center rounded-xl border border-safe/20 bg-safe/[0.06]">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className="text-safe">
            <path d="M22 11.08V12a10 10 0 11-5.93-9.14" /><polyline points="22 4 12 14.01 9 11.01" />
          </svg>
        </div>
        <p className="text-[16px] font-semibold text-safe">All clear</p>
        <p className="mt-1.5 max-w-xs text-[14px] text-dim">
          No suspicious or malicious requests detected. Veil is monitoring your traffic.
        </p>
      </div>
    )
  }

  return (
    <div className="flex min-h-[240px] flex-col items-center justify-center px-6 py-14 text-center">
      <div className="mb-4 flex h-12 w-12 items-center justify-center rounded-xl border border-border bg-surface">
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className="text-muted">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
        </svg>
      </div>
      <p className="text-[16px] font-semibold text-text">Veil is ready to protect your site</p>
      <p className="mt-1.5 max-w-xs text-[14px] text-dim">
        Connect your site to start seeing live activity, or run an improvement cycle from the Agents tab.
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
          className={`flex h-10 w-10 items-center justify-center rounded-xl ${allBlocked ? 'bg-safe/10 border border-safe/20' : 'bg-suspicious/10 border border-suspicious/20'
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
            className={`rounded-xl border p-5 transition-colors ${r.blocked
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
/*  Repo connect card (Setup tab)                                */
/* ------------------------------------------------------------ */
function RepoConnectCard({ siteId, repoInfo, setRepoInfo, repoLoading }) {
  const [repos, setRepos] = useState([])
  const [loadingRepos, setLoadingRepos] = useState(false)
  const [needsGithubConnect, setNeedsGithubConnect] = useState(false)
  const [linking, setLinking] = useState(false)
  const [unlinking, setUnlinking] = useState(false)
  const [selectedRepo, setSelectedRepo] = useState('')

  const fetchRepos = async () => {
    setLoadingRepos(true)
    try {
      const res = await fetch(`/api/sites/${siteId}/repos`)
      if (res.ok) {
        const data = await res.json()
        setRepos(Array.isArray(data) ? data : [])
        setNeedsGithubConnect(false)
      } else if (res.status === 400) {
        // 400 means no GitHub token with repo scope stored yet
        setNeedsGithubConnect(true)
      }
    } catch {}
    setLoadingRepos(false)
  }

  const beginRepoConnect = () => {
    // Redirect to the incremental OAuth flow that requests repo scope
    window.location.href = `/api/auth/github/repo-connect?site_id=${siteId}`
  }

  const linkRepo = async () => {
    if (!selectedRepo) return
    const repo = repos.find((r) => r.full_name === selectedRepo)
    if (!repo) return
    setLinking(true)
    try {
      const res = await fetch(`/api/sites/${siteId}/repos`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          owner: repo.owner,
          name: repo.name,
          branch: repo.default_branch,
        }),
      })
      if (res.ok) {
        setRepoInfo({
          linked: true,
          repo_owner: repo.owner,
          repo_name: repo.name,
          default_branch: repo.default_branch,
        })
      }
    } catch {}
    setLinking(false)
  }

  const unlinkRepo = async () => {
    setUnlinking(true)
    try {
      const res = await fetch(`/api/sites/${siteId}/repos`, { method: 'DELETE' })
      if (res.ok || res.status === 204) {
        setRepoInfo({ linked: false })
      }
    } catch {}
    setUnlinking(false)
  }

  // Probe GitHub connection status on mount when not linked
  useEffect(() => {
    if (repoLoading || repoInfo?.linked) return
    // Quick probe — try to list repos to see if we need the connect flow
    const probe = async () => {
      try {
        const res = await fetch(`/api/sites/${siteId}/repos`)
        if (res.status === 400) {
          setNeedsGithubConnect(true)
        }
      } catch {}
    }
    probe()
  }, [siteId, repoLoading, repoInfo?.linked])

  const isLinked = repoInfo?.linked === true

  return (
    <div className="rounded-xl border border-border bg-surface/30 p-6">
      <div className="flex items-start gap-4">
        <div className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-full border ${
          isLinked ? 'border-safe/30 bg-safe/10' : 'border-agent/30 bg-agent/10'
        }`}>
          {isLinked ? (
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" className="text-safe">
              <path d="M20 6L9 17l-5-5" />
            </svg>
          ) : (
            <span className="text-[15px] font-bold text-agent">3</span>
          )}
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-start justify-between gap-3">
            <div>
              <h3 className="text-[17px] font-semibold text-text">Link GitHub repository</h3>
              <p className="mt-1 text-[14px] text-muted">
                {isLinked
                  ? <>Repository <span className="font-mono text-text">{repoInfo.repo_owner}/{repoInfo.repo_name}</span> is linked. Veil will scan it for vulnerabilities.</>
                  : 'Connect a repo so Veil can find vulnerable code when it detects attacks in your traffic.'
                }
              </p>
            </div>
            {isLinked && (
              <span className="shrink-0 rounded-full bg-safe/15 px-3 py-1 text-[12px] font-semibold text-safe">
                Linked
              </span>
            )}
          </div>

          {repoLoading ? (
            <div className="mt-4 flex items-center gap-2 text-[13px] text-muted">
              <span className="h-3 w-3 animate-spin rounded-full border-2 border-muted/30 border-t-muted" />
              Loading...
            </div>
          ) : isLinked ? (
            <div className="mt-4 flex items-center gap-3">
              <div className="flex items-center gap-2 rounded-lg border border-border bg-bg px-3 py-2">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className="text-muted">
                  <path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 00-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0020 4.77 5.07 5.07 0 0019.91 1S18.73.65 16 2.48a13.38 13.38 0 00-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 005 4.77a5.44 5.44 0 00-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 009 18.13V22" />
                </svg>
                <span className="text-[13px] font-mono text-text">{repoInfo.repo_owner}/{repoInfo.repo_name}</span>
                <span className="text-[11px] text-muted">({repoInfo.default_branch})</span>
              </div>
              <button
                onClick={unlinkRepo}
                disabled={unlinking}
                className="rounded-lg border border-blocked/30 px-3 py-1.5 text-[12px] font-medium text-blocked transition-all hover:bg-blocked/10 disabled:opacity-40"
              >
                {unlinking ? 'Unlinking...' : 'Unlink'}
              </button>
            </div>
          ) : needsGithubConnect ? (
            <div className="mt-4 space-y-3">
              <p className="text-[13px] text-dim">
                Veil needs additional GitHub permissions to read your repositories. Click below to grant the <span className="font-mono text-text">repo</span> scope via GitHub OAuth.
              </p>
              <button
                onClick={beginRepoConnect}
                className="flex items-center gap-2 rounded-lg bg-text px-5 py-2.5 text-[14px] font-semibold text-bg transition-opacity hover:opacity-90"
              >
                <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor" className="opacity-70">
                  <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z" />
                </svg>
                Connect GitHub
              </button>
            </div>
          ) : (
            <div className="mt-4 space-y-3">
              {repos.length === 0 ? (
                <button
                  onClick={fetchRepos}
                  disabled={loadingRepos}
                  className="rounded-lg border border-border bg-transparent px-4 py-2 text-[13px] font-medium text-muted transition-all hover:border-dim hover:text-text disabled:opacity-40"
                >
                  {loadingRepos ? (
                    <span className="flex items-center gap-2">
                      <span className="h-3 w-3 animate-spin rounded-full border-2 border-muted/30 border-t-muted" />
                      Loading repos...
                    </span>
                  ) : 'Choose repository'}
                </button>
              ) : (
                <div className="flex items-center gap-2">
                  <select
                    value={selectedRepo}
                    onChange={(e) => setSelectedRepo(e.target.value)}
                    className="flex-1 rounded-lg border border-border bg-bg px-3 py-2 text-[13px] text-text focus:border-agent/50 focus:outline-none"
                  >
                    <option value="">Select a repository...</option>
                    {repos.map((r) => (
                      <option key={r.full_name} value={r.full_name}>
                        {r.full_name}
                      </option>
                    ))}
                  </select>
                  <button
                    onClick={linkRepo}
                    disabled={!selectedRepo || linking}
                    className="shrink-0 rounded-lg bg-text px-4 py-2 text-[13px] font-semibold text-bg transition-opacity hover:opacity-90 disabled:opacity-40"
                  >
                    {linking ? 'Linking...' : 'Link'}
                  </button>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

/* ------------------------------------------------------------ */
/*  Main Dashboard                                               */
/* ------------------------------------------------------------ */
export function Dashboard({ site, activeSection = 'site' }) {
  const { requests, agentEvents, stats, findings, setFindings } = useSiteData(site.site_id)
  const [testRunning, setTestRunning] = useState(false)
  const [testResults, setTestResults] = useState(null)
  const [cycleRunning, setCycleRunning] = useState(false)
  const [lastCycle, setLastCycle] = useState(null)
  const [dnsStatus, setDnsStatus] = useState(null)
  const [verifying, setVerifying] = useState(false)
  const [verifyCooldown, setVerifyCooldown] = useState(0)
  const [cnameValue, setCnameValue] = useState('')
  const [cnameCopied, setCnameCopied] = useState(false)
  const [repoInfo, setRepoInfo] = useState(null)
  const [repoLoading, setRepoLoading] = useState(true)

  // Fetch DNS status on mount
  useEffect(() => {
    const fetchDns = async () => {
      try {
        const res = await fetch(`/api/sites/${site.site_id}/status`)
        if (res.ok) {
          const data = await res.json()
          setDnsStatus(data)
          if (data.proxy_cname) setCnameValue(data.proxy_cname)
        }
      } catch {}
    }
    fetchDns()
    // Poll if pending
    if (site.status !== 'active') {
      const interval = setInterval(fetchDns, 15000)
      return () => clearInterval(interval)
    }
  }, [site.site_id, site.status])

  // Fetch repo link status
  useEffect(() => {
    const fetchRepo = async () => {
      try {
        const res = await fetch(`/api/sites/${site.site_id}/repo`)
        if (res.ok) {
          const data = await res.json()
          setRepoInfo(data)
        }
      } catch {}
      setRepoLoading(false)
    }
    fetchRepo()
  }, [site.site_id])

  const handleFindingStatusChange = useCallback((findingId, newStatus) => {
    setFindings((prev) =>
      prev.map((f) => (f.id === findingId ? { ...f, status: newStatus } : f))
    )
  }, [setFindings])

  const hasTraffic = requests.length > 0

  const copyCname = () => {
    navigator.clipboard.writeText(cnameValue)
    setCnameCopied(true)
    setTimeout(() => setCnameCopied(false), 2000)
  }

  // Cooldown ticker
  useEffect(() => {
    if (verifyCooldown <= 0) return
    const t = setTimeout(() => setVerifyCooldown((v) => v - 1), 1000)
    return () => clearTimeout(t)
  }, [verifyCooldown])

  const verifyDns = async () => {
    if (verifyCooldown > 0) return
    setVerifying(true)
    setVerifyCooldown(30)
    try {
      await fetch(`/api/sites/${site.site_id}/verify`, { method: 'POST' })
      const res = await fetch(`/api/sites/${site.site_id}/status`)
      if (res.ok) setDnsStatus(await res.json())
    } catch {}
    setVerifying(false)
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
    } catch {
      // Keep UI responsive if the cycle endpoint fails.
    }
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
        // Extract HTTP method + path from the raw request first line
        const firstLine = (r.message || '').split('\n')[0] || ''
        const methodMatch = firstLine.match(/^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)/)
        const method = methodMatch ? methodMatch[1] : null
        const path = methodMatch ? methodMatch[2] : null

        items.push({
          time: r.timestamp ? new Date(r.timestamp).getTime() : 0,
          timestamp: r.timestamp,
          summary,
          color,
          blocked: r.blocked,
          kind: 'request',
          category: attackCategory(r.attack_type),
          attackType: r.attack_type,
          classification: r.classification,
          confidence: r.confidence != null ? Math.round(r.confidence * 100) : null,
          explanation: attackExplanation(r.attack_type),
          rawRequest: r.message || '',
          classifier: r.classifier || '',
          sourceIp: r.source_ip || '',
          responseTimeMs: r.response_time_ms,
          method,
          path,
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
        category: 'agent',
        agentName: evt.agent ? evt.agent.charAt(0).toUpperCase() + evt.agent.slice(1) : null,
        explanation: summary,
      })
    })

    items.sort((a, b) => b.time - a.time)
    return items.slice(0, 50)
  }, [requests, agentEvents])

  const safeCount = requests.filter((r) => r.classification === 'SAFE').length
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
              helpText={SECTION_META.site.helpText}
            />

            {/* Connection status */}
            <ConnectionBanner
              hasTraffic={hasTraffic}
              site={site}
              dnsStatus={dnsStatus}
            />

            {/* Stats bar */}
            <StatsBar stats={stats} />

            {/* Activity feed */}
            <div className="border-b border-border">
              <div className="flex items-center justify-between px-6 py-4 border-b border-border/50">
                <div className="flex items-center gap-2.5">
                  {/* Animated live dot */}
                  <div className="relative flex h-3 w-3 items-center justify-center">
                    {hasTraffic && (
                      <span
                        className="absolute inline-flex h-full w-full rounded-full bg-safe/40"
                        style={{ animation: 'ping 2s cubic-bezier(0,0,0.2,1) infinite' }}
                      />
                    )}
                    <span className={`relative inline-flex h-2 w-2 rounded-full ${hasTraffic ? 'bg-safe' : 'bg-muted'}`} />
                  </div>
                  <h4 className="text-[15px] font-semibold text-text">Live activity</h4>
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
                <EmptyFeed hasTraffic={hasTraffic} />
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
              helpText={SECTION_META.agents.helpText}
              action={
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
              }
            />

            {/* Pipeline: Scout → Red Team → Adapt */}
            <AgentPipeline events={agentEvents} />

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

            {/* Activity feed + Protection timeline */}
            <div className="grid min-h-[500px] grid-cols-1 lg:grid-cols-[1fr_340px]">
              <div className="min-h-0 border-b border-border lg:border-b-0 lg:border-r">
                <AgentLog events={agentEvents} />
              </div>
              <div className="min-h-0 flex flex-col">
                <BlockRateChart siteId={site.site_id} />
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
              helpText={SECTION_META.threats.helpText}
            />
            <ThreatTable siteId={site.site_id} />
          </div>
        )}

        {/* ================================================================ */}
        {/*  FINDINGS SECTION                                                */}
        {/* ================================================================ */}
        {activeSection === 'findings' && (
          <div className="mx-auto max-w-5xl">
            <SectionHeader
              title={SECTION_META.findings.title}
              description={SECTION_META.findings.description}
              helpText={SECTION_META.findings.helpText}
            />
            {repoLoading ? (
              <div className="flex min-h-[200px] items-center justify-center">
                <div className="h-6 w-6 animate-spin rounded-full border-2 border-border border-t-agent" />
              </div>
            ) : (
              <FindingsPanel
                siteId={site.site_id}
                findings={findings}
                onFindingStatusChange={handleFindingStatusChange}
                repoLinked={repoInfo?.linked === true}
              />
            )}
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
              helpText={SECTION_META.setup.helpText}
            />

            <div className="px-6 py-8 space-y-6">
              {/* ---- DNS Status Banner ---- */}
              {(site.status === 'active' || dnsStatus?.status === 'active') ? (
                <div className="flex items-center gap-3 rounded-xl border border-safe/20 bg-safe/[0.06] px-5 py-4">
                  <div className="relative flex h-5 w-5 items-center justify-center">
                    <span className="absolute inline-flex h-3 w-3 rounded-full bg-safe/30" style={{ animation: 'ping 2s cubic-bezier(0,0,0.2,1) infinite' }} />
                    <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-safe" />
                  </div>
                  <div>
                    <p className="text-[15px] font-semibold text-safe">DNS verified — traffic is flowing through Veil</p>
                    <p className="mt-0.5 text-[13px] text-dim">
                      <span className="font-mono">{site.domain}</span> is pointed at Veil and all requests are being monitored.
                    </p>
                  </div>
                </div>
              ) : (
                <div className="flex items-center gap-3 rounded-xl border border-suspicious/20 bg-suspicious/[0.06] px-5 py-4">
                  <div className="relative flex h-5 w-5 items-center justify-center">
                    <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-suspicious" />
                  </div>
                  <div>
                    <p className="text-[15px] font-semibold text-suspicious">Pending DNS — not yet connected</p>
                    <p className="mt-0.5 text-[13px] text-dim">
                      Update your DNS to point <span className="font-mono text-text">{site.domain}</span> to Veil. Follow the instructions below.
                    </p>
                  </div>
                </div>
              )}

              {/* ---- Step 1: DNS ---- */}
              <div className="rounded-xl border border-border bg-surface/30 p-6">
                <div className="flex items-start gap-4">
                  <div className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-full border ${
                    (site.status === 'active' || dnsStatus?.status === 'active')
                      ? 'border-safe/30 bg-safe/10'
                      : 'border-peek/30 bg-peek/10'
                  }`}>
                    {(site.status === 'active' || dnsStatus?.status === 'active') ? (
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" className="text-safe">
                        <path d="M20 6L9 17l-5-5" />
                      </svg>
                    ) : (
                      <span className="text-[15px] font-bold text-peek">1</span>
                    )}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <h3 className="text-[17px] font-semibold text-text">Update your DNS</h3>
                        <p className="mt-1 text-[14px] text-muted">
                          Add a CNAME record to route <span className="font-mono text-text">{site.domain}</span> through Veil.
                        </p>
                      </div>
                      {(site.status === 'active' || dnsStatus?.status === 'active') && (
                        <span className="shrink-0 rounded-full bg-safe/15 px-3 py-1 text-[12px] font-semibold text-safe">
                          Verified
                        </span>
                      )}
                    </div>

                    {/* DNS record table */}
                    <div className="mt-4 overflow-hidden rounded-lg border border-border bg-bg">
                      <table className="w-full text-left">
                        <thead>
                          <tr className="border-b border-border/50 text-[11px] font-medium tracking-wide text-muted uppercase">
                            <th className="px-4 py-2">Type</th>
                            <th className="px-4 py-2">Name</th>
                            <th className="px-4 py-2">Value</th>
                          </tr>
                        </thead>
                        <tbody>
                          <tr className="text-[13px]">
                            <td className="px-4 py-3">
                              <span className="rounded bg-agent/10 px-2 py-0.5 text-[12px] font-semibold text-agent">CNAME</span>
                            </td>
                            <td className="px-4 py-3 font-mono text-text">{site.domain}</td>
                            <td className="px-4 py-3">
                              <div className="flex items-center gap-2">
                                <span className="font-mono text-safe">{cnameValue || 'loading...'}</span>
                                {cnameValue && (
                                  <button
                                    onClick={copyCname}
                                    className="shrink-0 rounded-md border border-border bg-surface px-2 py-0.5 text-[12px] font-medium text-muted transition-all hover:border-dim hover:text-text"
                                  >
                                    {cnameCopied ? 'Copied' : 'Copy'}
                                  </button>
                                )}
                              </div>
                            </td>
                          </tr>
                        </tbody>
                      </table>
                    </div>

                    {/* Verify button */}
                    {site.status !== 'active' && dnsStatus?.status !== 'active' && (
                      <div className="mt-3 flex items-center gap-3">
                        <button
                          onClick={verifyDns}
                          disabled={verifying || verifyCooldown > 0}
                          className="rounded-lg border border-border bg-transparent px-4 py-2 text-[13px] font-medium text-muted transition-all hover:border-dim hover:text-text disabled:opacity-40 disabled:cursor-not-allowed"
                        >
                          {verifying
                            ? 'Checking...'
                            : verifyCooldown > 0
                              ? `Wait ${verifyCooldown}s`
                              : 'Verify DNS'}
                        </button>
                        <span className="text-[12px] text-muted">Auto-checking every 15s</span>
                      </div>
                    )}
                  </div>
                </div>
              </div>

              {/* ---- Step 2: Test ---- */}
              <div className="rounded-xl border border-border bg-surface/30 p-6">
                <div className="flex items-start gap-4">
                  <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full border border-poke/30 bg-poke/10">
                    <span className="text-[15px] font-bold text-poke">2</span>
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <h3 className="text-[17px] font-semibold text-text">Test your defences</h3>
                        <p className="mt-1 text-[14px] text-muted">
                          Fire simulated attacks at the detection engine to see what gets caught.
                        </p>
                      </div>
                      <img src="/svg/3.png" alt="" className="h-16 w-16 shrink-0 object-contain opacity-60" />
                    </div>
                    <button
                      onClick={runTests}
                      disabled={testRunning}
                      className="mt-4 rounded-lg bg-text px-5 py-2.5 text-[14px] font-semibold text-bg transition-opacity hover:opacity-90 disabled:opacity-40"
                    >
                      {testRunning ? (
                        <span className="flex items-center gap-2">
                          <span className="h-3 w-3 animate-spin rounded-full border-2 border-bg/30 border-t-bg" />
                          Testing...
                        </span>
                      ) : 'Run tests'}
                    </button>

                    {testResults && (
                      <div className="mt-5">
                        <TestResultsSummary results={testResults} />
                      </div>
                    )}
                  </div>
                </div>
              </div>

              {/* ---- Step 3: Link Repository ---- */}
              <RepoConnectCard siteId={site.site_id} repoInfo={repoInfo} setRepoInfo={setRepoInfo} repoLoading={repoLoading} />

              {/* ---- Step 4: Improve ---- */}
              <div className="rounded-xl border border-border bg-surface/30 p-6">
                <div className="flex items-start gap-4">
                  <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full border border-patch/30 bg-patch/10">
                    <span className="text-[15px] font-bold text-patch">4</span>
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <h3 className="text-[17px] font-semibold text-text">Let the agents improve</h3>
                        <p className="mt-1 text-[14px] text-muted">
                          Head to the Agents tab and run an improvement cycle. Veil's AI agents will discover new attacks, test them, and patch any gaps automatically.
                        </p>
                      </div>
                      <div className="flex shrink-0 -space-x-3">
                        <img src="/svg/2.png" alt="" className="h-12 w-12 object-contain opacity-50" />
                        <img src="/svg/4.png" alt="" className="h-12 w-12 object-contain opacity-50" />
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              {/* ---- Danger zone ---- */}
              <div className="pt-4">
                <div className="flex items-center justify-between rounded-xl border border-border/50 px-5 py-4">
                  <div>
                    <p className="text-[14px] font-medium text-muted">Remove project</p>
                    <p className="mt-0.5 text-[13px] text-muted/70">
                      Stop protecting {site.target_url} and delete all data.
                    </p>
                  </div>
                  <button
                    onClick={async () => {
                      if (!window.confirm(`Remove this project? This will stop protecting ${site.target_url}.`)) return
                      try {
                        const res = await fetch(`/api/sites/${site.site_id}`, { method: 'DELETE' })
                        if (res.ok) window.location.href = '/app/projects'
                      } catch {
                        // Ignore delete errors here; user can retry.
                      }
                    }}
                    className="shrink-0 rounded-lg border border-blocked/30 px-3.5 py-1.5 text-[13px] font-medium text-blocked transition-all hover:bg-blocked/10"
                  >
                    Delete
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}
        {/* ── Section: Compliance & Analytics ── */}
        {activeSection === 'compliance' && (
          <ComplianceView />
        )}
      </div>
    </div>
  )
}
