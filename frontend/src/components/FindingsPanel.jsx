import { useState } from 'react'
import { relativeTime } from '../lib/humanise'

/* ── Status colours ─────────────────────────────────────── */
const STATUS_STYLES = {
  open:           { bg: 'bg-blocked/10', text: 'text-blocked',    label: 'Open' },
  acknowledged:   { bg: 'bg-suspicious/10', text: 'text-suspicious', label: 'Acknowledged' },
  fixed:          { bg: 'bg-safe/10', text: 'text-safe',          label: 'Fixed' },
  false_positive: { bg: 'bg-muted/10', text: 'text-muted',       label: 'False positive' },
}

const FINDING_TYPE_ICONS = {
  sqli: 'SQL Injection',
  xss: 'Cross-Site Scripting',
  ssrf: 'Server-Side Request Forgery',
  rce: 'Remote Code Execution',
  path_traversal: 'Path Traversal',
  command_injection: 'Command Injection',
  xxe: 'XML External Entity',
  idor: 'Insecure Direct Object Ref',
}

/* ── Summary bar ────────────────────────────────────────── */
function FindingsSummary({ findings }) {
  const open = findings.filter((f) => f.status === 'open').length
  const ack = findings.filter((f) => f.status === 'acknowledged').length
  const fixed = findings.filter((f) => f.status === 'fixed').length
  const fp = findings.filter((f) => f.status === 'false_positive').length

  return (
    <div className="grid grid-cols-4 gap-3 px-6 py-4 border-b border-border">
      <div className="rounded-lg border border-border bg-surface/30 px-4 py-3 text-center">
        <p className="text-[22px] font-bold text-blocked">{open}</p>
        <p className="text-[12px] font-medium text-muted uppercase tracking-wide">Open</p>
      </div>
      <div className="rounded-lg border border-border bg-surface/30 px-4 py-3 text-center">
        <p className="text-[22px] font-bold text-suspicious">{ack}</p>
        <p className="text-[12px] font-medium text-muted uppercase tracking-wide">Acknowledged</p>
      </div>
      <div className="rounded-lg border border-border bg-surface/30 px-4 py-3 text-center">
        <p className="text-[22px] font-bold text-safe">{fixed}</p>
        <p className="text-[12px] font-medium text-muted uppercase tracking-wide">Fixed</p>
      </div>
      <div className="rounded-lg border border-border bg-surface/30 px-4 py-3 text-center">
        <p className="text-[22px] font-bold text-dim">{fp}</p>
        <p className="text-[12px] font-medium text-muted uppercase tracking-wide">False +</p>
      </div>
    </div>
  )
}

/* ── Finding card ───────────────────────────────────────── */
function FindingCard({ finding, onStatusChange }) {
  const [expanded, setExpanded] = useState(false)
  const [updating, setUpdating] = useState(false)
  const status = STATUS_STYLES[finding.status] || STATUS_STYLES.open
  const typeLabel = FINDING_TYPE_ICONS[finding.finding_type] || finding.finding_type

  const lineRange = finding.line_start
    ? finding.line_end && finding.line_end !== finding.line_start
      ? `L${finding.line_start}-${finding.line_end}`
      : `L${finding.line_start}`
    : null

  const changeStatus = async (newStatus) => {
    setUpdating(true)
    try {
      const res = await fetch(`/api/sites/${finding.site_id}/findings/${finding.id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: newStatus }),
      })
      if (res.ok) {
        onStatusChange(finding.id, newStatus)
      }
    } catch {}
    setUpdating(false)
  }

  return (
    <div className="border-b border-border/40">
      <button
        onClick={() => setExpanded((v) => !v)}
        className="flex w-full items-center gap-3 bg-transparent border-none px-6 py-4 text-left transition-colors hover:bg-surface/30"
      >
        {/* Confidence indicator */}
        <div className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-lg ${
          finding.confidence >= 0.8 ? 'bg-blocked/15 text-blocked' :
          finding.confidence >= 0.5 ? 'bg-suspicious/15 text-suspicious' :
          'bg-muted/15 text-muted'
        }`}>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
            <polyline points="16 18 22 12 16 6" /><polyline points="8 6 2 12 8 18" />
          </svg>
        </div>

        {/* File path + type */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="truncate text-[14px] font-mono font-medium text-text">
              {finding.file_path}
              {lineRange && <span className="text-agent ml-1">:{lineRange}</span>}
            </span>
          </div>
          <p className="mt-0.5 truncate text-[13px] text-dim">{finding.description}</p>
        </div>

        {/* Type badge */}
        <span className="shrink-0 rounded-md bg-agent/10 px-2 py-0.5 text-[11px] font-semibold tracking-wide text-agent">
          {typeLabel}
        </span>

        {/* Status badge */}
        <span className={`shrink-0 rounded-md px-2 py-0.5 text-[11px] font-semibold tracking-wide uppercase ${status.bg} ${status.text}`}>
          {status.label}
        </span>

        {/* Timestamp */}
        <span className="shrink-0 text-[12px] text-muted tabular-nums">
          {relativeTime(finding.created_at)}
        </span>

        {/* Chevron */}
        <svg
          width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"
          className={`shrink-0 text-muted transition-transform duration-200 ${expanded ? 'rotate-90' : ''}`}
        >
          <polyline points="9 18 15 12 9 6" />
        </svg>
      </button>

      {/* Expanded detail */}
      <div className={`overflow-hidden transition-all duration-200 ease-out ${expanded ? 'max-h-[600px] opacity-100' : 'max-h-0 opacity-0'}`}>
        <div className="mx-6 mb-4 space-y-3">
          {/* Code snippet */}
          {finding.snippet && (
            <div className="rounded-lg border border-border bg-bg overflow-hidden">
              <div className="flex items-center justify-between px-3 py-1.5 border-b border-border/50 bg-surface/30">
                <span className="text-[11px] font-medium text-muted uppercase tracking-wide">Vulnerable code</span>
                {lineRange && (
                  <span className="text-[11px] font-mono text-dim">{lineRange}</span>
                )}
              </div>
              <pre className="px-4 py-3 text-[13px] leading-relaxed text-text font-mono overflow-x-auto whitespace-pre-wrap">
                {finding.snippet}
              </pre>
            </div>
          )}

          {/* Suggested fix */}
          {finding.suggested_fix && (
            <div className="rounded-lg border border-safe/20 bg-safe/[0.03] overflow-hidden">
              <div className="flex items-center gap-2 px-3 py-1.5 border-b border-safe/10">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="text-safe">
                  <path d="M22 11.08V12a10 10 0 11-5.93-9.14" /><polyline points="22 4 12 14.01 9 11.01" />
                </svg>
                <span className="text-[11px] font-medium text-safe uppercase tracking-wide">Suggested fix</span>
              </div>
              <pre className="px-4 py-3 text-[13px] leading-relaxed text-dim font-mono overflow-x-auto whitespace-pre-wrap">
                {finding.suggested_fix}
              </pre>
            </div>
          )}

          {/* Meta info */}
          <div className="flex flex-wrap gap-x-5 gap-y-2 text-[13px]">
            <span className="text-muted">
              Confidence: <span className="font-mono font-medium text-text">{Math.round(finding.confidence * 100)}%</span>
            </span>
            <span className="text-muted">
              Type: <span className="font-medium text-text">{typeLabel}</span>
            </span>
          </div>

          {/* Status actions */}
          <div className="flex items-center gap-2 pt-1">
            {finding.status !== 'acknowledged' && (
              <button
                onClick={() => changeStatus('acknowledged')}
                disabled={updating}
                className="rounded-lg border border-border px-3 py-1.5 text-[12px] font-medium text-muted transition-all hover:border-suspicious/40 hover:text-suspicious disabled:opacity-40"
              >
                Acknowledge
              </button>
            )}
            {finding.status !== 'fixed' && (
              <button
                onClick={() => changeStatus('fixed')}
                disabled={updating}
                className="rounded-lg border border-border px-3 py-1.5 text-[12px] font-medium text-muted transition-all hover:border-safe/40 hover:text-safe disabled:opacity-40"
              >
                Mark fixed
              </button>
            )}
            {finding.status !== 'false_positive' && (
              <button
                onClick={() => changeStatus('false_positive')}
                disabled={updating}
                className="rounded-lg border border-border px-3 py-1.5 text-[12px] font-medium text-muted transition-all hover:border-dim hover:text-dim disabled:opacity-40"
              >
                False positive
              </button>
            )}
            {finding.status !== 'open' && (
              <button
                onClick={() => changeStatus('open')}
                disabled={updating}
                className="rounded-lg border border-border px-3 py-1.5 text-[12px] font-medium text-muted transition-all hover:border-blocked/40 hover:text-blocked disabled:opacity-40"
              >
                Reopen
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

/* ── Empty states ───────────────────────────────────────── */
function NoRepoLinked({ siteId }) {
  return (
    <div className="flex min-h-[320px] flex-col items-center justify-center px-6 py-14 text-center">
      <div className="mb-4 flex h-12 w-12 items-center justify-center rounded-xl border border-border bg-surface">
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className="text-muted">
          <path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 00-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0020 4.77 5.07 5.07 0 0019.91 1S18.73.65 16 2.48a13.38 13.38 0 00-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 005 4.77a5.44 5.44 0 00-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 009 18.13V22" />
        </svg>
      </div>
      <p className="text-[16px] font-semibold text-text">Connect your GitHub repository</p>
      <p className="mt-1.5 max-w-sm text-[14px] text-dim">
        Link a repo to this site so Veil's AI agents can scan your source code for the vulnerabilities they discover in your traffic.
      </p>
      <p className="mt-3 text-[13px] text-muted">
        Go to <span className="font-medium text-text">Setup</span> to link your repository.
      </p>
    </div>
  )
}

function NoFindings() {
  return (
    <div className="flex min-h-[240px] flex-col items-center justify-center px-6 py-14 text-center">
      <div className="mb-4 flex h-12 w-12 items-center justify-center rounded-xl border border-safe/20 bg-safe/[0.06]">
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className="text-safe">
          <path d="M22 11.08V12a10 10 0 11-5.93-9.14" /><polyline points="22 4 12 14.01 9 11.01" />
        </svg>
      </div>
      <p className="text-[16px] font-semibold text-safe">No vulnerabilities found</p>
      <p className="mt-1.5 max-w-xs text-[14px] text-dim">
        Veil hasn't found any code-level vulnerabilities yet. Run a scan or wait for the next agent cycle.
      </p>
    </div>
  )
}

/* ── Main panel ─────────────────────────────────────────── */
export function FindingsPanel({ siteId, findings, onFindingStatusChange, repoLinked }) {
  const [scanning, setScanning] = useState(false)
  const [scanResult, setScanResult] = useState(null)
  const [filter, setFilter] = useState('all')

  const triggerScan = async () => {
    setScanning(true)
    setScanResult(null)
    try {
      const res = await fetch(`/api/sites/${siteId}/scan`, { method: 'POST' })
      if (res.ok) {
        const data = await res.json()
        setScanResult(data)
      }
    } catch {}
    setScanning(false)
  }

  if (!repoLinked) {
    return <NoRepoLinked siteId={siteId} />
  }

  const filtered = filter === 'all'
    ? findings
    : findings.filter((f) => f.status === filter)

  return (
    <div>
      {findings.length > 0 && <FindingsSummary findings={findings} />}

      {/* Filter + scan controls */}
      <div className="flex items-center justify-between gap-3 px-6 py-3 border-b border-border/50">
        <div className="flex items-center gap-1.5">
          {['all', 'open', 'acknowledged', 'fixed', 'false_positive'].map((f) => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={`rounded-md px-2.5 py-1 text-[12px] font-medium transition-colors ${
                filter === f
                  ? 'bg-white/[0.07] text-text'
                  : 'bg-transparent text-muted hover:text-dim'
              }`}
            >
              {f === 'all' ? 'All' : f === 'false_positive' ? 'False +' : f.charAt(0).toUpperCase() + f.slice(1)}
            </button>
          ))}
        </div>

        <div className="flex items-center gap-3">
          {scanResult && (
            <span className="text-[12px] text-safe">
              Found {scanResult.findings_count} issue{scanResult.findings_count !== 1 ? 's' : ''} across {scanResult.attacks_scanned} attack type{scanResult.attacks_scanned !== 1 ? 's' : ''}
            </span>
          )}
          <button
            onClick={triggerScan}
            disabled={scanning}
            className="shrink-0 rounded-lg border border-border bg-transparent px-4 py-2 text-[13px] font-medium text-muted transition-all hover:border-dim hover:text-text disabled:opacity-40"
          >
            {scanning ? (
              <span className="flex items-center gap-2">
                <span className="h-3 w-3 animate-spin rounded-full border-2 border-muted/30 border-t-muted" />
                Scanning...
              </span>
            ) : 'Scan Now'}
          </button>
        </div>
      </div>

      {/* Findings list */}
      {filtered.length === 0 ? (
        filter === 'all' ? <NoFindings /> : (
          <div className="flex min-h-[160px] items-center justify-center text-[14px] text-muted">
            No {filter === 'false_positive' ? 'false positive' : filter} findings
          </div>
        )
      ) : (
        <div>
          {filtered.map((f) => (
            <FindingCard
              key={f.id}
              finding={f}
              onStatusChange={onFindingStatusChange}
            />
          ))}
        </div>
      )}
    </div>
  )
}
