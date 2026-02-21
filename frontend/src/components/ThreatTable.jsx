import { useState, useEffect } from 'react'
import { humaniseAttackType, attackExplanation } from '../lib/humanise'

const severityConfig = {
  critical: {
    border: 'border-l-red-500',
    badge: 'bg-blocked/10 text-blocked',
    label: 'Critical',
  },
  high: {
    border: 'border-l-orange-400',
    badge: 'bg-suspicious/10 text-suspicious',
    label: 'High',
  },
  medium: {
    border: 'border-l-yellow-400',
    badge: 'bg-yellow-400/10 text-dim',
    label: 'Medium',
  },
  low: {
    border: 'border-l-zinc-500',
    badge: 'bg-muted/10 text-muted',
    label: 'Low',
  },
}

const defaultSeverity = {
  border: 'border-l-zinc-600',
  badge: 'bg-muted/10 text-muted',
  label: 'Unknown',
}

export function ThreatTable() {
  const [threats, setThreats] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const load = async () => {
      try {
        const res = await fetch('/api/threats')
        if (res.ok) setThreats(await res.json())
      } catch {
        // Silently handle -- empty state is shown
      } finally {
        setLoading(false)
      }
    }
    load()
    const interval = setInterval(load, 10000)
    return () => clearInterval(interval)
  }, [])

  const exposed = threats.filter((t) => !t.blocked)
  const patched = threats.filter((t) => t.blocked)
  const sorted = [...exposed, ...patched]

  return (
    <div className="flex min-h-0 flex-1 flex-col overflow-hidden">
      {/* Legend / description */}
      <div className="border-b border-border bg-surface px-6 py-4">
        <p className="text-[15px] leading-relaxed text-dim">
          Techniques discovered by Veil's agents.{' '}
          <span className="inline-flex items-center gap-1">
            <span className="inline-block h-2 w-2 rounded-full bg-safe" />
            <span className="font-medium text-safe">Patched</span>
          </span>{' '}
          = blocked.{' '}
          <span className="inline-flex items-center gap-1">
            <span className="inline-block h-2 w-2 rounded-full bg-blocked" />
            <span className="font-medium text-blocked">Exposed</span>
          </span>{' '}
          = gap being fixed.
        </p>
      </div>

      {/* Summary header */}
      <div className="flex items-center justify-between border-b border-border px-6 py-3">
        <span className="text-[15px] font-medium text-text">All threats</span>
        {threats.length > 0 && (
          <div className="flex items-center gap-3 text-[13px]">
            <span className="flex items-center gap-1.5 text-dim">
              <span className="inline-block h-1.5 w-1.5 rounded-full bg-dim" />
              {threats.length} discovered
            </span>
            <span className="flex items-center gap-1.5 text-safe">
              <span className="inline-block h-1.5 w-1.5 rounded-full bg-safe" />
              {patched.length} patched
            </span>
            {exposed.length > 0 && (
              <span className="flex items-center gap-1.5 text-blocked">
                <span className="inline-block h-1.5 w-1.5 rounded-full bg-blocked" />
                {exposed.length} exposed
              </span>
            )}
          </div>
        )}
      </div>

      {/* Threat list */}
      <div className="flex-1 overflow-y-auto px-6 py-4 space-y-2.5">
        {/* Loading state */}
        {loading && threats.length === 0 && (
          <div className="flex items-center justify-center py-12">
            <div className="flex flex-col items-center gap-3">
              <div className="h-6 w-6 animate-spin rounded-full border-2 border-border border-t-agent" />
              <span className="text-[15px] text-muted">Loading threats...</span>
            </div>
          </div>
        )}

        {/* Empty state */}
        {!loading && threats.length === 0 && (
          <div className="flex flex-col items-center justify-center px-4 py-12 text-center">
            <div className="mb-4 flex h-12 w-12 items-center justify-center rounded-full border border-border bg-surface">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" className="text-muted">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              </svg>
            </div>
            <p className="text-[16px] font-medium text-text">No threats discovered yet</p>
            <p className="mt-1.5 max-w-[300px] text-[15px] text-muted">
              Run an improvement cycle to let Veil's agents discover and test attack techniques against your API.
            </p>
          </div>
        )}

        {/* Threat cards */}
        {sorted.map((t) => {
          const severity = severityConfig[t.severity] || defaultSeverity

          return (
            <div
              key={t.id}
              className={`rounded-lg border border-border/60 border-l-[3px] bg-bg p-4 transition-colors duration-100 hover:border-border ${severity.border}`}
            >
              {/* Top row: title + badges */}
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0 flex-1">
                  <p className="text-[16px] font-medium leading-snug text-text">
                    {t.technique_name}
                  </p>
                  <p className="mt-1 text-[14px] text-muted">
                    {humaniseAttackType(t.category)}
                  </p>
                </div>

                {/* Badges */}
                <div className="flex shrink-0 items-center gap-2">
                  {/* Source badge */}
                  {t.source && (
                    <span
                      className={`rounded px-2 py-0.5 text-[12px] font-medium ${
                        t.source === 'ai' || t.source === 'ai-generated'
                          ? 'bg-agent/10 text-agent'
                          : 'bg-border/50 text-muted'
                      }`}
                    >
                      {t.source === 'ai' || t.source === 'ai-generated'
                        ? 'AI-generated'
                        : 'OWASP Top 10'}
                    </span>
                  )}

                  {/* Severity badge */}
                  <span
                    className={`rounded px-2 py-0.5 text-[12px] font-semibold ${severity.badge}`}
                  >
                    {severity.label}
                  </span>

                  {/* Status badge */}
                  {t.blocked ? (
                    <span className="flex items-center gap-1 rounded bg-safe/10 px-2 py-0.5 text-[13px] font-semibold text-safe">
                      <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round">
                        <path d="M20 6L9 17l-5-5" />
                      </svg>
                      Patched
                    </span>
                  ) : (
                    <span className="flex items-center gap-1 rounded bg-blocked/10 px-2 py-0.5 text-[13px] font-semibold text-blocked">
                      <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round">
                        <circle cx="12" cy="12" r="10" />
                      </svg>
                      Exposed
                    </span>
                  )}
                </div>
              </div>

              {/* Description */}
              <p className="mt-2.5 text-[14px] leading-relaxed text-muted/80">
                {attackExplanation(t.category)}
              </p>
            </div>
          )
        })}
      </div>
    </div>
  )
}
