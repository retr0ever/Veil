import { useState } from 'react'
import { humaniseRequest, humaniseAttackType, relativeTime } from '../lib/humanise'

const statusDotClass = {
  SUSPICIOUS: 'bg-suspicious shadow-[0_0_6px_rgba(242,199,122,0.5)]',
  MALICIOUS: 'bg-blocked shadow-[0_0_6px_rgba(240,138,149,0.5)]',
}

export function RequestFeed({ requests }) {
  const [expanded, setExpanded] = useState(null)

  const safeCount = requests.filter((r) => r.classification === 'SAFE').length
  const notable = requests.filter((r) => r.classification !== 'SAFE')

  return (
    <div className="flex min-h-0 flex-1 flex-col overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-border px-6 py-3">
        <div className="flex items-center gap-2.5">
          <div className="relative flex h-2 w-2">
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-agent opacity-50" style={{ animationDuration: '2s' }} />
            <span className="relative inline-flex h-2 w-2 rounded-full bg-agent" />
          </div>
          <span className="text-[15px] font-medium text-text">Live activity</span>
        </div>
        {safeCount > 0 && (
          <span className="flex items-center gap-1.5 rounded-md bg-safe/8 px-2.5 py-1 text-[13px] font-medium text-safe">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
              <path d="M20 6L9 17l-5-5" />
            </svg>
            {safeCount} safe request{safeCount !== 1 ? 's' : ''} passed
          </span>
        )}
      </div>

      {/* Context banner */}
      <div className="border-b border-border/50 bg-surface px-6 py-2">
        <p className="text-[13px] leading-relaxed text-muted">
          All classifications shown, including agent self-testing.
        </p>
      </div>

      {/* Feed items */}
      <div className="flex-1 overflow-y-auto">
        {/* Empty state */}
        {requests.length === 0 && (
          <div className="flex flex-col items-center justify-center px-6 py-12 text-center">
            <div className="mb-4 flex h-12 w-12 items-center justify-center rounded-full border border-border bg-surface">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" className="text-muted">
                <path d="M22 12h-4l-3 9L9 3l-3 9H2" />
              </svg>
            </div>
            <p className="text-[16px] font-medium text-text">No activity yet</p>
            <p className="mt-1.5 max-w-[280px] text-[15px] text-muted">
              Connect your site or start an improvement cycle to see live classifications here.
            </p>
          </div>
        )}

        {notable.map((req, i) => {
          const { summary, color } = humaniseRequest(req)
          const isExpanded = expanded === i
          const dotClass =
            statusDotClass[req.classification] || 'bg-muted'

          return (
            <div key={i}>
              <button
                type="button"
                onClick={() => setExpanded(isExpanded ? null : i)}
                className={`group flex w-full items-center gap-3 border-b border-border/50 px-6 py-3 text-left transition-colors duration-100 hover:bg-surface ${
                  req.blocked ? 'bg-blocked/[0.03]' : ''
                } ${isExpanded ? 'bg-surface' : ''}`}
              >
                {/* Status dot */}
                <div className={`h-2 w-2 shrink-0 rounded-full ${dotClass}`} />

                {/* Summary */}
                <span className={`flex-1 text-[15px] leading-snug ${color}`}>
                  {summary}
                </span>

                {/* Timestamp */}
                <span className="shrink-0 text-[13px] text-muted">
                  {relativeTime(req.timestamp)}
                </span>

                {/* Blocked badge */}
                {req.blocked && (
                  <span className="shrink-0 rounded bg-blocked/10 px-2 py-0.5 text-[12px] font-semibold tracking-wide text-blocked">
                    BLOCKED
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
                  className={`shrink-0 text-muted/50 transition-transform duration-150 group-hover:text-muted ${
                    isExpanded ? 'rotate-90' : ''
                  }`}
                >
                  <polyline points="9 18 15 12 9 6" />
                </svg>
              </button>

              {/* Expanded details */}
              {isExpanded && (
                <div className="border-b border-border/50 bg-surface-2 px-6 py-3.5">
                  <div className="grid grid-cols-2 gap-x-6 gap-y-2 text-[14px]">
                    <div>
                      <span className="text-muted">Classification</span>
                      <p className="mt-0.5 font-mono text-text">{req.classification}</p>
                    </div>
                    <div>
                      <span className="text-muted">Confidence</span>
                      <p className="mt-0.5 font-mono text-text">
                        {(req.confidence * 100).toFixed(0)}%
                      </p>
                    </div>
                    {req.attack_type && (
                      <div className="col-span-2">
                        <span className="text-muted">Attack type</span>
                        <p className="mt-0.5 text-text">
                          {humaniseAttackType(req.attack_type)}
                        </p>
                      </div>
                    )}
                    {req.message && (
                      <div className="col-span-2">
                        <span className="text-muted">Raw payload</span>
                        <p className="mt-1 break-all rounded-md bg-bg px-2.5 py-2 font-mono text-[13px] text-dim">
                          {req.message}
                        </p>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}
