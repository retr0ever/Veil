import { useState } from 'react'
import { humaniseRequest, humaniseAttackType, relativeTime } from '../lib/humanise'

export function RequestFeed({ requests }) {
  const [expanded, setExpanded] = useState(null)

  const safeCount = requests.filter((r) => r.classification === 'SAFE').length
  const notable = requests.filter((r) => r.classification !== 'SAFE')

  return (
    <div className="flex flex-1 min-h-0 flex-col overflow-hidden">
      <div className="flex items-center justify-between px-4 py-2.5 border-b border-border">
        <span className="text-muted text-[12px] font-medium">Classification feed</span>
        {safeCount > 0 && (
          <span className="text-[11px] text-safe">{safeCount} safe request{safeCount !== 1 ? 's' : ''} passed</span>
        )}
      </div>
      <div className="px-4 py-2 border-b border-border/40 bg-surface">
        <p className="text-[11px] text-dim leading-relaxed">
          All classifications shown, including agent self-testing.
        </p>
      </div>
      <div className="flex-1 overflow-y-auto">
        {requests.length === 0 && (
          <div className="px-4 py-8 text-muted text-center text-[13px]">
            No classifications yet. Connect your site or check the Agents tab.
          </div>
        )}
        {notable.map((req, i) => {
          const { summary, color } = humaniseRequest(req)
          const isExpanded = expanded === i
          return (
            <div key={i}>
              <button
                type="button"
                onClick={() => setExpanded(isExpanded ? null : i)}
                className={`w-full text-left px-4 py-2.5 border-b border-border/40 flex items-center gap-3 transition-colors hover:bg-surface ${
                  req.blocked ? 'bg-blocked/5' : ''
                }`}
              >
                <div className={`w-1.5 h-1.5 rounded-full shrink-0 ${
                  req.classification === 'SUSPICIOUS' ? 'bg-suspicious' : 'bg-blocked'
                }`} />
                <span className={`flex-1 text-[13px] ${color}`}>{summary}</span>
                <span className="text-[11px] text-muted shrink-0">{relativeTime(req.timestamp)}</span>
                {req.blocked && (
                  <span className="text-blocked text-[10px] font-semibold shrink-0 bg-blocked/10 px-2 py-0.5 rounded">
                    BLOCKED
                  </span>
                )}
              </button>
              {isExpanded && (
                <div className="px-4 py-3 bg-surface-2 border-b border-border/40 text-[12px] space-y-1">
                  <p className="text-muted">Classification: <span className="text-text font-mono">{req.classification}</span></p>
                  {req.attack_type && (
                    <p className="text-muted">Attack type: <span className="text-text">{humaniseAttackType(req.attack_type)}</span></p>
                  )}
                  <p className="text-muted">Confidence: <span className="text-text font-mono">{(req.confidence * 100).toFixed(0)}%</span></p>
                  {req.message && (
                    <p className="text-muted">Raw: <span className="text-dim font-mono text-[11px] break-all">{req.message}</span></p>
                  )}
                </div>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}
