import { useState, useEffect } from 'react'
import { humaniseAttackType, attackExplanation } from '../lib/humanise'

const severityBorders = {
  critical: 'border-l-red-500',
  high: 'border-l-orange-400',
  medium: 'border-l-yellow-400',
  low: 'border-l-zinc-500',
}

const severityLabels = {
  critical: 'text-blocked',
  high: 'text-suspicious',
  medium: 'text-dim',
  low: 'text-muted',
}

export function ThreatTable() {
  const [threats, setThreats] = useState([])

  useEffect(() => {
    const load = async () => {
      try {
        const res = await fetch('/api/threats')
        if (res.ok) setThreats(await res.json())
      } catch {}
    }
    load()
    const interval = setInterval(load, 10000)
    return () => clearInterval(interval)
  }, [])

  const exposed = threats.filter((t) => !t.blocked)
  const patched = threats.filter((t) => t.blocked)
  const sorted = [...exposed, ...patched]

  return (
    <div className="flex flex-1 min-h-0 flex-col overflow-hidden">
      <div className="flex items-center justify-between px-4 py-2.5 border-b border-border">
        <span className="text-muted text-[12px] font-medium">Threat intelligence</span>
        {threats.length > 0 && (
          <span className="text-[11px] text-dim">
            {threats.length} threat{threats.length !== 1 ? 's' : ''} found, {patched.length} patched
          </span>
        )}
      </div>
      <div className="flex-1 overflow-y-auto p-3 space-y-2">
        {threats.length === 0 && (
          <div className="py-8 text-muted text-center text-[13px]">
            No threats discovered yet.
          </div>
        )}
        {sorted.map((t) => (
          <div
            key={t.id}
            className={`rounded-lg border border-border border-l-[3px] bg-bg p-3 ${
              severityBorders[t.severity] || 'border-l-zinc-600'
            }`}
          >
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0">
                <p className="text-[13px] font-medium text-text truncate">{t.technique_name}</p>
                <p className="mt-0.5 text-[12px] text-dim">{humaniseAttackType(t.category)}</p>
              </div>
              <div className="flex shrink-0 items-center gap-2">
                <span className={`text-[11px] font-semibold capitalize ${severityLabels[t.severity] || 'text-muted'}`}>
                  {t.severity}
                </span>
                {t.blocked ? (
                  <span className="rounded bg-safe/10 px-2 py-0.5 text-[11px] font-semibold text-safe">Patched</span>
                ) : (
                  <span className="rounded bg-blocked/10 px-2 py-0.5 text-[11px] font-semibold text-blocked">Exposed</span>
                )}
              </div>
            </div>
            <p className="mt-2 text-[12px] leading-relaxed text-muted">
              {attackExplanation(t.category)}
            </p>
          </div>
        ))}
      </div>
    </div>
  )
}
