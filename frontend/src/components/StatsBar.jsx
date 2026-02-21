import { useState } from 'react'

export function StatsBar({ stats }) {
  const [showDetails, setShowDetails] = useState(false)
  const rate = stats.block_rate ?? 0
  const ringColor = rate > 80 ? '#22c55e' : rate > 50 ? '#eab308' : '#ef4444'
  const ringBg = rate > 80 ? 'rgba(34,197,94,0.12)' : rate > 50 ? 'rgba(234,179,8,0.12)' : 'rgba(239,68,68,0.12)'

  const circumference = 2 * Math.PI * 52
  const filled = (rate / 100) * circumference
  const gap = circumference - filled

  const cards = [
    { label: 'Attacks Stopped', value: stats.blocked_requests, color: 'text-blocked' },
    { label: 'Threats Patched', value: stats.threats_blocked, color: 'text-safe' },
    { label: 'Defence Updates', value: `v${stats.rules_version}`, color: 'text-agent' },
  ]

  return (
    <div className="border-b border-border bg-surface px-5 py-4">
      <div className="flex items-center gap-6">
        <div className="relative flex h-[120px] w-[120px] shrink-0 items-center justify-center">
          <svg viewBox="0 0 120 120" className="h-full w-full -rotate-90">
            <circle cx="60" cy="60" r="52" fill="none" stroke={ringBg} strokeWidth="8" />
            <circle
              cx="60"
              cy="60"
              r="52"
              fill="none"
              stroke={ringColor}
              strokeWidth="8"
              strokeLinecap="round"
              strokeDasharray={`${filled} ${gap}`}
            />
          </svg>
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <span className="text-[28px] font-semibold leading-none" style={{ color: ringColor }}>
              {rate}%
            </span>
            <span className="mt-1 text-[11px] text-muted">protected</span>
          </div>
        </div>

        <div className="flex flex-1 gap-4">
          {cards.map((card) => (
            <div key={card.label} className="flex-1 rounded-xl border border-border bg-bg p-3">
              <p className="text-[11px] text-muted">{card.label}</p>
              <p className={`mt-1 text-[22px] font-semibold leading-none font-mono ${card.color}`}>
                {card.value}
              </p>
            </div>
          ))}
        </div>
      </div>

      <button
        onClick={() => setShowDetails((v) => !v)}
        className="mt-3 border-none bg-transparent text-[12px] text-dim transition-colors hover:text-text"
      >
        {showDetails ? 'Hide details' : 'Show details'}
      </button>

      {showDetails && (
        <div className="mt-2 flex gap-6 text-[12px]">
          <span className="text-muted">Total requests: <span className="font-mono text-text">{stats.total_requests}</span></span>
          <span className="text-muted">Blocked: <span className="font-mono text-blocked">{stats.blocked_requests}</span></span>
          <span className="text-muted">Threats found: <span className="font-mono text-text">{stats.total_threats}</span></span>
          <span className="text-muted">Patched: <span className="font-mono text-safe">{stats.threats_blocked}</span></span>
          <span className="text-muted">Block rate: <span className="font-mono" style={{ color: ringColor }}>{rate}%</span></span>
          <span className="text-muted">Rules: <span className="font-mono text-agent">v{stats.rules_version}</span></span>
        </div>
      )}
    </div>
  )
}
