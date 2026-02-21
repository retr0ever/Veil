import { useState } from 'react'

export function StatsBar({ stats }) {
  const [showDetails, setShowDetails] = useState(false)
  const rate = stats.block_rate ?? 0

  // Colour thresholds
  const ringColor = rate > 80 ? '#8fd9a7' : rate > 50 ? '#f2c77a' : '#f08a95'
  const ringBg = rate > 80 ? 'rgba(143,217,167,0.10)' : rate > 50 ? 'rgba(242,199,122,0.10)' : 'rgba(240,138,149,0.10)'
  const ringGlow = rate > 80 ? 'rgba(143,217,167,0.15)' : rate > 50 ? 'rgba(242,199,122,0.15)' : 'rgba(240,138,149,0.15)'

  const radius = 52
  const circumference = 2 * Math.PI * radius
  const filled = (rate / 100) * circumference
  const gap = circumference - filled

  const cards = [
    {
      label: 'Known Techniques',
      value: stats.total_threats,
      color: 'text-text',
      icon: (
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="text-muted">
          <circle cx="12" cy="12" r="10" />
          <line x1="12" y1="8" x2="12" y2="12" />
          <line x1="12" y1="16" x2="12.01" y2="16" />
        </svg>
      ),
    },
    {
      label: 'Patched',
      value: stats.threats_blocked,
      color: 'text-safe',
      icon: (
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="text-safe/60">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
        </svg>
      ),
    },
    {
      label: 'Rules',
      value: `v${stats.rules_version}`,
      color: 'text-agent',
      icon: (
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="text-agent/60">
          <rect x="4" y="4" width="16" height="16" rx="2" />
          <rect x="9" y="9" width="6" height="6" />
          <path d="M12 2v2M12 20v2M2 12h2M20 12h2" />
        </svg>
      ),
    },
  ]

  return (
    <div className="border-b border-border bg-surface">
      <div className="px-5 py-5">
        <div className="flex items-center gap-8">
          {/* Ring chart */}
          <div className="relative flex h-[130px] w-[130px] shrink-0 items-center justify-center">
            {/* Subtle glow behind ring */}
            <div
              className="absolute inset-2 rounded-full"
              style={{
                background: `radial-gradient(circle, ${ringGlow} 0%, transparent 70%)`,
              }}
            />
            <svg viewBox="0 0 120 120" className="h-full w-full -rotate-90">
              {/* Background track */}
              <circle
                cx="60"
                cy="60"
                r={radius}
                fill="none"
                stroke={ringBg}
                strokeWidth="7"
              />
              {/* Filled arc */}
              <circle
                cx="60"
                cy="60"
                r={radius}
                fill="none"
                stroke={ringColor}
                strokeWidth="7"
                strokeLinecap="round"
                strokeDasharray={`${filled} ${gap}`}
                style={{
                  transition: 'stroke-dasharray 0.6s ease-out, stroke 0.4s ease',
                }}
              />
            </svg>
            {/* Centre label */}
            <div className="absolute inset-0 flex flex-col items-center justify-center">
              <span
                className="text-[36px] font-semibold leading-none font-mono"
                style={{ color: ringColor }}
              >
                {rate}%
              </span>
              <span className="mt-1.5 text-center text-[12px] leading-tight text-muted">
                threats
                <br />
                blocked
              </span>
            </div>
          </div>

          {/* Stat cards */}
          <div className="flex flex-1 gap-3">
            {cards.map((card) => (
              <div
                key={card.label}
                className="flex-1 rounded-xl border border-border/60 bg-bg p-3.5 transition-colors duration-150 hover:border-border"
              >
                <div className="flex items-center gap-2 mb-2">
                  {card.icon}
                  <p className="text-[13px] text-muted">{card.label}</p>
                </div>
                <p
                  className={`text-[28px] font-semibold leading-none font-mono ${card.color}`}
                >
                  {card.value}
                </p>
              </div>
            ))}
          </div>
        </div>

        {/* Toggle details */}
        <button
          onClick={() => setShowDetails((v) => !v)}
          className="mt-4 flex items-center gap-1.5 border-none bg-transparent text-[14px] text-dim transition-colors duration-150 hover:text-text"
        >
          <svg
            width="12"
            height="12"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
            className={`transition-transform duration-200 ${showDetails ? 'rotate-90' : ''}`}
          >
            <polyline points="9 18 15 12 9 6" />
          </svg>
          {showDetails ? 'Hide details' : 'Show details'}
        </button>

        {/* Expanded details */}
        <div
          className={`overflow-hidden transition-all duration-200 ease-out ${
            showDetails ? 'mt-3 max-h-40 opacity-100' : 'max-h-0 opacity-0'
          }`}
        >
          <div className="flex flex-wrap gap-x-6 gap-y-1.5 rounded-lg border border-border/40 bg-bg px-4 py-3 text-[14px]">
            <span className="text-muted">
              Total requests:{' '}
              <span className="font-mono text-text">{stats.total_requests}</span>
            </span>
            <span className="text-muted">
              Blocked:{' '}
              <span className="font-mono text-blocked">{stats.blocked_requests}</span>
            </span>
            <span className="text-muted">
              Threats found:{' '}
              <span className="font-mono text-text">{stats.total_threats}</span>
            </span>
            <span className="text-muted">
              Patched:{' '}
              <span className="font-mono text-safe">{stats.threats_blocked}</span>
            </span>
            <span className="text-muted">
              Block rate:{' '}
              <span className="font-mono" style={{ color: ringColor }}>
                {rate}%
              </span>
            </span>
            <span className="text-muted">
              Rules:{' '}
              <span className="font-mono text-agent">v{stats.rules_version}</span>
            </span>
          </div>
        </div>
      </div>
    </div>
  )
}
