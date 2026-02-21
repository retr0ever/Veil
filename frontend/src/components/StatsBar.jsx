import { useState } from 'react'

/* ── Agent cluster icon (replaces shield) ── */
function AgentCluster({ size = 48 }) {
  const s = size * 0.38
  return (
    <div className="flex items-end -space-x-2">
      <img src="/svg/2.png" alt="" className="object-contain" style={{ height: s, width: s }} />
      <img src="/svg/3.png" alt="" className="object-contain" style={{ height: s * 1.15, width: s * 1.15 }} />
      <img src="/svg/4.png" alt="" className="object-contain" style={{ height: s, width: s }} />
    </div>
  )
}

/* ── Determine health tier from block rate + traffic ── */
function getHealth(stats) {
  const hasTraffic = (stats.total_requests ?? 0) > 0
  const rate = stats.block_rate ?? 0
  const threats = stats.total_threats ?? 0

  if (!hasTraffic) {
    return {
      tier: 'waiting',
      colour: '#9387a0',
      headline: 'Waiting for traffic',
      subline: 'Connect your site to start protection',
      bgTint: 'rgba(147,135,160,0.06)',
    }
  }

  if (threats === 0) {
    return {
      tier: 'clear',
      colour: '#8fd9a7',
      headline: 'All clear -- no threats detected',
      subline: `Veil scanned ${stats.total_requests} request${stats.total_requests !== 1 ? 's' : ''} with no issues`,
      bgTint: 'rgba(143,217,167,0.06)',
    }
  }

  if (rate > 80) {
    return {
      tier: 'healthy',
      colour: '#8fd9a7',
      headline: 'Your site is well protected',
      subline: `Veil blocked ${stats.threats_blocked} of ${threats} threat${threats !== 1 ? 's' : ''} detected`,
      bgTint: 'rgba(143,217,167,0.06)',
    }
  }

  if (rate > 50) {
    return {
      tier: 'attention',
      colour: '#f2c77a',
      headline: 'Needs attention',
      subline: `Veil blocked ${stats.threats_blocked} of ${threats} threat${threats !== 1 ? 's' : ''} -- some got through`,
      bgTint: 'rgba(242,199,122,0.06)',
    }
  }

  return {
    tier: 'risk',
    colour: '#f08a95',
    headline: 'At risk',
    subline: `Only ${stats.threats_blocked} of ${threats} threat${threats !== 1 ? 's' : ''} blocked -- run an improvement cycle`,
    bgTint: 'rgba(240,138,149,0.06)',
  }
}

/* ── ProtectionSummary ── */
function ProtectionSummary({ stats }) {
  const health = getHealth(stats)
  const rate = stats.block_rate ?? 0
  const showBar = health.tier !== 'waiting'

  return (
    <div
      className="flex flex-col items-center px-6 py-8"
      style={{ background: health.bgTint }}
    >
      <AgentCluster size={56} />

      <h2
        className="mt-4 text-center text-[22px] font-semibold leading-tight"
        style={{ color: health.colour }}
      >
        {health.headline}
      </h2>

      <p className="mt-2 text-center text-[15px] text-dim">
        {health.subline}
      </p>

      {showBar && (
        <div className="mt-5 w-full max-w-sm">
          <div className="mb-1.5 flex items-center justify-between text-[13px]">
            <span className="text-muted">Block rate</span>
            <span className="font-mono font-semibold" style={{ color: health.colour }}>
              {rate}%
            </span>
          </div>
          <div className="h-2 w-full overflow-hidden rounded-full bg-border/40">
            <div
              className="h-full rounded-full transition-all duration-700 ease-out"
              style={{
                width: `${Math.max(rate, 2)}%`,
                backgroundColor: health.colour,
              }}
            />
          </div>
        </div>
      )}
    </div>
  )
}

/* ── OverviewStatCards ── */
function OverviewStatCards({ stats }) {
  const cards = [
    {
      label: 'Threats found',
      value: stats.total_threats ?? 0,
      explainer: 'Attack techniques discovered by Veil',
      colour: 'var(--color-text)',
      icon: (
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className="text-muted">
          <circle cx="12" cy="12" r="10" />
          <line x1="12" y1="8" x2="12" y2="12" />
          <line x1="12" y1="16" x2="12.01" y2="16" />
        </svg>
      ),
    },
    {
      label: 'Threats fixed',
      value: stats.threats_blocked ?? 0,
      explainer: 'Attacks that Veil now blocks automatically',
      colour: 'var(--color-safe)',
      icon: (
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className="text-safe">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          <path d="M9 12l2 2 4-4" />
        </svg>
      ),
    },
    {
      label: 'Protection version',
      value: `v${stats.rules_version ?? 0}`,
      explainer: 'Current ruleset version protecting your site',
      colour: 'var(--color-agent)',
      icon: (
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className="text-agent">
          <rect x="4" y="4" width="16" height="16" rx="2" />
          <rect x="9" y="9" width="6" height="6" />
          <path d="M12 2v2M12 20v2M2 12h2M20 12h2" />
        </svg>
      ),
    },
  ]

  return (
    <div className="grid grid-cols-3 gap-3 px-5 py-5">
      {cards.map((card) => (
        <div
          key={card.label}
          className="rounded-xl border border-border/60 bg-bg p-4 transition-colors duration-150 hover:border-border"
        >
          <div className="flex items-center gap-2 mb-3">
            {card.icon}
            <span className="text-[13px] text-muted">{card.label}</span>
          </div>
          <p
            className="text-[32px] font-semibold leading-none font-mono"
            style={{ color: card.colour }}
          >
            {card.value}
          </p>
          <p className="mt-2 text-[12px] leading-relaxed text-dim">
            {card.explainer}
          </p>
        </div>
      ))}
    </div>
  )
}

/* ── Exported StatsBar (keeps the same API) ── */
export function StatsBar({ stats }) {
  return (
    <div className="border-b border-border bg-surface">
      <ProtectionSummary stats={stats} />
      <OverviewStatCards stats={stats} />
    </div>
  )
}
