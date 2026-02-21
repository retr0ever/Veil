export function StatsBar({ stats }) {
  const items = [
    { label: 'REQUESTS', value: stats.total_requests },
    { label: 'BLOCKED', value: stats.blocked_requests, color: 'text-blocked' },
    { label: 'THREATS', value: stats.total_threats },
    { label: 'PATCHED', value: stats.threats_blocked, color: 'text-safe' },
    { label: 'BLOCK RATE', value: `${stats.block_rate}%`, color: stats.block_rate > 80 ? 'text-safe' : stats.block_rate > 50 ? 'text-suspicious' : 'text-blocked' },
    { label: 'RULES v', value: stats.rules_version, color: 'text-agent' },
  ]

  return (
    <div className="flex gap-6 px-4 py-3 border-b border-border bg-surface">
      {items.map((item) => (
        <div key={item.label} className="flex gap-2 items-baseline">
          <span className="text-muted text-[11px] tracking-wide">{item.label}</span>
          <span className={`text-[15px] font-bold ${item.color || 'text-text'}`}>{item.value}</span>
        </div>
      ))}
    </div>
  )
}
