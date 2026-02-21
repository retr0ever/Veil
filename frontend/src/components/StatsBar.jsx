export function StatsBar({ stats }) {
  const items = [
    { label: 'Requests', value: stats.total_requests },
    { label: 'Blocked', value: stats.blocked_requests, color: 'text-blocked' },
    { label: 'Threats found', value: stats.total_threats },
    { label: 'Patched', value: stats.threats_blocked, color: 'text-safe' },
    {
      label: 'Block rate',
      value: `${stats.block_rate}%`,
      color: stats.block_rate > 80 ? 'text-safe' : stats.block_rate > 50 ? 'text-suspicious' : 'text-blocked',
    },
    { label: 'Rules', value: `v${stats.rules_version}`, color: 'text-agent' },
  ]

  return (
    <div className="flex gap-6 px-5 py-3 border-b border-border bg-surface">
      {items.map((item) => (
        <div key={item.label} className="flex gap-2 items-baseline">
          <span className="text-muted text-[12px]">{item.label}</span>
          <span className={`text-[15px] font-semibold font-mono ${item.color || 'text-text'}`}>
            {item.value}
          </span>
        </div>
      ))}
    </div>
  )
}
