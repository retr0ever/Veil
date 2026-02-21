const agentColors = {
  peek: 'text-agent',
  poke: 'text-suspicious',
  patch: 'text-safe',
  system: 'text-muted',
}

const statusIndicators = {
  running: '>>',
  done: 'OK',
  idle: '--',
  error: '!!',
}

export function AgentLog({ events }) {
  return (
    <div className="flex-1 min-h-0 overflow-hidden flex flex-col">
      <div className="px-4 py-2 border-b border-border text-muted text-[11px] tracking-wide">
        AGENT ACTIVITY
      </div>
      <div className="flex-1 overflow-y-auto">
        {events.length === 0 && (
          <div className="px-4 py-8 text-muted text-center">Agents initialising...</div>
        )}
        {events.map((evt, i) => (
          <div key={i} className="px-4 py-1.5 border-b border-border/50 flex items-center gap-3">
            <span className="text-muted text-[11px]">
              {statusIndicators[evt.status] || '??'}
            </span>
            <span className={`w-12 shrink-0 text-[11px] font-bold uppercase ${agentColors[evt.agent]}`}>
              {evt.agent}
            </span>
            <span className="text-[12px] truncate">
              {evt.detail}
            </span>
          </div>
        ))}
      </div>
    </div>
  )
}
