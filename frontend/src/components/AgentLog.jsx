const agentMeta = {
  peek: { label: 'Peek', color: 'text-agent', desc: 'Scout' },
  poke: { label: 'Poke', color: 'text-suspicious', desc: 'Red team' },
  patch: { label: 'Patch', color: 'text-safe', desc: 'Fixer' },
  system: { label: 'System', color: 'text-muted', desc: '' },
}

const statusIcons = {
  running: '\u25B6',
  done: '\u2713',
  idle: '\u2014',
  error: '\u2717',
}

export function AgentLog({ events }) {
  return (
    <div className="flex-1 min-h-0 overflow-hidden flex flex-col">
      <div className="px-4 py-2.5 border-b border-border text-muted text-[12px] font-medium">
        Agent activity
      </div>
      <div className="flex-1 overflow-y-auto">
        {events.length === 0 && (
          <div className="px-4 py-8 text-muted text-center text-[13px]">
            Agents starting up...
          </div>
        )}
        {events.map((evt, i) => {
          const meta = agentMeta[evt.agent] || agentMeta.system
          return (
            <div key={i} className="px-4 py-2 border-b border-border/40 flex items-start gap-3">
              <span className={`text-[12px] mt-px ${evt.status === 'error' ? 'text-blocked' : evt.status === 'done' ? 'text-safe' : 'text-muted'}`}>
                {statusIcons[evt.status] || '?'}
              </span>
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <span className={`text-[12px] font-semibold ${meta.color}`}>
                    {meta.label}
                  </span>
                  {meta.desc && (
                    <span className="text-muted text-[11px]">{meta.desc}</span>
                  )}
                </div>
                <p className="text-dim text-[12px] mt-0.5 truncate">
                  {evt.detail}
                </p>
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
