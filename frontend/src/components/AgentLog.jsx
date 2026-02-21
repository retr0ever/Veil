import { humaniseAgentEvent, relativeTime } from '../lib/humanise'

export function AgentLog({ events }) {
  return (
    <div className="flex flex-1 min-h-0 flex-col overflow-hidden">
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
          const { summary, color } = humaniseAgentEvent(evt)
          const isRunning = evt.status === 'running'
          return (
            <div key={i} className="px-4 py-2.5 border-b border-border/40 flex items-start gap-3">
              <div className="mt-1.5 shrink-0">
                {isRunning ? (
                  <div className="h-2 w-2 animate-pulse rounded-full bg-agent" />
                ) : evt.status === 'done' ? (
                  <svg width="12" height="12" viewBox="0 0 16 16" className="text-safe">
                    <path d="M6.5 12L2 7.5l1.4-1.4L6.5 9.2l6.1-6.1L14 4.5z" fill="currentColor" />
                  </svg>
                ) : evt.status === 'error' ? (
                  <svg width="12" height="12" viewBox="0 0 16 16" className="text-blocked">
                    <path d="M4.5 3L8 6.5 11.5 3 13 4.5 9.5 8 13 11.5 11.5 13 8 9.5 4.5 13 3 11.5 6.5 8 3 4.5z" fill="currentColor" />
                  </svg>
                ) : (
                  <div className="h-2 w-2 rounded-full bg-border" />
                )}
              </div>
              <div className="min-w-0 flex-1">
                <p className={`text-[13px] ${color}`}>{summary}</p>
                {evt.detail && (
                  <p className="mt-0.5 truncate text-[11px] text-muted">{evt.detail}</p>
                )}
              </div>
              <span className="shrink-0 text-[11px] text-muted">{relativeTime(evt.timestamp)}</span>
            </div>
          )
        })}
      </div>
    </div>
  )
}
