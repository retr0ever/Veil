import { useMemo } from 'react'
import { humaniseAgentEvent, humaniseAgentRole, relativeTime } from '../lib/humanise'

const STAGES = ['peek', 'poke', 'patch']
const STAGE_LABELS = { peek: 'Peek', poke: 'Poke', patch: 'Patch' }

function PipelineStage({ agent, event, isLast }) {
  const role = humaniseAgentRole(agent)
  const status = event?.status || 'idle'

  const statusIcon =
    status === 'running' ? (
      <div className="h-2 w-2 animate-pulse rounded-full bg-agent" />
    ) : status === 'done' ? (
      <svg width="12" height="12" viewBox="0 0 16 16" className="text-safe">
        <path d="M6.5 12L2 7.5l1.4-1.4L6.5 9.2l6.1-6.1L14 4.5z" fill="currentColor" />
      </svg>
    ) : status === 'error' ? (
      <svg width="12" height="12" viewBox="0 0 16 16" className="text-blocked">
        <path d="M4.5 3L8 6.5 11.5 3 13 4.5 9.5 8 13 11.5 11.5 13 8 9.5 4.5 13 3 11.5 6.5 8 3 4.5z" fill="currentColor" />
      </svg>
    ) : (
      <div className="h-2 w-2 rounded-full bg-border" />
    )

  const statusLabel =
    status === 'running'
      ? 'Running'
      : status === 'done'
        ? 'Done'
        : status === 'error'
          ? 'Error'
          : 'Idle'

  const detail = event?.detail || ''
  const time = event?.timestamp ? relativeTime(event.timestamp) : ''

  return (
    <div className="flex items-start gap-3 flex-1 min-w-0">
      <div className="flex-1 min-w-0 rounded-lg border border-border bg-bg p-3">
        <div className="flex items-center gap-2 mb-1.5">
          <span className="text-[12px] font-semibold text-text">{STAGE_LABELS[agent]}: {role.name}</span>
        </div>
        <p className="text-[11px] text-muted leading-relaxed">{role.verb}</p>
        <div className="mt-2 flex items-center gap-2">
          {statusIcon}
          <span className={`text-[11px] font-medium ${
            status === 'running' ? 'text-agent' : status === 'done' ? 'text-safe' : status === 'error' ? 'text-blocked' : 'text-muted'
          }`}>
            {statusLabel}
          </span>
          {time && <span className="text-[10px] text-muted">{time}</span>}
        </div>
        {detail && status === 'done' && (
          <p className="mt-1 text-[11px] text-dim truncate">{detail}</p>
        )}
      </div>
      {!isLast && (
        <div className="flex items-center self-center shrink-0 text-muted">
          <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
            <path d="M6 4l4 4-4 4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
        </div>
      )}
    </div>
  )
}

export function AgentPipeline({ events }) {
  const latestByAgent = useMemo(() => {
    const map = {}
    for (const evt of events) {
      const agent = evt.agent
      if (!agent) continue
      if (!map[agent] || new Date(evt.timestamp) > new Date(map[agent].timestamp)) {
        map[agent] = evt
      }
    }
    return map
  }, [events])

  return (
    <div className="border-b border-border bg-surface px-5 py-4">
      <div className="flex gap-2">
        {STAGES.map((agent, i) => (
          <PipelineStage
            key={agent}
            agent={agent}
            event={latestByAgent[agent]}
            isLast={i === STAGES.length - 1}
          />
        ))}
      </div>
    </div>
  )
}

export function AgentLog({ events }) {
  return (
    <div className="flex flex-1 min-h-0 flex-col overflow-hidden">
      <div className="px-4 py-2.5 border-b border-border text-muted text-[12px] font-medium">
        Agent activity
      </div>
      <div className="flex-1 overflow-y-auto">
        {events.length === 0 && (
          <div className="px-4 py-8 text-muted text-center text-[13px]">
            Agents have not run yet. Start an improvement cycle to see activity.
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
