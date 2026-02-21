import { useMemo } from 'react'
import { humaniseAgentEvent, humaniseAgentRole, relativeTime } from '../lib/humanise'

const STAGES = ['peek', 'poke', 'patch']
const STAGE_LABELS = { peek: 'Peek', poke: 'Poke', patch: 'Patch' }

function PipelineStage({ agent, event, isLast }) {
  const role = humaniseAgentRole(agent)
  const status = event?.status || 'idle'
  const detail = event?.detail || ''

  // Extract round and verification info from detail
  const roundMatch = detail.match(/\(round\s*(\d+)\)/)
  const round = roundMatch ? parseInt(roundMatch[1], 10) : null
  const isRepoke = /re-test|re-poke/i.test(detail)
  const stillBypassing = detail.match(/(\d+)\s*still bypassing/)

  const statusIcon =
    status === 'running' ? (
      <div className="h-2 w-2 animate-pulse rounded-full bg-agent" />
    ) : status === 'done' ? (
      stillBypassing && parseInt(stillBypassing[1], 10) > 0 ? (
        <svg width="12" height="12" viewBox="0 0 16 16" className="text-suspicious">
          <path d="M8 1a7 7 0 110 14A7 7 0 018 1zm-.5 4h1v4h-1V5zm0 5.5h1v1h-1v-1z" fill="currentColor" fillRule="evenodd" />
        </svg>
      ) : (
        <svg width="12" height="12" viewBox="0 0 16 16" className="text-safe">
          <path d="M6.5 12L2 7.5l1.4-1.4L6.5 9.2l6.1-6.1L14 4.5z" fill="currentColor" />
        </svg>
      )
    ) : status === 'error' ? (
      <svg width="12" height="12" viewBox="0 0 16 16" className="text-blocked">
        <path d="M4.5 3L8 6.5 11.5 3 13 4.5 9.5 8 13 11.5 11.5 13 8 9.5 4.5 13 3 11.5 6.5 8 3 4.5z" fill="currentColor" />
      </svg>
    ) : (
      <div className="h-2 w-2 rounded-full bg-border" />
    )

  let statusLabel =
    status === 'running'
      ? 'Running'
      : status === 'done'
        ? 'Done'
        : status === 'error'
          ? 'Error'
          : 'Idle'

  // Enrich label for patch rounds and re-poke
  if (agent === 'patch' && round && status === 'running') {
    statusLabel = `Round ${round}`
  } else if (agent === 'poke' && isRepoke) {
    statusLabel = status === 'running' ? 'Verifying' : 'Verified'
  }

  const time = event?.timestamp ? relativeTime(event.timestamp) : ''
  const { summary } = humaniseAgentEvent(event || {})

  return (
    <div className="flex items-start gap-3 flex-1 min-w-0">
      <div className="flex-1 min-w-0 rounded-lg border border-border bg-bg p-3">
        <div className="flex items-center gap-2 mb-1.5">
          <span className="text-[14px] font-semibold text-text">{STAGE_LABELS[agent]}: {role.name}</span>
          {agent === 'patch' && round && round > 1 && (
            <span className="text-[12px] text-suspicious bg-suspicious/10 px-1.5 py-0.5 rounded">R{round}</span>
          )}
          {agent === 'poke' && isRepoke && (
            <span className="text-[12px] text-agent bg-agent/10 px-1.5 py-0.5 rounded">verify</span>
          )}
        </div>
        <p className="text-[13px] text-muted leading-relaxed">{role.verb}</p>
        <div className="mt-2 flex items-center gap-2">
          {statusIcon}
          <span className={`text-[13px] font-medium ${
            status === 'running' ? 'text-agent' : status === 'done' ? (stillBypassing && parseInt(stillBypassing[1], 10) > 0 ? 'text-suspicious' : 'text-safe') : status === 'error' ? 'text-blocked' : 'text-muted'
          }`}>
            {statusLabel}
          </span>
          {time && <span className="text-[12px] text-muted">{time}</span>}
        </div>
        {status === 'done' && summary && (
          <p className="mt-1 text-[13px] text-dim truncate">{summary}</p>
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
      <div className="px-4 py-2.5 border-b border-border text-muted text-[14px] font-medium">
        Agent activity
      </div>
      <div className="flex-1 overflow-y-auto">
        {events.length === 0 && (
          <div className="px-4 py-8 text-muted text-center text-[15px]">
            Agents have not run yet. Start an improvement cycle to see activity.
          </div>
        )}
        {events.map((evt, i) => {
          const { summary, color } = humaniseAgentEvent(evt)
          const isRunning = evt.status === 'running'
          const isCycleSummary = evt.agent === 'system' && /cycle/i.test(evt.detail || '')

          if (isCycleSummary) {
            return (
              <div key={i} className="px-4 py-2 border-b border-border/40 bg-surface-2/50">
                <div className="flex items-center gap-2">
                  <svg width="12" height="12" viewBox="0 0 16 16" className="text-muted shrink-0">
                    <path d="M8 1a7 7 0 110 14A7 7 0 018 1zm0 1.5a5.5 5.5 0 100 11 5.5 5.5 0 000-11zM8 4v4.25l2.5 1.5-.75 1.25L7 8.75V4h1z" fill="currentColor" fillRule="evenodd" />
                  </svg>
                  <span className={`text-[14px] ${color}`}>{summary}</span>
                  <span className="shrink-0 text-[12px] text-muted ml-auto">{relativeTime(evt.timestamp)}</span>
                </div>
              </div>
            )
          }

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
                <p className={`text-[15px] ${color}`}>{summary}</p>
                {evt.detail && (
                  <p className="mt-0.5 truncate text-[13px] text-muted">{evt.detail}</p>
                )}
              </div>
              <span className="shrink-0 text-[13px] text-muted">{relativeTime(evt.timestamp)}</span>
            </div>
          )
        })}
      </div>
    </div>
  )
}
