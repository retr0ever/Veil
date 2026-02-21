import { useMemo } from 'react'
import { humaniseAgentEvent, relativeTime } from '../lib/humanise'

const STAGES = ['peek', 'poke', 'patch']

/* ------------------------------------------------------------------ */
/*  Per-agent config: identity, copy, colours, icon                    */
/* ------------------------------------------------------------------ */
const AGENT_CONFIG = {
  peek: {
    label: 'Peek',
    name: 'Scout',
    description: 'Invents new attack techniques that might bypass your current defences',
    runningLabel: 'Scanning...',
    accentBg: 'bg-peek',
    activeBorder: 'border-peek/30',
    labelColor: 'text-peek',
    badgeClasses: 'bg-peek/10 text-peek',
    imgSrc: '/svg/2.png',
  },
  poke: {
    label: 'Poke',
    name: 'Red Team',
    description: 'Fires discovered attacks at your defences to find which ones get through',
    runningLabel: 'Testing...',
    accentBg: 'bg-poke',
    activeBorder: 'border-poke/30',
    labelColor: 'text-poke',
    badgeClasses: 'bg-poke/10 text-poke',
    imgSrc: '/svg/3.png',
  },
  patch: {
    label: 'Patch',
    name: 'Adapt',
    description: 'Analyses any gaps found and automatically strengthens your protection rules',
    runningLabel: 'Patching...',
    accentBg: 'bg-patch',
    activeBorder: 'border-patch/30',
    labelColor: 'text-patch',
    badgeClasses: 'bg-patch/10 text-patch',
    imgSrc: '/svg/4.png',
  },
}

/* ------------------------------------------------------------------ */
/*  Flow arrow between pipeline cards                                  */
/* ------------------------------------------------------------------ */
function FlowArrow({ active }) {
  return (
    <div className="hidden lg:flex items-center shrink-0 px-0.5">
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" className={active ? 'text-dim' : 'text-border'}>
        <path d="M9 6l6 6-6 6" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    </div>
  )
}

/* ------------------------------------------------------------------ */
/*  Single pipeline card                                               */
/* ------------------------------------------------------------------ */
function PipelineCard({ agent, event }) {
  const config = AGENT_CONFIG[agent]
  const status = event?.status || 'idle'
  const detail = event?.detail || ''
  const { summary } = humaniseAgentEvent(event || {})
  const time = event?.timestamp ? relativeTime(event.timestamp) : ''

  const stillBypassing = detail.match(/(\d+)\s*still bypassing/)
  const hasIssue = stillBypassing && parseInt(stillBypassing[1], 10) > 0
  const roundMatch = detail.match(/\(round\s*(\d+)\)/)
  const round = roundMatch ? parseInt(roundMatch[1], 10) : null
  const isRepoke = /re-test|re-poke/i.test(detail)

  let statusLabel
  if (status === 'running') {
    if (agent === 'patch' && round && round > 1) statusLabel = `Patching (round ${round})...`
    else if (agent === 'poke' && isRepoke) statusLabel = 'Verifying patches...'
    else statusLabel = config.runningLabel
  } else if (status === 'done') {
    statusLabel = hasIssue ? 'Needs attention' : 'Complete'
  } else if (status === 'error') {
    statusLabel = 'Error'
  } else {
    statusLabel = 'Waiting'
  }

  const statusColorClass =
    status === 'running'
      ? config.labelColor
      : status === 'done'
        ? hasIssue ? 'text-suspicious' : 'text-safe'
        : status === 'error'
          ? 'text-blocked'
          : 'text-muted'

  return (
    <div className={`flex-1 min-w-0 rounded-xl border ${status === 'running' ? config.activeBorder : 'border-border'} bg-bg overflow-hidden transition-colors`}>
      {/* Coloured accent bar */}
      <div className={`h-[3px] ${status !== 'idle' ? config.accentBg : 'bg-border/50'} transition-colors`} />

      <div className="p-5">
        {/* Identity */}
        <div className="flex items-center gap-3 mb-3">
          <img
            src={config.imgSrc}
            alt={config.name}
            className="h-14 w-14 object-contain shrink-0"
          />
          <div>
            <h4 className="text-[16px] font-semibold text-text">{config.name}</h4>
            <span className={`text-[12px] font-semibold uppercase tracking-wider ${config.labelColor}`}>
              {config.label}
            </span>
          </div>
        </div>

        {/* What it does */}
        <p className="text-[14px] text-muted leading-relaxed mb-4">{config.description}</p>

        <div className="h-px bg-border/40 mb-3" />

        {/* Status row */}
        <div className="flex items-center gap-2">
          {status === 'running' && (
            <span className="relative flex h-2.5 w-2.5">
              <span className={`absolute inline-flex h-full w-full rounded-full ${config.accentBg} opacity-50`} style={{ animation: 'ping 1.8s cubic-bezier(0,0,0.2,1) infinite' }} />
              <span className={`relative inline-flex h-2.5 w-2.5 rounded-full ${config.accentBg}`} />
            </span>
          )}
          {status === 'done' && !hasIssue && (
            <svg width="14" height="14" viewBox="0 0 16 16" className="text-safe shrink-0">
              <path d="M6.5 12L2 7.5l1.4-1.4L6.5 9.2l6.1-6.1L14 4.5z" fill="currentColor" />
            </svg>
          )}
          {status === 'done' && hasIssue && (
            <svg width="14" height="14" viewBox="0 0 16 16" className="text-suspicious shrink-0">
              <path d="M8 1a7 7 0 110 14A7 7 0 018 1zm-.5 4h1v4h-1V5zm0 5.5h1v1h-1v-1z" fill="currentColor" fillRule="evenodd" />
            </svg>
          )}
          {status === 'error' && (
            <svg width="14" height="14" viewBox="0 0 16 16" className="text-blocked shrink-0">
              <path d="M4.5 3L8 6.5 11.5 3 13 4.5 9.5 8 13 11.5 11.5 13 8 9.5 4.5 13 3 11.5 6.5 8 3 4.5z" fill="currentColor" />
            </svg>
          )}
          {status === 'idle' && <div className="h-2.5 w-2.5 rounded-full bg-border shrink-0" />}

          <span className={`text-[14px] font-medium ${statusColorClass}`}>{statusLabel}</span>
          {time && <span className="ml-auto text-[12px] text-muted tabular-nums">{time}</span>}
        </div>

        {/* Result summary -- never truncated */}
        {status !== 'idle' && summary && (
          <p className="mt-2 text-[13px] text-dim leading-relaxed">{summary}</p>
        )}
      </div>
    </div>
  )
}

/* ------------------------------------------------------------------ */
/*  Pipeline: three cards connected by arrows                          */
/* ------------------------------------------------------------------ */
export function AgentPipeline({ events }) {
  const latestByAgent = useMemo(() => {
    const map = {}
    for (const evt of events) {
      const agent = evt.agent
      if (!agent || agent === 'system') continue
      if (!map[agent] || new Date(evt.timestamp) > new Date(map[agent].timestamp)) {
        map[agent] = evt
      }
    }
    return map
  }, [events])

  const anyRunning = STAGES.some((s) => latestByAgent[s]?.status === 'running')

  return (
    <div className="px-6 py-6 border-b border-border">
      <div className="flex flex-col lg:flex-row lg:items-stretch gap-4">
        {STAGES.map((agent, i) => (
          <div key={agent} className="contents">
            <PipelineCard agent={agent} event={latestByAgent[agent]} />
            {i < STAGES.length - 1 && (
              <FlowArrow active={anyRunning || !!latestByAgent[agent]} />
            )}
          </div>
        ))}
      </div>
    </div>
  )
}

/* ------------------------------------------------------------------ */
/*  Activity feed                                                      */
/* ------------------------------------------------------------------ */
export function AgentLog({ events }) {
  return (
    <div className="flex flex-1 min-h-0 flex-col overflow-hidden">
      <div className="px-5 py-3 border-b border-border">
        <h4 className="text-[15px] font-semibold text-text">Recent activity</h4>
      </div>
      <div className="flex-1 overflow-y-auto">
        {events.length === 0 && (
          <div className="px-5 py-12 text-center">
            <div className="mb-3 mx-auto flex h-10 w-10 items-center justify-center rounded-xl border border-border bg-surface">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className="text-muted">
                <circle cx="12" cy="12" r="3" /><path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z" />
              </svg>
            </div>
            <p className="text-[15px] font-medium text-text">No activity yet</p>
            <p className="mt-1 text-[13px] text-muted">Run an improvement cycle to see agent activity here.</p>
          </div>
        )}
        {events.map((evt, i) => {
          const { summary, color } = humaniseAgentEvent(evt)
          const isCycleSummary = evt.agent === 'system' && /cycle/i.test(evt.detail || '')
          const agentConfig = AGENT_CONFIG[evt.agent]

          /* ---- Cycle separator ---- */
          if (isCycleSummary) {
            return (
              <div key={i} className="px-5 py-3 border-b border-border bg-surface/40">
                <div className="flex items-center gap-2.5">
                  <svg width="14" height="14" viewBox="0 0 16 16" className="text-muted shrink-0">
                    <path d="M8 1a7 7 0 110 14A7 7 0 018 1zm0 1.5a5.5 5.5 0 100 11 5.5 5.5 0 000-11zM8 4v4.25l2.5 1.5-.75 1.25L7 8.75V4h1z" fill="currentColor" fillRule="evenodd" />
                  </svg>
                  <span className="text-[14px] font-medium text-dim">{summary}</span>
                  <span className="shrink-0 text-[12px] text-muted ml-auto tabular-nums">
                    {relativeTime(evt.timestamp)}
                  </span>
                </div>
              </div>
            )
          }

          /* ---- Regular agent event ---- */
          return (
            <div key={i} className="px-5 py-3.5 border-b border-border/40 flex items-start gap-3">
              {/* Status icon */}
              <div className="mt-1.5 shrink-0">
                {evt.status === 'running' ? (
                  <span className="relative flex h-2.5 w-2.5">
                    <span
                      className={`absolute inline-flex h-full w-full rounded-full ${agentConfig ? agentConfig.accentBg : 'bg-agent'} opacity-50`}
                      style={{ animation: 'ping 1.8s cubic-bezier(0,0,0.2,1) infinite' }}
                    />
                    <span className={`relative inline-flex h-2.5 w-2.5 rounded-full ${agentConfig ? agentConfig.accentBg : 'bg-agent'}`} />
                  </span>
                ) : evt.status === 'done' ? (
                  <svg width="13" height="13" viewBox="0 0 16 16" className="text-safe">
                    <path d="M6.5 12L2 7.5l1.4-1.4L6.5 9.2l6.1-6.1L14 4.5z" fill="currentColor" />
                  </svg>
                ) : evt.status === 'error' ? (
                  <svg width="13" height="13" viewBox="0 0 16 16" className="text-blocked">
                    <path d="M4.5 3L8 6.5 11.5 3 13 4.5 9.5 8 13 11.5 11.5 13 8 9.5 4.5 13 3 11.5 6.5 8 3 4.5z" fill="currentColor" />
                  </svg>
                ) : (
                  <div className="h-2.5 w-2.5 rounded-full bg-border" />
                )}
              </div>

              {/* Content */}
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2 mb-1">
                  {agentConfig && (
                    <span className={`rounded-md px-1.5 py-0.5 text-[11px] font-semibold uppercase tracking-wide ${agentConfig.badgeClasses}`}>
                      {agentConfig.label}
                    </span>
                  )}
                  <span className="shrink-0 text-[12px] text-muted ml-auto tabular-nums">
                    {relativeTime(evt.timestamp)}
                  </span>
                </div>
                <p className={`text-[15px] leading-relaxed ${color}`}>{summary}</p>
                {evt.detail && (
                  <p className="mt-0.5 text-[13px] text-muted leading-relaxed">{evt.detail}</p>
                )}
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
