import { useState } from 'react'
import { useVeilSocket } from '../hooks/useVeilSocket'
import { StatsBar } from './StatsBar'
import { RequestFeed } from './RequestFeed'
import { AgentLog } from './AgentLog'
import { ThreatTable } from './ThreatTable'
import { BlockRateChart } from './BlockRateChart'

export function Dashboard({ site }) {
  const { requests, agentEvents, stats } = useVeilSocket()
  const [copied, setCopied] = useState(false)
  const [showSetup, setShowSetup] = useState(false)

  const proxyUrl = `${window.location.origin}/p/${site.site_id}`

  const copyUrl = () => {
    navigator.clipboard.writeText(proxyUrl)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const triggerCycle = async () => {
    await fetch('/api/agents/cycle', { method: 'POST' })
  }

  return (
    <div className="h-screen flex flex-col bg-bg overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-5 py-3 border-b border-border">
        <div className="flex items-center gap-4">
          <span className="text-base font-semibold tracking-tight">veil</span>
          <div className="h-4 w-px bg-border" />
          <span className="text-dim text-[13px]">{site.target_url}</span>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <div className="w-1.5 h-1.5 rounded-full bg-safe animate-pulse" />
            <span className="text-safe text-[11px] font-medium">PROTECTED</span>
          </div>
          <button
            onClick={triggerCycle}
            className="ml-3 px-3 py-1.5 border border-border text-[12px] text-muted hover:text-text hover:border-dim rounded-md transition-colors bg-transparent"
          >
            Run cycle
          </button>
        </div>
      </div>

      {/* Proxy URL bar */}
      <div className="px-5 py-3 bg-surface border-b border-border flex items-center gap-4">
        <span className="text-muted text-[12px] shrink-0">Your protected URL</span>
        <div className="flex-1 flex items-center gap-2 bg-surface-2 border border-border rounded-md px-3 py-2">
          <code className="text-[13px] font-mono text-text flex-1 truncate">{proxyUrl}</code>
          <button
            onClick={copyUrl}
            className="text-[11px] text-muted hover:text-text transition-colors shrink-0 bg-transparent border-none"
          >
            {copied ? 'Copied' : 'Copy'}
          </button>
        </div>
        <button
          onClick={() => setShowSetup(!showSetup)}
          className="text-[12px] text-agent hover:underline bg-transparent border-none shrink-0"
        >
          {showSetup ? 'Hide setup' : 'How to connect'}
        </button>
      </div>

      {/* Setup instructions (collapsible) */}
      {showSetup && (
        <div className="px-5 py-4 bg-surface-2 border-b border-border">
          <p className="text-dim text-[13px] mb-3">
            Replace your backend URL with the protected URL above. One line change:
          </p>
          <div className="bg-bg border border-border rounded-md p-3 font-mono text-[12px]">
            <div className="text-muted">
              <span className="text-blocked">- </span>API_URL={site.target_url}
            </div>
            <div className="mt-1">
              <span className="text-safe">+ </span>API_URL={proxyUrl}
            </div>
          </div>
          <p className="text-muted text-[12px] mt-3">
            All traffic to your API now flows through Veil. No other changes needed.
          </p>
        </div>
      )}

      {/* Stats */}
      <StatsBar stats={stats} />

      {/* Main grid */}
      <div className="flex-1 min-h-0 grid grid-cols-[1fr_340px] grid-rows-[1fr_auto] overflow-hidden">
        {/* Left: Request feed */}
        <div className="border-r border-border flex flex-col min-h-0">
          <RequestFeed requests={requests} />
        </div>

        {/* Right: Agents + Chart */}
        <div className="flex flex-col min-h-0">
          <AgentLog events={agentEvents} />
          <div className="border-t border-border">
            <BlockRateChart />
          </div>
        </div>

        {/* Bottom: Threat table */}
        <div className="col-span-2 border-t border-border h-[200px]">
          <ThreatTable />
        </div>
      </div>
    </div>
  )
}
