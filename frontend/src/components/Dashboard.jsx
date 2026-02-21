import { useState } from 'react'
import { useVeilSocket } from '../hooks/useVeilSocket'
import { StatsBar } from './StatsBar'
import { RequestFeed } from './RequestFeed'
import { AgentLog } from './AgentLog'
import { ThreatTable } from './ThreatTable'
import { BlockRateChart } from './BlockRateChart'
import { NavBar } from './NavBar'
import { APP_NAV_LINKS } from '../lib/navLinks'

const tabs = [
  { key: 'live', label: 'Live' },
  { key: 'threats', label: 'Threats' },
  { key: 'agents', label: 'Agents' },
]

export function Dashboard({ site, projectName }) {
  const { requests, agentEvents, stats } = useVeilSocket()
  const [copied, setCopied] = useState(false)
  const [showSetup, setShowSetup] = useState(false)
  const [activeTab, setActiveTab] = useState('live')

  const proxyUrl = `${window.location.origin}/p/${site.site_id}`
  const title = projectName || site.target_url

  const copyUrl = () => {
    navigator.clipboard.writeText(proxyUrl)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const triggerCycle = async () => {
    await fetch('/api/agents/cycle', { method: 'POST' })
  }

  return (
    <div className="flex h-screen flex-col overflow-hidden bg-bg">
      <div className="px-5 pt-3">
        <NavBar links={APP_NAV_LINKS} activeHref="/app/projects" size="compact" showDivider />
      </div>

      <div className="flex items-center justify-between border-b border-border px-5 py-3">
        <div className="flex min-w-0 items-center gap-4">
          <span className="rounded-full border border-safe/40 px-2 py-0.5 text-[11px] text-safe">PROJECT</span>
          <div className="min-w-0">
            <p className="truncate text-[14px] font-semibold text-text">{title}</p>
            <p className="truncate text-[12px] text-dim">{site.target_url}</p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <div className="h-1.5 w-1.5 animate-pulse rounded-full bg-safe" />
            <span className="text-[11px] font-medium text-safe">PROTECTED</span>
          </div>
          <button
            onClick={triggerCycle}
            className="rounded-md border border-border bg-transparent px-3 py-1.5 text-[12px] text-muted transition-colors hover:border-dim hover:text-text"
          >
            Run cycle
          </button>
        </div>
      </div>

      <div className="flex items-center gap-4 border-b border-border bg-surface px-5 py-3">
        <span className="shrink-0 text-[12px] text-muted">Protected proxy</span>
        <div className="flex flex-1 items-center gap-2 rounded-md border border-border bg-surface-2 px-3 py-2">
          <code className="flex-1 truncate font-mono text-[13px] text-text">{proxyUrl}</code>
          <button
            onClick={copyUrl}
            className="shrink-0 border-none bg-transparent text-[11px] text-muted transition-colors hover:text-text"
          >
            {copied ? 'Copied' : 'Copy'}
          </button>
        </div>
        <button
          onClick={() => setShowSetup(!showSetup)}
          className="shrink-0 border-none bg-transparent text-[12px] text-agent hover:underline"
        >
          {showSetup ? 'Hide setup' : 'How to connect'}
        </button>
      </div>

      {showSetup && (
        <div className="border-b border-border bg-surface-2 px-5 py-4">
          <p className="mb-3 text-[13px] text-dim">Replace your backend URL with the protected URL above:</p>
          <div className="rounded-md border border-border bg-bg p-3 font-mono text-[12px]">
            <div className="text-muted">
              <span className="text-blocked">- </span>API_URL={site.target_url}
            </div>
            <div className="mt-1">
              <span className="text-safe">+ </span>API_URL={proxyUrl}
            </div>
          </div>
        </div>
      )}

      <StatsBar stats={stats} />

      <div className="flex gap-2 border-b border-border bg-surface px-5 py-2">
        {tabs.map((tab) => (
          <button
            key={tab.key}
            type="button"
            onClick={() => setActiveTab(tab.key)}
            className={`rounded-md px-3 py-1.5 text-[12px] font-medium transition-colors ${
              activeTab === tab.key
                ? 'bg-bg text-text'
                : 'bg-transparent text-muted hover:text-text'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      <div className="flex-1 min-h-0">
        {activeTab === 'live' && (
          <div className="grid h-full min-h-0 grid-cols-1 lg:grid-cols-[1fr_340px]">
            <div className="min-h-0 border-b border-border lg:border-b-0 lg:border-r">
              <RequestFeed requests={requests} />
            </div>
            <div className="min-h-0">
              <AgentLog events={agentEvents} />
            </div>
          </div>
        )}

        {activeTab === 'threats' && (
          <div className="h-full min-h-0">
            <ThreatTable />
          </div>
        )}

        {activeTab === 'agents' && (
          <div className="grid h-full min-h-0 grid-cols-1 lg:grid-cols-[340px_1fr]">
            <div className="min-h-0 border-b border-border lg:border-b-0 lg:border-r">
              <AgentLog events={agentEvents} />
            </div>
            <div className="flex min-h-0 flex-col">
              <div className="border-b border-border">
                <BlockRateChart />
              </div>
              <div className="flex-1 p-4">
                <h3 className="text-[13px] font-semibold text-text">Agent notes</h3>
                <p className="mt-2 max-w-2xl text-[13px] leading-relaxed text-dim">
                  Peek discovers techniques, Poke replays and mutates them, and Patch updates detection prompts/rules and verifies the fix in the next cycle.
                </p>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
