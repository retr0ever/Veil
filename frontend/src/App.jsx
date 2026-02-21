import { useVeilSocket } from './hooks/useVeilSocket'
import { StatsBar } from './components/StatsBar'
import { RequestFeed } from './components/RequestFeed'
import { AgentLog } from './components/AgentLog'
import { ThreatTable } from './components/ThreatTable'
import { BlockRateChart } from './components/BlockRateChart'

function App() {
  const { requests, agentEvents, stats } = useVeilSocket()

  const triggerCycle = async () => {
    await fetch('/api/agents/cycle', { method: 'POST' })
  }

  return (
    <div className="h-screen flex flex-col bg-bg overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-2 border-b border-border">
        <div className="flex items-center gap-3">
          <span className="text-[16px] font-bold tracking-tight">VEIL</span>
          <span className="text-muted text-[11px]">self-improving llm firewall</span>
        </div>
        <div className="flex items-center gap-3">
          <div className="w-1.5 h-1.5 bg-safe animate-pulse" />
          <span className="text-safe text-[11px]">LIVE</span>
          <button
            onClick={triggerCycle}
            className="ml-4 px-3 py-1 border border-border text-[11px] text-muted hover:text-text hover:border-text/30 transition-colors bg-transparent cursor-pointer"
          >
            RUN CYCLE
          </button>
        </div>
      </div>

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
        <div className="col-span-2 border-t border-border h-[220px]">
          <ThreatTable />
        </div>
      </div>
    </div>
  )
}

export default App
