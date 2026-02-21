import { useState, useEffect } from 'react'

export function BlockRateChart() {
  const [history, setHistory] = useState([])

  useEffect(() => {
    const load = async () => {
      try {
        const res = await fetch('/api/rules')
        if (res.ok) {
          const rules = await res.json()
          setHistory(rules.reverse())
        }
      } catch {}
    }
    load()
    const interval = setInterval(load, 10000)
    return () => clearInterval(interval)
  }, [])

  return (
    <div className="flex flex-col">
      <div className="px-4 py-2.5 border-b border-border text-muted text-[12px] font-medium">
        Protection timeline
      </div>
      <div className="p-4">
        {history.length === 0 && (
          <p className="text-[13px] text-muted py-4 text-center">Collecting rule history...</p>
        )}
        {history.length > 0 && (
          <div className="relative pl-6">
            <div className="absolute left-[11px] top-2 bottom-2 w-px bg-border" />
            {history.map((rule, i) => {
              const isLatest = i === history.length - 1
              const time = rule.updated_at
                ? new Date(rule.updated_at).toLocaleString('en-GB', {
                    day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit',
                  })
                : ''
              return (
                <div key={rule.version} className="relative flex items-start gap-3 pb-4 last:pb-0">
                  <div className={`absolute left-[-13px] top-1.5 h-2.5 w-2.5 rounded-full border-2 ${
                    isLatest ? 'border-safe bg-safe' : 'border-border bg-bg'
                  }`} />
                  <div>
                    <p className={`text-[13px] font-medium ${isLatest ? 'text-safe' : 'text-text'}`}>
                      Rule set v{rule.version}
                    </p>
                    {time && <p className="text-[11px] text-muted mt-0.5">{time}</p>}
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </div>
    </div>
  )
}
