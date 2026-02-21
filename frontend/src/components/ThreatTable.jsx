import { useState, useEffect } from 'react'

const severityColors = {
  critical: 'text-blocked',
  high: 'text-suspicious',
  medium: 'text-dim',
  low: 'text-muted',
}

export function ThreatTable() {
  const [threats, setThreats] = useState([])

  useEffect(() => {
    const load = async () => {
      try {
        const res = await fetch('/api/threats')
        if (res.ok) setThreats(await res.json())
      } catch {}
    }
    load()
    const interval = setInterval(load, 10000)
    return () => clearInterval(interval)
  }, [])

  return (
    <div className="flex-1 min-h-0 overflow-hidden flex flex-col">
      <div className="px-4 py-2.5 border-b border-border text-muted text-[12px] font-medium">
        Threat intelligence
        <span className="ml-2 text-dim">{threats.length}</span>
      </div>
      <div className="flex-1 overflow-y-auto">
        <table className="w-full">
          <thead>
            <tr className="text-[11px] text-muted border-b border-border">
              <th className="text-left px-4 py-2 font-medium">Technique</th>
              <th className="text-left px-3 py-2 font-medium">Category</th>
              <th className="text-left px-3 py-2 font-medium">Severity</th>
              <th className="text-left px-3 py-2 font-medium">Status</th>
              <th className="text-left px-3 py-2 font-medium">Source</th>
            </tr>
          </thead>
          <tbody>
            {threats.map((t) => (
              <tr key={t.id} className="border-b border-border/30 text-[12px]">
                <td className="px-4 py-2 truncate max-w-[220px] text-text">{t.technique_name}</td>
                <td className="px-3 py-2 text-muted font-mono text-[11px]">{t.category}</td>
                <td className={`px-3 py-2 font-semibold ${severityColors[t.severity]}`}>
                  {t.severity}
                </td>
                <td className="px-3 py-2">
                  {t.blocked ? (
                    <span className="text-safe text-[11px] bg-safe/10 px-1.5 py-0.5 rounded">blocked</span>
                  ) : (
                    <span className="text-blocked text-[11px] bg-blocked/10 px-1.5 py-0.5 rounded">exposed</span>
                  )}
                </td>
                <td className="px-3 py-2 text-muted text-[11px] truncate max-w-[140px]">{t.source}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
