import { useState, useEffect } from 'react'

const severityColors = {
  critical: 'text-blocked',
  high: 'text-suspicious',
  medium: 'text-text',
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
      <div className="px-4 py-2 border-b border-border text-muted text-[11px] tracking-wide">
        THREAT INTELLIGENCE ({threats.length})
      </div>
      <div className="flex-1 overflow-y-auto">
        <table className="w-full">
          <thead>
            <tr className="text-[10px] text-muted tracking-wide border-b border-border">
              <th className="text-left px-4 py-1.5 font-normal">TECHNIQUE</th>
              <th className="text-left px-2 py-1.5 font-normal">CATEGORY</th>
              <th className="text-left px-2 py-1.5 font-normal">SEVERITY</th>
              <th className="text-left px-2 py-1.5 font-normal">STATUS</th>
              <th className="text-left px-2 py-1.5 font-normal">SOURCE</th>
            </tr>
          </thead>
          <tbody>
            {threats.map((t) => (
              <tr key={t.id} className="border-b border-border/30 text-[12px]">
                <td className="px-4 py-1.5 truncate max-w-[200px]">{t.technique_name}</td>
                <td className="px-2 py-1.5 text-muted">{t.category}</td>
                <td className={`px-2 py-1.5 font-bold ${severityColors[t.severity]}`}>
                  {t.severity}
                </td>
                <td className="px-2 py-1.5">
                  {t.blocked ? (
                    <span className="text-safe">blocked</span>
                  ) : (
                    <span className="text-blocked">exposed</span>
                  )}
                </td>
                <td className="px-2 py-1.5 text-muted truncate max-w-[140px]">{t.source}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
