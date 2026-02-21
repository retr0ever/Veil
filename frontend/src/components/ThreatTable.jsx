import { useState, useEffect, useMemo } from 'react'
import { humaniseAttackType, codeFixForCategory } from '../lib/humanise'

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 }

const FILTERS = [
  { key: 'all', label: 'All' },
  { key: 'exposed', label: 'Exposed' },
  { key: 'patched', label: 'Patched' },
]

export function ThreatTable() {
  const [threats, setThreats] = useState([])
  const [loading, setLoading] = useState(true)
  const [filter, setFilter] = useState('all')
  const [openGroups, setOpenGroups] = useState(new Set())

  useEffect(() => {
    const load = async () => {
      try {
        const res = await fetch('/api/threats')
        if (res.ok) setThreats(await res.json())
      } catch {
        // Silently handle -- empty state is shown
      } finally {
        setLoading(false)
      }
    }
    load()
    const interval = setInterval(load, 10000)
    return () => clearInterval(interval)
  }, [])

  const counts = useMemo(() => ({
    all: threats.length,
    exposed: threats.filter((t) => !t.blocked).length,
    patched: threats.filter((t) => t.blocked).length,
  }), [threats])

  // Group by category, sorted by exposure count
  const groups = useMemo(() => {
    let list = threats
    if (filter === 'exposed') list = threats.filter((t) => !t.blocked)
    if (filter === 'patched') list = threats.filter((t) => t.blocked)

    const map = {}
    for (const t of list) {
      const key = t.category || 'unknown'
      if (!map[key]) map[key] = { category: key, threats: [] }
      map[key].threats.push(t)
    }

    return Object.values(map)
      .map((g) => {
        const exposed = g.threats.filter((t) => !t.blocked).length
        const blocked = g.threats.filter((t) => t.blocked).length
        // Sort threats: exposed first, then by severity
        g.threats.sort((a, b) => {
          if (a.blocked !== b.blocked) return a.blocked ? 1 : -1
          return (SEVERITY_ORDER[a.severity] ?? 4) - (SEVERITY_ORDER[b.severity] ?? 4)
        })
        return { ...g, exposed, blocked }
      })
      .sort((a, b) => {
        // Groups with exposed threats first, then by total count
        if (a.exposed !== b.exposed) return b.exposed - a.exposed
        return b.threats.length - a.threats.length
      })
  }, [threats, filter])

  const toggleGroup = (category) => {
    setOpenGroups((prev) => {
      const next = new Set(prev)
      if (next.has(category)) next.delete(category)
      else next.add(category)
      return next
    })
  }

  return (
    <div className="flex min-h-0 flex-1 flex-col overflow-hidden">
      {/* Filter tabs */}
      <div className="flex items-center gap-1 border-b border-border px-6 py-2">
        {FILTERS.map((f) => (
          <button
            key={f.key}
            onClick={() => setFilter(f.key)}
            className={`rounded-md px-3 py-1.5 text-[13px] font-medium transition-colors ${
              filter === f.key
                ? 'bg-surface-2 text-text'
                : 'text-muted hover:text-dim'
            }`}
          >
            {f.label}
            {counts[f.key] > 0 && (
              <span className={`ml-1.5 tabular-nums ${filter === f.key ? 'text-dim' : 'text-muted'}`}>
                {counts[f.key]}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* Loading state */}
      {loading && threats.length === 0 && (
        <div className="flex items-center justify-center py-16">
          <div className="flex flex-col items-center gap-3">
            <div className="h-5 w-5 animate-spin rounded-full border-2 border-border border-t-agent" />
            <span className="text-[14px] text-muted">Loading threats...</span>
          </div>
        </div>
      )}

      {/* Empty state */}
      {!loading && threats.length === 0 && (
        <div className="flex flex-col items-center justify-center px-4 py-16 text-center">
          <div className="mb-3 flex h-10 w-10 items-center justify-center rounded-xl border border-border bg-surface">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" className="text-muted">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            </svg>
          </div>
          <p className="text-[15px] font-medium text-text">No threats discovered yet</p>
          <p className="mt-1 max-w-[280px] text-[13px] text-muted">
            Run an improvement cycle to let agents discover attack techniques.
          </p>
        </div>
      )}

      {/* Grouped list */}
      {groups.length > 0 && (
        <div className="flex-1 overflow-y-auto">
          {groups.map((group) => {
            const isOpen = openGroups.has(group.category)
            const allBlocked = group.exposed === 0
            const label = humaniseAttackType(group.category)

            return (
              <div key={group.category}>
                {/* Category header row */}
                <button
                  onClick={() => toggleGroup(group.category)}
                  className="flex w-full items-center gap-3 border-b border-border px-6 py-3 text-left transition-colors hover:bg-surface/40"
                >
                  {/* Chevron */}
                  <svg
                    width="14" height="14" viewBox="0 0 16 16" fill="currentColor"
                    className={`shrink-0 text-muted transition-transform ${isOpen ? 'rotate-90' : ''}`}
                  >
                    <path d="M6 3l5 5-5 5V3z" />
                  </svg>

                  {/* Category name */}
                  <span className="text-[14px] font-medium text-text">{label}</span>

                  {/* Count */}
                  <span className="text-[13px] tabular-nums text-muted">
                    {group.threats.length}
                  </span>

                  {/* Status bar — mini stacked bar showing blocked vs exposed ratio */}
                  <div className="ml-auto flex items-center gap-3">
                    <div className="flex h-1.5 w-20 overflow-hidden rounded-full bg-border/50">
                      {group.blocked > 0 && (
                        <div
                          className="h-full bg-safe"
                          style={{ width: `${(group.blocked / group.threats.length) * 100}%` }}
                        />
                      )}
                      {group.exposed > 0 && (
                        <div
                          className="h-full bg-blocked"
                          style={{ width: `${(group.exposed / group.threats.length) * 100}%` }}
                        />
                      )}
                    </div>
                    <span className={`text-[12px] tabular-nums font-medium ${allBlocked ? 'text-safe' : 'text-blocked'}`}>
                      {allBlocked ? 'All blocked' : `${group.exposed} exposed`}
                    </span>
                  </div>
                </button>

                {/* Expanded threat rows */}
                {isOpen && (
                  <>
                    {group.threats.map((t) => (
                      <div
                        key={t.id}
                        className="flex items-center gap-3 border-b border-border/30 bg-surface/20 py-2.5 pl-14 pr-6"
                      >
                        <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${t.blocked ? 'bg-safe' : 'bg-blocked'}`} />
                        <span className="min-w-0 flex-1 truncate text-[13px] text-dim">
                          {t.technique_name}
                        </span>
                        {(t.source === 'ai' || t.source === 'ai-generated') && (
                          <span className="shrink-0 rounded bg-agent/10 px-1.5 py-0.5 text-[10px] font-medium text-agent">AI</span>
                        )}
                        {t.blocked ? (
                          <svg width="12" height="12" viewBox="0 0 16 16" className="shrink-0 text-safe">
                            <path d="M6.5 12L2 7.5l1.4-1.4L6.5 9.2l6.1-6.1L14 4.5z" fill="currentColor" />
                          </svg>
                        ) : (
                          <span className="relative flex h-2 w-2 shrink-0">
                            <span className="absolute inline-flex h-full w-full rounded-full bg-blocked opacity-40" style={{ animation: 'ping 2s cubic-bezier(0,0,0.2,1) infinite' }} />
                            <span className="relative inline-flex h-2 w-2 rounded-full bg-blocked" />
                          </span>
                        )}
                      </div>
                    ))}
                    {/* Suggested fix card */}
                    {(() => {
                      const fix = codeFixForCategory(group.category)
                      return (
                        <div className="mx-6 my-3 ml-14 rounded-lg border border-border/40 bg-surface/30 px-4 py-3">
                          <div className="flex items-center gap-2 text-[13px] font-medium text-dim">
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" className="shrink-0 text-muted">
                              <path d="M12 2a7 7 0 0 1 7 7c0 2.38-1.19 4.47-3 5.74V17a1 1 0 0 1-1 1H9a1 1 0 0 1-1-1v-2.26C6.19 13.47 5 11.38 5 9a7 7 0 0 1 7-7z" />
                              <line x1="9" y1="21" x2="15" y2="21" />
                            </svg>
                            Suggested fix &mdash; {fix.title}
                          </div>
                          <p className="mt-1.5 text-[12px] leading-relaxed text-muted">{fix.suggestion}</p>
                          {fix.example && (
                            <pre className="mt-2 overflow-x-auto rounded-md bg-black/20 px-3 py-2 text-[11px] leading-relaxed text-dim">
                              <code>{fix.example}</code>
                            </pre>
                          )}
                        </div>
                      )
                    })()}
                  </>
                )}
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
