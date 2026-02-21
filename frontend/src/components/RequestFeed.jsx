const classColors = {
  SAFE: 'text-safe',
  SUSPICIOUS: 'text-suspicious',
  MALICIOUS: 'text-blocked',
}

const dotColors = {
  SAFE: 'bg-safe',
  SUSPICIOUS: 'bg-suspicious',
  MALICIOUS: 'bg-blocked',
}

export function RequestFeed({ requests }) {
  return (
    <div className="flex-1 min-h-0 overflow-hidden flex flex-col">
      <div className="px-4 py-2 border-b border-border text-muted text-[11px] tracking-wide">
        LIVE REQUEST FEED
      </div>
      <div className="flex-1 overflow-y-auto">
        {requests.length === 0 && (
          <div className="px-4 py-8 text-muted text-center">Waiting for requests...</div>
        )}
        {requests.map((req, i) => (
          <div
            key={i}
            className={`px-4 py-1.5 border-b border-border/50 flex items-center gap-3 ${
              req.blocked ? 'bg-blocked/5' : ''
            }`}
          >
            <div className={`w-1.5 h-1.5 ${dotColors[req.classification]}`} />
            <span className="text-muted text-[11px] w-20 shrink-0">
              {req.timestamp?.split('T')[1]?.slice(0, 8) || '—'}
            </span>
            <span className={`w-20 shrink-0 text-[11px] font-bold ${classColors[req.classification]}`}>
              {req.classification}
            </span>
            <span className="text-muted text-[11px] w-12 shrink-0">
              {(req.confidence * 100).toFixed(0)}%
            </span>
            <span className="text-muted text-[11px] w-14 shrink-0">
              {req.classifier}
            </span>
            <span className="truncate text-[12px]">
              {req.message}
            </span>
            {req.blocked && (
              <span className="ml-auto text-blocked text-[10px] font-bold tracking-wider shrink-0">
                BLOCKED
              </span>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}
