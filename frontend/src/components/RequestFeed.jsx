const classColors = {
  SAFE: 'text-safe',
  SUSPICIOUS: 'text-suspicious',
  MALICIOUS: 'text-blocked',
}

export function RequestFeed({ requests }) {
  return (
    <div className="flex-1 min-h-0 overflow-hidden flex flex-col">
      <div className="px-4 py-2.5 border-b border-border text-muted text-[12px] font-medium">
        Live requests
      </div>
      <div className="flex-1 overflow-y-auto">
        {requests.length === 0 && (
          <div className="px-4 py-8 text-muted text-center text-[13px]">
            Waiting for traffic...
          </div>
        )}
        {requests.map((req, i) => (
          <div
            key={i}
            className={`px-4 py-2 border-b border-border/40 flex items-center gap-3 ${
              req.blocked ? 'bg-blocked/5' : ''
            }`}
          >
            <div className={`w-1.5 h-1.5 rounded-full shrink-0 ${
              req.classification === 'SAFE' ? 'bg-safe' :
              req.classification === 'SUSPICIOUS' ? 'bg-suspicious' : 'bg-blocked'
            }`} />
            <span className="text-muted text-[11px] font-mono w-16 shrink-0">
              {req.timestamp?.split('T')[1]?.slice(0, 8) || '\u2014'}
            </span>
            <span className={`w-20 shrink-0 text-[12px] font-semibold ${classColors[req.classification]}`}>
              {req.classification}
            </span>
            <span className="text-muted text-[11px] font-mono w-10 shrink-0">
              {(req.confidence * 100).toFixed(0)}%
            </span>
            <span className="truncate text-dim text-[12px] font-mono">
              {req.message}
            </span>
            {req.blocked && (
              <span className="ml-auto text-blocked text-[10px] font-semibold tracking-wider shrink-0 bg-blocked/10 px-2 py-0.5 rounded">
                BLOCKED
              </span>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}
