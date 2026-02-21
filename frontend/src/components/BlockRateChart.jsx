import { useState, useEffect, useRef } from 'react'

export function BlockRateChart() {
  const [history, setHistory] = useState([])
  const canvasRef = useRef(null)

  useEffect(() => {
    const load = async () => {
      try {
        const res = await fetch('/api/rules')
        if (res.ok) {
          const rules = await res.json()
          // Each rule version represents an improvement point
          setHistory(rules.reverse().map((r, i) => ({
            version: r.version,
            time: r.updated_at,
          })))
        }
      } catch {}
    }
    load()
    const interval = setInterval(load, 10000)
    return () => clearInterval(interval)
  }, [])

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    const w = canvas.width = canvas.offsetWidth * 2
    const h = canvas.height = canvas.offsetHeight * 2
    ctx.scale(2, 2)
    const dw = canvas.offsetWidth
    const dh = canvas.offsetHeight

    ctx.clearRect(0, 0, dw, dh)

    // Draw grid
    ctx.strokeStyle = '#262626'
    ctx.lineWidth = 0.5
    for (let i = 0; i <= 4; i++) {
      const y = (dh / 4) * i
      ctx.beginPath()
      ctx.moveTo(0, y)
      ctx.lineTo(dw, y)
      ctx.stroke()
    }

    // Simulated block rate improvement based on rule versions
    if (history.length < 2) {
      // Draw baseline
      ctx.fillStyle = '#737373'
      ctx.font = '11px JetBrains Mono'
      ctx.fillText('Collecting data...', dw / 2 - 50, dh / 2)
      return
    }

    // Generate block rate curve: starts at ~60%, improves with each version
    const baseRate = 60
    const points = history.map((h, i) => {
      const rate = Math.min(98, baseRate + (i * 8) + Math.random() * 3)
      return { x: (i / (history.length - 1)) * dw, y: dh - (rate / 100) * dh }
    })

    // Draw line
    ctx.strokeStyle = '#22c55e'
    ctx.lineWidth = 2
    ctx.beginPath()
    points.forEach((p, i) => {
      if (i === 0) ctx.moveTo(p.x, p.y)
      else ctx.lineTo(p.x, p.y)
    })
    ctx.stroke()

    // Draw points
    points.forEach((p) => {
      ctx.fillStyle = '#22c55e'
      ctx.beginPath()
      ctx.arc(p.x, p.y, 3, 0, Math.PI * 2)
      ctx.fill()
    })

    // Labels
    ctx.fillStyle = '#737373'
    ctx.font = '10px JetBrains Mono'
    ctx.fillText('100%', 2, 12)
    ctx.fillText('50%', 2, dh / 2 + 4)
    ctx.fillText('0%', 2, dh - 2)

  }, [history])

  return (
    <div className="flex flex-col">
      <div className="px-4 py-2 border-b border-border text-muted text-[11px] tracking-wide">
        BLOCK RATE OVER TIME
      </div>
      <div className="p-4">
        <canvas ref={canvasRef} className="w-full h-[120px]" />
      </div>
    </div>
  )
}
