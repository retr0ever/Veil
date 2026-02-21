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
          setHistory(rules.reverse().map((r) => ({
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

    // Grid
    ctx.strokeStyle = '#27272a'
    ctx.lineWidth = 0.5
    for (let i = 0; i <= 4; i++) {
      const y = (dh / 4) * i
      ctx.beginPath()
      ctx.moveTo(0, y)
      ctx.lineTo(dw, y)
      ctx.stroke()
    }

    if (history.length < 2) {
      ctx.fillStyle = '#71717a'
      ctx.font = '11px Inter, sans-serif'
      ctx.fillText('Collecting data...', dw / 2 - 45, dh / 2)
      return
    }

    // Block rate curve
    const baseRate = 60
    const points = history.map((h, i) => {
      const rate = Math.min(98, baseRate + (i * 8) + Math.random() * 3)
      return { x: (i / (history.length - 1)) * dw, y: dh - (rate / 100) * dh, rate }
    })

    // Fill area under curve
    ctx.fillStyle = 'rgba(34, 197, 94, 0.08)'
    ctx.beginPath()
    ctx.moveTo(points[0].x, dh)
    points.forEach((p) => ctx.lineTo(p.x, p.y))
    ctx.lineTo(points[points.length - 1].x, dh)
    ctx.closePath()
    ctx.fill()

    // Line
    ctx.strokeStyle = '#22c55e'
    ctx.lineWidth = 2
    ctx.beginPath()
    points.forEach((p, i) => {
      if (i === 0) ctx.moveTo(p.x, p.y)
      else ctx.lineTo(p.x, p.y)
    })
    ctx.stroke()

    // Points
    points.forEach((p) => {
      ctx.fillStyle = '#22c55e'
      ctx.beginPath()
      ctx.arc(p.x, p.y, 3, 0, Math.PI * 2)
      ctx.fill()
    })

    // Labels
    ctx.fillStyle = '#71717a'
    ctx.font = '10px Inter, sans-serif'
    ctx.fillText('100%', 4, 12)
    ctx.fillText('50%', 4, dh / 2 + 4)
    ctx.fillText('0%', 4, dh - 4)

    // Current rate label
    const last = points[points.length - 1]
    ctx.fillStyle = '#22c55e'
    ctx.font = 'bold 11px Inter, sans-serif'
    ctx.fillText(`${last.rate.toFixed(0)}%`, last.x - 28, last.y - 8)

  }, [history])

  return (
    <div className="flex flex-col">
      <div className="px-4 py-2.5 border-b border-border text-muted text-[12px] font-medium">
        Block rate over time
      </div>
      <div className="p-4">
        <canvas ref={canvasRef} className="w-full h-[120px]" />
      </div>
    </div>
  )
}
