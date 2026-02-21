import { useState } from 'react'

export function Onboarding({ onSiteAdded }) {
  const [url, setUrl] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState('')

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')

    let cleanUrl = url.trim()
    if (!cleanUrl) return

    if (!cleanUrl.startsWith('http://') && !cleanUrl.startsWith('https://')) {
      cleanUrl = 'https://' + cleanUrl
    }

    setSubmitting(true)
    try {
      const res = await fetch('/api/sites', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: cleanUrl }),
      })
      if (res.ok) {
        const site = await res.json()
        onSiteAdded(site)
      } else {
        setError('Failed to add site. Check the URL and try again.')
      }
    } catch {
      setError('Could not connect to Veil server.')
    }
    setSubmitting(false)
  }

  return (
    <div className="h-screen flex flex-col bg-bg">
      {/* Header */}
      <div className="px-6 py-4 border-b border-border">
        <span className="text-base font-semibold tracking-tight">veil</span>
      </div>

      {/* Centre content */}
      <div className="flex-1 flex items-center justify-center">
        <div className="w-full max-w-[480px] px-6">
          {/* Headline */}
          <h1 className="text-[28px] font-semibold leading-tight mb-3">
            Protect your website
          </h1>
          <p className="text-muted text-[15px] leading-relaxed mb-8">
            Paste your URL below. Veil will give you a protected link that
            shields your site from attacks — and gets smarter over time.
          </p>

          {/* Input */}
          <form onSubmit={handleSubmit}>
            <div className="flex gap-2">
              <input
                type="text"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="https://api.yoursite.com"
                className="flex-1 bg-surface border border-border rounded-lg px-4 py-3 text-[15px] text-text placeholder:text-muted/50 focus:border-dim transition-colors"
                autoFocus
                disabled={submitting}
              />
              <button
                type="submit"
                disabled={submitting || !url.trim()}
                className="px-5 py-3 bg-text text-bg font-medium text-[14px] rounded-lg hover:bg-dim transition-colors disabled:opacity-40 disabled:cursor-not-allowed shrink-0"
              >
                {submitting ? 'Adding...' : 'Protect'}
              </button>
            </div>
            {error && (
              <p className="text-blocked text-[13px] mt-3">{error}</p>
            )}
          </form>

          {/* Steps preview */}
          <div className="mt-10 space-y-4">
            <Step n="1" text="Paste your backend or API URL above" />
            <Step n="2" text="Get a protected proxy URL back" />
            <Step n="3" text="Swap one line in your config — done" />
          </div>

          {/* Bottom note */}
          <p className="mt-10 text-muted text-[12px] leading-relaxed">
            No packages to install. No code to change. Veil sits in front
            of your site, checks every request, and blocks attacks before
            they reach you. It constantly tests its own defences and patches
            any gaps automatically.
          </p>
        </div>
      </div>
    </div>
  )
}

function Step({ n, text }) {
  return (
    <div className="flex items-center gap-3">
      <div className="w-6 h-6 rounded-full border border-border flex items-center justify-center shrink-0">
        <span className="text-[11px] text-muted font-medium">{n}</span>
      </div>
      <span className="text-dim text-[13px]">{text}</span>
    </div>
  )
}
