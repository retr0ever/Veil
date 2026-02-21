import { useState } from 'react'

export function Onboarding({ user, onSiteAdded }) {
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
            {user
              ? 'Paste your URL below. Veil will give you a protected link that shields your site from attacks — and gets smarter over time.'
              : 'Sign in with GitHub to get started. Veil shields your site from attacks and gets smarter over time.'}
          </p>

          {user ? (
            <>
              {/* URL Input */}
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
            </>
          ) : (
            <>
              {/* Sign in with GitHub */}
              <a
                href="/auth/github"
                className="inline-flex items-center gap-3 px-5 py-3 bg-text text-bg font-medium text-[14px] rounded-lg hover:bg-dim transition-colors no-underline"
              >
                <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
                  <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z" />
                </svg>
                Sign in with GitHub
              </a>

              {/* Steps preview */}
              <div className="mt-10 space-y-4">
                <Step n="1" text="Sign in with your GitHub account" />
                <Step n="2" text="Paste your backend or API URL" />
                <Step n="3" text="Get a protected proxy URL — done" />
              </div>
            </>
          )}

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
