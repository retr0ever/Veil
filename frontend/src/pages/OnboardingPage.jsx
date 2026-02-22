import { useState, useRef, useEffect } from 'react'
import { useAuth } from '../hooks/useAuth'
import { setProjectName } from '../lib/projectNames'
import { AppShell, LoadingSpinner } from '../components/AppShell'
import { APP_SIDEBAR_LINKS } from '../lib/navLinks'
import { getBaseUrl, proxyUrl as buildProxyUrl } from '../lib/baseUrl'

function normalizeUrl(raw) {
  const value = raw.trim()
  if (!value) return ''
  if (value.startsWith('http://') || value.startsWith('https://')) return value
  return `https://${value}`
}

function CopyButton({ text }) {
  const [copied, setCopied] = useState(false)

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(text)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch {
      const el = document.createElement('textarea')
      el.value = text
      document.body.appendChild(el)
      el.select()
      document.execCommand('copy')
      document.body.removeChild(el)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    }
  }

  return (
    <button
      type="button"
      onClick={handleCopy}
      className="shrink-0 rounded-md border border-border bg-bg px-3 py-1.5 text-[13px] font-medium text-dim transition-all duration-150 hover:border-agent/40 hover:text-agent"
    >
      {copied ? (
        <span className="flex items-center gap-1.5">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" className="text-safe">
            <path d="M20 6L9 17l-5-5" />
          </svg>
          Copied
        </span>
      ) : (
        <span className="flex items-center gap-1.5">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
            <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
          </svg>
          Copy
        </span>
      )}
    </button>
  )
}

export function OnboardingPage() {
  const { user, loading: authLoading, logout } = useAuth()
  const [name, setName] = useState('')
  const [url, setUrl] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState('')
  const [created, setCreated] = useState(null)
  const [protectedUrl, setProtectedUrl] = useState('')
  const urlInputRef = useRef(null)

  useEffect(() => {
    if (created) {
      getBaseUrl().then(() => setProtectedUrl(buildProxyUrl(created.site_id)))
    }
  }, [created])

  if (authLoading) {
    return (
      <AppShell links={APP_SIDEBAR_LINKS} activeKey="new" user={user} logout={logout} pageTitle="New Project">
        <LoadingSpinner />
      </AppShell>
    )
  }

  if (!user) {
    window.location.href = '/auth'
    return null
  }

  const canSubmit = url.trim().length > 0 && !submitting

  const submit = async (event) => {
    event.preventDefault()
    setError('')

    const cleanUrl = normalizeUrl(url)
    if (!cleanUrl) {
      setError('Please enter a valid upstream URL.')
      return
    }

    setSubmitting(true)
    try {
      const res = await fetch('/api/sites', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: cleanUrl }),
      })

      if (!res.ok) {
        const body = await res.text().catch(() => '')
        setError(
          body || 'Veil could not create this project. Check the URL format and try again.'
        )
      } else {
        const site = await res.json()
        const savedName = name.trim() || new URL(cleanUrl).hostname
        setProjectName(site.site_id, savedName)
        setCreated({ ...site, name: savedName })
      }
    } catch {
      setError('Could not reach the Veil API. Check your connection and try again.')
    }
    setSubmitting(false)
  }


  return (
    <AppShell links={APP_SIDEBAR_LINKS} activeKey="new" user={user} logout={logout} pageTitle="New Project">
      <div className="flex flex-1 items-center justify-center px-6 py-10">
        {!created ? (
          /* ── Creation form ── */
          <div className="w-full max-w-xl">
            {/* Badge + heading */}
            <div className="mb-8">
              <span className="inline-block rounded-md bg-agent/10 px-3 py-1 text-[12px] font-semibold tracking-[0.15em] text-agent">
                NEW PROJECT
              </span>
              <h1 className="mt-4 text-[30px] font-semibold leading-tight tracking-tight">
                Protect a site
              </h1>
              <p className="mt-3 text-[16px] leading-relaxed text-dim">
                Enter a project name and the upstream URL you want to shield.
                Veil will generate a protected reverse-proxy endpoint.
              </p>
            </div>

            {/* Form card */}
            <div className="rounded-2xl border border-border/60 bg-surface p-8">
              <form className="space-y-6" onSubmit={submit}>
                {/* Project name */}
                <div>
                  <label
                    htmlFor="project-name"
                    className="mb-2 block text-[15px] font-medium text-dim"
                  >
                    Project name
                    <span className="ml-1.5 text-[13px] font-normal text-muted">
                      (optional)
                    </span>
                  </label>
                  <input
                    id="project-name"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    placeholder="e.g. Customer API"
                    className="w-full rounded-lg border border-border bg-bg px-4 py-3 text-[16px] text-text placeholder:text-muted/50 transition-colors duration-150 focus:border-agent/50 focus:ring-1 focus:ring-agent/20"
                    disabled={submitting}
                  />
                </div>

                {/* Upstream URL */}
                <div>
                  <label
                    htmlFor="upstream-url"
                    className="mb-2 block text-[15px] font-medium text-dim"
                  >
                    Upstream URL
                  </label>
                  <input
                    ref={urlInputRef}
                    id="upstream-url"
                    value={url}
                    onChange={(e) => {
                      setUrl(e.target.value)
                      if (error) setError('')
                    }}
                    placeholder="https://api.example.com"
                    className={`w-full rounded-lg border bg-bg px-4 py-3 text-[16px] text-text placeholder:text-muted/50 transition-colors duration-150 focus:ring-1 ${
                      error
                        ? 'border-blocked/60 focus:border-blocked/60 focus:ring-blocked/20'
                        : 'border-border focus:border-agent/50 focus:ring-agent/20'
                    }`}
                    disabled={submitting}
                    required
                  />
                  <p className="mt-2 text-[14px] text-muted">
                    The backend or API you want Veil to protect
                  </p>
                </div>

                {/* Error message */}
                {error && (
                  <div className="flex items-start gap-2.5 rounded-lg border border-blocked/20 bg-blocked/5 px-4 py-3">
                    <svg
                      width="16"
                      height="16"
                      viewBox="0 0 24 24"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="2"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      className="mt-0.5 shrink-0 text-blocked"
                    >
                      <circle cx="12" cy="12" r="10" />
                      <line x1="15" y1="9" x2="9" y2="15" />
                      <line x1="9" y1="9" x2="15" y2="15" />
                    </svg>
                    <p className="text-[14px] leading-relaxed text-blocked/90">{error}</p>
                  </div>
                )}

                {/* Submit button */}
                <button
                  type="submit"
                  disabled={!canSubmit}
                  className={`flex w-full items-center justify-center gap-2.5 rounded-xl px-5 py-4 text-[16px] font-medium transition-all duration-150 ${
                    canSubmit
                      ? 'bg-agent text-[#1a1322] hover:brightness-110'
                      : 'cursor-not-allowed bg-border/60 text-muted/50'
                  }`}
                >
                  {submitting ? (
                    <>
                      <div className="h-4 w-4 animate-spin rounded-full border-2 border-[#1a1322]/35 border-t-[#1a1322]" />
                      Creating project...
                    </>
                  ) : (
                    <>
                      <svg
                        width="18"
                        height="18"
                        viewBox="0 0 24 24"
                        fill="none"
                        stroke="currentColor"
                        strokeWidth="2"
                        strokeLinecap="round"
                        strokeLinejoin="round"
                      >
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                      </svg>
                      Create project
                    </>
                  )}
                </button>
              </form>
            </div>
          </div>
        ) : (
          /* ── Success state ── */
          <div className="w-full max-w-lg">
            <div className="flex flex-col items-center text-center">
              {/* Animated checkmark ring */}
              <div className="relative mb-6">
                <div className="absolute inset-0 animate-ping rounded-full bg-safe/10" style={{ animationDuration: '2s' }} />
                <div className="relative flex h-20 w-20 items-center justify-center rounded-full border-2 border-safe/30 bg-safe/10">
                  <svg width="36" height="36" viewBox="0 0 36 36" fill="none">
                    <path
                      d="M10 18.5L15.5 24L26 12"
                      stroke="#8fd9a7"
                      strokeWidth="3"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                    />
                  </svg>
                </div>
              </div>

              <h2 className="text-[28px] font-semibold tracking-tight text-text">
                Project ready
              </h2>
              <p className="mt-2 text-[16px] leading-relaxed text-dim">
                <span className="font-medium text-text">{created.name}</span> is now protected by Veil.
                Route traffic through the protected URL below.
              </p>
            </div>

            {/* Details card */}
            <div className="mt-6 rounded-xl border border-border/60 bg-surface p-6 space-y-4">
              {/* Upstream */}
              <div>
                <p className="text-[12px] font-medium tracking-wide text-muted">
                  UPSTREAM
                </p>
                <p className="mt-1 truncate font-mono text-[15px] text-dim">
                  {created.target_url}
                </p>
              </div>

              {/* Divider */}
              <div className="border-t border-border/50" />

              {/* Protected URL */}
              <div>
                <p className="text-[12px] font-medium tracking-wide text-muted">
                  PROTECTED URL
                </p>
                <div className="mt-2 flex items-center gap-2">
                  <p className="min-w-0 flex-1 truncate rounded-md bg-bg px-3.5 py-2.5 font-mono text-[15px] text-safe">
                    {protectedUrl}
                  </p>
                  <CopyButton text={protectedUrl} />
                </div>
              </div>
            </div>

            {/* Action buttons */}
            <div className="mt-6 flex gap-3">
              <a
                href={`/app/projects/${created.site_id}`}
                className="flex flex-1 items-center justify-center gap-2 rounded-xl bg-agent px-5 py-3.5 text-[16px] font-medium text-[#1a1322] transition-all duration-150 hover:brightness-110"
              >
                <svg
                  width="18"
                  height="18"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                >
                  <rect x="3" y="3" width="7" height="7" />
                  <rect x="14" y="3" width="7" height="7" />
                  <rect x="3" y="14" width="7" height="7" />
                  <rect x="14" y="14" width="7" height="7" />
                </svg>
                Open dashboard
              </a>
              <a
                href="/app/projects"
                className="flex items-center justify-center rounded-xl border border-border px-5 py-3.5 text-[15px] text-dim transition-colors duration-150 hover:border-dim hover:bg-surface-2 hover:text-text"
              >
                All projects
              </a>
            </div>
          </div>
        )}
      </div>
    </AppShell>
  )
}
