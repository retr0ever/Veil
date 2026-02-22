import { useState, useEffect } from 'react'
import { useAuth } from '../hooks/useAuth'
import { setProjectName } from '../lib/projectNames'
import { AppShell, LoadingSpinner } from '../components/AppShell'
import { APP_SIDEBAR_LINKS } from '../lib/navLinks'

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
  const [domain, setDomain] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState('')
  const [created, setCreated] = useState(null)
  const [verifying, setVerifying] = useState(false)
  const [siteStatus, setSiteStatus] = useState(null)

  // Poll for DNS verification after creation
  useEffect(() => {
    if (!created || siteStatus?.status === 'active') return
    const interval = setInterval(async () => {
      try {
        const res = await fetch(`/api/sites/${created.site_id}/status`)
        if (res.ok) {
          const data = await res.json()
          setSiteStatus(data)
          if (data.status === 'active') clearInterval(interval)
        }
      } catch {}
    }, 15000) // check every 15 seconds
    return () => clearInterval(interval)
  }, [created, siteStatus?.status])

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

  const canSubmit = domain.trim().length > 0 && !submitting

  const submit = async (event) => {
    event.preventDefault()
    setError('')

    const cleanDomain = domain.trim().replace(/^https?:\/\//, '').replace(/\/.*$/, '')
    if (!cleanDomain) {
      setError('Please enter a valid domain name.')
      return
    }

    setSubmitting(true)
    try {
      const res = await fetch('/api/sites', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain: cleanDomain, name: name.trim() || cleanDomain }),
      })

      if (!res.ok) {
        const body = await res.json().catch(() => ({}))
        setError(body.error || 'Veil could not create this project. Check the domain and try again.')
      } else {
        const data = await res.json()
        const savedName = name.trim() || cleanDomain
        setProjectName(data.site_id, savedName)
        setCreated(data)
        setSiteStatus({ status: data.site?.status || 'pending' })
      }
    } catch {
      setError('Could not reach the Veil API. Check your connection and try again.')
    }
    setSubmitting(false)
  }

  const verifyDns = async () => {
    if (!created) return
    setVerifying(true)
    try {
      const res = await fetch(`/api/sites/${created.site_id}/verify`, { method: 'POST' })
      if (res.ok) {
        const site = await res.json()
        setSiteStatus({ status: site.status || site.Status || 'active' })
      } else {
        const body = await res.json().catch(() => ({}))
        setError(body.error || 'DNS verification failed. Make sure your CNAME record is set.')
      }
    } catch {
      setError('Could not verify DNS. Try again in a moment.')
    }
    setVerifying(false)
  }

  const isActive = siteStatus?.status === 'active'
  const instructions = created?.instructions

  return (
    <AppShell links={APP_SIDEBAR_LINKS} activeKey="new" user={user} logout={logout} pageTitle="New Project">
      <div className="flex flex-1 items-center justify-center px-6 py-10">
        {!created ? (
          /* ── Creation form ── */
          <div className="w-full max-w-xl">
            <div className="mb-8">
              <span className="inline-block rounded-md bg-agent/10 px-3 py-1 text-[12px] font-semibold tracking-[0.15em] text-agent">
                NEW PROJECT
              </span>
              <h1 className="mt-4 text-[30px] font-semibold leading-tight tracking-tight">
                Protect your site
              </h1>
              <p className="mt-3 text-[16px] leading-relaxed text-dim">
                Enter your domain and Veil will set up a reverse proxy. Just update your DNS record to route traffic through Veil.
              </p>
            </div>

            <div className="rounded-2xl border border-border/60 bg-surface p-8">
              <form className="space-y-6" onSubmit={submit}>
                {/* Domain */}
                <div>
                  <label htmlFor="domain" className="mb-2 block text-[15px] font-medium text-dim">
                    Domain
                  </label>
                  <input
                    id="domain"
                    value={domain}
                    onChange={(e) => { setDomain(e.target.value); if (error) setError('') }}
                    placeholder="myapp.example.com"
                    className={`w-full rounded-lg border bg-bg px-4 py-3 text-[16px] text-text placeholder:text-muted/50 transition-colors duration-150 focus:ring-1 ${
                      error
                        ? 'border-blocked/60 focus:border-blocked/60 focus:ring-blocked/20'
                        : 'border-border focus:border-agent/50 focus:ring-agent/20'
                    }`}
                    disabled={submitting}
                    required
                  />
                  <p className="mt-2 text-[14px] text-muted">
                    The domain your users visit — Veil will protect all traffic to it
                  </p>
                </div>

                {/* Project name */}
                <div>
                  <label htmlFor="project-name" className="mb-2 block text-[15px] font-medium text-dim">
                    Project name
                    <span className="ml-1.5 text-[13px] font-normal text-muted">(optional)</span>
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

                {/* Error */}
                {error && (
                  <div className="flex items-start gap-2.5 rounded-lg border border-blocked/20 bg-blocked/5 px-4 py-3">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="mt-0.5 shrink-0 text-blocked">
                      <circle cx="12" cy="12" r="10" /><line x1="15" y1="9" x2="9" y2="15" /><line x1="9" y1="9" x2="15" y2="15" />
                    </svg>
                    <p className="text-[14px] leading-relaxed text-blocked/90">{error}</p>
                  </div>
                )}

                {/* Submit */}
                <button
                  type="submit"
                  disabled={!canSubmit}
                  className={`flex w-full items-center justify-center gap-2.5 rounded-xl px-5 py-4 text-[16px] font-medium transition-all duration-150 ${
                    canSubmit
                      ? 'bg-agent text-[#1a1322] hover:brightness-110'
                      : 'cursor-not-allowed bg-border/60 text-muted/50'
                  }`}
                  style={canSubmit ? { color: '#1a1322' } : undefined}
                >
                  {submitting ? (
                    <>
                      <div className="h-4 w-4 animate-spin rounded-full border-2 border-[#1a1322]/35 border-t-[#1a1322]" />
                      Setting up...
                    </>
                  ) : (
                    <>
                      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                      </svg>
                      Add site
                    </>
                  )}
                </button>
              </form>
            </div>
          </div>
        ) : (
          /* ── DNS Instructions ── */
          <div className="w-full max-w-xl">
            <div className="flex flex-col items-center text-center">
              {isActive ? (
                /* Verified state */
                <>
                  <div className="relative mb-6">
                    <div className="absolute inset-0 animate-ping rounded-full bg-safe/10" style={{ animationDuration: '2s' }} />
                    <div className="relative flex h-20 w-20 items-center justify-center rounded-full border-2 border-safe/30 bg-safe/10">
                      <svg width="36" height="36" viewBox="0 0 36 36" fill="none">
                        <path d="M10 18.5L15.5 24L26 12" stroke="#8fd9a7" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" />
                      </svg>
                    </div>
                  </div>
                  <h2 className="text-[28px] font-semibold tracking-tight text-text">DNS verified</h2>
                  <p className="mt-2 text-[16px] leading-relaxed text-dim">
                    <span className="font-medium text-safe">{created.site?.domain || domain}</span> is now routing through Veil. All traffic is being monitored and protected.
                  </p>
                </>
              ) : (
                /* Pending DNS state */
                <>
                  <div className="relative mb-6">
                    <div className="relative flex h-20 w-20 items-center justify-center rounded-full border-2 border-agent/30 bg-agent/10">
                      <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" className="text-agent">
                        <circle cx="12" cy="12" r="10" />
                        <line x1="2" y1="12" x2="22" y2="12" />
                        <path d="M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z" />
                      </svg>
                    </div>
                  </div>
                  <h2 className="text-[28px] font-semibold tracking-tight text-text">Update your DNS</h2>
                  <p className="mt-2 text-[16px] leading-relaxed text-dim">
                    Add a CNAME record to route traffic through Veil. This is all you need to do.
                  </p>
                </>
              )}
            </div>

            {/* DNS Record Card */}
            {!isActive && instructions && (
              <div className="mt-6 rounded-xl border border-border/60 bg-surface p-6 space-y-5">
                <div>
                  <p className="text-[12px] font-medium tracking-wide text-muted mb-3">DNS RECORD TO ADD</p>
                  <div className="overflow-hidden rounded-lg border border-border bg-bg">
                    <table className="w-full text-left">
                      <thead>
                        <tr className="border-b border-border/50 text-[12px] font-medium tracking-wide text-muted">
                          <th className="px-4 py-2.5">Type</th>
                          <th className="px-4 py-2.5">Name</th>
                          <th className="px-4 py-2.5">Value</th>
                        </tr>
                      </thead>
                      <tbody>
                        <tr className="text-[14px]">
                          <td className="px-4 py-3">
                            <span className="rounded bg-agent/10 px-2 py-0.5 text-[13px] font-semibold text-agent">
                              {instructions.record_type}
                            </span>
                          </td>
                          <td className="px-4 py-3 font-mono text-text">{instructions.name}</td>
                          <td className="px-4 py-3">
                            <div className="flex items-center gap-2">
                              <span className="font-mono text-safe">{instructions.value}</span>
                              <CopyButton text={instructions.value} />
                            </div>
                          </td>
                        </tr>
                      </tbody>
                    </table>
                  </div>
                </div>

                {/* Where to do this */}
                <div className="rounded-lg border border-border/40 bg-bg/50 px-4 py-3">
                  <p className="text-[14px] leading-relaxed text-dim">
                    Go to your DNS provider (Cloudflare, Namecheap, Route 53, etc.) and add this record. DNS changes typically propagate within a few minutes.
                  </p>
                </div>

                {/* Verify button */}
                <div className="flex items-center gap-3">
                  <button
                    onClick={verifyDns}
                    disabled={verifying}
                    className="flex items-center gap-2.5 rounded-lg bg-text px-5 py-3 text-[15px] font-semibold text-bg transition-opacity hover:opacity-90 disabled:opacity-40"
                  >
                    {verifying ? (
                      <>
                        <div className="h-4 w-4 animate-spin rounded-full border-2 border-bg/30 border-t-bg" />
                        Checking DNS...
                      </>
                    ) : (
                      <>
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                          <polyline points="23 4 23 10 17 10" />
                          <path d="M20.49 15a9 9 0 11-2.12-9.36L23 10" />
                        </svg>
                        Verify DNS
                      </>
                    )}
                  </button>
                  <span className="text-[13px] text-muted">
                    Auto-checking every 15s
                  </span>
                </div>

                {error && (
                  <div className="flex items-start gap-2.5 rounded-lg border border-blocked/20 bg-blocked/5 px-4 py-3">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="mt-0.5 shrink-0 text-blocked">
                      <circle cx="12" cy="12" r="10" /><line x1="15" y1="9" x2="9" y2="15" /><line x1="9" y1="9" x2="15" y2="15" />
                    </svg>
                    <p className="text-[14px] leading-relaxed text-blocked/90">{error}</p>
                  </div>
                )}
              </div>
            )}

            {/* Action buttons */}
            <div className="mt-6 flex gap-3">
              <a
                href={`/app/projects/${created.site_id}`}
                className="flex flex-1 items-center justify-center gap-2 rounded-xl bg-agent px-5 py-3.5 text-[16px] font-medium text-[#1a1322] transition-all duration-150 hover:brightness-110"
                style={{ color: '#1a1322' }}
              >
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <rect x="3" y="3" width="7" height="7" /><rect x="14" y="3" width="7" height="7" /><rect x="3" y="14" width="7" height="7" /><rect x="14" y="14" width="7" height="7" />
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
