import { useState } from 'react'
import { setProjectName } from '../lib/projectNames'

function normalizeUrl(raw) {
  const value = raw.trim()
  if (!value) return ''
  if (value.startsWith('http://') || value.startsWith('https://')) return value
  return `https://${value}`
}

export function OnboardingPage() {
  const [name, setName] = useState('')
  const [url, setUrl] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState('')
  const [created, setCreated] = useState(null)

  const submit = async (event) => {
    event.preventDefault()
    setError('')

    const cleanUrl = normalizeUrl(url)
    if (!cleanUrl) {
      setError('Enter an upstream URL.')
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
        setError('Veil could not create this project. Check URL format and retry.')
      } else {
        const site = await res.json()
        const savedName = name.trim() || new URL(cleanUrl).hostname
        setProjectName(site.site_id, savedName)
        setCreated({ ...site, name: savedName })
      }
    } catch {
      setError('Could not reach Veil API.')
    }
    setSubmitting(false)
  }

  const protectedUrl = created ? `${window.location.origin}/p/${created.site_id}` : ''

  return (
    <div className="flex min-h-screen items-center justify-center bg-bg px-4 text-text">
      <div className="w-full max-w-2xl rounded-2xl border border-border bg-surface p-6">
        <p className="font-mono text-[12px] tracking-[0.2em] text-dim">ONBOARDING</p>
        <h1 className="mt-3 text-3xl font-semibold tracking-tight">Create protected project</h1>
        <p className="mt-2 text-[14px] text-dim">
          Enter a project name and upstream backend/API URL. Veil will return a protected reverse-proxy URL.
        </p>

        <form className="mt-6 space-y-4" onSubmit={submit}>
          <label className="block">
            <span className="mb-1 block text-[13px] text-muted">Project name</span>
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Customer API"
              className="w-full rounded-lg border border-border bg-bg px-3 py-2.5 text-[14px]"
              disabled={submitting}
            />
          </label>

          <label className="block">
            <span className="mb-1 block text-[13px] text-muted">Upstream URL</span>
            <input
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://api.example.com"
              className="w-full rounded-lg border border-border bg-bg px-3 py-2.5 text-[14px]"
              disabled={submitting}
              required
            />
          </label>

          <button
            type="submit"
            disabled={submitting || !url.trim()}
            className="rounded-lg bg-text px-4 py-2.5 text-[14px] font-medium text-bg disabled:cursor-not-allowed disabled:opacity-50"
          >
            {submitting ? 'Creating...' : 'Create project'}
          </button>
        </form>

        {error && <p className="mt-3 text-[13px] text-blocked">{error}</p>}

        {created && (
          <section className="mt-6 rounded-xl border border-safe/40 bg-safe/8 p-4">
            <p className="text-[13px] text-safe">Project ready</p>
            <h2 className="mt-1 text-lg font-semibold">{created.name}</h2>
            <p className="mt-2 text-[13px] text-dim">Upstream: {created.target_url}</p>
            <p className="mt-1 font-mono text-[12px] text-text">Protected: {protectedUrl}</p>
            <div className="mt-4 flex gap-4 text-[13px]">
              <a href={`/app/projects/${created.site_id}`} className="text-agent hover:underline">Open dashboard</a>
              <a href="/app/projects" className="text-dim hover:text-text">All projects</a>
            </div>
          </section>
        )}
      </div>
    </div>
  )
}
