import { useEffect, useState } from 'react'
import { getProjectNames } from '../lib/projectNames'
import { NavBar } from '../components/NavBar'
import { APP_NAV_LINKS } from '../lib/navLinks'

export function ProjectsPage() {
  const [sites, setSites] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    const load = async () => {
      try {
        const res = await fetch('/api/sites')
        if (!res.ok) throw new Error('Failed to load projects')
        const data = await res.json()
        setSites(data)
      } catch {
        setError('Could not load projects from Veil API.')
      }
      setLoading(false)
    }
    load()
  }, [])

  const names = getProjectNames()

  return (
    <div className="min-h-screen bg-bg text-text">
      <div className="mx-auto max-w-6xl px-6 pt-4">
        <NavBar links={APP_NAV_LINKS} activeHref="/app/projects" showDivider />
      </div>

      <main className="mx-auto max-w-6xl px-6 py-6">
        <div className="mb-5 flex items-center justify-between gap-4">
          <h1 className="text-xl font-semibold">Projects</h1>
          <a href="/app/onboarding" className="rounded-lg bg-text px-3 py-1.5 text-[14px] font-medium text-bg">New project</a>
        </div>

        {loading && <p className="text-[14px] text-muted">Loading projects...</p>}
        {error && <p className="text-[14px] text-blocked">{error}</p>}

        {!loading && !error && sites.length === 0 && (
          <div className="rounded-2xl border border-border bg-surface p-8 text-center">
            <p className="text-[15px] text-dim">No projects yet.</p>
            <a href="/app/onboarding" className="mt-4 inline-flex rounded-lg bg-text px-4 py-2 text-[14px] font-medium text-bg">
              Create your first protected API
            </a>
          </div>
        )}

        {!loading && !error && sites.length > 0 && (
          <div className="grid gap-4 md:grid-cols-2">
            {sites.map((site, index) => {
              const fallbackName = `Project ${sites.length - index}`
              const projectName = names[site.site_id] || fallbackName
              const protectedUrl = `${window.location.origin}/p/${site.site_id}`

              return (
                <article key={site.site_id} className="rounded-2xl border border-border bg-surface p-5">
                  <h2 className="text-lg font-semibold">{projectName}</h2>
                  <p className="mt-1 truncate text-[13px] text-dim">{site.target_url}</p>
                  <p className="mt-3 font-mono text-[11px] text-muted">{protectedUrl}</p>
                  <div className="mt-4 flex items-center gap-3 text-[13px]">
                    <a href={`/app/projects/${site.site_id}`} className="text-agent hover:underline">Open dashboard</a>
                    <a href={protectedUrl} className="text-dim hover:text-text">Proxy URL</a>
                  </div>
                </article>
              )
            })}
          </div>
        )}
      </main>
    </div>
  )
}
