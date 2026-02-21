import { useEffect, useState } from 'react'
import { useAuth } from '../hooks/useAuth'
import { getProjectNames } from '../lib/projectNames'

export function ProjectsPage() {
  const { user, loading: authLoading, logout } = useAuth()
  const [sites, setSites] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    if (authLoading) return
    if (!user) {
      window.location.href = '/auth'
      return
    }

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
  }, [user, authLoading])

  if (authLoading || (!user && !authLoading)) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-bg text-muted">
        Loading...
      </div>
    )
  }

  const names = getProjectNames()

  return (
    <div className="min-h-screen bg-bg text-text">
      <main className="mx-auto max-w-6xl px-6 pb-8 pt-0">
        <div className="mb-5 flex items-center justify-between gap-4">
          <h1 className="text-xl font-semibold">Projects</h1>
          <div className="flex items-center gap-3">
            <a href="/app/onboarding" className="rounded-lg bg-text px-3 py-1.5 text-[14px] font-medium text-bg">New project</a>
            {user && (
              <>
                <div className="h-4 w-px bg-border" />
                <div className="flex items-center gap-2">
                  {user.avatar_url && (
                    <img src={user.avatar_url} alt={user.github_login} className="h-6 w-6 rounded-full" />
                  )}
                  <span className="text-[12px] text-dim">{user.name || user.github_login}</span>
                  <button onClick={logout} className="border-none bg-transparent text-[11px] text-muted transition-colors hover:text-text">
                    Sign out
                  </button>
                </div>
              </>
            )}
          </div>
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
