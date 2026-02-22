import { useEffect, useState } from 'react'
import { useAuth } from '../hooks/useAuth'
import { getProjectNames } from '../lib/projectNames'
import { AppShell, LoadingSpinner } from '../components/AppShell'
import { APP_SIDEBAR_LINKS } from '../lib/navLinks'

function ProjectCard({ site, projectName }) {
  const isActive = site.status === 'active'

  return (
    <a
      href={`/app/projects/${site.site_id}`}
      className="group relative block rounded-xl border border-border bg-surface/80 p-7 shadow-[0_1px_3px_rgba(0,0,0,0.2)] transition-all duration-200 hover:border-agent/40 hover:bg-surface hover:shadow-[0_4px_20px_rgba(0,0,0,0.4),0_0_0_1px_rgba(212,167,218,0.15)] hover:-translate-y-0.5 cursor-pointer"
    >
      {/* Status + Name row */}
      <div className="flex items-center gap-3">
        <div className="relative flex h-5 w-5 items-center justify-center">
          {isActive ? (
            <>
              <span
                className="absolute inline-flex h-3 w-3 rounded-full bg-safe/30"
                style={{ animation: 'ping 2s cubic-bezier(0,0,0.2,1) infinite' }}
              />
              <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-safe" />
            </>
          ) : (
            <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-suspicious" />
          )}
        </div>
        <div className="flex items-center gap-3 min-w-0 flex-1">
          <h2 className="truncate text-[22px] font-semibold text-text leading-tight">
            {projectName}
          </h2>
          <span className={`shrink-0 rounded-full px-3 py-1 text-[13px] font-semibold tracking-wide ${
            isActive
              ? 'bg-safe/15 text-safe'
              : 'bg-suspicious/15 text-suspicious'
          }`}>
            {isActive ? 'Protected' : 'Pending DNS'}
          </span>
        </div>
        {/* Arrow affordance */}
        <svg
          width="20"
          height="20"
          viewBox="0 0 16 16"
          fill="none"
          className="shrink-0 text-dim opacity-0 transition-all duration-200 group-hover:opacity-100 group-hover:translate-x-0.5"
        >
          <path d="M6 3l5 5-5 5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      </div>

      {/* Domain */}
      <div className="mt-3.5 flex items-center gap-2.5 rounded-lg border border-border/60 bg-bg/50 px-4 py-2.5">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" className="shrink-0 text-muted">
          <circle cx="12" cy="12" r="10" />
          <line x1="2" y1="12" x2="22" y2="12" />
          <path d="M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z" />
        </svg>
        <code className="flex-1 truncate text-[15px] text-text">{site.domain}</code>
      </div>

      {/* Upstream */}
      {site.upstream_ip && site.upstream_ip !== '0.0.0.0' && (
        <p className="mt-2.5 truncate text-[14px] text-muted">
          Origin: <span className="font-mono">{site.upstream_ip}</span>
        </p>
      )}

      {/* Created date */}
      {site.created_at && (
        <p className="mt-2 text-[14px] text-muted">
          Created {new Date(site.created_at).toLocaleDateString('en-GB', {
            day: 'numeric', month: 'short', year: 'numeric',
          })}
        </p>
      )}
    </a>
  )
}

function ProjectsEmptyState() {
  return (
    <div className="flex min-h-[60vh] items-center justify-center px-6">
      <div className="flex max-w-lg flex-col items-center text-center">
        {/* Shield icon with subtle glow */}
        <div className="relative mb-8">
          <div
            className="absolute inset-0 rounded-full"
            style={{
              background: 'radial-gradient(circle, rgba(99,167,255,0.12) 0%, transparent 70%)',
              transform: 'scale(3)',
            }}
          />
          <div className="relative flex h-20 w-20 items-center justify-center rounded-full border border-agent/20 bg-agent/5">
            <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" className="text-agent">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              <path d="M9 12l2 2 4-4" />
            </svg>
          </div>
        </div>

        <h2 className="text-[32px] font-semibold text-text">No projects yet</h2>
        <p className="mt-3 max-w-md text-[20px] leading-relaxed text-dim">
          Create your first project to start protecting your API with Veil's self-improving AI firewall.
        </p>

        <a
          href="/app/onboarding"
          className="mt-8 inline-flex items-center gap-3 rounded-xl bg-agent px-9 py-4.5 text-[20px] font-semibold text-[#1a1322] transition-all hover:brightness-110"
          style={{ color: '#1a1322' }}
        >
          <svg width="22" height="22" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
            <path d="M8 3v10M3 8h10" />
          </svg>
          Create your first project
        </a>

        <p className="mt-5 text-[18px] text-muted">
          It only takes a minute to get started
        </p>
      </div>
    </div>
  )
}

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
      <AppShell links={APP_SIDEBAR_LINKS} activeKey="projects" user={user} logout={logout} pageTitle="Projects">
        <LoadingSpinner />
      </AppShell>
    )
  }

  const names = getProjectNames()

  return (
    <AppShell links={APP_SIDEBAR_LINKS} activeKey="projects" user={user} logout={logout} pageTitle="Projects">
      <div className="px-8 py-10 lg:px-12">
        {/* Page header */}
        <div className="mb-8 flex items-center justify-between gap-4">
          <div>
            <h1 className="text-[38px] font-semibold text-text">Projects</h1>
            {!loading && !error && sites.length > 0 && (
              <p className="mt-2 text-[20px] text-dim">
                {sites.length} project{sites.length !== 1 ? 's' : ''} protected by Veil
              </p>
            )}
          </div>
          {!loading && sites.length > 0 && (
            <a
              href="/app/onboarding"
              className="flex items-center gap-2.5 rounded-xl bg-agent px-7 py-3.5 text-[18px] font-semibold text-[#1a1322] transition-all hover:brightness-110"
              style={{ color: '#1a1322' }}
            >
              <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
                <path d="M8 3v10M3 8h10" />
              </svg>
              New project
            </a>
          )}
        </div>

        {/* Loading state */}
        {loading && <LoadingSpinner label="Loading projects..." />}

        {/* Error state */}
        {error && (
          <div className="flex min-h-[30vh] items-center justify-center">
            <div className="flex max-w-sm flex-col items-center text-center">
              <div className="mb-4 flex h-12 w-12 items-center justify-center rounded-xl border border-blocked/30 bg-blocked/5">
                <svg width="20" height="20" viewBox="0 0 20 20" fill="none" className="text-blocked">
                  <circle cx="10" cy="10" r="8" stroke="currentColor" strokeWidth="1.5" />
                  <path d="M10 6v5M10 13.5v.5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
                </svg>
              </div>
              <p className="text-[16px] font-medium text-text">Failed to load projects</p>
              <p className="mt-1.5 text-[14px] text-dim">{error}</p>
              <button
                onClick={() => window.location.reload()}
                className="mt-4 rounded-lg border border-border bg-transparent px-4 py-2.5 text-[14px] text-dim transition-colors hover:border-dim hover:text-text"
              >
                Try again
              </button>
            </div>
          </div>
        )}

        {/* Empty state */}
        {!loading && !error && sites.length === 0 && <ProjectsEmptyState />}

        {/* Project cards grid */}
        {!loading && !error && sites.length > 0 && (
          <div className="grid gap-6 sm:grid-cols-2 xl:grid-cols-3">
            {sites.map((site, index) => {
              const fallbackName = `Project ${sites.length - index}`
              const projectName = names[site.site_id] || fallbackName

              return (
                <ProjectCard
                  key={site.site_id}
                  site={site}
                  projectName={projectName}
                />
              )
            })}
          </div>
        )}
      </div>
    </AppShell>
  )
}
