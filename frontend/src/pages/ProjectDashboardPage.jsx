import { useEffect, useState, useCallback } from 'react'
import { useAuth } from '../hooks/useAuth'
import { Dashboard } from '../components/Dashboard'
import { AppShell, LoadingSpinner } from '../components/AppShell'
import { PROJECT_SIDEBAR_LINKS } from '../lib/navLinks'
import { getProjectName } from '../lib/projectNames'

function sectionFromHash() {
  const hash = window.location.hash.replace('#', '')
  const valid = PROJECT_SIDEBAR_LINKS.map((l) => l.key)
  return valid.includes(hash) ? hash : 'site'
}

function NotFoundState() {
  return (
    <div className="flex min-h-[60vh] items-center justify-center px-4">
      <div className="flex max-w-md flex-col items-center text-center">
        {/* Icon */}
        <div className="relative mb-5">
          <div
            className="absolute inset-0 rounded-full"
            style={{
              background: 'radial-gradient(circle, rgba(240,138,149,0.1) 0%, transparent 70%)',
              transform: 'scale(2.5)',
            }}
          />
          <div className="relative flex h-14 w-14 items-center justify-center rounded-2xl border border-blocked/20 bg-blocked/5">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" className="text-blocked">
              <circle cx="12" cy="12" r="10" />
              <path d="M15 9l-6 6M9 9l6 6" />
            </svg>
          </div>
        </div>

        <h2 className="text-[17px] font-semibold text-text">Project not found</h2>
        <p className="mt-2 max-w-xs text-[13px] leading-relaxed text-dim">
          This project may have been removed, or you might not have access to it. Check your project list or create a new one.
        </p>

        <div className="mt-5 flex items-center gap-3">
          <a
            href="/app/projects"
            className="inline-flex items-center gap-2 rounded-lg bg-agent px-4 py-2 text-[13px] font-semibold text-[#1a1322] transition-all hover:brightness-110"
          >
            <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
              <path d="M10 3L5 8l5 5" />
            </svg>
            Back to projects
          </a>
          <a
            href="/app/onboarding"
            className="inline-flex rounded-lg border border-border px-4 py-2 text-[13px] font-medium text-muted transition-colors hover:border-dim hover:text-text"
          >
            New project
          </a>
        </div>
      </div>
    </div>
  )
}

export function ProjectDashboardPage({ siteId }) {
  const { user, loading: authLoading, logout } = useAuth()
  const [site, setSite] = useState(null)
  const [loading, setLoading] = useState(true)
  const [activeSection, setActiveSection] = useState(sectionFromHash)

  useEffect(() => {
    if (authLoading) return
    if (!user) {
      window.location.href = '/auth'
      return
    }

    const load = async () => {
      try {
        const res = await fetch('/api/sites')
        if (res.ok) {
          const sites = await res.json()
          const found = sites.find((item) => item.site_id === siteId)
          setSite(found || null)
        }
      } catch {
        setSite(null)
      }
      setLoading(false)
    }
    load()
  }, [siteId, user, authLoading])

  // Listen for hash changes (browser back/forward)
  useEffect(() => {
    const onHashChange = () => {
      setActiveSection(sectionFromHash())
    }
    window.addEventListener('hashchange', onHashChange)
    return () => window.removeEventListener('hashchange', onHashChange)
  }, [])

  const handleNavClick = useCallback((key) => {
    setActiveSection(key)
    window.location.hash = key === 'site' ? 'overview' : key
  }, [])

  // Auth loading or data loading — minimal shell, no sidebar
  if (authLoading || loading) {
    return (
      <div className="flex min-h-screen flex-col bg-bg text-text">
        <header className="flex h-14 shrink-0 items-center border-b border-border/40 px-6">
          <a href="/app/projects" className="font-logo text-[24px] leading-none tracking-wide text-[#f6f1f9]">
            VEIL.
          </a>
        </header>
        <LoadingSpinner label="Loading project..." />
      </div>
    )
  }

  if (!user) return null

  // Project not found — show full-page error without sidebar
  if (!site) {
    return (
      <div className="flex min-h-screen flex-col bg-bg text-text">
        <header className="flex h-14 shrink-0 items-center border-b border-border/40 px-6">
          <a href="/app/projects" className="font-logo text-[24px] leading-none tracking-wide text-[#f6f1f9]">
            VEIL.
          </a>
        </header>
        <NotFoundState />
      </div>
    )
  }

  const projectName = site.is_demo
    ? (site.project_name || 'Demo VulnShop')
    : getProjectName(siteId)
  const dnsActive = site.is_demo || site.status === 'active' || site.status === 'live'
  const disabledKeys = dnsActive ? [] : ['site', 'agents', 'threats', 'findings', 'blocklist']

  // Force to setup tab when DNS isn't active
  const effectiveSection = !dnsActive && disabledKeys.includes(activeSection) ? 'setup' : activeSection
  const currentLink = PROJECT_SIDEBAR_LINKS.find((l) => l.key === effectiveSection)
  const pageTitle = currentLink?.label || 'Overview'

  return (
    <AppShell
      links={PROJECT_SIDEBAR_LINKS}
      activeKey={effectiveSection}
      onNavClick={handleNavClick}
      user={user}
      logout={logout}
      projectTitle={projectName || site.domain || site.target_url}
      projectUrl={site.domain || site.target_url}
      pageTitle={pageTitle}
      disabledKeys={disabledKeys}
    >
      <Dashboard site={site} activeSection={effectiveSection} />
    </AppShell>
  )
}
