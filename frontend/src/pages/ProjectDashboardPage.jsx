import { useEffect, useState } from 'react'
import { useAuth } from '../hooks/useAuth'
import { Dashboard } from '../components/Dashboard'
import { getProjectName } from '../lib/projectNames'

export function ProjectDashboardPage({ siteId }) {
  const { user, loading: authLoading, logout } = useAuth()
  const [site, setSite] = useState(null)
  const [loading, setLoading] = useState(true)

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

  if (authLoading || loading) {
    return (
      <div className="flex h-screen items-center justify-center bg-bg text-muted">
        Loading project...
      </div>
    )
  }

  if (!user) return null

  if (!site) {
    return (
      <div className="flex h-screen items-center justify-center bg-bg px-4 text-text">
        <div className="rounded-xl border border-border bg-surface p-6 text-center">
          <p className="text-[16px]">Project not found.</p>
          <a href="/app/projects" className="mt-3 inline-block text-[13px] text-agent hover:underline">
            Return to projects
          </a>
        </div>
      </div>
    )
  }

  return <Dashboard site={site} projectName={getProjectName(siteId)} user={user} logout={logout} />
}
