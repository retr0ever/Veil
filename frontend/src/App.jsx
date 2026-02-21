import { useState, useEffect } from 'react'
import { Onboarding } from './components/Onboarding'
import { Dashboard } from './components/Dashboard'

function App() {
  const [site, setSite] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const load = async () => {
      try {
        const res = await fetch('/api/sites')
        if (res.ok) {
          const sites = await res.json()
          if (sites.length > 0) {
            setSite(sites[0])
          }
        }
      } catch {}
      setLoading(false)
    }
    load()
  }, [])

  if (loading) {
    return (
      <div className="h-screen flex items-center justify-center bg-bg">
        <div className="text-muted text-sm">Loading...</div>
      </div>
    )
  }

  if (!site) {
    return <Onboarding onSiteAdded={setSite} />
  }

  return <Dashboard site={site} />
}

export default App
