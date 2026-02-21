import { LandingPage } from './pages/LandingPage'
import { DemoPage } from './pages/DemoPage'
import { AuthPage } from './pages/AuthPage'
import { ProjectsPage } from './pages/ProjectsPage'
import { OnboardingPage } from './pages/OnboardingPage'
import { ProjectDashboardPage } from './pages/ProjectDashboardPage'

function normalizePath(pathname) {
  if (!pathname) return '/'
  if (pathname.length > 1 && pathname.endsWith('/')) {
    return pathname.slice(0, -1)
  }
  return pathname
}

function getProjectId(pathname) {
  const match = pathname.match(/^\/app\/projects\/([^/]+)$/)
  if (!match) return null

  try {
    return decodeURIComponent(match[1])
  } catch {
    return match[1]
  }
}

function NotFoundPage() {
  return (
    <div className="flex h-screen items-center justify-center bg-bg px-4 text-text">
      <div className="rounded-xl border border-border bg-surface p-6 text-center">
        <p className="text-[18px] font-semibold">Page not found</p>
        <p className="mt-1 text-[13px] text-dim">The route you requested is not part of this hackathon surface.</p>
        <a href="/" className="mt-4 inline-block text-[13px] text-agent hover:underline">Back to landing</a>
      </div>
    </div>
  )
}

function App() {
  const pathname = normalizePath(window.location.pathname)
  const projectId = getProjectId(pathname)

  // Let /auth/github* hit the backend directly (OAuth flow)
  if (pathname.startsWith('/auth/github')) return null

  if (pathname === '/') return <LandingPage />
  if (pathname === '/demo') return <DemoPage />
  if (pathname === '/auth') return <AuthPage />
  if (pathname === '/app/projects') return <ProjectsPage />
  if (pathname === '/app/onboarding') return <OnboardingPage />
  if (projectId) return <ProjectDashboardPage siteId={projectId} />

  return <NotFoundPage />
}

export default App
