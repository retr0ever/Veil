import { LandingPage } from './pages/LandingPage'
import { DemoPage } from './pages/DemoPage'
import { AuthPage } from './pages/AuthPage'
import { ProjectsPage } from './pages/ProjectsPage'
import { OnboardingPage } from './pages/OnboardingPage'
import { ProjectDashboardPage } from './pages/ProjectDashboardPage'
import { NavBar } from './components/NavBar'
import { PUBLIC_NAV_LINKS, APP_NAV_LINKS } from './lib/navLinks'

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

  const navLinks = pathname.startsWith('/app') || Boolean(projectId)
    ? APP_NAV_LINKS
    : PUBLIC_NAV_LINKS

  const activeHref = projectId
    ? '/app/projects'
    : pathname === '/demo'
      ? '/demo'
      : pathname === '/auth'
        ? '/auth'
        : pathname === '/app/onboarding'
          ? '/app/onboarding'
          : pathname === '/app/projects'
            ? '/app/projects'
            : '/'

  let page = <NotFoundPage />
  if (pathname === '/') page = <LandingPage />
  else if (pathname === '/demo') page = <DemoPage />
  else if (pathname === '/auth') page = <AuthPage />
  else if (pathname === '/app/projects') page = <ProjectsPage />
  else if (pathname === '/app/onboarding') page = <OnboardingPage />
  else if (projectId) page = <ProjectDashboardPage siteId={projectId} />

  return (
    <div className="min-h-screen bg-[#1a1322] text-text">
      <div className="sticky top-0 z-50 bg-[#1a1322] px-6 pt-10 md:px-12 md:pt-8">
        <NavBar
          links={navLinks}
          activeHref={activeHref}
          size="hero"
          showDivider
          dividerClassName="mt-5 w-[calc(100%+3rem)] -mx-6 md:w-[calc(100%+6rem)] md:-mx-12"
        />
      </div>
      {page}
    </div>
  )
}

export default App
