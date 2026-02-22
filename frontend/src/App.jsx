import { LandingPage } from './pages/LandingPage'
import { DemoPage } from './pages/DemoPage'
import { AuthPage } from './pages/AuthPage'
import { ProjectsPage } from './pages/ProjectsPage'
import { OnboardingPage } from './pages/OnboardingPage'
import { ProjectDashboardPage } from './pages/ProjectDashboardPage'
import { DocsPage } from './pages/DocsPage'
import { NavBar } from './components/NavBar'
import { PUBLIC_NAV_LINKS } from './lib/navLinks'

/* ── Helpers ─────────────────────────────────────────────── */

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

/* ── Shared 404 ──────────────────────────────────────────── */

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

/* ── Route definitions ───────────────────────────────────── */

/**
 * PUBLIC routes (/, /demo) -- rendered with the top NavBar, no sidebar.
 * STANDALONE routes (/auth) -- rendered directly with no shell (page controls its own layout).
 * APP routes (/app/*) -- each page wraps itself in <AppShell> with the sidebar.
 */

const PUBLIC_ROUTES = ['/', '/demo', '/docs', '/auth']

function App() {
  const pathname = normalizePath(window.location.pathname)
  const projectId = getProjectId(pathname)

  // OAuth callback -- let it pass through to the backend
  if (pathname.startsWith('/auth/github')) return null

  const isPublic = PUBLIC_ROUTES.includes(pathname)

  /* ── Resolve page component ── */
  let page = <NotFoundPage />
  if (pathname === '/')                   page = <LandingPage />
  else if (pathname === '/demo')          page = <DemoPage />
  else if (pathname === '/auth')          page = <AuthPage />
  else if (pathname === '/docs')          page = <DocsPage public />
  else if (pathname === '/app/projects')  page = <ProjectsPage />
  else if (pathname === '/app/onboarding') page = <OnboardingPage />
  else if (pathname === '/app/docs')      page = <DocsPage />
  else if (projectId)                     page = <ProjectDashboardPage siteId={projectId} />

  /* ── Public shell: NavBar + page, NO sidebar ── */
  if (isPublic) {
    const activeHref = pathname === '/demo' ? '/demo' : pathname === '/docs' ? '/docs' : pathname === '/auth' ? '/auth' : '/'

    return (
      <div className="min-h-screen bg-[#1a1322] text-text">
        <div className="sticky top-0 z-50 bg-[#1a1322] px-6 pt-10 md:px-12 md:pt-8">
          <NavBar
            links={PUBLIC_NAV_LINKS}
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

  /* ── App shell: each /app/* page renders its own <AppShell> sidebar wrapper ── */
  return page
}

export default App
