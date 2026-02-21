import { NavBar } from '../components/NavBar'
import { PUBLIC_NAV_LINKS } from '../lib/navLinks'
import { useAuth } from '../hooks/useAuth'

export function AuthPage() {
  const { user, loading } = useAuth()

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-bg text-muted">
        Checking session...
      </div>
    )
  }

  if (user) {
    window.location.href = '/app/projects'
    return null
  }

  return (
    <div className="flex min-h-screen flex-col bg-bg text-text">
      <div className="mx-auto w-full max-w-6xl px-4 pt-4 md:px-6">
        <NavBar links={PUBLIC_NAV_LINKS} activeHref="/auth" showDivider />
      </div>

      <main className="flex flex-1 items-center justify-center px-4 py-8">
        <div className="w-full max-w-lg rounded-2xl border border-border bg-surface p-6">
          <p className="font-logo text-[22px] leading-none text-dim">VEIL</p>

          <h1 className="mt-3 text-2xl font-semibold">Sign in with GitHub</h1>
          <p className="mt-2 text-[14px] text-dim">
            Authenticate to create and manage protected projects. No repo access required — just your GitHub identity.
          </p>

          <a
            href="/auth/github"
            className="mt-5 inline-flex items-center gap-3 rounded-xl bg-text px-5 py-2.5 text-[14px] font-medium text-bg"
          >
            <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
              <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z" />
            </svg>
            Continue with GitHub
          </a>

          <div className="mt-6 flex gap-3 text-[13px]">
            <a href="/" className="text-dim hover:text-text">Landing</a>
            <a href="/demo" className="text-dim hover:text-text">Demo</a>
          </div>
        </div>
      </main>
    </div>
  )
}
