import { NavBar } from '../components/NavBar'
import { PUBLIC_NAV_LINKS } from '../lib/navLinks'

function buildMockCallbackUrl() {
  const params = new URLSearchParams({
    provider: 'github',
    code: 'demo_oauth_code',
    state: 'veil-demo-state',
  })
  return `/auth?${params.toString()}`
}

export function AuthPage() {
  const params = new URLSearchParams(window.location.search)
  const code = params.get('code')
  const provider = params.get('provider') || 'github'
  const state = params.get('state') || 'none'

  return (
    <div className="flex min-h-screen flex-col bg-bg text-text">
      <div className="mx-auto w-full max-w-6xl px-4 pt-4 md:px-6">
        <NavBar links={PUBLIC_NAV_LINKS} activeHref="/auth" showDivider />
      </div>

      <main className="flex flex-1 items-center justify-center px-4 py-8">
        <div className="w-full max-w-lg rounded-2xl border border-border bg-surface p-6">
          <p className="text-[12px] tracking-[0.2em] text-dim">AUTH FLOW</p>

          {!code && (
            <>
              <h1 className="mt-3 text-2xl font-semibold">Sign in with GitHub</h1>
              <p className="mt-2 text-[14px] text-dim">
                OAuth entry point for Veil. In this hackathon build, this route simulates a GitHub return.
              </p>
              <a
                href={buildMockCallbackUrl()}
                className="mt-5 inline-flex rounded-xl bg-text px-4 py-2 text-[14px] font-medium text-bg"
              >
                Continue with GitHub
              </a>
            </>
          )}

          {code && (
            <>
              <h1 className="mt-3 text-2xl font-semibold">OAuth callback received</h1>
              <p className="mt-2 text-[14px] text-dim">Provider response parsed successfully.</p>
              <div className="mt-4 space-y-2 rounded-xl border border-border bg-bg p-4 font-mono text-[12px]">
                <Row label="provider" value={provider} />
                <Row label="code" value={code} />
                <Row label="state" value={state} />
              </div>
              <a
                href="/app/projects"
                className="mt-5 inline-flex rounded-xl bg-safe/15 px-4 py-2 text-[14px] font-medium text-safe"
              >
                Continue to projects
              </a>
            </>
          )}

          <div className="mt-6">
            <a href="/app/projects" className="text-[13px] text-agent hover:underline">Go to projects</a>
          </div>
        </div>
      </main>
    </div>
  )
}

function Row({ label, value }) {
  return (
    <div className="flex items-center gap-2">
      <span className="text-muted">{label}:</span>
      <span className="text-text">{value}</span>
    </div>
  )
}
