import { useAuth } from '../hooks/useAuth'

export function AuthPage() {
  const { user, loading } = useAuth()

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-bg">
        <div className="flex flex-col items-center gap-4">
          <div className="h-10 w-10 animate-spin rounded-full border-2 border-border border-t-agent" />
        </div>
      </div>
    )
  }

  if (user) {
    window.location.href = '/app/projects'
    return null
  }

  return (
    <div className="relative min-h-[calc(100vh-140px)] overflow-hidden bg-[#1a1322]">
      <div
        className="pointer-events-none absolute inset-0"
        style={{
          background:
            'radial-gradient(circle at top right, rgba(112,130,207,0.34) 0%, rgba(112,130,207,0.2) 12%, rgba(112,130,207,0.08) 22%, transparent 36%), radial-gradient(circle at bottom left, rgba(176,98,177,0.34) 0%, rgba(176,98,177,0.2) 14%, rgba(176,98,177,0.08) 24%, transparent 38%), radial-gradient(circle at 52% 38%, rgba(142,108,190,0.1) 0%, rgba(142,108,190,0.04) 16%, transparent 30%)',
        }}
      />

      <div className="relative z-10 flex min-h-[calc(100vh-140px)] items-center justify-center px-6">
      <div className="w-full max-w-[600px]">
        {/* Card */}
        <div className="rounded-2xl border border-border/60 bg-[#1a1322] px-8 py-10 md:px-10 md:py-12">
          {/* Vibes icon */}
          <div className="mb-6 flex justify-center">
            <img
              src="/svg/vibes.png"
              alt="Veil vibes"
              className="h-21 w-21 object-contain"
              loading="lazy"
            />
          </div>

          <h1 className="text-center text-[30px] font-semibold leading-tight tracking-[0.05em] text-text md:text-[34px]">
            Sign in to Veil
          </h1>
          <p className="mx-auto mt-3 max-w-[440px] text-center text-[16px] leading-relaxed text-dim">
            Connect your GitHub account to start protecting your APIs.
          </p>

          {/* GitHub button */}
          <a
            href="/auth/github"
            className="mt-8 flex w-full items-center justify-center gap-3 rounded-xl bg-[#f0a9e6] px-5 py-4 transition duration-150 hover:-translate-y-[1px] hover:brightness-105"
            style={{ color: '#1a1322' }}
          >
            <svg width="22" height="22" viewBox="0 0 24 24" fill="#1a1322" className="shrink-0">
              <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z" />
            </svg>
            <span className="text-[20px] font-semibold tracking-wide">
              Continue with GitHub
            </span>
          </a>
          {/* <p className="mt-2.5 text-center text-[13px] text-muted">
            No repository access required
          </p> */}

          {/* Divider */}
          <div className="my-7 flex items-center gap-4">
            <div className="h-px flex-1 bg-border/50" />
            <span className="text-[13px] tracking-wide text-muted">or</span>
            <div className="h-px flex-1 bg-border/50" />
          </div>

          {/* Demo button */}
          <a
            href="/demo"
            className="flex w-full items-center justify-center rounded-xl border border-border px-5 py-3.5 text-[20px] font-medium tracking-wide text-dim transition duration-150 hover:border-dim hover:text-text"
          >
            Try the demo instead
          </a>
        </div>
      </div>
      </div>
    </div>
  )
}
