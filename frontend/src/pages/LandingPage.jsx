const productLinks = [
  { label: 'Live demo', href: '/demo', desc: 'Read-only control room with replay controls.' },
  { label: 'SSO auth', href: '/auth', desc: 'GitHub OAuth entry and return flow.' },
  { label: 'Projects', href: '/app/projects', desc: 'Protected apps with per-project controls.' },
  { label: 'Onboarding', href: '/app/onboarding', desc: 'Create project and get protected proxy URL.' },
]

const flow = [
  {
    title: 'Stage 1: Fast triage',
    body: 'Crusoe-hosted small model classifies each request as SAFE, SUSPICIOUS, or MALICIOUS in low latency.',
    badge: 'Crusoe',
  },
  {
    title: 'Stage 2: Deep verdict',
    body: 'Suspicious traffic is escalated to Claude for final verdict and attack category before forwarding or blocking.',
    badge: 'Claude',
  },
]

const agents = [
  {
    name: 'Peek',
    color: 'text-agent',
    copy: 'Continuously ingests new SQLi, XSS, SSRF, RCE, and evasion techniques from threat feeds and research.',
  },
  {
    name: 'Poke',
    color: 'text-suspicious',
    copy: 'Mutates and replays discovered payloads against Veil to identify real bypasses before attackers do.',
  },
  {
    name: 'Patch',
    color: 'text-safe',
    copy: 'Auto-updates prompts and rules from bypass evidence, then verifies fixes in the next red-team cycle.',
  },
]

export function LandingPage() {
  return (
    <div className="relative min-h-screen overflow-x-hidden bg-bg text-text">
      <div className="pointer-events-none absolute -left-24 top-[-120px] h-[360px] w-[360px] rounded-full bg-agent/20 blur-3xl" />
      <div className="pointer-events-none absolute right-[-120px] top-[220px] h-[320px] w-[320px] rounded-full bg-safe/20 blur-3xl" />

      <header className="relative border-b border-border/70 bg-bg/80 backdrop-blur">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-4">
          <span className="font-logo text-[28px] leading-none text-dim">VEIL</span>
          <nav className="flex items-center gap-3 text-[13px]">
            <a className="rounded-full border border-border px-3 py-1.5 text-dim hover:text-text" href="/demo">Demo</a>
            <a className="rounded-full border border-border px-3 py-1.5 text-dim hover:text-text" href="/app/projects">Projects</a>
            <a className="rounded-full bg-text px-3 py-1.5 font-medium text-bg" href="/app/onboarding">Protect API</a>
          </nav>
        </div>
      </header>

      <main className="relative mx-auto max-w-6xl px-6 pb-16 pt-12">
        <section className="grid gap-8 lg:grid-cols-[1.2fr_0.8fr]">
          <div>
            <p className="mb-4 inline-flex rounded-full border border-border bg-surface px-3 py-1 text-[11px] uppercase tracking-[0.18em] text-muted">
              Self-improving AI WAF reverse proxy
            </p>
            <h1 className="font-hero max-w-2xl text-6xl leading-[1.02] tracking-tight">
              Drop-in protection that learns from every bypass attempt.
            </h1>
            <p className="mt-5 max-w-xl text-[16px] leading-relaxed text-dim">
              Register your backend URL, swap to a Veil proxy URL, and every request is classified before it reaches upstream.
              Malicious traffic is blocked at the edge.
            </p>
            <div className="mt-8 flex flex-wrap items-center gap-3">
              <a href="/app/onboarding" className="rounded-xl bg-text px-5 py-2.5 text-[14px] font-semibold text-bg">
                Launch onboarding
              </a>
              <a href="/demo" className="rounded-xl border border-border px-5 py-2.5 text-[14px] text-dim hover:text-text">
                Open control room demo
              </a>
              <a href="/auth" className="text-[14px] text-agent underline-offset-4 hover:underline">
                Try GitHub SSO flow
              </a>
            </div>
          </div>

          <div className="rounded-2xl border border-border bg-surface p-5 shadow-[0_0_0_1px_rgba(255,255,255,0.03)_inset]">
            <p className="text-[12px] uppercase tracking-[0.16em] text-muted">Request Decision Pipeline</p>
            <div className="mt-4 space-y-3">
              {flow.map((item) => (
                <article key={item.title} className="rounded-xl border border-border/80 bg-bg/60 p-4">
                  <div className="mb-2 flex items-center justify-between">
                    <h3 className="text-[15px] font-semibold">{item.title}</h3>
                    <span className="rounded-full border border-border px-2 py-0.5 font-mono text-[11px] text-dim">{item.badge}</span>
                  </div>
                  <p className="text-[13px] leading-relaxed text-dim">{item.body}</p>
                </article>
              ))}
              <div className="rounded-xl border border-safe/30 bg-safe/8 p-4 text-[13px] text-safe">
                MALICIOUS requests are blocked before upstream. SAFE requests are forwarded and return normal response.
              </div>
            </div>
          </div>
        </section>

        <section className="mt-12 grid gap-4 md:grid-cols-3">
          {agents.map((agent) => (
            <article key={agent.name} className="rounded-2xl border border-border bg-surface p-5">
              <p className={`font-mono text-[13px] tracking-wide ${agent.color}`}>{agent.name}</p>
              <p className="mt-3 text-[14px] leading-relaxed text-dim">{agent.copy}</p>
            </article>
          ))}
        </section>

        <section className="mt-12 rounded-2xl border border-border bg-surface p-6">
          <div className="flex flex-wrap items-end justify-between gap-4">
            <div>
              <h2 className="text-2xl font-semibold tracking-tight">Hackathon Product Surface</h2>
              <p className="mt-2 text-[14px] text-dim">All required pages are linked and usable right now.</p>
            </div>
            <a href="/app/projects" className="text-[14px] text-agent underline-offset-4 hover:underline">
              Jump to app
            </a>
          </div>
          <div className="mt-5 grid gap-3 md:grid-cols-2">
            {productLinks.map((link) => (
              <a key={link.href} href={link.href} className="rounded-xl border border-border/80 bg-bg/50 p-4 transition hover:border-dim">
                <p className="text-[15px] font-semibold">{link.label}</p>
                <p className="mt-1 text-[13px] text-dim">{link.desc}</p>
                <p className="mt-3 font-mono text-[11px] text-muted">{link.href}</p>
              </a>
            ))}
          </div>
        </section>
      </main>
    </div>
  )
}
