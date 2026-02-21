import { NavBar } from '../components/NavBar'
import { PUBLIC_NAV_LINKS } from '../lib/navLinks'

const agents = [
  { id: 'peek', label: 'PEEK', src: '/svg/2.png', shiftClass: 'translate-y-0' },
  { id: 'poke', label: 'POKE', src: '/svg/3.png', shiftClass: 'translate-y-[2px]' },
  { id: 'patch', label: 'PATCH', src: '/svg/4.png', shiftClass: 'translate-y-[4px]' },
]

export function LandingPage() {
  return (
    <div className="min-h-screen w-full bg-[#1a1322] text-[#f4eff7]">
      <div className="flex min-h-screen w-full flex-col px-6 pb-16 pt-6 md:px-12 md:pt-8">
        <NavBar
          links={PUBLIC_NAV_LINKS}
          activeHref="/"
          size="hero"
          showDivider
          dividerClassName="mt-5 w-[calc(100%+3rem)] -mx-6 md:w-[calc(100%+6rem)] md:-mx-12"
        />

        <section className="mt-10 flex flex-col items-start justify-between gap-8 md:flex-row md:items-center">
          <div>
            <h1 className="max-w-3xl text-[38px] leading-[1.05] text-[#f8f4fb] md:text-[64px]">
              The first self-improving firewall
            </h1>
            <p className="mt-4 max-w-3xl text-[14px] leading-relaxed tracking-[0.02em] text-[#c8c1d0] md:text-[17px]">
              Drop-in reverse proxy that blocks malicious requests and patches itself when it fails.
            </p>
            <div className="mt-5 flex flex-wrap gap-6 text-[12px] tracking-[0.18em] text-[#f0eaf6] md:text-[13px]">
              <a href="/app/onboarding" className="hover:opacity-80">START PROTECTING</a>
              <a href="/app/projects" className="hover:opacity-80">OPEN PROJECTS</a>
            </div>
          </div>

          <div className="mr-2">
            <ShieldGlyph />
          </div>
        </section>

        <section className="mt-10 w-full md:mt-8">
          <div className="mx-auto hidden w-[clamp(520px,50vw,960px)] sm:block">
            <div className="relative aspect-square w-full">
              <div className="pointer-events-none absolute inset-0 z-20">
                <svg viewBox="0 0 1000 1000" className="h-full w-full" aria-hidden="true">
                  <defs>
                    <path id="agents-arc" d="M8 700 A492 492 0 0 1 992 700" />
                  </defs>
                  <text fill="#F4B6EB" style={{ fontFamily: 'Heartland Script, serif', fontSize: '200px' }}>
                    <textPath
                      href="#agents-arc"
                      startOffset="50%"
                      textAnchor="middle"
                      textLength="984"
                      lengthAdjust="spacingAndGlyphs"
                    >
                      Meet your agents
                    </textPath>
                  </text>
                </svg>
              </div>

              <div className="absolute inset-x-0 top-[61%] z-10 -translate-y-1/2">
                <div className="grid grid-cols-3 items-end justify-items-center gap-x-2">
                  {agents.map((agent) => (
                    <article key={agent.id} className="flex flex-col items-center">
                      <img
                        src={agent.src}
                        alt={agent.label}
                        className={`h-[170px] w-[170px] object-contain lg:h-[190px] lg:w-[190px] ${agent.shiftClass}`}
                        loading="lazy"
                      />
                      <p className="mt-4 text-[18px] tracking-[0.14em] text-[#f6f1f8] lg:text-[20px]">
                        {agent.label}
                      </p>
                    </article>
                  ))}
                </div>
              </div>
            </div>
          </div>

          <div className="sm:hidden">
            <h2 className="font-hero text-center text-[56px] leading-none text-[#F4B6EB]">
              Meet your agents
            </h2>
            <div className="mt-4 grid w-full grid-cols-1 items-end justify-items-center gap-y-8">
              {agents.map((agent) => (
                <article key={agent.id} className="flex flex-col items-center">
                  <img
                    src={agent.src}
                    alt={agent.label}
                    className={`h-[220px] w-[220px] object-contain ${agent.shiftClass}`}
                    loading="lazy"
                  />
                  <p className="mt-5 text-[20px] tracking-[0.14em] text-[#f6f1f8]">
                    {agent.label}
                  </p>
                </article>
              ))}
            </div>
          </div>
        </section>
      </div>
    </div>
  )
}

function ShieldGlyph() {
  return (
    <svg width="66" height="66" viewBox="0 0 66 66" fill="none" aria-hidden="true">
      <path
        d="M33 6l18 7v15c0 14-8 24-18 30-10-6-18-16-18-30V13l18-7z"
        stroke="#EDE7F3"
        strokeWidth="2.2"
      />
      <path
        d="M24 32l6 6 12-12"
        stroke="#EDE7F3"
        strokeWidth="2.2"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  )
}
