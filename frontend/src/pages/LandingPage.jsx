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

        <section className="relative w-[calc(100%+3rem)] -mx-6 overflow-hidden bg-[#1a1322] md:w-[calc(100%+6rem)] md:-mx-12">
          <div
            className="pointer-events-none absolute inset-0"
            style={{
              background:
                'radial-gradient(circle at top left, rgba(112,130,207,0.38) 0%, rgba(112,130,207,0.22) 15%, rgba(112,130,207,0.1) 28%, transparent 40%), radial-gradient(circle at bottom right, rgba(176,98,177,0.34) 0%, rgba(176,98,177,0.2) 14%, rgba(176,98,177,0.09) 28%, transparent 42%)',
            }}
          />

          <div className="relative z-10 mx-auto max-w-[1600px] px-2 py-24 md:px-4 md:py-36">
            <div className="grid items-center gap-10 md:flex md:items-center md:justify-between md:gap-20">
              <div className="max-w-[900px]">
                <h1 className="text-[44px] font-semibold leading-[1.08] text-[#f8f4fb] md:text-[56px]">
                  The first self-improving firewall.
                </h1>
                <p className="mt-6 text-[21px] leading-[1.55] text-[#cbc4d2] md:text-[25px]">
                  Drop-in reverse proxy that blocks malicious requests before they reach your backend.
                  When something bypasses, Veil red-teams itself and auto-patches its detection rules, then verifies the fix by replay.
                </p>
              </div>

              <div className="w-full md:w-[470px] md:shrink-0">
                <a
                  href="/app/projects"
                  className="block rounded-[12px] bg-[#f1b461] px-8 py-7 text-[#1a1322] transition duration-150 hover:-translate-y-[1px] hover:brightness-105"
                  style={{ color: '#1a1322' }}
                >
                  <span className="block text-[34px] leading-[0.9] tracking-[0.06em] !text-[#1a1322] md:text-[38px]">OPEN</span>
                  <span className="mt-1 block text-[34px] leading-[0.9] tracking-[0.06em] !text-[#1a1322] md:text-[38px]">PROJECTS</span>
                </a>

                <a
                  href="/app/onboarding"
                  className="mt-5 block rounded-[12px] bg-[#f0a9e6] px-8 py-7 text-[#1a1322] transition duration-150 hover:-translate-y-[1px] hover:brightness-105"
                  style={{ color: '#1a1322' }}
                >
                  <span className="block text-[34px] leading-[0.9] tracking-[0.06em] !text-[#1a1322] md:text-[38px]">START</span>
                  <span className="mt-1 block text-[34px] leading-[0.9] tracking-[0.06em] !text-[#1a1322] md:text-[38px]">PROTECTING</span>
                </a>
              </div>
            </div>
          </div>

          <div className="absolute inset-x-0 bottom-0 h-px bg-[#848188]/70" />
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
