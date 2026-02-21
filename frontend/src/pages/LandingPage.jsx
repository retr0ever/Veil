import { useEffect, useState } from 'react'

const AGENT_ITEMS = [
  { id: 'peek', label: 'PEEK' },
  { id: 'poke', label: 'POKE' },
  { id: 'patch', label: 'PATCH' },
]

const AGENT_DETAILS = {
  all: {
    heading: 'Three agents. One goal.',
    body: 'Peek discovers new attack techniques, Poke stress-tests Veil with variants, and Patch updates the rules - then verifies the fix by replaying the bypass.',
  },
  peek: {
    heading: 'PEEK: Threat Discovery',
    body: 'Continuously collects emerging attack techniques and patterns, labels them by category and severity, and stores them in the threat intelligence database with sources.',
  },
  poke: {
    heading: 'POKE: Red Team',
    body: 'Generates attack variations and fires them at Veil’s own classifier. Logs what gets blocked vs. what slips through, and escalates any bypass as a report for patching.',
  },
  patch: {
    heading: 'PATCH: Adaptation',
    body: 'Analyzes why a bypass worked, updates the detection prompts/rules, redeploys immediately, and verifies the fix by re-running the exact same attack until it’s blocked.',
  },
}

const AGENT_BORDER_COLORS = {
  all: 'rgba(132, 129, 136, 0.7)',
  peek: '#F4B6EB',
  poke: '#B9A1F4',
  patch: '#F6C371',
}

const HOW_IT_WORKS_STEPS = [
  {
    id: '01',
    label: 'Drop-in reverse proxy',
    detail: 'Point traffic at Veil instead of your backend - no code changes.',
  },
  {
    id: '02',
    label: 'Fast first-pass triage',
    detail: 'Llama on Crusoe classifies SAFE / SUSPICIOUS / MALICIOUS.',
  },
  {
    id: '03',
    label: 'Deep analysis on flagged traffic',
    detail: 'Claude reviews suspicious requests for a final verdict + category.',
  },
  {
    id: '04',
    label: 'Block or forward instantly',
    detail: 'Malicious is blocked; safe traffic reaches your backend unchanged.',
  },
  {
    id: '05',
    label: 'Red-team -> patch -> verify',
    detail: 'Agents generate bypasses and auto-update detection prompts.',
  },
]

export function LandingPage() {
  const [activeHowItWorks, setActiveHowItWorks] = useState(0)
  const [activeAgent, setActiveAgent] = useState('all')
  const [agentPanelVisible, setAgentPanelVisible] = useState(true)

  useEffect(() => {
    setAgentPanelVisible(false)
    const timeout = window.setTimeout(() => setAgentPanelVisible(true), 24)
    return () => window.clearTimeout(timeout)
  }, [activeAgent])

  const activeAgentDetails = AGENT_DETAILS[activeAgent]
  const activeAgentBorderColor = AGENT_BORDER_COLORS[activeAgent]

  return (
    <div className="min-h-screen w-full bg-[#1a1322] text-[#f4eff7]">
      <div className="flex min-h-screen w-full flex-col px-6 pb-16 md:px-12">
        <section className="order-1 relative w-[calc(100%+3rem)] -mx-6 overflow-hidden bg-[#1a1322] md:w-[calc(100%+6rem)] md:-mx-12">
          <div
            className="pointer-events-none absolute inset-0"
            style={{
              background:
                'radial-gradient(circle at top left, rgba(112,130,207,0.38) 0%, rgba(112,130,207,0.22) 9%, rgba(112,130,207,0.1) 17%, transparent 24%), radial-gradient(circle at bottom right, rgba(176,98,177,0.34) 0%, rgba(176,98,177,0.2) 8%, rgba(176,98,177,0.09) 17%, transparent 25%)',
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
                  className="block rounded-[12px] bg-[#f1b461] px-4 py-3.5 text-[#1a1322] transition duration-150 hover:-translate-y-[1px] hover:brightness-105"
                  style={{ color: '#1a1322' }}
                >
                  <span className="font-logo block text-[34px] leading-[0.9] font-medium tracking-[0.06em] !text-[#1a1322] md:text-[38px]">OPEN</span>
                  <span className="font-logo mt-0.5 block text-[34px] leading-[0.9] font-medium tracking-[0.06em] !text-[#1a1322] md:text-[38px]">PROJECTS</span>
                </a>

                <a
                  href="/app/onboarding"
                  className="mt-2.5 block rounded-[12px] bg-[#f0a9e6] px-4 py-3.5 text-[#1a1322] transition duration-150 hover:-translate-y-[1px] hover:brightness-105"
                  style={{ color: '#1a1322' }}
                >
                  <span className="font-logo block text-[34px] leading-[0.9] font-medium tracking-[0.06em] !text-[#1a1322] md:text-[38px]">START</span>
                  <span className="font-logo mt-0.5 block text-[34px] leading-[0.9] font-medium tracking-[0.06em] !text-[#1a1322] md:text-[38px]">PROTECTING</span>
                </a>
              </div>
            </div>
          </div>
        </section>

        <section className="order-2 relative w-[calc(100%+3rem)] -mx-6 overflow-hidden bg-[#1a1322] md:w-[calc(100%+6rem)] md:-mx-12">
          <div
            className="pointer-events-none absolute inset-0"
            style={{
              background:
                'radial-gradient(circle at top right, rgba(176,98,177,0.34) 0%, rgba(176,98,177,0.2) 8%, rgba(176,98,177,0.09) 17%, transparent 25%)',
            }}
          />

          <div className="relative z-10 mx-auto max-w-[1450px] px-6 py-24 md:px-10 md:py-32">
            <div className="grid items-start gap-16 md:grid-cols-[0.42fr_0.58fr] lg:gap-20">
              <div>
                <div className="space-y-3">
                  {HOW_IT_WORKS_STEPS.map((step, index) => {
                    const active = index === activeHowItWorks
                    return (
                      <button
                        key={step.id}
                        type="button"
                        onMouseEnter={() => setActiveHowItWorks(index)}
                        onFocus={() => setActiveHowItWorks(index)}
                        onClick={() => setActiveHowItWorks(index)}
                        className={`w-full border-l-2 px-5 py-4 text-left transition-colors ${
                          active
                            ? 'border-[#d4a7da] bg-white/[0.03]'
                            : 'border-transparent hover:border-[#8d809a]'
                        }`}
                      >
                        <div className="flex items-center gap-2">
                          <span className="text-[16px] tracking-[0.14em] text-[#9387a0]">{step.id}</span>
                          {active && <span className="h-2 w-2 rounded-full bg-[#d4a7da]" />}
                        </div>
                        <p className={`mt-1.5 text-[28px] leading-tight ${active ? 'text-[#f4eff7]' : 'text-[#ddd5e6]'}`}>
                          {step.label}
                        </p>
                        <p className={`mt-2 text-[21px] leading-[1.45] ${active ? 'text-[#cdc5d6]' : 'text-[#a79cb5]'}`}>
                          {step.detail}
                        </p>
                      </button>
                    )
                  })}
                </div>
              </div>

              <div className="flex w-full justify-center md:self-center">
                <div className="w-full max-w-[820px] rounded-[12px] border border-[#6d6872]/70 bg-[#151022] p-5 md:p-6">
                <div className="mb-5 flex items-center justify-between border-b border-[#6d6872]/55 pb-3 text-[15px] tracking-[0.16em] text-[#b5acbf] md:text-[16px]">
                  <span>VEIL / HOW IT WORKS</span>
                </div>

                <div className="relative min-h-[420px] md:min-h-[460px]">
                  {HOW_IT_WORKS_STEPS.map((step, index) => (
                    <div
                      key={step.id}
                      className={`absolute inset-0 transition-opacity duration-200 ${
                        activeHowItWorks === index ? 'opacity-100' : 'pointer-events-none opacity-0'
                      }`}
                    >
                      <HowItWorksPreview index={index} />
                    </div>
                  ))}
                </div>
                </div>
              </div>
            </div>
          </div>
        </section>

        <section
          className="order-3 relative mt-12 w-[calc(100%+3rem)] -mx-6 bg-[#1a1322] bg-cover bg-center bg-no-repeat md:mt-10 md:w-[calc(100%+6rem)] md:-mx-12"
          style={{ backgroundImage: "url('/images/rays.png')" }}
        >
          <div className="h-px w-full bg-[#848188]/70" />
          <div className="px-6 md:px-12">
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
                      Meet your agents!
                    </textPath>
                  </text>
                </svg>
              </div>

              <div className="absolute inset-x-0 top-[61%] z-10 -translate-y-1/2">
                <div className="mx-auto w-[96%]">
                  <div className="relative">
                    <img
                      src="/svg/gang.svg"
                      alt="PEEK, POKE, and PATCH agents"
                      className="h-auto w-full object-contain"
                      loading="lazy"
                    />
                    <div
                      className="absolute left-[8%] right-[8%] top-[34%] grid h-[38%] grid-cols-3"
                      onMouseLeave={() => setActiveAgent('all')}
                    >
                      {AGENT_ITEMS.map((agent) => (
                        <button
                          key={agent.id}
                          type="button"
                          aria-label={`Show details for ${agent.label}`}
                          onMouseEnter={() => setActiveAgent(agent.id)}
                          onFocus={() => setActiveAgent(agent.id)}
                          onClick={() => setActiveAgent(agent.id)}
                          className="h-full w-full bg-transparent"
                        />
                      ))}
                    </div>
                  </div>
                </div>
              </div>

              <div className="absolute inset-x-[6%] top-[82%] z-0">
                <div
                  className="rounded-[6px] border bg-[#21192b] px-6 py-6 transition-colors duration-200 md:px-7 md:py-7"
                  style={{ borderColor: activeAgentBorderColor }}
                >
                  <div className={`transition-opacity duration-200 ${agentPanelVisible ? 'opacity-100' : 'opacity-0'}`}>
                    <h3 className={`text-[22px] leading-tight text-[#f4eff7] md:text-[24px] ${activeAgent === 'all' ? 'text-center' : 'text-left'}`}>
                      {activeAgentDetails.heading}
                    </h3>
                    <p className="mt-3 text-[19px] leading-[1.6] text-[#d0c8da] md:text-[20px]">
                      {activeAgentDetails.body}
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <div className="sm:hidden">
            <h2 className="font-hero text-center text-[56px] leading-none text-[#F4B6EB]">
              Meet your agents
            </h2>
            <div className="mt-4">
              <div className="relative mx-auto w-full max-w-[540px]">
                <img
                  src="/svg/gang.svg"
                  alt="PEEK, POKE, and PATCH agents"
                  className="mx-auto h-auto w-full object-contain"
                  loading="lazy"
                />
                <div className="absolute left-[8%] right-[8%] top-[34%] grid h-[38%] grid-cols-3">
                  {AGENT_ITEMS.map((agent) => (
                    <button
                      key={agent.id}
                      type="button"
                      aria-label={`Show details for ${agent.label}`}
                      onClick={() => setActiveAgent(agent.id)}
                      className="h-full w-full bg-transparent"
                    />
                  ))}
                </div>
              </div>
            </div>
              <div className="mx-auto mt-6 w-full max-w-[860px] px-1">
              <div
                className="rounded-[6px] border bg-[#21192b] px-6 py-6 transition-colors duration-200"
                style={{ borderColor: activeAgentBorderColor }}
              >
                <div className={`transition-opacity duration-200 ${agentPanelVisible ? 'opacity-100' : 'opacity-0'}`}>
                  <h3 className={`text-[22px] leading-tight text-[#f4eff7] ${activeAgent === 'all' ? 'text-center' : 'text-left'}`}>
                    {activeAgentDetails.heading}
                  </h3>
                  <p className="mt-3 text-[19px] leading-[1.6] text-[#d0c8da]">
                    {activeAgentDetails.body}
                  </p>
                </div>
              </div>
            </div>
          </div>
          </div>
          <div className="mt-10 h-px w-full bg-[#848188]/70 md:mt-12" />
        </section>
      </div>
    </div>
  )
}

function HowItWorksPreview({ index }) {
  if (index === 0) {
    return (
      <div className="space-y-6">
        <p className="text-[20px] tracking-[0.16em] text-[#c3bbce] md:text-[22px]">PROTECTED URL: https://veil.sh/p/site_47a8</p>
        <div className="grid grid-cols-[1fr_auto_1fr_auto_1fr] items-center gap-4 text-center text-[24px]">
          <Node label="Client" />
          <Arrow />
          <Node label="VEIL" />
          <Arrow />
          <Node label="Upstream API" />
        </div>
      </div>
    )
  }

  if (index === 1) {
    return (
      <div className="space-y-5">
        <p className="text-[21px] text-[#d5cede]">Classification</p>
        <ClassRow label="SAFE" pct={86} color="#8fd9a7" />
        <ClassRow label="SUSPICIOUS" pct={47} color="#f2c77a" />
        <ClassRow label="MALICIOUS" pct={64} color="#f09ca8" />
      </div>
    )
  }

  if (index === 2) {
    return (
      <div className="rounded-[10px] border border-[#7a7385] bg-[#120d1e] p-5">
        <p className="text-[18px] tracking-[0.12em] text-[#d6cfde]">FINAL VERDICT</p>
        <p className="mt-2 text-[40px] font-semibold text-[#f08a95]">MALICIOUS</p>
        <p className="mt-1 text-[26px] text-[#f2cf90]">SQLi (High)</p>
        <p className="mt-4 text-[23px] leading-[1.45] text-[#b8aec4]">
          Pattern matched boolean-based injection payload in query parameter `id`.
        </p>
      </div>
    )
  }

  if (index === 3) {
    return (
      <div className="overflow-hidden rounded-[10px] border border-[#6f687c]">
        <div className="grid grid-cols-[150px_1fr_130px] border-b border-[#6f687c] bg-[#1a1527] px-4 py-3 text-[18px] tracking-[0.12em] text-[#aaa1b7]">
          <span>STATUS</span>
          <span>REQUEST</span>
          <span>ACTION</span>
        </div>
        <div className="grid grid-cols-[150px_1fr_130px] border-b border-[#6f687c]/60 bg-[#261420] px-4 py-3 text-[22px]">
          <span className="text-[#f08a95]">BLOCK</span>
          <span className="text-[#d0c8db]">GET /users?id=' OR 1=1</span>
          <span className="text-[#f08a95]">403</span>
        </div>
        <div className="grid grid-cols-[150px_1fr_130px] bg-[#12211b] px-4 py-3 text-[22px]">
          <span className="text-[#8fd9a7]">FORWARD</span>
          <span className="text-[#d0c8db]">GET /products?page=2</span>
          <span className="text-[#8fd9a7]">200</span>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <TimelineItem text="BYPASS FOUND" color="#f09ca8" />
      <TimelineItem text="PATCH DEPLOYED" color="#f2c77a" />
      <TimelineItem text="REPLAY BLOCKED" color="#8fd9a7" />
    </div>
  )
}

function Node({ label }) {
  return (
    <div className="rounded-[8px] border border-[#6f687c] bg-[#1a1527] px-4 py-5 text-[#e5dfec]">
      {label}
    </div>
  )
}

function Arrow() {
  return <span className="text-[30px] text-[#8f86a2]">-&gt;</span>
}

function ClassRow({ label, pct, color }) {
  return (
    <div>
      <div className="mb-2 flex items-center justify-between text-[21px]">
        <span className="text-[#ddd5e6]">{label}</span>
        <span className="text-[#a79cb5]">{pct}%</span>
      </div>
      <div className="h-4 overflow-hidden rounded-[5px] bg-[#241c31]">
        <div className="h-full" style={{ width: `${pct}%`, background: color }} />
      </div>
    </div>
  )
}

function TimelineItem({ text, color }) {
  return (
    <div className="flex items-center gap-4 rounded-[8px] border border-[#6f687c] bg-[#1a1527] px-5 py-4 text-[22px] text-[#d8d0e2]">
      <span className="h-3 w-3 rounded-full" style={{ background: color }} />
      <span>{text}</span>
    </div>
  )
}
