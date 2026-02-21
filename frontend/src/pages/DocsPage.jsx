import { useAuth } from '../hooks/useAuth'
import { AppShell, LoadingSpinner } from '../components/AppShell'
import { APP_SIDEBAR_LINKS } from '../lib/navLinks'
import { useState } from 'react'

const SECTIONS = [
  {
    id: 'overview',
    title: 'What is Veil?',
    content: `Veil is a self-improving AI firewall that sits between your users and your API. It classifies every incoming request in real time — detecting SQL injection, XSS, SSRF, and other attacks — and blocks malicious traffic before it reaches your backend.

Unlike static WAFs, Veil gets smarter over time. Its three-agent loop (Scout, Red Team, Adapt) continuously discovers new attack techniques, tests your defences, and patches gaps automatically.`,
  },
  {
    id: 'how-it-works',
    title: 'How it works',
    content: `1. **Create a project** — Give Veil the upstream URL of your API (e.g. \`https://api.example.com\`).

2. **Route traffic through the proxy** — Veil gives you a protected URL. Point your frontend or clients at this URL instead of your real backend.

3. **Every request is classified** — Veil's AI analyses each request in real time and assigns a classification: SAFE, SUSPICIOUS, or MALICIOUS.

4. **Malicious requests are blocked** — Blocked requests never reach your backend. You can see them in your dashboard's live feed.

5. **Agents improve your defences** — Run an improvement cycle to let Veil's agents discover new threats, test your rules, and patch any gaps.`,
  },
  {
    id: 'proxy',
    title: 'Using the proxy',
    content: `After creating a project, Veil generates a protected URL like:

\`\`\`
https://your-veil-instance.up.railway.app/p/SITE_ID
\`\`\`

Replace your upstream API calls with this URL. For example, if you normally call:

\`\`\`
GET https://api.example.com/users/123
\`\`\`

Instead call:

\`\`\`
GET https://your-veil-instance.up.railway.app/p/SITE_ID/users/123
\`\`\`

All HTTP methods are supported (GET, POST, PUT, PATCH, DELETE). Headers, query parameters, and request bodies are forwarded transparently.`,
  },
  {
    id: 'agents',
    title: 'The agent loop',
    content: `Veil uses three specialised AI agents that work in a closed loop:

**Scout (Peek)** — Scans public threat databases and generates new attack payloads tailored to your API's stack. It discovers techniques your current rules might miss.

**Red Team (Poke)** — Fires the discovered attacks against your proxy to test which ones get through. It reports exactly which payloads bypass your defences.

**Adapt (Patch)** — Analyses the gaps found by Red Team and writes new classification rules to block them. If some attacks still evade after patching, it loops back for another round.

You can trigger an improvement cycle from the Agents tab in your project dashboard. Each cycle makes Veil smarter.`,
  },
  {
    id: 'classifications',
    title: 'Classifications',
    content: `Every request that passes through Veil is classified into one of three categories:

**SAFE** — Normal, legitimate traffic. Forwarded to your backend without interference.

**SUSPICIOUS** — Potentially malicious but not confirmed. Forwarded but flagged in your dashboard for review.

**MALICIOUS** — Confirmed attack attempt. Blocked by default — your backend never sees it. The request appears in your live feed with the attack type and confidence score.

Each classification includes a confidence score (0-100%) and, for threats, the specific attack type (e.g. SQL injection, XSS, SSRF).`,
  },
  {
    id: 'dashboard',
    title: 'Dashboard sections',
    content: `Your project dashboard has four sections:

**Overview** — Live feed of classified requests, connection status, and recent activity at a glance.

**Agents** — Trigger improvement cycles and watch the Scout/Red Team/Adapt agents work in real time. See cycle history and patched threats.

**Threats** — Full library of every attack technique Veil knows about for your project. Shows severity, category, whether it's been patched, and remediation advice.

**Setup** — Your proxy URL, integration instructions, and test runner to verify your defences are working.`,
  },
  {
    id: 'attack-types',
    title: 'Supported attack types',
    content: `Veil detects and blocks the following attack categories:

- **SQL Injection (SQLi)** — Injecting SQL code into input fields to manipulate database queries
- **Cross-Site Scripting (XSS)** — Injecting malicious scripts into web pages
- **Server-Side Request Forgery (SSRF)** — Tricking the server into making requests to internal resources
- **Remote Code Execution (RCE)** — Running arbitrary commands on the server
- **Path Traversal / LFI / RFI** — Accessing files outside the intended directory
- **XML External Entity (XXE)** — Exploiting XML parsers to access internal files
- **IDOR** — Manipulating object references to access other users' resources
- **CSRF** — Forging requests on behalf of authenticated users
- **Authentication Bypass** — Circumventing authentication mechanisms
- **Header Injection** — Manipulating HTTP headers
- **Open Redirect** — Exploiting URL redirects to external sites

New attack types are continuously discovered by the Scout agent.`,
  },
]

function DocSection({ section, isOpen, onToggle }) {
  return (
    <div className="border-b border-border/40">
      <button
        type="button"
        onClick={onToggle}
        className="flex w-full items-center justify-between px-6 py-5 text-left transition-colors hover:bg-surface/50"
      >
        <span className="text-[17px] font-medium text-text">{section.title}</span>
        <svg
          width="18"
          height="18"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
          className={`shrink-0 text-muted transition-transform duration-200 ${isOpen ? 'rotate-180' : ''}`}
        >
          <polyline points="6 9 12 15 18 9" />
        </svg>
      </button>
      {isOpen && (
        <div className="px-6 pb-6">
          <div className="prose-veil text-[15px] leading-[1.75] text-dim">
            {section.content.split('\n\n').map((block, i) => {
              // Code block
              if (block.startsWith('```')) {
                const code = block.replace(/```\w*/g, '').trim()
                return (
                  <pre key={i} className="my-3 overflow-x-auto rounded-lg border border-border/40 bg-bg px-4 py-3 font-mono text-[14px] text-muted">
                    {code}
                  </pre>
                )
              }
              // Numbered list
              if (/^\d+\./.test(block)) {
                return (
                  <div key={i} className="my-2 space-y-2">
                    {block.split('\n').map((line, j) => (
                      <p key={j} dangerouslySetInnerHTML={{ __html: formatLine(line) }} />
                    ))}
                  </div>
                )
              }
              // Bullet list
              if (block.startsWith('- ')) {
                return (
                  <ul key={i} className="my-2 space-y-1.5 pl-1">
                    {block.split('\n').map((line, j) => (
                      <li key={j} className="flex gap-2">
                        <span className="mt-[10px] h-1 w-1 shrink-0 rounded-full bg-agent/60" />
                        <span dangerouslySetInnerHTML={{ __html: formatLine(line.replace(/^- /, '')) }} />
                      </li>
                    ))}
                  </ul>
                )
              }
              // Regular paragraph
              return <p key={i} className="my-2" dangerouslySetInnerHTML={{ __html: formatLine(block) }} />
            })}
          </div>
        </div>
      )}
    </div>
  )
}

function formatLine(text) {
  return text
    .replace(/\*\*(.+?)\*\*/g, '<strong class="font-medium text-text">$1</strong>')
    .replace(/`([^`]+)`/g, '<code class="rounded bg-bg px-1.5 py-0.5 font-mono text-[13px] text-agent">$1</code>')
}

export function DocsPage() {
  const { user, loading: authLoading, logout } = useAuth()
  const [openSections, setOpenSections] = useState(new Set(['overview']))

  const toggle = (id) => {
    setOpenSections((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  if (authLoading) {
    return (
      <AppShell links={APP_SIDEBAR_LINKS} activeKey="docs" user={user} logout={logout} pageTitle="Documentation">
        <LoadingSpinner />
      </AppShell>
    )
  }

  if (!user) {
    window.location.href = '/auth'
    return null
  }

  return (
    <AppShell links={APP_SIDEBAR_LINKS} activeKey="docs" user={user} logout={logout} pageTitle="Documentation">
      <div className="px-8 py-10 lg:px-12">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-[32px] font-semibold text-text">Documentation</h1>
          <p className="mt-1.5 text-[17px] text-dim">
            Learn how Veil protects your APIs and how to get the most out of it.
          </p>
        </div>

        {/* Sections */}
        <div className="overflow-hidden rounded-xl border border-border/60 bg-surface/40">
          {SECTIONS.map((section) => (
            <DocSection
              key={section.id}
              section={section}
              isOpen={openSections.has(section.id)}
              onToggle={() => toggle(section.id)}
            />
          ))}
        </div>
      </div>
    </AppShell>
  )
}
