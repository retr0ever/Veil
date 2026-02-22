import { useState, useEffect, useRef } from 'react'

/* ── Sidebar width constants ─────────────────────────────── */
const SIDEBAR_WIDTH_EXPANDED = 320
const SIDEBAR_WIDTH_COLLAPSED = 64
const SIDEBAR_WIDTH_MOBILE = 340

/* ── Inline SVG icon map ─────────────────────────────────── */
const icons = {
  grid: (
    <svg width="20" height="20" viewBox="0 0 18 18" fill="none">
      <rect x="2.5" y="2.5" width="5" height="5" rx="2" fill="currentColor" opacity="0.25" />
      <rect x="10.5" y="2.5" width="5" height="5" rx="2" fill="currentColor" opacity="0.25" />
      <rect x="2.5" y="10.5" width="5" height="5" rx="2" fill="currentColor" opacity="0.25" />
      <rect x="10.5" y="10.5" width="5" height="5" rx="2" fill="currentColor" opacity="0.25" />
      <rect x="2.5" y="2.5" width="5" height="5" rx="2" stroke="currentColor" strokeWidth="1.2" />
      <rect x="10.5" y="2.5" width="5" height="5" rx="2" stroke="currentColor" strokeWidth="1.2" />
      <rect x="2.5" y="10.5" width="5" height="5" rx="2" stroke="currentColor" strokeWidth="1.2" />
      <rect x="10.5" y="10.5" width="5" height="5" rx="2" stroke="currentColor" strokeWidth="1.2" />
    </svg>
  ),
  cpu: (
    <svg width="20" height="20" viewBox="0 0 18 18" fill="none">
      <circle cx="5.5" cy="6" r="2.2" fill="currentColor" opacity="0.2" stroke="currentColor" strokeWidth="1" />
      <circle cx="9" cy="6" r="2.2" fill="currentColor" opacity="0.2" stroke="currentColor" strokeWidth="1" />
      <circle cx="12.5" cy="6" r="2.2" fill="currentColor" opacity="0.2" stroke="currentColor" strokeWidth="1" />
      <path d="M3 12.5c0-1.5 1.5-3 3-3h6c1.5 0 3 1.5 3 3v1a1.5 1.5 0 0 1-1.5 1.5h-9A1.5 1.5 0 0 1 3 13.5v-1z" fill="currentColor" opacity="0.12" stroke="currentColor" strokeWidth="1" />
    </svg>
  ),
  shield: (
    <svg width="20" height="20" viewBox="0 0 18 18" fill="none">
      <path d="M9 2L3.5 4.5v4c0 3.8 2.8 6.2 5.5 7.5 2.7-1.3 5.5-3.7 5.5-7.5v-4L9 2z" fill="currentColor" opacity="0.15" stroke="currentColor" strokeWidth="1.2" strokeLinejoin="round" />
      <circle cx="9" cy="8.5" r="1.8" fill="currentColor" opacity="0.3" />
    </svg>
  ),
  settings: (
    <svg width="20" height="20" viewBox="0 0 18 18" fill="none">
      <circle cx="9" cy="9" r="5.5" fill="currentColor" opacity="0.1" stroke="currentColor" strokeWidth="1.1" />
      <circle cx="9" cy="9" r="2" fill="currentColor" opacity="0.3" stroke="currentColor" strokeWidth="1" />
      <line x1="9" y1="1.5" x2="9" y2="3.5" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
      <line x1="9" y1="14.5" x2="9" y2="16.5" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
      <line x1="1.5" y1="9" x2="3.5" y2="9" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
      <line x1="14.5" y1="9" x2="16.5" y2="9" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
    </svg>
  ),
  folder: (
    <svg width="20" height="20" viewBox="0 0 18 18" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M16 14.5a1.5 1.5 0 0 1-1.5 1.5h-11A1.5 1.5 0 0 1 2 14.5v-11A1.5 1.5 0 0 1 3.5 2H7l1.5 2.5h6A1.5 1.5 0 0 1 16 6v8.5z" />
    </svg>
  ),
  plus: (
    <svg width="20" height="20" viewBox="0 0 18 18" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
      <path d="M9 3v12M3 9h12" />
    </svg>
  ),
  'arrow-left': (
    <svg width="20" height="20" viewBox="0 0 18 18" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M11 4l-5 5 5 5" />
    </svg>
  ),
  'log-out': (
    <svg width="16" height="16" viewBox="0 0 18 18" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M6.5 16h-3A1.5 1.5 0 0 1 2 14.5v-11A1.5 1.5 0 0 1 3.5 2h3M12.5 13L16 9l-3.5-4M16 9H6.5" />
    </svg>
  ),
  user: (
    <svg width="16" height="16" viewBox="0 0 18 18" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="9" cy="6" r="3.5" />
      <path d="M2.5 16.5c0-3.3 2.9-6 6.5-6s6.5 2.7 6.5 6" />
    </svg>
  ),
  'chevron-left': (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M10 3L5 8l5 5" />
    </svg>
  ),
  'chevron-right': (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M6 3l5 5-5 5" />
    </svg>
  ),
  hamburger: (
    <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round">
      <path d="M4 6h12M4 10h12M4 14h12" />
    </svg>
  ),
  close: (
    <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round">
      <path d="M5 5l10 10M15 5L5 15" />
    </svg>
  ),
  'file-text': (
    <svg width="20" height="20" viewBox="0 0 18 18" fill="none" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M10.5 2H5a1.5 1.5 0 0 0-1.5 1.5v11A1.5 1.5 0 0 0 5 16h8a1.5 1.5 0 0 0 1.5-1.5V6L10.5 2z" fill="currentColor" opacity="0.1" />
      <path d="M10.5 2H5a1.5 1.5 0 0 0-1.5 1.5v11A1.5 1.5 0 0 0 5 16h8a1.5 1.5 0 0 0 1.5-1.5V6L10.5 2z" />
      <polyline points="10.5 2 10.5 6 14.5 6" />
      <line x1="6.5" y1="9.5" x2="11.5" y2="9.5" />
      <line x1="6.5" y1="12" x2="11.5" y2="12" />
    </svg>
  ),
}

function SidebarIcon({ name }) {
  return icons[name] || null
}


/* ── Tooltip (for collapsed sidebar icons) ───────────────── */
function Tooltip({ text, children, sidebarWidth }) {
  const [show, setShow] = useState(false)
  const [pos, setPos] = useState({ top: 0 })
  const ref = useRef(null)

  const handleEnter = () => {
    if (ref.current) {
      const rect = ref.current.getBoundingClientRect()
      setPos({ top: rect.top + rect.height / 2 })
    }
    setShow(true)
  }

  return (
    <div
      ref={ref}
      className="relative"
      onMouseEnter={handleEnter}
      onMouseLeave={() => setShow(false)}
    >
      {children}
      {show && (
        <div
          className="pointer-events-none fixed z-[100] ml-2 -translate-y-1/2 rounded-md bg-[#241c31] px-2.5 py-1.5 text-[14px] font-medium text-text shadow-lg shadow-black/30 whitespace-nowrap"
          style={{ top: pos.top, left: (sidebarWidth || SIDEBAR_WIDTH_COLLAPSED) + 4 }}
        >
          {text}
        </div>
      )}
    </div>
  )
}


/* ── ContentHeader ───────────────────────────────────────── */
function ContentHeader({ pageTitle, projectTitle }) {
  if (!pageTitle) return null

  return (
    <div className="flex h-14 shrink-0 items-center border-b border-border/40 px-6">
      {projectTitle ? (
        <div className="flex items-center gap-2 text-[18px]">
          <a
            href="/app/projects"
            className="text-muted transition-colors hover:text-text"
          >
            Projects
          </a>
          <span className="text-muted/50">/</span>
          <span className="font-medium text-text">{projectTitle}</span>
          {pageTitle !== projectTitle && (
            <>
              <span className="text-muted/50">/</span>
              <span className="text-dim">{pageTitle}</span>
            </>
          )}
        </div>
      ) : (
        <span className="text-[16px] font-medium text-text">{pageTitle}</span>
      )}
    </div>
  )
}


/* ── LoadingSpinner ──────────────────────────────────────── */
export function LoadingSpinner({ label = 'Loading...' }) {
  return (
    <div className="flex h-full min-h-[60vh] items-center justify-center">
      <div className="flex flex-col items-center gap-3">
        <div className="h-8 w-8 animate-spin rounded-full border-2 border-border border-t-agent" />
        <span className="text-[15px] text-muted">{label}</span>
      </div>
    </div>
  )
}


/* ── EmptyState ──────────────────────────────────────────── */
export function EmptyState({ icon, heading, description, ctaLabel, ctaHref }) {
  return (
    <div className="flex h-full min-h-[40vh] items-center justify-center px-4">
      <div className="flex max-w-sm flex-col items-center text-center">
        {icon && <div className="mb-4 text-muted">{icon}</div>}
        <h2 className="text-[16px] font-semibold text-text">{heading}</h2>
        {description && <p className="mt-2 text-[15px] text-dim">{description}</p>}
        {ctaLabel && ctaHref && (
          <a
            href={ctaHref}
            className="mt-5 inline-flex rounded-lg bg-text px-4 py-2 text-[15px] font-medium text-bg"
          >
            {ctaLabel}
          </a>
        )}
      </div>
    </div>
  )
}


/* ── AppShell ────────────────────────────────────────────── */
export function AppShell({
  links,
  activeKey,
  onNavClick,
  user,
  logout,
  projectTitle,
  projectUrl,
  pageTitle,
  children,
}) {
  const [collapsed, setCollapsed] = useState(false)
  const [isMobile, setIsMobile] = useState(false)
  const [mobileOpen, setMobileOpen] = useState(false)

  useEffect(() => {
    const check = () => {
      const mobile = window.innerWidth < 768
      setIsMobile(mobile)
      if (mobile) {
        setCollapsed(true)
        setMobileOpen(false)
      }
    }
    check()
    window.addEventListener('resize', check)
    return () => window.removeEventListener('resize', check)
  }, [])

  // Close mobile sidebar on escape
  useEffect(() => {
    if (!mobileOpen) return
    const handleKey = (e) => {
      if (e.key === 'Escape') setMobileOpen(false)
    }
    window.addEventListener('keydown', handleKey)
    return () => window.removeEventListener('keydown', handleKey)
  }, [mobileOpen])

  // Derive the page title from activeKey + links if not explicitly provided
  const resolvedPageTitle = pageTitle !== undefined
    ? pageTitle
    : (() => {
        const active = links.find((l) => l.key === activeKey)
        return active ? active.label : null
      })()

  const currentSidebarWidth = isMobile
    ? SIDEBAR_WIDTH_MOBILE
    : collapsed
      ? SIDEBAR_WIDTH_COLLAPSED
      : SIDEBAR_WIDTH_EXPANDED

  const sidebarContent = (
    <aside
      className="flex h-full flex-col bg-surface transition-[width] duration-[250ms] ease-[cubic-bezier(0.4,0,0.2,1)]"
      style={{ width: currentSidebarWidth }}
    >
      {/* ── Logo area ── */}
      <div className={`flex h-[68px] shrink-0 items-center border-b border-border/40 ${collapsed && !isMobile ? 'justify-center px-0' : 'px-6'}`}>
        {(!collapsed || isMobile) && (
          <a
            href="/app/projects"
            className="font-logo text-[24px] leading-none tracking-wide text-[#f6f1f9]"
          >
            VEIL.
          </a>
        )}

        {/* Desktop collapse toggle */}
        {!isMobile && (
          <button
            onClick={() => setCollapsed((v) => !v)}
            className={`
              flex h-7 w-7 items-center justify-center rounded-md
              border-none bg-transparent text-muted
              transition-colors duration-150 hover:bg-white/[0.06] hover:text-text
              ${collapsed ? '' : 'ml-auto'}
            `}
            title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          >
            <SidebarIcon name={collapsed ? 'chevron-right' : 'chevron-left'} />
          </button>
        )}

        {/* Mobile close button */}
        {isMobile && (
          <button
            onClick={() => setMobileOpen(false)}
            className="ml-auto flex h-7 w-7 items-center justify-center rounded-md border-none bg-transparent text-muted transition-colors duration-150 hover:text-text"
            aria-label="Close sidebar"
          >
            <SidebarIcon name="close" />
          </button>
        )}
      </div>

      {/* ── Project context block ── */}
      {projectTitle && (!collapsed || isMobile) && (
        <div className="border-b border-border/40 px-6 py-4">
          <a
            href="/app/projects"
            className="group mb-2 flex items-center gap-2 text-[15px] text-muted transition-colors hover:text-text"
          >
            <span className="shrink-0 transition-transform duration-150 group-hover:-translate-x-0.5">
              <SidebarIcon name="arrow-left" />
            </span>
            <span>All projects</span>
          </a>
          <div className="mt-1 flex items-start gap-2.5">
            <div className="mt-1.5 flex items-center gap-1.5 shrink-0">
              <div className="h-2 w-2 rounded-full bg-safe animate-pulse" />
            </div>
            <div className="min-w-0 flex-1">
              <p className="truncate text-[18px] font-medium text-text leading-snug">{projectTitle}</p>
              {projectUrl && (
                <p className="mt-0.5 truncate text-[15px] text-muted">{projectUrl}</p>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Collapsed project indicator */}
      {projectTitle && collapsed && !isMobile && (
        <Tooltip text={projectTitle} sidebarWidth={SIDEBAR_WIDTH_COLLAPSED}>
          <div className="flex justify-center border-b border-border/40 py-3">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-safe/10">
              <div className="h-2 w-2 rounded-full bg-safe animate-pulse" />
            </div>
          </div>
        </Tooltip>
      )}

      {/* ── Navigation (flat list, no section grouping) ── */}
      <nav className="flex-1 overflow-y-auto overflow-x-hidden py-3">
        {/* Back to projects (collapsed mode, when inside a project) */}
        {projectTitle && collapsed && !isMobile && (
          <Tooltip text="All projects" sidebarWidth={SIDEBAR_WIDTH_COLLAPSED}>
            <a
              href="/app/projects"
              className="mx-auto mb-2 flex h-9 w-9 items-center justify-center rounded-md text-muted transition-colors duration-150 hover:bg-white/[0.06] hover:text-text"
            >
              <SidebarIcon name="arrow-left" />
            </a>
          </Tooltip>
        )}

        {links.filter((l) => l.key !== 'docs').map((link) => {
          const active = link.key === activeKey

          const handleClick = () => {
            if (isMobile) setMobileOpen(false)
            if (onNavClick) {
              onNavClick(link.key)
            } else if (link.href.startsWith('#')) {
              window.location.hash = link.href
            } else {
              window.location.href = link.href
            }
          }

          const btn = (
            <button
              key={link.key}
              type="button"
              onClick={handleClick}
              className={`
                group/nav relative flex w-full items-center
                text-[19px] transition-colors duration-150
                ${collapsed && !isMobile
                  ? 'mx-auto h-9 w-9 justify-center rounded-md'
                  : 'mx-3 gap-3.5 rounded-lg px-3.5 py-2.5'
                }
                ${active
                  ? 'bg-white/[0.07] text-text font-medium'
                  : 'bg-transparent text-muted hover:bg-white/[0.04] hover:text-dim'
                }
              `}
              title={collapsed && !isMobile ? link.label : undefined}
            >
              {/* Active left accent bar */}
              {active && (!collapsed || isMobile) && (
                <span
                  className="absolute left-0 top-1/2 -translate-y-1/2 h-[18px] w-[2.5px] rounded-r-full bg-agent"
                  aria-hidden="true"
                />
              )}

              {/* Active dot for collapsed mode */}
              {active && collapsed && !isMobile && (
                <span
                  className="absolute -left-[2px] top-1/2 -translate-y-1/2 h-[18px] w-[2.5px] rounded-r-full bg-agent"
                  aria-hidden="true"
                />
              )}

              <span className="shrink-0 flex items-center justify-center w-[20px] h-[20px]">
                <SidebarIcon name={link.icon} />
              </span>

              {(!collapsed || isMobile) && (
                <span className="truncate">{link.label}</span>
              )}
            </button>
          )

          if (collapsed && !isMobile) {
            return (
              <Tooltip key={link.key} text={link.label} sidebarWidth={SIDEBAR_WIDTH_COLLAPSED}>
                {btn}
              </Tooltip>
            )
          }

          return btn
        })}
      </nav>

      {/* ── Docs link (pinned above footer) ── */}
      {(() => {
        const docsLink = links.find((l) => l.key === 'docs')
        if (!docsLink) return null
        const active = docsLink.key === activeKey
        const handleClick = () => {
          if (isMobile) setMobileOpen(false)
          window.location.href = docsLink.href
        }
        const btn = (
          <button
            type="button"
            onClick={handleClick}
            className={`
              group/nav relative flex w-full items-center
              text-[19px] transition-colors duration-150
              ${collapsed && !isMobile
                ? 'mx-auto h-9 w-9 justify-center rounded-md'
                : 'mx-3 gap-3.5 rounded-lg px-3.5 py-2.5'
              }
              ${active
                ? 'bg-white/[0.07] text-text font-medium'
                : 'bg-transparent text-muted hover:bg-white/[0.04] hover:text-dim'
              }
            `}
            title={collapsed && !isMobile ? docsLink.label : undefined}
          >
            {active && (!collapsed || isMobile) && (
              <span className="absolute left-0 top-1/2 -translate-y-1/2 h-[18px] w-[2.5px] rounded-r-full bg-agent" aria-hidden="true" />
            )}
            {active && collapsed && !isMobile && (
              <span className="absolute -left-[2px] top-1/2 -translate-y-1/2 h-[18px] w-[2.5px] rounded-r-full bg-agent" aria-hidden="true" />
            )}
            <span className="shrink-0 flex items-center justify-center w-[20px] h-[20px]">
              <SidebarIcon name={docsLink.icon} />
            </span>
            {(!collapsed || isMobile) && (
              <span className="truncate">{docsLink.label}</span>
            )}
          </button>
        )
        return (
          <div className="shrink-0 overflow-hidden pb-1 pt-1">
            {collapsed && !isMobile ? (
              <Tooltip text={docsLink.label} sidebarWidth={SIDEBAR_WIDTH_COLLAPSED}>{btn}</Tooltip>
            ) : btn}
          </div>
        )
      })()}

      {/* ── User footer ── */}
      {user && (
        <div className="shrink-0 border-t border-border/40">
          {collapsed && !isMobile ? (
            <div className="flex flex-col items-center gap-1 py-3">
              {/* Avatar with tooltip showing name */}
              <Tooltip text={user.name || user.github_login} sidebarWidth={SIDEBAR_WIDTH_COLLAPSED}>
                <div className="flex h-8 w-8 items-center justify-center rounded-md">
                  {user.avatar_url ? (
                    <img
                      src={user.avatar_url}
                      alt=""
                      className="h-6 w-6 rounded-full opacity-70"
                    />
                  ) : (
                    <span className="text-muted">
                      <SidebarIcon name="user" />
                    </span>
                  )}
                </div>
              </Tooltip>

              {/* Separate sign-out button */}
              <Tooltip text="Sign out" sidebarWidth={SIDEBAR_WIDTH_COLLAPSED}>
                <button
                  onClick={logout}
                  className="flex h-7 w-7 items-center justify-center rounded-md border-none bg-transparent text-muted transition-colors duration-150 hover:bg-white/[0.06] hover:text-text"
                  aria-label="Sign out"
                >
                  <SidebarIcon name="log-out" />
                </button>
              </Tooltip>
            </div>
          ) : (
            <div className="flex items-center gap-3.5 px-6 py-4">
              {user.avatar_url && (
                <img
                  src={user.avatar_url}
                  alt=""
                  className="h-9 w-9 shrink-0 rounded-full"
                />
              )}
              <div className="min-w-0 flex-1">
                <p className="truncate text-[17px] font-medium text-text leading-tight">
                  {user.name || user.github_login}
                </p>
                {user.github_login && user.name && (
                  <p className="truncate text-[14px] text-muted leading-tight mt-0.5">
                    @{user.github_login}
                  </p>
                )}
              </div>
              <button
                onClick={logout}
                className="shrink-0 flex h-7 w-7 items-center justify-center rounded-md border-none bg-transparent text-muted transition-colors duration-150 hover:bg-white/[0.06] hover:text-text"
                title="Sign out"
                aria-label="Sign out"
              >
                <SidebarIcon name="log-out" />
              </button>
            </div>
          )}
        </div>
      )}
    </aside>
  )

  return (
    <div className="flex h-screen overflow-hidden bg-bg text-text">
      {/* ── Mobile: hamburger trigger ── */}
      {isMobile && !mobileOpen && (
        <button
          onClick={() => setMobileOpen(true)}
          className="fixed top-3 left-3 z-50 flex h-9 w-9 items-center justify-center rounded-lg bg-surface/90 text-muted backdrop-blur-sm border border-border/40 transition-colors hover:text-text"
          aria-label="Open sidebar"
        >
          <SidebarIcon name="hamburger" />
        </button>
      )}

      {/* ── Mobile overlay ── */}
      {isMobile && mobileOpen && (
        <div
          className="fixed inset-0 z-40 bg-black/50 backdrop-blur-[2px] transition-opacity duration-250"
          onClick={() => setMobileOpen(false)}
          aria-hidden="true"
        />
      )}

      {/* ── Sidebar wrapper ── */}
      {isMobile ? (
        <div
          className={`
            fixed inset-y-0 left-0 z-50
            transition-transform duration-[250ms] ease-[cubic-bezier(0.4,0,0.2,1)]
            ${mobileOpen ? 'translate-x-0' : '-translate-x-full'}
          `}
        >
          {sidebarContent}
        </div>
      ) : (
        <div className="relative shrink-0 border-r border-border/40">
          {sidebarContent}
        </div>
      )}

      {/* ── Main content ── */}
      <main className="flex-1 min-w-0 flex flex-col overflow-y-auto">
        <ContentHeader pageTitle={resolvedPageTitle} projectTitle={projectTitle} />
        <div className="flex-1">
          {children}
        </div>
      </main>
    </div>
  )
}
