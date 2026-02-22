function cx(...parts) {
  return parts.filter(Boolean).join(' ')
}

export function NavBar({
  links,
  activeHref,
  size = 'default',
  showDivider = false,
  dividerClassName = '',
  className = '',
  navClassName = '',
}) {
  const logoSizeClass = size === 'hero'
    ? 'text-[72px] md:text-[124px] leading-[0.88]'
    : size === 'compact'
      ? 'text-[30px] md:text-[34px] leading-none'
      : 'text-[34px] md:text-[40px] leading-none'

  return (
    <>
      <header className={cx('flex flex-wrap items-center justify-between gap-6', className)}>
        <a href="/" className={cx('font-logo font-logo-main text-[#f6f1f9]', logoSizeClass)}>
          VEIL.
        </a>

        <nav className={cx('flex items-center gap-5 md:gap-8', navClassName)}>
          {links.map((link) => {
            const active = link.href === activeHref
            return (
              <a
                key={link.href}
                href={link.href}
                aria-current={active ? 'page' : undefined}
                className={cx(
                  'nav-link-block text-[16px] md:text-[20px] transition-opacity hover:opacity-100',
                  active ? 'text-[#f6f1f9] opacity-100' : 'text-[#d7d0dd] opacity-90',
                )}
              >
                {link.label}
              </a>
            )
          })}
        </nav>
      </header>

      {showDivider && (
        <div className={cx('mt-4 h-px w-full bg-[#848188]/70', dividerClassName)} />
      )}
    </>
  )
}
