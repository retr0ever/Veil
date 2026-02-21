const ATTACK_LABELS = {
  sql_injection: 'SQL injection',
  sqli: 'SQL injection',
  xss: 'Cross-site scripting',
  cross_site_scripting: 'Cross-site scripting',
  ssrf: 'Server-side request forgery',
  rce: 'Remote code execution',
  path_traversal: 'Path traversal',
  command_injection: 'Command injection',
  lfi: 'Local file inclusion',
  rfi: 'Remote file inclusion',
  xxe: 'XML external entity',
  idor: 'Insecure direct object reference',
  csrf: 'Cross-site request forgery',
  auth_bypass: 'Authentication bypass',
  header_injection: 'Header injection',
  open_redirect: 'Open redirect',
}

const ATTACK_EXPLANATIONS = {
  sql_injection: 'An attacker tries to manipulate database queries by injecting SQL code into input fields.',
  sqli: 'An attacker tries to manipulate database queries by injecting SQL code into input fields.',
  xss: 'Malicious scripts are injected into web pages viewed by other users to steal data or hijack sessions.',
  cross_site_scripting: 'Malicious scripts are injected into web pages viewed by other users to steal data or hijack sessions.',
  ssrf: 'The server is tricked into making requests to internal resources that should not be publicly accessible.',
  rce: 'An attacker attempts to run arbitrary commands on the server, potentially taking full control.',
  path_traversal: 'File paths are manipulated to access files outside the intended directory.',
  command_injection: 'System commands are injected through user input to execute on the server.',
  lfi: 'Local files on the server are accessed by manipulating file path parameters.',
  rfi: 'External malicious files are loaded and executed through manipulated file references.',
  xxe: 'XML parsers are exploited to access internal files or make server-side requests.',
  idor: 'Object references are manipulated to access resources belonging to other users.',
  csrf: 'Users are tricked into performing actions they did not intend through forged requests.',
  auth_bypass: 'Authentication mechanisms are circumvented to gain unauthorised access.',
  header_injection: 'HTTP headers are manipulated to inject malicious content or redirect responses.',
  open_redirect: 'URL redirects are exploited to send users to malicious external sites.',
}

const MEANINGLESS = new Set(['none', 'null', 'unknown', 'undefined', ''])

export function humaniseAttackType(type) {
  if (!type) return 'Unknown attack'
  const key = type.toLowerCase().replace(/[\s-]+/g, '_')
  if (MEANINGLESS.has(key)) return 'Unknown attack'
  return ATTACK_LABELS[key] || type.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase())
}

export function attackExplanation(category) {
  if (!category) return 'A potentially malicious request was detected.'
  const key = category.toLowerCase().replace(/[\s-]+/g, '_')
  return ATTACK_EXPLANATIONS[key] || `A ${humaniseAttackType(category).toLowerCase()} attempt was detected.`
}

export function humaniseRequest(req) {
  if (!req) return { summary: 'Unknown request', color: 'text-muted' }

  if (req.classification === 'SAFE') {
    return { summary: 'Safe request passed through', color: 'text-safe' }
  }

  if (req.classification === 'SUSPICIOUS') {
    const raw = req.attack_type
    const isMeaningless = !raw || MEANINGLESS.has(raw.toLowerCase().replace(/[\s-]+/g, '_'))
    if (isMeaningless) {
      return { summary: 'Flagged a suspicious request', color: 'text-suspicious' }
    }
    return {
      summary: `Flagged possible ${humaniseAttackType(raw).toLowerCase()}`,
      color: 'text-suspicious',
    }
  }

  if (req.classification === 'MALICIOUS') {
    const raw = req.attack_type
    const isMeaningless = !raw || MEANINGLESS.has(raw.toLowerCase().replace(/[\s-]+/g, '_'))
    const action = req.blocked ? 'Blocked' : 'Detected'
    if (isMeaningless) {
      return { summary: `${action} a malicious request`, color: 'text-blocked' }
    }
    return {
      summary: `${action} a ${humaniseAttackType(raw).toLowerCase()} attempt`,
      color: 'text-blocked',
    }
  }

  return { summary: req.message || 'Request processed', color: 'text-muted' }
}

export function humaniseAgentEvent(evt) {
  if (!evt) return { summary: 'Agent event', color: 'text-muted' }

  const agent = evt.agent || 'system'
  const status = evt.status || 'idle'
  const detail = evt.detail || ''

  if (agent === 'peek') {
    if (status === 'running') {
      return { summary: 'Scanning for new attack techniques...', color: 'text-agent' }
    }
    const count = extractNumber(detail)
    if (status === 'done' && count !== null) {
      const hintMatch = detail.match(/\[hint:\s*([^\]]+)\]/)
      const hint = hintMatch ? ` (adapting to ${hintMatch[1].replace(/_/g, ' ')})` : ''
      return { summary: `Veil discovered ${count} new attack technique${count !== 1 ? 's' : ''}${hint}`, color: 'text-agent' }
    }
    if (status === 'done') {
      return { summary: 'Finished scanning for attack techniques', color: 'text-agent' }
    }
    if (status === 'error') {
      return { summary: 'Scanning encountered an issue', color: 'text-blocked' }
    }
  }

  if (agent === 'poke') {
    const isRepoke = /re-test|re-poke/i.test(detail)
    if (status === 'running' && isRepoke) {
      const count = extractNumber(detail)
      return { summary: `Verifying ${count || ''} threat${count !== 1 ? 's' : ''} after patch...`.replace('  ', ' '), color: 'text-suspicious' }
    }
    if (status === 'running') {
      return { summary: 'Testing your defences against known attacks...', color: 'text-suspicious' }
    }
    if (status === 'done' && isRepoke) {
      const count = extractNumber(detail)
      if (count === 0) {
        return { summary: 'All threats now blocked after patch', color: 'text-safe' }
      }
      return { summary: `${count} threat${count !== 1 ? 's' : ''} still evading after patch`, color: 'text-blocked' }
    }
    if (status === 'done') {
      const match = detail.match(/(\d+)\s*(?:of|\/)\s*(\d+)/)
      if (match) {
        return {
          summary: `Tested your defences \u2014 blocked ${match[1]} of ${match[2]} attacks`,
          color: 'text-suspicious',
        }
      }
      const bypasses = extractNumber(detail)
      if (bypasses !== null) {
        return {
          summary: bypasses === 0
            ? 'Tested your defences \u2014 all attacks blocked'
            : `Tested your defences \u2014 ${bypasses} bypass${bypasses !== 1 ? 'es' : ''} found`,
          color: bypasses === 0 ? 'text-safe' : 'text-suspicious',
        }
      }
      return { summary: 'Finished testing your defences', color: 'text-suspicious' }
    }
    if (status === 'error') {
      return { summary: 'Defence testing encountered an issue', color: 'text-blocked' }
    }
  }

  if (agent === 'patch') {
    const roundMatch = detail.match(/\(round\s*(\d+)\)/)
    const round = roundMatch ? parseInt(roundMatch[1], 10) : null
    const roundLabel = round && round > 1 ? ` (round ${round})` : ''

    if (status === 'running') {
      return { summary: `Strengthening your protection${roundLabel}...`, color: 'text-safe' }
    }
    if (status === 'done') {
      const stillMatch = detail.match(/(\d+)\s*still bypassing/)
      const still = stillMatch ? parseInt(stillMatch[1], 10) : 0
      if (still > 0) {
        return { summary: `Patched rules${roundLabel} \u2014 ${still} threat${still !== 1 ? 's' : ''} still evading, retrying`, color: 'text-suspicious' }
      }
      return { summary: `Strengthened your protection${roundLabel}`, color: 'text-safe' }
    }
    if (status === 'error') {
      return { summary: 'Protection update encountered an issue', color: 'text-blocked' }
    }
  }

  if (agent === 'system') {
    const cycleMatch = detail.match(/Cycle\s*#(\d+)/)
    if (cycleMatch) {
      const parts = []
      const disc = detail.match(/discovered=(\d+)/)
      const tested = detail.match(/tested=(\d+)/)
      const patched = detail.match(/patched=(\d+)/)
      const rounds = detail.match(/patch_rounds=(\d+)/)
      if (disc) parts.push(`${disc[1]} discovered`)
      if (tested) parts.push(`${tested[1]} tested`)
      if (patched) parts.push(`${patched[1]} patched`)
      if (rounds && parseInt(rounds[1], 10) > 1) parts.push(`${rounds[1]} patch rounds`)
      return {
        summary: `Cycle #${cycleMatch[1]} complete \u2014 ${parts.join(', ') || 'no activity'}`,
        color: 'text-dim',
      }
    }
    return { summary: detail || 'System event', color: 'text-dim' }
  }

  return { summary: detail || 'System event', color: 'text-muted' }
}

export function relativeTime(timestamp) {
  if (!timestamp) return ''
  const now = Date.now()
  const then = new Date(timestamp).getTime()
  if (isNaN(then)) return ''

  const diffSeconds = Math.floor((now - then) / 1000)

  if (diffSeconds < 5) return 'just now'
  if (diffSeconds < 60) return `${diffSeconds}s ago`

  const diffMinutes = Math.floor(diffSeconds / 60)
  if (diffMinutes < 60) return `${diffMinutes}m ago`

  const diffHours = Math.floor(diffMinutes / 60)
  if (diffHours < 24) return `${diffHours}h ago`

  const diffDays = Math.floor(diffHours / 24)
  return `${diffDays}d ago`
}

export function humaniseAgentRole(agent) {
  const roles = {
    peek: { name: 'Scout', verb: 'Discovers new attack patterns' },
    poke: { name: 'Red Team', verb: 'Tests if Veil can block them' },
    patch: { name: 'Adapt', verb: 'Analyses gaps and updates rules' },
    system: { name: 'Orchestrator', verb: 'Coordinates the improvement cycle' },
  }
  return roles[agent] || { name: agent, verb: '' }
}

export function humaniseRuleSource(version) {
  if (version <= 1) return 'Initial'
  return 'AI patch'
}

export function humaniseEmptyState(context) {
  const messages = {
    feed: 'No classifications yet. Connect your site or check the Agents tab.',
    agents: 'Agents have not run yet. Start an improvement cycle to see activity.',
    threats: 'No threats discovered yet. Run an improvement cycle to begin scanning.',
  }
  return messages[context] || 'No data yet.'
}

export function attackCategory(type) {
  if (!type) return 'unknown'
  const key = type.toLowerCase().replace(/[\s-]+/g, '_')
  if (MEANINGLESS.has(key)) return 'unknown'
  if (key === 'sql_injection' || key === 'sqli') return 'sqli'
  if (key === 'xss' || key === 'cross_site_scripting') return 'xss'
  if (key === 'ssrf') return 'ssrf'
  if (key === 'rce' || key === 'command_injection') return 'rce'
  if (key === 'path_traversal' || key === 'lfi' || key === 'rfi') return 'file'
  if (key === 'xxe') return 'xxe'
  if (key === 'auth_bypass' || key === 'idor') return 'auth'
  if (key === 'csrf' || key === 'open_redirect' || key === 'header_injection') return 'web'
  return 'unknown'
}

const CODE_FIX_SUGGESTIONS = {
  sqli: {
    title: 'Use parameterised queries',
    suggestion: 'Never concatenate user input into SQL strings. Use prepared statements or an ORM with bound parameters.',
    example: `// Instead of:\ndb.query("SELECT * FROM users WHERE id = " + req.params.id)\n\n// Use parameterised queries:\ndb.query("SELECT * FROM users WHERE id = $1", [req.params.id])`,
  },
  sql_injection: {
    title: 'Use parameterised queries',
    suggestion: 'Never concatenate user input into SQL strings. Use prepared statements or an ORM with bound parameters.',
    example: `// Instead of:\ndb.query("SELECT * FROM users WHERE id = " + req.params.id)\n\n// Use parameterised queries:\ndb.query("SELECT * FROM users WHERE id = $1", [req.params.id])`,
  },
  xss: {
    title: 'Escape output and set a Content-Security-Policy',
    suggestion: 'Always escape or sanitise user-supplied content before rendering it in HTML. Use a templating engine that auto-escapes by default, and set a strict CSP header.',
    example: `// Set CSP header:\nContent-Security-Policy: default-src 'self'; script-src 'self'\n\n// In React, avoid dangerouslySetInnerHTML.\n// In plain HTML, escape before inserting:\nconst safe = text.replace(/[&<>"']/g, c =>\n  ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":"&#39;" })[c])`,
  },
  cross_site_scripting: {
    title: 'Escape output and set a Content-Security-Policy',
    suggestion: 'Always escape or sanitise user-supplied content before rendering it in HTML. Use a templating engine that auto-escapes by default, and set a strict CSP header.',
    example: `Content-Security-Policy: default-src 'self'; script-src 'self'`,
  },
  ssrf: {
    title: 'Validate and restrict outbound URLs',
    suggestion: 'Allowlist permitted hosts and schemes. Block requests to private/internal IP ranges and metadata endpoints.',
    example: `// Validate the URL before fetching:\nconst url = new URL(userInput)\nconst blocked = ['127.0.0.1', 'localhost', '169.254.169.254']\nif (blocked.includes(url.hostname)) throw new Error('Blocked host')`,
  },
  rce: {
    title: 'Avoid dynamic code execution',
    suggestion: 'Never pass user input to eval(), Function(), or child_process.exec(). Use safer alternatives like execFile() with a fixed command and argument array.',
    example: `// Instead of:\nexec("convert " + userFile)\n\n// Use execFile with explicit args:\nexecFile("convert", [userFile], callback)`,
  },
  command_injection: {
    title: 'Use execFile instead of exec',
    suggestion: 'Avoid shell interpolation by using execFile() or spawn() with an argument array. Never pass user input through a shell.',
    example: `// Instead of:\nexec("ls " + userDir)\n\n// Use execFile:\nexecFile("ls", [userDir], callback)`,
  },
  path_traversal: {
    title: 'Resolve and confine file paths',
    suggestion: 'Resolve the full path and verify it stays within your intended base directory. Reject paths containing .. sequences.',
    example: `const path = require('path')\nconst base = '/app/uploads'\nconst resolved = path.resolve(base, userInput)\nif (!resolved.startsWith(base)) throw new Error('Path traversal blocked')`,
  },
  lfi: {
    title: 'Allowlist permitted file paths',
    suggestion: 'Use a fixed map of allowed files instead of accepting arbitrary paths from user input.',
    example: `const ALLOWED = { 'terms': '/pages/terms.html', 'privacy': '/pages/privacy.html' }\nconst file = ALLOWED[req.params.page]\nif (!file) return res.status(404).send('Not found')`,
  },
  rfi: {
    title: 'Disable remote file includes',
    suggestion: 'In PHP, set allow_url_include = Off. In other languages, never fetch and execute code from user-supplied URLs.',
    example: `; php.ini\nallow_url_include = Off\nallow_url_fopen = Off`,
  },
  xxe: {
    title: 'Disable external entities in XML parsers',
    suggestion: 'Configure your XML parser to disallow DTDs and external entity resolution.',
    example: `// Node.js (libxmljs):\nconst doc = libxmljs.parseXml(input, { noent: false, dtdload: false })\n\n// Java:\nfactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`,
  },
  idor: {
    title: 'Enforce ownership checks on every request',
    suggestion: 'Always verify the authenticated user has permission to access the requested resource. Never rely on obscurity of IDs.',
    example: `// Check ownership:\nconst item = await db.query("SELECT * FROM orders WHERE id = $1", [id])\nif (item.user_id !== req.user.id) return res.status(403).send('Forbidden')`,
  },
  csrf: {
    title: 'Use anti-CSRF tokens',
    suggestion: 'Include a unique, per-session CSRF token in state-changing forms and validate it server-side. Use SameSite cookie attributes.',
    example: `// Set cookie attributes:\nres.cookie('session', token, { sameSite: 'Strict', httpOnly: true })\n\n// Validate CSRF token on POST:\nif (req.body._csrf !== req.session.csrfToken) return res.status(403).end()`,
  },
  auth_bypass: {
    title: 'Centralise authentication middleware',
    suggestion: 'Apply auth checks via middleware on all protected routes rather than per-handler. Fail closed — deny by default.',
    example: `// Express middleware:\napp.use('/api', (req, res, next) => {\n  if (!req.session?.userId) return res.status(401).json({ error: 'Unauthenticated' })\n  next()\n})`,
  },
  header_injection: {
    title: 'Strip newlines from header values',
    suggestion: 'Never include raw user input in HTTP response headers. Remove or reject \\r and \\n characters.',
    example: `// Sanitise before setting header:\nconst safe = userInput.replace(/[\\r\\n]/g, '')\nres.setHeader('X-Custom', safe)`,
  },
  open_redirect: {
    title: 'Validate redirect targets against an allowlist',
    suggestion: 'Only redirect to known, trusted URLs. Reject absolute URLs or those pointing to external domains.',
    example: `// Only allow relative paths:\nconst target = req.query.next\nif (target.startsWith('/') && !target.startsWith('//')) {\n  res.redirect(target)\n} else {\n  res.redirect('/')\n}`,
  },
}

export { CODE_FIX_SUGGESTIONS }

export function codeFixForCategory(category) {
  if (!category) return { title: 'Review input handling', suggestion: 'Validate and sanitise all user input at your application boundary.', example: null }
  const key = category.toLowerCase().replace(/[\s-]+/g, '_')
  return CODE_FIX_SUGGESTIONS[key] || { title: 'Review input handling', suggestion: 'Validate and sanitise all user input at your application boundary.', example: null }
}

function extractNumber(text) {
  if (!text) return null
  const match = text.match(/(\d+)/)
  return match ? parseInt(match[1], 10) : null
}
