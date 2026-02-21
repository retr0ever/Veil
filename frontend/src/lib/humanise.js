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

export function humaniseAttackType(type) {
  if (!type) return 'Unknown attack'
  const key = type.toLowerCase().replace(/[\s-]+/g, '_')
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
    const type = req.attack_type ? humaniseAttackType(req.attack_type) : 'suspicious activity'
    return {
      summary: `Flagged possible ${type.toLowerCase()}`,
      color: 'text-suspicious',
    }
  }

  if (req.classification === 'MALICIOUS') {
    const type = req.attack_type ? humaniseAttackType(req.attack_type) : 'malicious request'
    const action = req.blocked ? 'Blocked' : 'Detected'
    return {
      summary: `${action} a ${type.toLowerCase()} attempt`,
      color: 'text-blocked',
    }
  }

  return { summary: req.message || 'Request processed', color: 'text-muted' }
}

export function humaniseAgentEvent(evt) {
  if (!evt) return { summary: 'Agent event', color: 'text-muted' }

  const agent = evt.agent || 'system'
  const status = evt.status || 'idle'

  if (agent === 'peek') {
    if (status === 'running') {
      return { summary: 'Scanning for new attack techniques...', color: 'text-agent' }
    }
    const count = extractNumber(evt.detail)
    if (status === 'done' && count !== null) {
      return { summary: `Veil discovered ${count} new attack technique${count !== 1 ? 's' : ''}`, color: 'text-agent' }
    }
    if (status === 'done') {
      return { summary: 'Finished scanning for attack techniques', color: 'text-agent' }
    }
    if (status === 'error') {
      return { summary: 'Scanning encountered an issue', color: 'text-blocked' }
    }
  }

  if (agent === 'poke') {
    if (status === 'running') {
      return { summary: 'Testing your defences against known attacks...', color: 'text-suspicious' }
    }
    if (status === 'done') {
      const match = evt.detail?.match(/(\d+)\s*(?:of|\/)\s*(\d+)/)
      if (match) {
        return {
          summary: `Tested your defences \u2014 blocked ${match[1]} of ${match[2]} attacks`,
          color: 'text-suspicious',
        }
      }
      return { summary: 'Finished testing your defences', color: 'text-suspicious' }
    }
    if (status === 'error') {
      return { summary: 'Defence testing encountered an issue', color: 'text-blocked' }
    }
  }

  if (agent === 'patch') {
    if (status === 'running') {
      return { summary: 'Strengthening your protection...', color: 'text-safe' }
    }
    if (status === 'done') {
      return { summary: 'Strengthened your protection', color: 'text-safe' }
    }
    if (status === 'error') {
      return { summary: 'Protection update encountered an issue', color: 'text-blocked' }
    }
  }

  return { summary: evt.detail || 'System event', color: 'text-muted' }
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

function extractNumber(text) {
  if (!text) return null
  const match = text.match(/(\d+)/)
  return match ? parseInt(match[1], 10) : null
}
