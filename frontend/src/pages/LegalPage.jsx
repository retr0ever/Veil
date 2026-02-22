const LEGAL_PAGES = {
  terms: {
    title: 'Terms & Conditions',
    lastUpdated: '22 February 2026',
    sections: [
      {
        heading: 'Acceptance of Terms',
        body: 'By accessing or using the Veil platform ("Service"), you agree to be bound by these Terms & Conditions. If you do not agree, do not use the Service.',
      },
      {
        heading: 'Description of Service',
        body: 'Veil is an AI-powered API security firewall that analyses inbound traffic, classifies threats, and provides automated defence recommendations. The Service is provided on an "as is" and "as available" basis.',
      },
      {
        heading: 'Account Registration',
        body: 'You must authenticate via GitHub OAuth to access the Service. You are responsible for maintaining the security of your account and for all activity under it. You must be at least 18 years old to use the Service.',
      },
      {
        heading: 'Acceptable Use',
        body: 'You agree not to: (a) use the Service for any unlawful purpose; (b) attempt to reverse-engineer, disassemble, or decompile any part of the Service; (c) interfere with or disrupt the integrity or performance of the Service; (d) use the Service to attack or probe systems you do not own or have authorisation to test.',
      },
      {
        heading: 'Intellectual Property',
        body: 'All rights, title, and interest in the Service, including all intellectual property rights, belong to Veil and its licensors. You retain ownership of your own data and configurations.',
      },
      {
        heading: 'Limitation of Liability',
        body: 'To the maximum extent permitted by law, Veil shall not be liable for any indirect, incidental, special, consequential, or punitive damages, or any loss of profits or revenues, whether incurred directly or indirectly. The Service is a hackathon prototype and is not intended for production use protecting critical infrastructure.',
      },
      {
        heading: 'Termination',
        body: 'We may suspend or terminate your access to the Service at any time, with or without cause, with or without notice. Upon termination, your right to use the Service ceases immediately.',
      },
      {
        heading: 'Changes to Terms',
        body: 'We reserve the right to modify these Terms at any time. Continued use of the Service after changes constitutes acceptance of the revised Terms.',
      },
      {
        heading: 'Governing Law',
        body: 'These Terms are governed by and construed in accordance with the laws of Ireland. Any disputes shall be subject to the exclusive jurisdiction of the courts of Ireland.',
      },
    ],
  },
  privacy: {
    title: 'Privacy Policy',
    lastUpdated: '22 February 2026',
    sections: [
      {
        heading: 'Information We Collect',
        body: 'We collect: (a) GitHub profile information (username, email, avatar) when you authenticate; (b) domain and API configuration data you provide during onboarding; (c) HTTP request metadata (headers, paths, query parameters) that flows through the Veil proxy; (d) usage analytics and session data.',
      },
      {
        heading: 'How We Use Your Information',
        body: 'We use your information to: (a) provide and operate the Service; (b) classify and analyse API traffic for security threats; (c) train and improve our AI classification models; (d) communicate with you about the Service; (e) comply with legal obligations.',
      },
      {
        heading: 'Data Storage & Security',
        body: 'Your data is stored in PostgreSQL databases hosted on secure cloud infrastructure. We use AES-GCM encryption for session tokens and TLS for all data in transit. We retain request logs for up to 30 days.',
      },
      {
        heading: 'Third-Party Services',
        body: 'We use the following third-party services: GitHub (OAuth authentication), AWS Bedrock / Anthropic Claude (AI classification), Railway (hosting infrastructure). Each has its own privacy policy governing your data.',
      },
      {
        heading: 'Data Sharing',
        body: 'We do not sell your personal data. We may share data with: (a) service providers who assist in operating the Service; (b) law enforcement when required by law; (c) other parties with your explicit consent.',
      },
      {
        heading: 'Your Rights',
        body: 'Under GDPR, you have the right to: access your personal data; rectify inaccurate data; erase your data; restrict processing; data portability; and object to processing. To exercise these rights, contact us via our GitHub repository.',
      },
      {
        heading: 'Cookies & Sessions',
        body: 'We use secure, HTTP-only session cookies to maintain your authenticated session. We do not use tracking cookies or third-party advertising cookies.',
      },
      {
        heading: 'Changes to This Policy',
        body: 'We may update this Privacy Policy from time to time. We will notify you of material changes by posting the updated policy on the Service.',
      },
    ],
  },
  security: {
    title: 'Security',
    lastUpdated: '22 February 2026',
    sections: [
      {
        heading: 'Architecture Overview',
        body: 'Veil operates as a reverse proxy between your clients and your upstream API. All traffic is routed through our infrastructure via DNS (CNAME records), where it is inspected, classified, and forwarded. Requests are forwarded immediately with zero added latency -- classification happens asynchronously.',
      },
      {
        heading: 'Encryption',
        body: 'All traffic between clients and Veil is encrypted with TLS, provisioned automatically via Caddy on-demand certificates. Session tokens use AES-GCM authenticated encryption. Secrets and API keys are stored as environment variables, never in source code.',
      },
      {
        heading: 'Authentication',
        body: 'User authentication is handled via GitHub OAuth 2.0 with secure, HTTP-only, SameSite cookies. Session secrets are rotated periodically. There is no password storage.',
      },
      {
        heading: 'AI Classification',
        body: 'Inbound requests are classified using a layered approach: fast regex-based pattern matching for known attacks, followed by LLM-powered analysis (Claude) for novel or ambiguous payloads. Classification results are stored for audit and agent learning.',
      },
      {
        heading: 'Agent Security',
        body: 'Our autonomous agents (Peek, Poke, Patch) operate in sandboxed environments. The red-team agent (Poke) only targets your own protected endpoints -- never third-party systems. All agent actions are logged and auditable.',
      },
      {
        heading: 'Infrastructure',
        body: 'The Service is hosted on Railway with isolated containers. The Go backend enforces SSRF protections, host-header validation, and rate limiting. Database access is restricted to internal service connections only.',
      },
      {
        heading: 'Vulnerability Disclosure',
        body: 'If you discover a security vulnerability in Veil, please report it responsibly via our GitHub repository. We aim to acknowledge reports within 48 hours and provide a fix or mitigation within 7 days.',
      },
      {
        heading: 'Compliance',
        body: 'Veil is designed with GDPR compliance in mind. We minimise data collection, provide data export capabilities, and respect user deletion requests. As a hackathon prototype, we are working towards full compliance certifications.',
      },
    ],
  },
}

export function LegalPage({ type = 'terms' }) {
  const page = LEGAL_PAGES[type]
  if (!page) return null

  return (
    <div className="min-h-screen bg-bg text-text">
      <div className="mx-auto max-w-3xl px-6 py-16 md:px-8">
        {/* Back link */}
        <a
          href="/"
          className="inline-flex items-center gap-2 text-[15px] text-dim transition-colors hover:text-text"
        >
          <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
            <path d="M10 13l-5-5 5-5" />
          </svg>
          Back to home
        </a>

        {/* Header */}
        <div className="mt-8 border-b border-border pb-8">
          <h1 className="text-[36px] font-semibold tracking-tight">{page.title}</h1>
          <p className="mt-3 text-[16px] text-dim">
            Last updated: {page.lastUpdated}
          </p>
        </div>

        {/* Sections */}
        <div className="mt-10 space-y-10">
          {page.sections.map((section, i) => (
            <div key={i}>
              <h2 className="text-[20px] font-semibold text-text">
                {i + 1}. {section.heading}
              </h2>
              <p className="mt-3 text-[16px] leading-relaxed text-dim">
                {section.body}
              </p>
            </div>
          ))}
        </div>

        {/* Footer */}
        <div className="mt-16 border-t border-border pt-8">
          <p className="text-[14px] text-muted">
            Veil -- Built for Hack Europe 2026, Dublin.
          </p>
          <div className="mt-3 flex gap-6 text-[14px]">
            {type !== 'terms' && (
              <a href="/terms" className="text-dim transition-colors hover:text-text">Terms & Conditions</a>
            )}
            {type !== 'privacy' && (
              <a href="/privacy" className="text-dim transition-colors hover:text-text">Privacy Policy</a>
            )}
            {type !== 'security' && (
              <a href="/security" className="text-dim transition-colors hover:text-text">Security</a>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
