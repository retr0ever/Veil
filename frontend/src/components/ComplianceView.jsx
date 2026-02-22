import { useState, useEffect } from 'react'
import { relativeTime } from '../lib/humanise'

export function ComplianceView() {
    const [report, setReport] = useState(null)
    const [distribution, setDistribution] = useState([])
    const [loading, setLoading] = useState(true)

    useEffect(() => {
        const load = async () => {
            try {
                const [reportRes, distRes] = await Promise.all([
                    fetch('/api/compliance/report'),
                    fetch('/api/analytics/threat-distribution')
                ])
                if (reportRes.ok) setReport(await reportRes.json())
                if (distRes.ok) setDistribution(await distRes.json())
            } catch (err) {
                console.error('Failed to load analytics', err)
            } finally {
                setLoading(false)
            }
        }
        load()
    }, [])

    const downloadReport = () => {
        if (!report) return
        const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' })
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = `veil-compliance-report-${new Date().toISOString().slice(0, 10)}.json`
        a.click()
    }

    if (loading) return <div className="p-8 text-center text-dim">Generating intelligence report...</div>

    return (
        <div className="p-6 space-y-6">
            {/* Header */}
            <div className="flex items-center justify-between">
                <div>
                    <h2 className="text-[18px] font-semibold text-white">Compliance & Analytics</h2>
                    <p className="text-[13px] text-dim">Autonomous security posture auditing and threat intelligence.</p>
                </div>
                <button
                    onClick={downloadReport}
                    className="rounded-lg bg-agent px-4 py-2 text-[13px] font-medium text-white transition-opacity hover:opacity-90"
                >
                    Download JSON Report
                </button>
            </div>

            <div className="grid gap-6 md:grid-cols-2">
                {/* Posture Card */}
                <div className="rounded-xl border border-border bg-surface p-5">
                    <h3 className="text-[12px] font-medium uppercase tracking-wider text-muted mb-4">Security Posture</h3>
                    <div className="flex items-end gap-3">
                        <span className="text-4xl font-bold text-white">{report?.security_score}%</span>
                        <span className={`mb-1 px-2 py-0.5 rounded text-[10px] font-bold ${report?.compliance_status === 'HIGH' ? 'bg-safe/20 text-safe' : 'bg-suspicious/20 text-suspicious'
                            }`}>
                            {report?.compliance_status} COMPLIANCE
                        </span>
                    </div>
                    <p className="mt-4 text-[13px] text-dim leading-relaxed">
                        Veil has remediated {report?.summary?.vulnerabilities_remediated} out of {report?.summary?.total_threats_identified} identified vulnerabilities using automated patching.
                    </p>
                </div>

                {/* Threat Distribution */}
                <div className="rounded-xl border border-border bg-surface p-5">
                    <h3 className="text-[12px] font-medium uppercase tracking-wider text-muted mb-4">Threat Distribution (SIG Track)</h3>
                    <div className="space-y-3">
                        {distribution.length === 0 && <p className="text-[12px] text-muted">No data points available yet.</p>}
                        {distribution.map((d) => (
                            <div key={d.category} className="space-y-1">
                                <div className="flex justify-between text-[11px]">
                                    <span className="text-dim uppercase">{d.category}</span>
                                    <span className="text-white">{d.patched}/{d.total} Patched</span>
                                </div>
                                <div className="h-1.5 w-full bg-border rounded-full overflow-hidden flex">
                                    <div
                                        className="h-full bg-safe"
                                        style={{ width: `${(d.patched / Math.max(d.total, 1)) * 100}%` }}
                                    />
                                </div>
                            </div>
                        ))}
                    </div>
                </div>

                {/* Recent Hardening */}
                <div className="md:col-span-2 rounded-xl border border-border bg-surface p-5">
                    <h3 className="text-[12px] font-medium uppercase tracking-wider text-muted mb-4">Recent Autonomous Remediations</h3>
                    <div className="space-y-3">
                        {report?.recent_hardened_assets?.length === 0 && <p className="text-[12px] text-muted">No remediations logged in current session.</p>}
                        {report?.recent_hardened_assets?.map((p, i) => (
                            <div key={i} className="flex items-center justify-between py-2 border-b border-white/5 last:border-0 font-mono">
                                <div className="flex items-center gap-3">
                                    <div className="h-2 w-2 rounded-full bg-safe" />
                                    <span className="text-[13px] text-white">[{p.technique}]</span>
                                </div>
                                <span className="text-[11px] text-muted">{relativeTime(p.date)}</span>
                            </div>
                        ))}
                    </div>
                </div>
            </div>
        </div>
    )
}
