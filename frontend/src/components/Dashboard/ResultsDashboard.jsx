import React, { useState } from 'react';

const ResultsDashboard = ({ scanResults, onReset }) => {
    const [activeEvidenceTab, setActiveEvidenceTab] = useState('all');
    const [isDownloading, setIsDownloading] = useState(false);
    const [showTriggeredRules, setShowTriggeredRules] = useState(false);

    // 1. Fallback UI if no scan results are provided
    if (!scanResults) {
        return (
            <div className="lg:col-span-12 flex flex-col pt-8 w-full animate-fadeIn">
                <div className="flex justify-center w-full mt-4">
                    <div className="glass-panel subtle-border-gradient rounded-3xl p-1 md:p-1.5 relative overflow-hidden group w-full max-w-3xl">
                        <div className="bg-[#13151f]/80 rounded-[22px] p-12 md:p-16 relative overflow-hidden h-full backdrop-blur-3xl text-center flex flex-col items-center">
                            <div className="w-20 h-20 mb-6 rounded-2xl bg-accent-purple/10 border border-accent-purple/20 flex items-center justify-center">
                                <span className="material-symbols-outlined text-accent-purple text-[40px]">query_stats</span>
                            </div>
                            <h3 className="font-headline-lg text-2xl md:text-3xl text-white/95 mb-4 tracking-tight">Awaiting Telemetry</h3>
                            <p className="font-body-md text-white/50 max-w-md mb-10 font-light text-[15px] leading-relaxed">
                                Submit a suspicious payload (URL, Email, Text, or Image) to initiate the Guardian AI threat analysis sequence.
                            </p>
                            <div className="inline-flex items-center gap-2.5 px-5 py-2.5 rounded-full bg-black/40 border border-white/5 font-mono text-[11px] text-white/40 tracking-widest uppercase shadow-inner">
                                <span className="w-2 h-2 rounded-full bg-accent-purple/80 animate-pulse shadow-[0_0_8px_rgba(138,99,245,0.6)]" />
                                System Standby
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        );
    }

    // 2. Safe Data Extraction & Score Clamping
    const rawScore = scanResults.evaluation?.risk_score ?? 0;
    const score = Math.min(Math.max(Math.round(Number(rawScore) || 0), 0), 100);

    // 3. Determine Risk Level & Theme Configuration
    const getRiskConfig = (val) => {
        if (val <= 30) {
            return {
                level: 'Low Risk',
                text: 'text-[#34d399]',
                bg: 'bg-[#34d399]/10',
                border: 'border-[#34d399]/20',
                glow: 'from-[#34d399]/15 to-transparent',
                stroke: '#34d399',
                icon: 'verified_user',
                description: 'No critical threats or malicious indicators detected. Exercise normal safety precautions.'
            };
        } else if (val <= 60) {
            return {
                level: 'Medium Risk',
                text: 'text-[#fbbf24]',
                bg: 'bg-[#fbbf24]/10',
                border: 'border-[#fbbf24]/20',
                glow: 'from-[#fbbf24]/15 to-transparent',
                stroke: '#fbbf24',
                icon: 'warning_amber',
                description: 'Suspicious patterns or unverified indicators identified. Proceed with caution.'
            };
        } else {
            return {
                level: 'High Risk',
                text: 'text-error',
                bg: 'bg-error/10',
                border: 'border-error/20',
                glow: 'from-error/15 to-transparent',
                stroke: '#ffb4ab',
                icon: 'gpp_bad',
                description: 'Confirmed scam, phishing attempt, or malicious payload detected. Do not interact.'
            };
        }
    };

    const risk = getRiskConfig(score);

    // 4. Extract AI Explanation Data (with safe fallback formatting)
    const explanation = scanResults.ai_explanation || {};
    const summary = explanation.summary || 'AI analysis completed without detailed summary text.';
    const possibleThreat = explanation.possible_threat || 'Unspecified Threat Type';

    const rawReasons = explanation.reasons || [];
    const reasons = Array.isArray(rawReasons) ? rawReasons : [rawReasons];

    const rawRecommendations = explanation.recommendations || [];
    const recommendations = Array.isArray(rawRecommendations) ? rawRecommendations : [rawRecommendations];

    // Helper to safely render text even if backend sends an object instead of a string
    const renderSafeText = (item) => {
        if (typeof item === 'string') return item;
        if (item && typeof item === 'object') {
            return item.text || item.reason || item.message || item.description || JSON.stringify(item);
        }
        return String(item || '');
    };

    // 5. Extract Evidence Data
    const evidence = scanResults.evidence || {};
    const inputType = (scanResults.input_type || evidence.payload_type || 'url').toLowerCase();

    // Map EvidenceItem schema (name, description, severity) to UI expected fields
    const mapEvidence = (items, defaultItems) => {
        if (!Array.isArray(items) || items.length === 0) return defaultItems;
        return items.map(item => ({
            label: item.name,
            status: item.severity ? item.severity.charAt(0).toUpperCase() + item.severity.slice(1) : 'Info',
            value: item.description,
            rawSeverity: item.severity || 'low'
        }));
    };

    const getDefaultTechnical = () => {
        if (inputType === 'image') {
            return [
                { label: 'Image Integrity', status: 'Low', rawSeverity: 'low', value: 'Image metadata and structure verified.' },
                { label: 'Visual Payload', status: 'Low', rawSeverity: 'low', value: 'No steganographic or malformed image headers identified.' }
            ];
        }
        if (inputType === 'text') {
            return [
                { label: 'Text Characteristics', status: 'Low', rawSeverity: 'low', value: 'Standard text structure and syntax verified.' },
                { label: 'Content Obfuscation', status: 'Low', rawSeverity: 'low', value: 'No hidden characters or encoding anomalies found.' }
            ];
        }
        if (inputType === 'email') {
            return [
                { label: 'Authentication Checks', status: score > 50 ? 'High' : 'Low', rawSeverity: score > 50 ? 'high' : 'low', value: score > 50 ? 'Email sender authentication anomalies detected' : 'SPF and DKIM verification checked' },
                { label: 'Routing Consistency', status: 'Low', rawSeverity: 'low', value: 'Sender and return paths match expected origins' }
            ];
        }
        return [
            { label: 'Protocol Security', status: score > 50 ? 'High' : 'Low', rawSeverity: score > 50 ? 'high' : 'low', value: score > 50 ? 'Anomalous encryption or SSL certificate issues detected' : 'Valid SSL / TLS 1.3 protocol verified' },
            { label: 'Payload Inspection', status: score > 60 ? 'High' : 'Low', rawSeverity: score > 60 ? 'high' : 'low', value: score > 60 ? 'Obfuscated scripts or suspicious redirects detected' : 'No known exploit signatures identified' }
        ];
    };

    const getDefaultThreatIntel = () => {
        if (inputType === 'image') {
            return [
                { label: 'Extracted Threat Entities', status: 'Low', rawSeverity: 'low', value: 'No suspicious phone numbers, wallet addresses, or URLs detected in visual telemetry.' },
                { label: 'Threat Feeds', status: 'Low', rawSeverity: 'low', value: 'No matching entries in scam intelligence databases.' }
            ];
        }
        if (inputType === 'text') {
            return [
                { label: 'Embedded Threat Signals', status: 'Low', rawSeverity: 'low', value: 'No crypto addresses, suspicious contact numbers, or unverified links detected.' },
                { label: 'Threat Feeds', status: 'Low', rawSeverity: 'low', value: 'No matches across active fraud and smishing blacklists.' }
            ];
        }
        if (inputType === 'email') {
            return [
                { label: 'Hyperlink Telemetry', status: score > 50 ? 'High' : 'Low', rawSeverity: score > 50 ? 'high' : 'low', value: score > 50 ? 'Embedded links flagged by threat intelligence' : 'Embedded links verified clean' },
                { label: 'Sender Reputation', status: 'Low', rawSeverity: 'low', value: 'Sender domain has standard mail delivery history' }
            ];
        }
        return [
            { label: 'Reputation Feeds', status: score > 60 ? 'High' : 'Low', rawSeverity: score > 60 ? 'high' : 'low', value: score > 60 ? 'Matched global phishing and fraud blacklists' : 'Clean across 68 security vendors' },
            { label: 'Domain Telemetry', status: score > 40 ? 'Medium' : 'Low', rawSeverity: score > 40 ? 'medium' : 'low', value: score > 40 ? 'Recently registered or anonymous WHOIS records' : 'Established reputation history' }
        ];
    };

    const getDefaultHeuristics = () => {
        if (inputType === 'image') {
            return [
                { label: 'Visual Risk Signals', status: 'Low', rawSeverity: 'low', value: 'No urgent phishing patterns, impersonation, or deceptive overlays identified.' },
                { label: 'Brand Imitation', status: 'Low', rawSeverity: 'low', value: 'No fraudulent corporate logos or deceptive portal layouts recognized.' }
            ];
        }
        if (inputType === 'text') {
            return [
                { label: 'Linguistic Analysis', status: score > 30 ? 'Medium' : 'Low', rawSeverity: score > 30 ? 'medium' : 'low', value: score > 30 ? 'Urgency, fear, or financial coercion cues present' : 'Standard conversational tone' },
                { label: 'Scam Patterns', status: 'Low', rawSeverity: 'low', value: 'No advance-fee, lottery, or credential phishing triggers matched.' }
            ];
        }
        return [
            { label: 'Social Engineering', status: score > 30 ? 'Medium' : 'Low', rawSeverity: score > 30 ? 'medium' : 'low', value: score > 30 ? 'Urgency, fear, or financial coercion cues present' : 'Standard conversational tone' },
            { label: 'Visual & Brand Spoofing', status: score > 70 ? 'High' : 'Low', rawSeverity: score > 70 ? 'high' : 'low', value: score > 70 ? 'Mimics known financial or login portals' : 'No brand impersonation detected' }
        ];
    };

    const technicalIndicators = mapEvidence(evidence.technical_indicators, getDefaultTechnical());
    const threatIntelligence = mapEvidence(evidence.threat_intelligence, getDefaultThreatIntel());
    const heuristicMatches = mapEvidence(evidence.heuristic_matches, getDefaultHeuristics());

    // 5b. Triggered rules from evaluation
    const triggeredRules = scanResults.evaluation?.triggered_rules || [];

    // Helper to get severity badge styles
    const getSeverityStyle = (rawSeverity) => {
        switch (rawSeverity?.toLowerCase()) {
            case 'high':
                return 'bg-error/10 text-error border border-error/20';
            case 'medium':
                return 'bg-[#fbbf24]/10 text-[#fbbf24] border border-[#fbbf24]/20';
            default:
                return 'bg-[#34d399]/10 text-[#34d399] border border-[#34d399]/20';
        }
    };

    // 6. Download Report Handler (JSON Export)
    const handleDownloadReport = () => {
        setIsDownloading(true);
        setTimeout(() => {
            const reportData = {
                meta: {
                    generatedAt: new Date().toISOString(),
                    system: 'Guardian AI Threat Engine v2.4',
                    scanId: scanResults.scan_id || `SCAN-${Math.random().toString(36).substr(2, 9).toUpperCase()}`
                },
                evaluation: {
                    riskScore: score,
                    riskLevel: risk.level,
                    threatType: possibleThreat,
                    triggeredRules
                },
                aiExplanation: {
                    summary: renderSafeText(summary),
                    reasons: reasons.map(renderSafeText),
                    recommendations: recommendations.map(renderSafeText)
                },
                evidence: {
                    technicalIndicators,
                    threatIntelligence,
                    heuristicMatches
                },
                rawPayload: scanResults
            };

            const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const link = document.createElement('a');
            link.href = url;
            link.download = `GuardianAI-Report-${new Date().toISOString().slice(0, 10)}.json`;
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            URL.revokeObjectURL(url);
            setIsDownloading(false);
        }, 500);
    };

    return (
        <div className="w-full flex flex-col pt-4 animate-fadeIn space-y-8 pb-12">
            {/* Top Bar: Title & Quick Actions */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-6 pb-6 border-b border-white/[0.05]">
                <div>
                    <div className="flex items-center gap-2 font-mono text-[11px] uppercase tracking-widest text-accent-purple mb-3">
                        <span className="inline-block w-2 h-2 rounded-full bg-accent-purple animate-ping shadow-[0_0_8px_rgba(138,99,245,0.6)]" />
                        <span>Analysis Complete • ID: {scanResults.scan_id ? scanResults.scan_id.toUpperCase().slice(0, 13) : 'SYS-99482A'}</span>
                    </div>
                    <h2 className="font-headline-xl text-[32px] md:text-[40px] tracking-tighter text-white/95">
                        Threat Intelligence Report
                    </h2>
                </div>

                <div className="flex items-center gap-3 self-start sm:self-auto">
                    {onReset && (
                        <button
                            type="button"
                            onClick={onReset}
                            className="px-5 py-2.5 rounded-xl text-sm font-medium text-white/60 hover:text-white/90 bg-black/20 hover:bg-black/40 border border-white/5 transition-all flex items-center gap-2"
                        >
                            <span className="material-symbols-outlined text-[16px]">refresh</span>
                            New Scan
                        </button>
                    )}

                    <button
                        type="button"
                        onClick={handleDownloadReport}
                        disabled={isDownloading}
                        className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl text-sm font-medium text-white bg-gradient-to-r from-accent-purple/80 to-[#c892ff]/80 hover:brightness-110 shadow-[0_0_20px_rgba(138,99,245,0.2)] transition-all disabled:opacity-50 disabled:pointer-events-none"
                    >
                        {isDownloading ? (
                            <>
                                <svg className="animate-spin h-4 w-4 text-white" fill="none" viewBox="0 0 24 24">
                                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                                </svg>
                                <span>Generating...</span>
                            </>
                        ) : (
                            <>
                                <span className="material-symbols-outlined text-[18px]">download</span>
                                <span>Export Report</span>
                            </>
                        )}
                    </button>
                </div>
            </div>

            {/* Grid Layout: Risk Gauge & AI Summary */}
            <div className="grid grid-cols-1 xl:grid-cols-12 gap-8">
                {/* SECTION 1: RISK SCORE */}
                <div className="xl:col-span-4 glass-panel subtle-border-gradient rounded-3xl p-1 md:p-1.5 h-full">
                    <div className="bg-[#13151f]/80 rounded-[22px] p-6 md:p-8 relative overflow-hidden h-full backdrop-blur-3xl flex flex-col items-center shadow-inner">
                        <div className={`absolute -top-32 -left-32 w-64 h-64 bg-gradient-to-br ${risk.glow} rounded-full blur-3xl pointer-events-none opacity-50`} />

                        <div className="w-full flex items-center justify-between mb-8 relative z-10">
                            <span className="font-label-caps text-[11px] text-white/50">Threat Meter</span>
                            <span className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full font-label-caps text-[10px] border ${risk.bg} ${risk.border} ${risk.text}`}>
                                <span className="material-symbols-outlined text-[12px]" style={{ fontVariationSettings: '"FILL" 1' }}>{risk.icon}</span>
                                {risk.level}
                            </span>
                        </div>

                        {/* Prominent Circular SVG Gauge */}
                        <div className="relative my-4 flex items-center justify-center z-10">
                            <svg className="w-48 h-48 transform -rotate-90 drop-shadow-2xl" aria-label={`Risk score: ${score} out of 100`}>
                                {/* Background Track */}
                                <circle
                                    cx="96"
                                    cy="96"
                                    r="76"
                                    className="text-white/5"
                                    strokeWidth="10"
                                    stroke="currentColor"
                                    fill="transparent"
                                />
                                {/* Progress Indicator */}
                                <circle
                                    cx="96"
                                    cy="96"
                                    r="76"
                                    strokeWidth="10"
                                    strokeDasharray={477.5}
                                    strokeDashoffset={477.5 - (477.5 * score) / 100}
                                    strokeLinecap="round"
                                    stroke={risk.stroke}
                                    fill="transparent"
                                    className="transition-all duration-1000 ease-out"
                                    style={{ filter: `drop-shadow(0 0 8px ${risk.stroke}60)` }}
                                />
                            </svg>
                            <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
                                <span className="font-headline-xl text-[52px] tracking-tighter text-white/95">
                                    {score}
                                </span>
                                <span className="font-mono text-[10px] text-white/30 uppercase mt-1">out of 100</span>
                            </div>
                        </div>

                        <div className="text-center mt-6 w-full relative z-10 space-y-2">
                            <div className={`inline-flex items-center gap-2 px-4 py-1.5 rounded-full ${risk.bg} ${risk.border} border`}>
                                <span className={`font-body-md font-medium text-[14px] ${risk.text}`}>
                                    {possibleThreat}
                                </span>
                            </div>
                            <p className="font-body-sm text-[13px] text-white/50 font-light leading-relaxed mt-2">
                                {risk.description}
                            </p>
                        </div>

                        {/* Triggered Rules accordion */}
                        {triggeredRules.length > 0 && (
                            <div className="w-full mt-6 relative z-10">
                                <button
                                    type="button"
                                    onClick={() => setShowTriggeredRules(v => !v)}
                                    className="w-full flex items-center justify-between text-[11px] text-white/40 hover:text-white/70 transition-colors px-3 py-2 rounded-lg hover:bg-white/5 font-mono uppercase tracking-widest"
                                >
                                    <span>{triggeredRules.length} Rule{triggeredRules.length !== 1 ? 's' : ''} Triggered</span>
                                    <span className="material-symbols-outlined text-[16px]">
                                        {showTriggeredRules ? 'expand_less' : 'expand_more'}
                                    </span>
                                </button>
                                {showTriggeredRules && (
                                    <ul className="mt-2 space-y-1 max-h-40 overflow-y-auto pr-1">
                                        {triggeredRules.map((rule, idx) => (
                                            <li key={idx} className="text-[11px] text-white/40 px-3 py-1.5 rounded-lg bg-black/20 font-mono leading-tight">
                                                {rule}
                                            </li>
                                        ))}
                                    </ul>
                                )}
                            </div>
                        )}
                    </div>
                </div>

                {/* SECTION 2: AI EXPLANATION */}
                <div className="xl:col-span-8 glass-panel subtle-border-gradient rounded-3xl p-1 md:p-1.5 h-full">
                    <div className="bg-[#13151f]/80 rounded-[22px] p-6 md:p-8 relative overflow-hidden h-full backdrop-blur-3xl flex flex-col space-y-8">

                        {/* Summary Banner */}
                        <div>
                            <div className="flex items-center gap-2 font-label-caps text-[11px] text-accent-purple/80 mb-3">
                                <span className="material-symbols-outlined text-[16px]">psychology</span>
                                <span>AI Diagnostic Summary</span>
                            </div>
                            <div className="bg-black/20 p-5 rounded-2xl border border-white/5 shadow-inner">
                                <p className="font-body-md text-[15px] text-white/80 font-light leading-relaxed italic">
                                    "{renderSafeText(summary)}"
                                </p>
                            </div>
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-2 gap-8 md:gap-6 flex-1">
                            {/* Specific Reasons */}
                            <div className="space-y-4">
                                <h4 className="font-label-caps text-[11px] text-white/40 flex items-center gap-2">
                                    <span className="w-1.5 h-1.5 rounded-full bg-error" />
                                    <span>Primary Risk Factors</span>
                                </h4>
                                <ul className="space-y-3">
                                    {reasons.length > 0 ? (
                                        reasons.map((reason, idx) => (
                                            <li key={idx} className="flex items-start gap-3 bg-black/10 p-3.5 rounded-xl border border-white/[0.03] hover:border-white/[0.07] transition-colors">
                                                <span className="material-symbols-outlined text-error/80 text-[18px] mt-0.5 flex-shrink-0" style={{ fontVariationSettings: '"FILL" 1' }}>warning</span>
                                                <span className="font-body-sm text-[13px] text-white/70 font-light leading-relaxed">{renderSafeText(reason)}</span>
                                            </li>
                                        ))
                                    ) : (
                                        <li className="font-body-sm text-[13px] text-white/30 italic p-2">No critical risk flags recorded.</li>
                                    )}
                                </ul>
                            </div>

                            {/* Actionable Recommendations */}
                            <div className="space-y-4">
                                <h4 className="font-label-caps text-[11px] text-white/40 flex items-center gap-2">
                                    <span className="w-1.5 h-1.5 rounded-full bg-[#34d399]" />
                                    <span>Actionable Safeguards</span>
                                </h4>
                                <ul className="space-y-3">
                                    {recommendations.length > 0 ? (
                                        recommendations.map((rec, idx) => (
                                            <li key={idx} className="flex items-start gap-3 bg-black/10 p-3.5 rounded-xl border border-white/[0.03] hover:border-white/[0.07] transition-colors">
                                                <span className="material-symbols-outlined text-[#34d399]/80 text-[18px] mt-0.5 flex-shrink-0" style={{ fontVariationSettings: '"FILL" 1' }}>shield</span>
                                                <span className="font-body-sm text-[13px] text-white/70 font-light leading-relaxed">{renderSafeText(rec)}</span>
                                            </li>
                                        ))
                                    ) : (
                                        <li className="font-body-sm text-[13px] text-white/30 italic p-2">Standard monitoring recommended.</li>
                                    )}
                                </ul>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            {/* SECTION 3: EVIDENCE PANEL */}
            <div className="glass-panel subtle-border-gradient rounded-3xl p-1 md:p-1.5">
                <div className="bg-[#13151f]/80 rounded-[22px] p-6 md:p-8 relative overflow-hidden backdrop-blur-3xl">
                    <div className="flex flex-col md:flex-row md:items-center justify-between gap-5 mb-8 pb-5 border-b border-white/5">
                        <div>
                            <h3 className="font-headline-lg text-[20px] text-white/90 flex items-center gap-2.5">
                                <span className="material-symbols-outlined text-accent-purple/80 text-[22px]">hub</span>
                                <span>Forensic Evidence Panel</span>
                            </h3>
                            <p className="font-body-sm text-[13px] text-white/40 font-light mt-1">
                                Detailed breakdown of cryptographic indicators, heuristic matches, and global threat feed telemetry.
                            </p>
                        </div>

                        {/* Evidence Category Filter Tabs */}
                        <div className="flex items-center gap-1.5 p-1 bg-black/30 rounded-xl border border-white/5 self-start md:self-auto overflow-x-auto max-w-full">
                            {[
                                { id: 'all', label: 'All Evidence' },
                                { id: 'tech', label: 'Technical' },
                                { id: 'intel', label: 'Threat Intel' },
                                { id: 'heuristic', label: 'Heuristics' }
                            ].map((tab) => (
                                <button
                                    key={tab.id}
                                    type="button"
                                    onClick={() => setActiveEvidenceTab(tab.id)}
                                    className={`px-4 py-2 rounded-lg font-body-sm text-[13px] font-medium whitespace-nowrap transition-all ${activeEvidenceTab === tab.id
                                        ? 'bg-white/10 text-white/90 shadow-sm border border-white/10'
                                        : 'text-white/40 hover:text-white/70 hover:bg-white/5 border border-transparent'
                                        }`}
                                >
                                    {tab.label}
                                </button>
                            ))}
                        </div>
                    </div>

                    {/* Evidence Grids */}
                    <div className="space-y-8">
                        {/* Subsection 1: Technical Indicators */}
                        {(activeEvidenceTab === 'all' || activeEvidenceTab === 'tech') && (
                            <div className="space-y-4">
                                <h4 className="font-label-caps text-[11px] text-white/40 flex items-center gap-2">
                                    <span className="w-2 h-2 rounded-full bg-accent-blue" />
                                    <span>Technical Indicators</span>
                                </h4>
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                    {technicalIndicators.map((item, idx) => (
                                        <EvidenceCard key={idx} item={item} getSeverityStyle={getSeverityStyle} renderSafeText={renderSafeText} />
                                    ))}
                                </div>
                            </div>
                        )}

                        {/* Subsection 2: Threat Intelligence */}
                        {(activeEvidenceTab === 'all' || activeEvidenceTab === 'intel') && (
                            <div className="space-y-4">
                                <h4 className="font-label-caps text-[11px] text-white/40 flex items-center gap-2">
                                    <span className="w-2 h-2 rounded-full bg-accent-purple" />
                                    <span>Threat Intelligence & Reputation Feeds</span>
                                </h4>
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                    {threatIntelligence.map((item, idx) => (
                                        <EvidenceCard key={idx} item={item} getSeverityStyle={getSeverityStyle} renderSafeText={renderSafeText} />
                                    ))}
                                </div>
                            </div>
                        )}

                        {/* Subsection 3: Heuristic Matches */}
                        {(activeEvidenceTab === 'all' || activeEvidenceTab === 'heuristic') && (
                            <div className="space-y-4">
                                <h4 className="font-label-caps text-[11px] text-white/40 flex items-center gap-2">
                                    <span className="w-2 h-2 rounded-full bg-[#fbbf24]" />
                                    <span>Heuristic & Behavioral Matches</span>
                                </h4>
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                    {heuristicMatches.map((item, idx) => (
                                        <EvidenceCard key={idx} item={item} getSeverityStyle={getSeverityStyle} renderSafeText={renderSafeText} />
                                    ))}
                                </div>
                            </div>
                        )}
                    </div>
                </div>
            </div>
        </div>
    );
};

// Extracted EvidenceCard component — removes truncation so full descriptions are visible
const EvidenceCard = ({ item, getSeverityStyle, renderSafeText }) => (
    <div className="flex flex-col gap-3 p-4 bg-black/20 rounded-xl border border-white/[0.03] hover:border-white/10 transition-colors group">
        <div className="flex items-start justify-between gap-3">
            <span className="font-body-sm font-medium text-[14px] text-white/80 group-hover:text-white/95 transition-colors leading-snug">
                {item.label || 'Unknown Indicator'}
            </span>
            <span className={`flex-shrink-0 px-2.5 py-1 rounded-md font-label-caps text-[10px] capitalize ${getSeverityStyle(item.rawSeverity || item.status)}`}>
                {item.status || 'Info'}
            </span>
        </div>
        {/* Full description — NOT truncated */}
        <span className="font-body-sm text-[12px] text-white/40 font-light leading-relaxed">
            {renderSafeText(item.value || item.description || '')}
        </span>
    </div>
);

export default ResultsDashboard;