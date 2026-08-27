import React, { useState } from 'react';

const UrlScanner = ({ onSubmit, isLoading = false }) => {
    const [url, setUrl] = useState('');
    const [error, setError] = useState('');

    const validateUrl = (input) => {
        const trimmed = input.trim();
        if (!trimmed) {
            return 'Please enter a URL to scan.';
        }
        try {
            const urlToTest = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
            new URL(urlToTest);
            return '';
        } catch (err) {
            return 'Please enter a valid website link (e.g., example.com or https://example.com).';
        }
    };

    const handleSubmit = (e) => {
        e.preventDefault();
        const validationError = validateUrl(url);

        if (validationError) {
            setError(validationError);
            return;
        }

        setError('');
        const formattedUrl = /^https?:\/\//i.test(url.trim()) ? url.trim() : `https://${url.trim()}`;
        onSubmit(formattedUrl);
    };

    const handleInputChange = (e) => {
        setUrl(e.target.value);
        if (error) {
            setError('');
        }
    };

    return (
        <div className="lg:col-span-12 flex flex-col pt-8 w-full">
            <h2 className="font-headline-xl text-[40px] md:text-headline-xl text-white/95 mb-4 tracking-tighter">Target Analysis</h2>
            <p className="text-white/50 font-body-md text-lg max-w-2xl font-light mb-8">
                Initiate deep-scan forensic analysis on external domains. Our engine detects hidden payloads, malicious routing, and phishing attempts in real-time.
            </p>
            
            <div className="flex justify-center w-full">
                <div className="glass-panel subtle-border-gradient rounded-3xl p-1 md:p-1.5 relative overflow-hidden group w-full">
                    {/* Inner Container to hold content away from gradient border */}
                    <div className="bg-[#13151f]/80 rounded-[22px] p-6 md:p-10 relative overflow-hidden h-full backdrop-blur-3xl">
                        {isLoading && <div className="scan-line" style={{ opacity: 1 }}></div>}
                        
                        <div className="space-y-6">
                            <div className="flex items-center gap-3">
                                <span className="material-symbols-outlined text-accent-purple text-[20px]">radar</span>
                                <label className="text-[12px] font-semibold text-white/60 uppercase tracking-[0.15em]" htmlFor="url-input">
                                    Target URL / IP
                                </label>
                            </div>
                            
                            <form onSubmit={handleSubmit} noValidate>
                                <div className={`relative flex items-center input-glow transition-all duration-500 rounded-2xl bg-black/20 border ${error ? 'border-error/40' : 'border-white/[0.08]'}`}>
                                    <div className="absolute left-6 text-white/30 flex items-center pointer-events-none">
                                        <span className="material-symbols-outlined">link</span>
                                    </div>
                                    <input
                                        autoComplete="off"
                                        className="w-full bg-transparent border-none focus:ring-0 text-white/90 text-[15px] font-light pl-16 pr-32 md:pr-44 py-5 rounded-2xl focus:outline-none placeholder:text-white/20 font-mono-data"
                                        id="url-input"
                                        placeholder="https://example.com/suspect-payload"
                                        type="text"
                                        value={url}
                                        onChange={handleInputChange}
                                        disabled={isLoading}
                                    />
                                    <button
                                        disabled={isLoading}
                                        type="submit"
                                        className="absolute right-2 top-2 bottom-2 bg-gradient-to-r from-accent-purple/80 to-[#c892ff]/80 text-white px-4 md:px-8 rounded-xl font-medium shadow-[0_0_20px_rgba(138,99,245,0.2)] hover:shadow-[0_0_30px_rgba(138,99,245,0.4)] hover:brightness-110 flex items-center justify-center gap-2 transition-all duration-300 disabled:opacity-50 disabled:pointer-events-none min-w-[100px] md:min-w-[120px]"
                                    >
                                        {isLoading ? 'Scanning...' : 'Scan'}
                                    </button>
                                </div>
                                {error && (
                                    <div className="text-error text-sm mt-3 px-4 flex items-center gap-2 font-mono-data">
                                        <span className="material-symbols-outlined text-[16px]">error</span>
                                        {error}
                                    </div>
                                )}
                            </form>
                            
                            <div className="flex flex-col sm:flex-row sm:items-center gap-4 text-[13px] text-white/40 font-light pt-2">
                                <div className="flex items-center gap-1.5">
                                    <span className="material-symbols-outlined text-[16px] text-secondary-fixed-dim/70">check_circle</span>
                                    <span>Engine Ready</span>
                                </div>
                                <span className="hidden sm:block w-1 h-1 rounded-full bg-white/10"></span>
                                <span>Press Enter to initiate</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default UrlScanner;