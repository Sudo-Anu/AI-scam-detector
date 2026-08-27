import React, { useState } from 'react';

const TextScanner = ({ onSubmit, isLoading = false }) => {
    const [text, setText] = useState('');
    const [error, setError] = useState('');

    const minChars = 10;
    const maxChars = 5000;

    const validateText = (input) => {
        const trimmed = input.trim();
        if (!trimmed) {
            return 'Please enter some suspicious text or message to scan.';
        }
        if (trimmed.length < minChars) {
            return `Please enter at least ${minChars} characters for accurate AI threat analysis.`;
        }
        if (trimmed.length > maxChars) {
            return `Text exceeds the maximum limit of ${maxChars} characters.`;
        }
        return '';
    };

    const handleSubmit = (e) => {
        e.preventDefault();
        const validationError = validateText(text);

        if (validationError) {
            setError(validationError);
            return;
        }

        setError('');
        onSubmit(text.trim());
    };

    const handleTextChange = (e) => {
        setText(e.target.value);
        if (error) {
            setError('');
        }
    };

    const handleClear = () => {
        if (isLoading) return;
        setText('');
        setError('');
    };

    const charCount = text.length;
    const wordCount = text.trim() ? text.trim().split(/\s+/).length : 0;

    return (
        <div className="lg:col-span-12 flex flex-col pt-8 w-full">
            <h2 className="font-headline-xl text-[40px] md:text-headline-xl text-white/95 mb-4 tracking-tighter">Text & SMS Scanner</h2>
            <p className="text-white/50 font-body-md text-lg max-w-2xl font-light mb-8">
                Paste any suspicious SMS message, social media DM, WhatsApp text, or raw email body to detect social engineering and scam linguistics.
            </p>
            
            <div className="flex justify-center w-full">
                <div className="glass-panel subtle-border-gradient rounded-3xl p-1 md:p-1.5 relative overflow-hidden group w-full">
                    <div className="bg-[#13151f]/80 rounded-[22px] p-6 md:p-10 relative overflow-hidden h-full backdrop-blur-3xl">
                        {isLoading && <div className="scan-line" style={{ opacity: 1 }}></div>}
                        
                        <div className="space-y-6">
                            <div className="flex items-center justify-between gap-3">
                                <div className="flex items-center gap-3">
                                    <span className="material-symbols-outlined text-accent-purple text-[20px]">notes</span>
                                    <label className="text-[12px] font-semibold text-white/60 uppercase tracking-[0.15em]" htmlFor="text-input">
                                        Suspicious Text
                                    </label>
                                </div>
                                {text.length > 0 && !isLoading && (
                                    <button
                                        type="button"
                                        onClick={handleClear}
                                        className="text-[12px] font-medium text-white/40 hover:text-error px-2 py-1 rounded-md hover:bg-black/30 transition-colors duration-150 flex items-center gap-1"
                                    >
                                        <span className="material-symbols-outlined text-[14px]">backspace</span>
                                        <span>Clear</span>
                                    </button>
                                )}
                            </div>
                            
                            <form onSubmit={handleSubmit} noValidate>
                                <div className={`relative flex flex-col input-glow transition-all duration-500 rounded-2xl bg-black/20 border ${error ? 'border-error/40' : 'border-white/[0.08]'}`}>
                                    <textarea
                                        value={text}
                                        onChange={handleTextChange}
                                        disabled={isLoading}
                                        rows={6}
                                        id="text-input"
                                        placeholder="Paste suspicious text or SMS message here (e.g., 'URGENT: Your account has been suspended. Click here immediately to verify your identity...')..."
                                        className="w-full bg-transparent border-none focus:ring-0 text-white/90 text-[15px] font-light p-6 rounded-2xl focus:outline-none placeholder:text-white/20 font-mono-data resize-y min-h-[140px] max-h-[350px]"
                                    />

                                    {/* Subtle floating character & word counter badge */}
                                    <div className="absolute bottom-4 right-4 px-3 py-1.5 rounded-lg bg-black/40 border border-white/[0.05] text-[11px] font-mono-data text-white/40 flex items-center gap-2 pointer-events-none select-none backdrop-blur-md">
                                        <span>{wordCount} {wordCount === 1 ? 'word' : 'words'}</span>
                                        <span className="text-white/20">|</span>
                                        <span className={charCount > maxChars ? 'text-error font-bold' : ''}>
                                            {charCount} / {maxChars}
                                        </span>
                                    </div>
                                </div>
                                
                                {error && (
                                    <div className="text-error text-sm mt-3 px-4 flex items-center gap-2 font-mono-data">
                                        <span className="material-symbols-outlined text-[16px]">error</span>
                                        {error}
                                    </div>
                                )}

                                <div className="mt-6">
                                    <button
                                        type="submit"
                                        disabled={isLoading || !text.trim()}
                                        className="w-full bg-gradient-to-r from-accent-purple/80 to-[#c892ff]/80 text-white py-4 rounded-xl font-medium shadow-[0_0_20px_rgba(138,99,245,0.2)] hover:shadow-[0_0_30px_rgba(138,99,245,0.4)] hover:brightness-110 flex items-center justify-center gap-2 transition-all duration-300 disabled:opacity-50 disabled:pointer-events-none"
                                    >
                                        {isLoading ? 'Scanning...' : 'Scan Text'}
                                    </button>
                                </div>
                            </form>
                            
                            <div className="flex flex-col sm:flex-row sm:items-center gap-4 text-[13px] text-white/40 font-light pt-2">
                                <div className="flex items-center gap-1.5">
                                    <span className="material-symbols-outlined text-[16px] text-secondary-fixed-dim/70">check_circle</span>
                                    <span>Engine Ready</span>
                                </div>
                                <span className="hidden sm:block w-1 h-1 rounded-full bg-white/10"></span>
                                <span>NLP Semantic Analysis Active</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default TextScanner;