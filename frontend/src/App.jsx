import React, { useState, useCallback, useEffect } from "react";
import UrlScanner from "./components/Inputs/UrlScanner";
import EmailScanner from "./components/Inputs/EmailScanner";
import TextScanner from "./components/Inputs/TextScanner";
import ImageScanner from "./components/Inputs/ImageScanner";
import ResultsDashboard from "./components/Dashboard/ResultsDashboard";

const API_BASE_URL =
    (typeof import.meta !== "undefined" && import.meta.env && import.meta.env.VITE_API_BASE_URL) ||
    (typeof process !== "undefined" && process?.env?.REACT_APP_API_BASE_URL) ||
    "http://localhost:8000";

const SCAN_METHODS = [
    { key: "url", label: "URL Analysis", icon: "link", endpoint: "/scan/url" },
    { key: "email", label: "Email Scanner", icon: "alternate_email", endpoint: "/scan/email" },
    { key: "text", label: "Text Guard", icon: "shield", endpoint: "/scan/text" },
    { key: "image", label: "Image Forensic", icon: "image_search", endpoint: "/scan/image" },
];

function App() {
    const [activeMethod, setActiveMethod] = useState("url");
    const [isLoading, setIsLoading] = useState(false);
    const [scanResults, setScanResults] = useState(null);
    const [error, setError] = useState(null);
    const [theme, setTheme] = useState(() => {
        return localStorage.getItem('theme') || 'dark';
    });

    useEffect(() => {
        const root = document.documentElement;
        if (theme === 'light') {
            root.classList.add('light-theme-filter');
        } else {
            root.classList.remove('light-theme-filter');
        }
        localStorage.setItem('theme', theme);
    }, [theme]);

    const handleScanSubmit = useCallback(
        async (payload, methodKeyOverride) => {
            const methodKey = methodKeyOverride || activeMethod;
            const method = SCAN_METHODS.find((m) => m.key === methodKey);

            if (!method) {
                setError(`Unknown scan method: ${methodKey}`);
                return;
            }

            setIsLoading(true);
            setError(null);
            setScanResults(null);

            try {
                const isFormData =
                    typeof FormData !== "undefined" && payload instanceof FormData;

                let body;
                if (isFormData) {
                    body = payload;
                } else {
                    const payloadMap = {
                        url:   { url:  payload },
                        text:  { text: payload },
                    };
                    body = JSON.stringify(payloadMap[methodKey] || { input: payload });
                }

                const response = await fetch(`${API_BASE_URL}${method.endpoint}`, {
                    method: "POST",
                    headers: isFormData ? undefined : { "Content-Type": "application/json" },
                    body,
                });

                if (!response.ok) {
                    let message = `Request failed with status ${response.status}`;
                    try {
                        const errorBody = await response.json();
                        message = errorBody?.detail || errorBody?.message || message;
                    } catch (_) {
                        // response body wasn't JSON; keep default message
                    }
                    throw new Error(message);
                }

                const data = await response.json();
                setScanResults(data);
            } catch (err) {
                const msg =
                    typeof err?.message === "string"
                        ? err.message
                        : typeof err === "string"
                        ? err
                        : JSON.stringify(err);
                setError(msg || "An unexpected error occurred while scanning.");
            } finally {
                setIsLoading(false);
            }
        },
        [activeMethod]
    );

    const handleMethodChange = (methodKey) => {
        setActiveMethod(methodKey);
        setScanResults(null);
        setError(null);
    };

    const renderActiveScanner = () => {
        const commonProps = {
            onSubmit: (payload) => handleScanSubmit(payload, activeMethod),
            isLoading,
        };

        switch (activeMethod) {
            case "url":
                return <UrlScanner {...commonProps} />;
            case "email":
                return <EmailScanner {...commonProps} />;
            case "text":
                return <TextScanner {...commonProps} />;
            case "image":
                return <ImageScanner {...commonProps} />;
            default:
                return null;
        }
    };

    return (
        <div className="flex h-screen w-full">
            {/* Atmospheric Background Effects */}
            <div className="fixed inset-0 pointer-events-none overflow-hidden z-0 bg-[radial-gradient(ellipse_at_top_right,_var(--tw-gradient-stops))] from-[#111320] via-background to-background">
                <div className="ambient-glow" style={{ top: '20%', left: '80%' }}></div>
                <div className="ambient-glow" style={{ top: '80%', left: '20%', background: 'radial-gradient(circle, rgba(255, 171, 243, 0.05) 0%, rgba(0,0,0,0) 70%)' }}></div>
            </div>

            {/* SideNavBar */}
            <nav className="hidden md:flex flex-col h-full w-[280px] fixed left-0 top-0 py-10 bg-surface-container/40 backdrop-blur-[30px] border-r border-white/[0.03] z-50">
                {/* Header */}
                <div className="px-8 mb-12 flex items-center gap-4 group cursor-pointer">
                    <div className="w-10 h-10 rounded-2xl bg-gradient-to-br from-[#2a2d42] to-[#1a1c29] border border-white/10 flex items-center justify-center shadow-lg shadow-black/50 group-hover:border-accent-purple/50 transition-colors duration-500">
                        <span className="material-symbols-outlined text-accent-purple/90" style={{ fontVariationSettings: '"FILL" 1' }}>security</span>
                    </div>
                    <div>
                        <h1 className="text-xl tracking-tight font-semibold text-white/90">Guardian AI</h1>
                        <p className="text-[10px] uppercase tracking-[0.2em] text-white/40 font-semibold mt-0.5">Vigilant Protection</p>
                    </div>
                </div>
                {/* Navigation Links */}
                <div className="flex-1 px-4 flex flex-col gap-1.5">
                    {SCAN_METHODS.map((method) => {
                        const isActive = activeMethod === method.key;
                        return (
                            <button
                                key={method.key}
                                onClick={() => handleMethodChange(method.key)}
                                className={`flex items-center gap-3.5 px-4 py-3.5 rounded-2xl transition-all duration-300 group relative overflow-hidden w-full text-left ${isActive ? 'bg-white/[0.04] text-white/90 font-medium border border-white/[0.05] shadow-sm' : 'text-white/50 hover:text-white/80 hover:bg-white/[0.02]'}`}
                            >
                                {isActive && <div className="absolute left-0 top-0 bottom-0 w-1 bg-accent-purple rounded-r-full shadow-[0_0_10px_theme('colors.accent-purple')]"></div>}
                                <span className={`material-symbols-outlined text-[20px] transition-colors ${isActive ? 'text-accent-purple' : 'group-hover:text-white/70'}`}>{method.icon}</span>
                                <span className="text-sm">{method.label}</span>
                            </button>
                        );
                    })}
                </div>
            </nav>

            {/* Main Content Wrapper */}
            <div className="flex-1 ml-0 md:ml-[280px] flex flex-col min-h-screen relative z-10 w-full overflow-y-auto">
                {/* TopAppBar */}
                <header className="fixed top-0 right-0 w-full md:w-[calc(100%-280px)] z-40 bg-transparent flex justify-end items-center h-24 px-6 md:px-12 pointer-events-none">
                    <div className="flex items-center gap-5 pointer-events-auto">
                        <div className="flex items-center gap-2.5 bg-surface-container/60 backdrop-blur-xl px-4 py-2 rounded-full border border-white/5 shadow-lg">
                            <div className="relative flex h-2 w-2">
                                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-secondary-fixed-dim opacity-40"></span>
                                <span className="relative inline-flex rounded-full h-2 w-2 bg-secondary-fixed-dim"></span>
                            </div>
                            <span className="text-[11px] font-semibold text-white/70 tracking-widest uppercase">Engine Online</span>
                        </div>
                        <button 
                            aria-label="Toggle Theme" 
                            onClick={() => setTheme(t => t === 'dark' ? 'light' : 'dark')}
                            className="w-10 h-10 flex items-center justify-center rounded-full bg-surface-container/60 border border-white/5 text-white/50 hover:text-white/90 hover:bg-white/10 transition-all duration-300 backdrop-blur-xl shadow-lg"
                        >
                            <span className="material-symbols-outlined text-[20px]">
                                {theme === 'dark' ? 'light_mode' : 'dark_mode'}
                            </span>
                        </button>
                    </div>
                </header>

                {/* Main Canvas */}
                <main className="flex-1 mt-24 p-6 md:p-12 lg:p-16 flex flex-col min-h-[calc(100vh-96px)] items-center">
                    <div className="w-full max-w-[1000px] flex flex-col gap-12">
                        {renderActiveScanner()}
                        
                        {isLoading && (
                            <div className="w-full text-center p-6 bg-surface-container-high/50 backdrop-blur-md rounded-2xl border border-white/5 text-white/60 text-sm font-medium animate-pulse">
                                Analyzing target, please wait...
                            </div>
                        )}

                        {error && (
                            <div className="w-full text-center p-6 bg-error-container/30 backdrop-blur-md rounded-2xl border border-error/20 text-error-container font-medium">
                                <span className="material-symbols-outlined align-middle mr-2">error</span>
                                {error}
                            </div>
                        )}

                        {!isLoading && !error && (
                            <ResultsDashboard scanResults={scanResults} onReset={() => setScanResults(null)} />
                        )}
                    </div>
                </main>
            </div>
        </div>
    );
}

export default App;