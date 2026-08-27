import React, { useState, useRef } from 'react';

const EmailScanner = ({ onSubmit, isLoading = false }) => {
    const [selectedFile, setSelectedFile] = useState(null);
    const [isDragging, setIsDragging] = useState(false);
    const [error, setError] = useState('');
    const fileInputRef = useRef(null);

    const allowedExtensions = ['.eml', '.msg', '.txt'];

    const validateFile = (file) => {
        if (!file) {
            return 'Please select or drop an email file to analyze.';
        }
        const fileName = file.name.toLowerCase();
        const isValidExtension = allowedExtensions.some(ext => fileName.endsWith(ext));
        if (!isValidExtension) {
            return `Invalid file type. Please upload an email file (${allowedExtensions.join(', ')}).`;
        }
        if (file.size > 10 * 1024 * 1024) {
            return 'File size exceeds the 10MB limit.';
        }
        return '';
    };

    const handleFileSelection = (file) => {
        const validationError = validateFile(file);
        if (validationError) {
            setError(validationError);
            setSelectedFile(null);
            return;
        }
        setError('');
        setSelectedFile(file);
    };

    const handleFileChange = (e) => {
        const file = e.target.files?.[0];
        if (file) {
            handleFileSelection(file);
        }
    };

    const handleDragOver = (e) => {
        e.preventDefault();
        e.stopPropagation();
        if (!isLoading) {
            setIsDragging(true);
        }
    };

    const handleDragLeave = (e) => {
        e.preventDefault();
        e.stopPropagation();
        setIsDragging(false);
    };

    const handleDrop = (e) => {
        e.preventDefault();
        e.stopPropagation();
        setIsDragging(false);

        if (isLoading) return;

        const droppedFile = e.dataTransfer.files?.[0];
        if (droppedFile) {
            handleFileSelection(droppedFile);
        }
    };

    const handleSubmit = (e) => {
        e.preventDefault();
        const validationError = validateFile(selectedFile);
        if (validationError) {
            setError(validationError);
            return;
        }

        setError('');
        const formData = new FormData();
        formData.append('file', selectedFile);

        onSubmit(formData, selectedFile);
    };

    const removeFile = () => {
        if (isLoading) return;
        setSelectedFile(null);
        setError('');
        if (fileInputRef.current) {
            fileInputRef.current.value = '';
        }
    };

    const formatFileSize = (bytes) => {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    };

    return (
        <div className="lg:col-span-12 flex flex-col pt-8 w-full">
            <h2 className="font-headline-xl text-[40px] md:text-headline-xl text-white/95 mb-4 tracking-tighter">Email Scanner</h2>
            <p className="text-white/50 font-body-md text-lg max-w-2xl font-light mb-8">
                Upload a suspicious email file (.eml, .msg, or .txt) to inspect headers, hidden attachments, and AI-generated social engineering cues.
            </p>
            
            <div className="flex justify-center w-full">
                <div className="glass-panel subtle-border-gradient rounded-3xl p-1 md:p-1.5 relative overflow-hidden group w-full">
                    <div className="bg-[#13151f]/80 rounded-[22px] p-6 md:p-10 relative overflow-hidden h-full backdrop-blur-3xl">
                        {isLoading && <div className="scan-line" style={{ opacity: 1 }}></div>}
                        
                        <div className="space-y-6">
                            <div className="flex items-center gap-3">
                                <span className="material-symbols-outlined text-accent-purple text-[20px]">alternate_email</span>
                                <label className="text-[12px] font-semibold text-white/60 uppercase tracking-[0.15em]" htmlFor="file-input">
                                    Target Email File
                                </label>
                            </div>
                            
                            <form onSubmit={handleSubmit} noValidate>
                                <div
                                    onDragOver={handleDragOver}
                                    onDragLeave={handleDragLeave}
                                    onDrop={handleDrop}
                                    onClick={() => !isLoading && fileInputRef.current?.click()}
                                    className={`relative flex flex-col items-center justify-center p-8 border border-dashed rounded-2xl cursor-pointer transition-all duration-300 ${isLoading
                                        ? 'opacity-50 cursor-not-allowed bg-black/40 border-white/[0.04]'
                                        : isDragging
                                            ? 'border-accent-purple bg-accent-purple/5'
                                            : error
                                                ? 'border-error/40 bg-error/5'
                                                : selectedFile
                                                    ? 'border-secondary-fixed-dim/40 bg-secondary-fixed-dim/5'
                                                    : 'border-white/[0.08] bg-black/20 hover:border-white/20'
                                        }`}
                                >
                                    <input
                                        ref={fileInputRef}
                                        type="file"
                                        accept=".eml,.msg,.txt"
                                        onChange={handleFileChange}
                                        disabled={isLoading}
                                        className="hidden"
                                        id="file-input"
                                    />
                                    
                                    {!selectedFile ? (
                                        <div className="flex flex-col items-center text-center space-y-4 pointer-events-none">
                                            <span className={`material-symbols-outlined text-4xl transition-colors ${isDragging ? 'text-accent-purple' : 'text-white/30'}`}>cloud_upload</span>
                                            <div>
                                                <p className="text-[15px] font-light text-white/90">
                                                    <span className="text-accent-purple underline decoration-accent-purple/40 underline-offset-4">Click to upload</span> or drag and drop
                                                </p>
                                                <p className="text-xs text-white/40 mt-2 font-mono-data">
                                                    .EML, .MSG, .TXT (Max 10MB)
                                                </p>
                                            </div>
                                        </div>
                                    ) : (
                                        <div className="w-full flex items-center justify-between gap-3 p-4 bg-black/30 border border-white/[0.05] rounded-xl" onClick={(e) => e.stopPropagation()}>
                                            <div className="flex items-center gap-4 overflow-hidden">
                                                <span className="material-symbols-outlined text-secondary-fixed-dim">draft</span>
                                                <div className="overflow-hidden text-left">
                                                    <p className="text-[15px] font-light text-white/90 truncate font-mono-data">
                                                        {selectedFile.name}
                                                    </p>
                                                    <p className="text-xs text-white/40 font-mono-data mt-1">
                                                        {formatFileSize(selectedFile.size)}
                                                    </p>
                                                </div>
                                            </div>
                                            {!isLoading && (
                                                <button
                                                    type="button"
                                                    onClick={removeFile}
                                                    className="p-2 text-white/40 hover:text-error hover:bg-error/10 rounded-lg transition-colors"
                                                    title="Remove file"
                                                >
                                                    <span className="material-symbols-outlined text-[20px]">close</span>
                                                </button>
                                            )}
                                        </div>
                                    )}
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
                                        disabled={isLoading || !selectedFile}
                                        className="w-full bg-gradient-to-r from-accent-purple/80 to-[#c892ff]/80 text-white py-4 rounded-xl font-medium shadow-[0_0_20px_rgba(138,99,245,0.2)] hover:shadow-[0_0_30px_rgba(138,99,245,0.4)] hover:brightness-110 flex items-center justify-center gap-2 transition-all duration-300 disabled:opacity-50 disabled:pointer-events-none"
                                    >
                                        {isLoading ? 'Scanning...' : 'Scan Email'}
                                    </button>
                                </div>
                            </form>
                            
                            <div className="flex flex-col sm:flex-row sm:items-center gap-4 text-[13px] text-white/40 font-light pt-2">
                                <div className="flex items-center gap-1.5">
                                    <span className="material-symbols-outlined text-[16px] text-secondary-fixed-dim/70">check_circle</span>
                                    <span>Engine Ready</span>
                                </div>
                                <span className="hidden sm:block w-1 h-1 rounded-full bg-white/10"></span>
                                <span>Encrypted Parsing Sandbox</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default EmailScanner;