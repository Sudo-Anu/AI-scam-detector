import React, { useState, useRef, useEffect } from 'react';

const ImageScanner = ({ onSubmit, isLoading = false }) => {
    const [selectedFile, setSelectedFile] = useState(null);
    const [previewUrl, setPreviewUrl] = useState(null);
    const [isDragging, setIsDragging] = useState(false);
    const [error, setError] = useState('');
    const fileInputRef = useRef(null);

    const allowedExtensions = ['.jpg', '.jpeg', '.png', '.webp', '.gif', '.bmp', '.jfif'];
    const allowedTypes = [
        'image/jpeg',
        'image/jpg',
        'image/pjpeg',
        'image/png',
        'image/x-png',
        'image/webp',
        'image/gif',
        'image/bmp',
        'image/x-ms-bmp'
    ];

    useEffect(() => {
        // Cleanup memory for object URLs when component unmounts or file changes
        return () => {
            if (previewUrl) {
                URL.revokeObjectURL(previewUrl);
            }
        };
    }, [previewUrl]);

    const validateFile = (file) => {
        if (!file) {
            return 'Please select or drop a screenshot or image file to scan.';
        }
        const fileName = (file.name || '').toLowerCase();
        const hasValidExt = allowedExtensions.some(ext => fileName.endsWith(ext));
        const fileType = (file.type || '').toLowerCase();
        const hasValidType = allowedTypes.includes(fileType) || fileType.startsWith('image/');

        if (!hasValidExt && !hasValidType) {
            return 'Invalid file type. Please upload a valid image file (PNG, JPG, JPEG, WEBP, GIF, or BMP).';
        }
        // Limit file size to 15MB for OCR and Vision AI analysis
        if (file.size > 15 * 1024 * 1024) {
            return 'Image file size exceeds the 15MB limit.';
        }
        return '';
    };

    const handleFileSelection = (file) => {
        const validationError = validateFile(file);
        if (validationError) {
            setError(validationError);
            removeFile();
            return;
        }

        setError('');
        setSelectedFile(file);

        if (previewUrl) {
            URL.revokeObjectURL(previewUrl);
        }
        setPreviewUrl(URL.createObjectURL(file));
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

        // Pass FormData as the primary payload per specifications, along with raw File as fallback
        onSubmit(formData, selectedFile);
    };

    const removeFile = (e) => {
        if (e) e.stopPropagation();
        if (isLoading) return;

        setSelectedFile(null);
        if (previewUrl) {
            URL.revokeObjectURL(previewUrl);
            setPreviewUrl(null);
        }
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
            <h2 className="font-headline-xl text-[40px] md:text-headline-xl text-white/95 mb-4 tracking-tighter">Image & Screenshot Scanner</h2>
            <p className="text-white/50 font-body-md text-lg max-w-2xl font-light mb-8">
                Upload a suspicious screenshot, receipt, QR code, or document image to analyze for fraudulent OCR patterns, deepfakes, and visual phishing scams.
            </p>
            
            <div className="flex justify-center w-full">
                <div className="glass-panel subtle-border-gradient rounded-3xl p-1 md:p-1.5 relative overflow-hidden group w-full">
                    <div className="bg-[#13151f]/80 rounded-[22px] p-6 md:p-10 relative overflow-hidden h-full backdrop-blur-3xl">
                        {isLoading && <div className="scan-line" style={{ opacity: 1 }}></div>}
                        
                        <div className="space-y-6">
                            <div className="flex items-center gap-3">
                                <span className="material-symbols-outlined text-accent-purple text-[20px]">image</span>
                                <label className="text-[12px] font-semibold text-white/60 uppercase tracking-[0.15em]" htmlFor="file-input">
                                    Target Image
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
                                        accept="image/*,.jpg,.jpeg,.png,.webp,.gif,.bmp"
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
                                                    <span className="text-accent-purple underline decoration-accent-purple/40 underline-offset-4">Click to upload image</span> or drag and drop
                                                </p>
                                                <p className="text-xs text-white/40 mt-2 font-mono-data">
                                                    PNG, JPG, WEBP, GIF, BMP (Max 15MB)
                                                </p>
                                            </div>
                                        </div>
                                    ) : (
                                        <div className="w-full flex items-center justify-between gap-3 p-4 bg-black/30 border border-white/[0.05] rounded-xl" onClick={(e) => e.stopPropagation()}>
                                            <div className="flex items-center gap-4 overflow-hidden">
                                                <div className="relative flex-shrink-0 w-12 h-12 rounded-lg overflow-hidden bg-black/50 border border-white/10 flex items-center justify-center group-preview">
                                                    {previewUrl ? (
                                                        <img
                                                            src={previewUrl}
                                                            alt="Upload preview"
                                                            className="w-full h-full object-cover"
                                                        />
                                                    ) : (
                                                        <span className="text-[10px] text-white/50 uppercase">Preview</span>
                                                    )}
                                                </div>
                                                <div className="overflow-hidden text-left">
                                                    <p className="text-[15px] font-light text-white/90 truncate font-mono-data">
                                                        {selectedFile.name}
                                                    </p>
                                                    <p className="text-xs text-white/40 font-mono-data mt-1">
                                                        {formatFileSize(selectedFile.size)} • {selectedFile.type.replace('image/', '').toUpperCase()}
                                                    </p>
                                                </div>
                                            </div>
                                            {!isLoading && (
                                                <button
                                                    type="button"
                                                    onClick={removeFile}
                                                    className="p-2 text-white/40 hover:text-error hover:bg-error/10 rounded-lg transition-colors"
                                                    title="Remove image"
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
                                        {isLoading ? 'Scanning...' : 'Scan Image'}
                                    </button>
                                </div>
                            </form>
                            
                            <div className="flex flex-col sm:flex-row sm:items-center gap-4 text-[13px] text-white/40 font-light pt-2">
                                <div className="flex items-center gap-1.5">
                                    <span className="material-symbols-outlined text-[16px] text-secondary-fixed-dim/70">check_circle</span>
                                    <span>Engine Ready</span>
                                </div>
                                <span className="hidden sm:block w-1 h-1 rounded-full bg-white/10"></span>
                                <span>Vision AI & OCR Engine Online</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default ImageScanner;