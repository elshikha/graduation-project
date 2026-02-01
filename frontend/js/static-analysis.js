// DOM Elements
const sidebar = document.getElementById('sidebar');
const sidebarToggle = document.getElementById('sidebarToggle');
const uploadArea = document.getElementById('uploadArea');
const fileInput = document.getElementById('fileInput');
const uploadSection = document.getElementById('uploadSection');
const resultsSection = document.getElementById('resultsSection');
const warningMessage = document.getElementById('warningMessage');
const btnBack = document.getElementById('btnBack');
const btnDismissWarning = document.getElementById('btnDismissWarning');
const dynamicAnalysisBtn = document.getElementById('dynamicAnalysisBtn');

console.log('Static Analysis JS Loaded');
console.log('Upload Area:', uploadArea);
console.log('File Input:', fileInput);

// Check if user is logged in
const token = localStorage.getItem('token');
const user = JSON.parse(localStorage.getItem('user') || '{}');
const analysisMode = localStorage.getItem('analysisMode');

if (!token) {
    window.location.href = 'index.html';
}

// Display user name
if (user.username) {
    document.querySelector('.user-name').textContent = user.username;
}

// Show dynamic analysis button if mode is "both"
if (analysisMode === 'both') {
    dynamicAnalysisBtn.style.display = 'block';
    
    dynamicAnalysisBtn.querySelector('button').addEventListener('click', () => {
        showNotification('Dynamic analysis will be available later', 'info');
    });
}

// Sidebar Toggle
sidebarToggle.addEventListener('click', () => {
    sidebar.classList.toggle('collapsed');
});

// Card Collapse/Expand Toggle
document.addEventListener('click', (e) => {
    const header = e.target.closest('[data-toggle]');
    if (header) {
        const toggleId = header.getAttribute('data-toggle');
        const cardBody = document.getElementById(`${toggleId}-body`);
        const arrow = header.querySelector('.toggle-arrow');
        
        if (cardBody) {
            cardBody.classList.toggle('expanded');
            arrow.classList.toggle('rotated');
        }
    }
});

// File Upload Handling
uploadArea.addEventListener('click', () => {
    fileInput.click();
});

const btnBrowse = document.querySelector('.btn-browse');
if (btnBrowse) {
    btnBrowse.addEventListener('click', (e) => {
        e.stopPropagation();
        fileInput.click();
    });
}

fileInput.addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (file) {
        handleFileUpload(file);
    }
});

// Drag and Drop
uploadArea.addEventListener('dragover', (e) => {
    e.preventDefault();
    uploadArea.classList.add('dragover');
});

uploadArea.addEventListener('dragleave', () => {
    uploadArea.classList.remove('dragover');
});

uploadArea.addEventListener('drop', (e) => {
    e.preventDefault();
    uploadArea.classList.remove('dragover');
    
    const file = e.dataTransfer.files[0];
    if (file) {
        handleFileUpload(file);
    }
});

// File Upload Handler
async function handleFileUpload(file) {
    console.log('handleFileUpload called with:', file.name, file.type, file.size);
    
    // Show funny loader
    showFunnyLoader();
    
    // Create FormData
    const formData = new FormData();
    formData.append('file', file);
    
    try {
        // Upload to backend
        const token = localStorage.getItem('token');
        const response = await fetch('http://localhost:5000/api/upload-file', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`
            },
            body: formData
        });
        
        const result = await response.json();
        
        hideFunnyLoader();
        
        if (!result.success) {
            if (result.file_type && !['PE', 'ELF', 'PDF', 'Office'].includes(result.file_type)) {
                showUnsupportedWarning(result.file_type);
            } else {
                showNotification(result.message || 'Upload failed', 'error');
            }
            return;
        }
        
        // Show results
        showResultsFromServer(file, result.data);
        showNotification('File analyzed successfully!', 'success');
        
    } catch (error) {
        console.error('Upload error:', error);
        hideFunnyLoader();
        showNotification('Failed to upload file. Please try again.', 'error');
        
        // Fallback to client-side analysis
        const fileType = detectFileType(file);
        const supportedTypes = ['PE', 'ELF', 'PDF', 'Office'];
        
        if (!supportedTypes.includes(fileType)) {
            showUnsupportedWarning(fileType);
            return;
        }
        
        showResults(file, fileType);
        await calculateHashes(file);
    }
}

// File Type Detection
function detectFileType(file) {
    const fileName = file.name.toLowerCase();
    const extension = fileName.split('.').pop();
    
    // Check for PE files (Windows executables)
    if (extension === 'exe' || extension === 'dll' || extension === 'sys') {
        return 'PE';
    }
    
    // Check for ELF files (Linux executables)
    if (extension === 'elf' || extension === 'so' || !extension || extension === 'bin') {
        // Additional check needed - for now assume ELF if no extension
        return 'ELF';
    }
    
    // Check for PDF files
    if (extension === 'pdf') {
        return 'PDF';
    }
    
    // Check for Office files
    if (['doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx'].includes(extension)) {
        return 'Office';
    }
    
    // Check for mobile apps (unsupported)
    if (extension === 'apk' || extension === 'ipa') {
        return 'Mobile App';
    }
    
    return 'Unknown';
}

// Show Unsupported Warning
function showUnsupportedWarning(fileType) {
    uploadSection.style.display = 'none';
    resultsSection.style.display = 'none';
    warningMessage.style.display = 'block';
    
    const warningText = document.getElementById('warningText');
    
    if (fileType === 'Mobile App') {
        warningText.textContent = 'Mobile applications (APK, IPA) are not currently supported. Please upload a PE, ELF, PDF, or Office file.';
    } else if (fileType === 'Unknown') {
        warningText.textContent = 'This file type could not be identified. Please upload a PE, ELF, PDF, or Office file.';
    } else {
        warningText.textContent = `${fileType} files are not currently supported. Please upload a PE, ELF, PDF, or Office file.`;
    }
}

// Show Results from Server
function showResultsFromServer(file, data) {
    uploadSection.style.display = 'none';
    warningMessage.style.display = 'none';
    resultsSection.style.display = 'block';
    
    // Store analysis data globally for CVSS access
    window.currentAnalysisData = data;
    
    // Log CVSS score if available
    if (data.cvss_score !== undefined) {
        console.log('CVSS Score received:', data.cvss_score);
        console.log('Severity:', data.severity);
        console.log('Verdict:', data.verdict);
        
        // Display CVSS card if score is available
        displayCVSSCard(data);
    }
    
    // Populate file info
    document.getElementById('fileName').textContent = data.filename;
    document.getElementById('fileSize').textContent = formatFileSize(data.file_size);
    document.getElementById('fileType').textContent = data.file_type;
    document.getElementById('uploadDate').textContent = new Date().toLocaleString();
    document.getElementById('fileTypeBadge').textContent = data.file_type;
    
    // Populate hashes
    document.getElementById('md5Hash').textContent = data.hashes.md5;
    document.getElementById('sha1Hash').textContent = data.hashes.sha1;
    document.getElementById('sha256Hash').textContent = data.hashes.sha256;
    document.getElementById('sha512Hash').textContent = data.hashes.sha512 || 'N/A';
    document.getElementById('blake2bHash').textContent = data.hashes.blake2b || 'N/A';
    
    // Populate entropy
    if (data.entropy !== undefined) {
        document.getElementById('entropyValue').textContent = data.entropy.toFixed(4);
        document.getElementById('entropyStatus').textContent = data.entropy_status || getEntropyStatus(data.entropy);
        
        // Update entropy bar
        const entropyPercent = (data.entropy / 8) * 100;
        const entropyFill = document.getElementById('entropyFill');
        entropyFill.style.width = entropyPercent + '%';
        
        // Color based on entropy level
        if (data.entropy > 7.5) {
            entropyFill.style.background = 'linear-gradient(90deg, #ff4444, #cc0000)';
        } else if (data.entropy > 6) {
            entropyFill.style.background = 'linear-gradient(90deg, #ffaa00, #ff6600)';
        } else {
            entropyFill.style.background = 'linear-gradient(90deg, #00cc00, #008800)';
        }
    }
    
    // Show PE analysis for Windows executables
    if (data.file_type === 'PE' && data.pe_analysis) {
        console.log('PE analysis data:', data.pe_analysis);
        console.log('DIE analysis:', data.pe_analysis.die_analysis);
        console.log('DIE summary:', data.pe_analysis.die_summary);
        const peCard = document.getElementById('peAnalysisCard');
        const peInfo = document.getElementById('peInfo');
        
        if (!data.pe_analysis.error) {
            peCard.style.display = 'block';
            peInfo.innerHTML = generatePEAnalysisHTML(data.pe_analysis);
        }
    } else {
        document.getElementById('peAnalysisCard').style.display = 'none';
    }
    
    // Show CAPA capability analysis for PE files
    console.log('CAPA analysis data:', data.capa_analysis);
    if (data.file_type === 'PE' && data.capa_analysis) {
        const capaCard = document.getElementById('capaAnalysisCard');
        const capaInfo = document.getElementById('capaInfo');
        
        if (data.capa_analysis.success && !data.capa_analysis.error) {
            capaCard.style.display = 'block';
            capaInfo.innerHTML = generateCapaAnalysisHTML(data.capa_analysis);
        } else {
            console.error('CAPA analysis error:', data.capa_analysis.error);
        }
    } else {
        document.getElementById('capaAnalysisCard').style.display = 'none';
    }
    
    // Show PE Structure analysis for PE files
    console.log('PE Structure analysis data:', data.pe_structure);
    if (data.file_type === 'PE' && data.pe_structure) {
        const peStructureCard = document.getElementById('peStructureCard');
        const peStructureInfo = document.getElementById('peStructureInfo');
        
        if (!data.pe_structure.error) {
            peStructureCard.style.display = 'block';
            peStructureInfo.innerHTML = generatePEStructureHTML(data.pe_structure);
        } else {
            console.error('PE Structure analysis error:', data.pe_structure.error);
        }
    } else {
        document.getElementById('peStructureCard').style.display = 'none';
    }
    
    // Show PDF analysis for PDF files
    if (data.file_type === 'PDF' && data.pdf_analysis) {
        const pdfCard = document.getElementById('pdfAnalysisCard');
        const pdfInfo = document.getElementById('pdfInfo');
        
        if (!data.pdf_analysis.error) {
            pdfCard.style.display = 'block';
            pdfInfo.innerHTML = generatePDFAnalysisHTML(data.pdf_analysis);
        }
    } else {
        document.getElementById('pdfAnalysisCard').style.display = 'none';
    }
    
    // Show PDF obfuscation analysis for PDF files
    console.log('PDF obfuscation data:', data.pdf_obfuscation);
    if (data.file_type === 'PDF' && data.pdf_obfuscation) {
        const obfCard = document.getElementById('pdfObfuscationCard');
        const obfInfo = document.getElementById('pdfObfuscationInfo');
        
        if (!data.pdf_obfuscation.error) {
            obfCard.style.display = 'block';
            obfInfo.innerHTML = generatePDFObfuscationHTML(data.pdf_obfuscation);
        } else {
            obfCard.style.display = 'block';
            obfInfo.innerHTML = `<div class="error-message"><i class="fas fa-exclamation-circle"></i> ${data.pdf_obfuscation.error}</div>`;
        }
    } else {
        document.getElementById('pdfObfuscationCard').style.display = 'none';
    }
    
    // Show Strings analysis for all files
    console.log('Strings analysis data:', data.strings_analysis);
    if (data.strings_analysis) {
        const stringsCard = document.getElementById('stringsAnalysisCard');
        const stringsInfo = document.getElementById('stringsInfo');
        
        if (!data.strings_analysis.error) {
            stringsCard.style.display = 'block';
            stringsInfo.innerHTML = generateStringsAnalysisHTML(data.strings_analysis);
        } else {
            console.error('Strings analysis error:', data.strings_analysis.error);
        }
    } else {
        console.log('No strings analysis data received');
        document.getElementById('stringsAnalysisCard').style.display = 'none';
    }
    
    // Show VirusTotal results for all files
    if (data.virustotal) {
        const vtCard = document.getElementById('virusTotalCard');
        const vtInfo = document.getElementById('vtInfo');
        
        if (!data.virustotal.error && data.virustotal.found) {
            vtCard.style.display = 'block';
            vtInfo.innerHTML = generateVirusTotalHTML(data.virustotal);
        } else if (!data.virustotal.found) {
            vtCard.style.display = 'block';
            vtInfo.innerHTML = '<div class="vt-not-found"><i class="fas fa-info-circle"></i> File not found in VirusTotal database. This file may be new or rarely seen.</div>';
        }
    } else {
        document.getElementById('virusTotalCard').style.display = 'none';
    }
}

function getEntropyStatus(entropy) {
    if (entropy > 7.5) return 'High (Possibly encrypted/packed)';
    if (entropy > 6.0) return 'Medium (Compressed or mixed content)';
    return 'Low (Plain text or low complexity)';
}

function generatePEAnalysisHTML(pe) {
    let html = '<div class="pe-grid">';
    
    // DIE Analysis Summary (if available) - Show at the top as it's important
    if (pe.die_summary && Object.keys(pe.die_summary).length > 0 && !pe.die_summary.error) {
        html += '<div class="die-analysis-container">';
        html += '<div class="die-header"><i class="fas fa-microscope"></i> Detection Analysis</div>';
        html += '<div class="die-content">';
        
        const summary = pe.die_summary;
        
        // Create info grid
        html += '<div class="die-info-grid">';
        
        // File Type
        if (summary.file_type) {
            html += `<div class="die-info-item">
                <div class="die-info-icon"><i class="fas fa-file-code"></i></div>
                <div class="die-info-details">
                    <div class="die-info-label">File Type</div>
                    <div class="die-info-value">${escapeHtml(summary.file_type)}</div>
                </div>
            </div>`;
        }
        
        // Operation System
        if (summary.operation_system) {
            html += `<div class="die-info-item">
                <div class="die-info-icon"><i class="fab fa-windows"></i></div>
                <div class="die-info-details">
                    <div class="die-info-label">Operating System</div>
                    <div class="die-info-value">${escapeHtml(summary.operation_system)}</div>
                </div>
            </div>`;
        }
        
        // Compiler
        if (summary.compiler) {
            html += `<div class="die-info-item">
                <div class="die-info-icon compiler-icon"><i class="fas fa-cogs"></i></div>
                <div class="die-info-details">
                    <div class="die-info-label">Compiler</div>
                    <div class="die-info-value">${escapeHtml(summary.compiler)}</div>
                </div>
            </div>`;
        }
        
        // Language
        if (summary.language) {
            html += `<div class="die-info-item">
                <div class="die-info-icon compiler-icon"><i class="fas fa-code"></i></div>
                <div class="die-info-details">
                    <div class="die-info-label">Language</div>
                    <div class="die-info-value">${escapeHtml(summary.language)}</div>
                </div>
            </div>`;
        }
        
        html += '</div>'; // Close die-info-grid
        
        // Packer (Warning) - Full width
        if (summary.packer) {
            html += `<div class="die-alert die-alert-danger">
                <div class="die-alert-header">
                    <i class="fas fa-exclamation-triangle"></i>
                    <strong>Packer Detected</strong>
                </div>
                <div class="die-alert-content">${escapeHtml(summary.packer)}</div>
            </div>`;
        }
        
        // Protector (Warning) - Full width
        if (summary.protector) {
            html += `<div class="die-alert die-alert-danger">
                <div class="die-alert-header">
                    <i class="fas fa-shield-alt"></i>
                    <strong>Protector Detected</strong>
                </div>
                <div class="die-alert-content">${escapeHtml(summary.protector)}</div>
            </div>`;
        }
        
        // Sign Tool (Good) - Full width
        if (summary.sign_tool) {
            html += `<div class="die-alert die-alert-success">
                <div class="die-alert-header">
                    <i class="fas fa-certificate"></i>
                    <strong>Digital Signature</strong>
                </div>
                <div class="die-alert-content">${escapeHtml(summary.sign_tool)}</div>
            </div>`;
        }
        
        html += '</div></div>'; // Close die-content and die-analysis-container
    } else if (pe.die_analysis && pe.die_analysis.note) {
        // Show note if DIE is unavailable with error details
        html += '<div style="grid-column: 1 / -1; margin-bottom: 1rem;">';
        html += `<div style="background: rgba(255, 212, 59, 0.2); padding: 0.75rem; border-radius: 8px; border-left: 3px solid #ffa000; color: #cc6600;">`;
        html += `<i class="fas fa-info-circle"></i> <strong>${pe.die_analysis.note}</strong>`;
        if (pe.die_analysis.error) {
            html += `<div style="margin-top: 0.5rem; font-size: 0.9rem; color: #d32f2f; font-weight: 600;">${escapeHtml(pe.die_analysis.error)}</div>`;
        }
        html += '</div></div>';
    }
    
    // Basic PE info
    html += `
        <div class="pe-item">
            <span class="pe-label">Machine Type:</span>
            <span class="pe-value">${pe.machine_type}</span>
        </div>
        <div class="pe-item">
            <span class="pe-label">Timestamp:</span>
            <span class="pe-value">${pe.timestamp}</span>
        </div>
        <div class="pe-item">
            <span class="pe-label">Sections:</span>
            <span class="pe-value">${pe.number_of_sections}</span>
        </div>
        <div class="pe-item">
            <span class="pe-label">Entry Point:</span>
            <span class="pe-value"><code>${pe.entry_point}</code></span>
        </div>
        <div class="pe-item">
            <span class="pe-label">Image Base:</span>
            <span class="pe-value"><code>${pe.image_base}</code></span>
        </div>
        <div class="pe-item">
            <span class="pe-label">Type:</span>
            <span class="pe-value">${pe.is_dll ? 'DLL' : 'EXE'}</span>
        </div>
    `;
    html += '</div>';
    
    // Sections
    if (pe.sections && pe.sections.length > 0) {
        html += '<h4 style="margin-top: 1.5rem; margin-bottom: 1rem;"><i class="fas fa-layer-group"></i> Sections</h4>';
        html += '<div class="pe-sections">';
        pe.sections.forEach(section => {
            html += `
                <div class="pe-section">
                    <div class="section-name">${section.name}</div>
                    <div class="section-details">
                        <span>Virtual: ${section.virtual_address}</span>
                        <span>Size: ${section.raw_size}</span>
                        <span>Entropy: ${section.entropy ? section.entropy.toFixed(2) : 'N/A'}</span>
                    </div>
                </div>
            `;
        });
        html += '</div>';
    }
    
    // Imported DLLs
    if (pe.imports && pe.imports.length > 0) {
        html += '<h4 style="margin-top: 1.5rem; margin-bottom: 1rem;"><i class="fas fa-book"></i> Imported DLLs</h4>';
        html += '<div class="pe-imports">';
        pe.imports.forEach(dll => {
            html += `<span class="import-badge">${dll}</span>`;
        });
        if (pe.imports.length === 20) {
            html += '<span class="import-badge" style="background: #ccc;">... and more</span>';
        }
        html += '</div>';
    }
    
    return html;
}

function generatePDFAnalysisHTML(pdf) {
    let html = '';
    
    // Verdict banner
    const structure = pdf.structure || {};
    const riskLevel = pdf.risk_level || structure.risk_level || 'UNKNOWN';
    const verdict = pdf.verdict || 'Analysis incomplete';
    const totalScore = pdf.total_risk_score || structure.risk_score || 0;
    
    let bannerClass = 'pdf-verdict-low';
    if (riskLevel === 'CRITICAL' || riskLevel === 'HIGH') {
        bannerClass = 'pdf-verdict-high';
    } else if (riskLevel === 'MEDIUM') {
        bannerClass = 'pdf-verdict-medium';
    }
    
    html += `
        <div class="pdf-verdict ${bannerClass}">
            <i class="fas fa-exclamation-triangle"></i>
            <div>
                <strong>Risk Level: ${riskLevel}</strong>
                <p>${verdict}</p>
            </div>
            <div class="risk-score">Score: ${totalScore}</div>
        </div>
    `;
    
    // YARA Results
    const yara = pdf.yara || {};
    if (yara.matches && yara.matches.length > 0) {
        html += '<h4 style="margin-top: 1.5rem; margin-bottom: 1rem;"><i class="fas fa-search"></i> YARA Rule Matches</h4>';
        html += '<div class="yara-matches">';
        yara.matches.forEach(match => {
            html += `
                <div class="yara-match">
                    <div class="yara-match-header">
                        <i class="fas fa-flag"></i>
                        <strong>${match.rule}</strong>
                        <span class="yara-weight">Weight: ${match.weight}</span>
                    </div>
                    ${match.description ? `<div class="yara-description">${match.description}</div>` : ''}
                    ${match.tags && match.tags.length > 0 ? `<div class="yara-tags">${match.tags.map(tag => `<span class="tag-badge">${tag}</span>`).join('')}</div>` : ''}
                </div>
            `;
        });
        html += `<div class="yara-summary">Total YARA Score: <strong>${yara.total_score}</strong> (${yara.rule_count} rule${yara.rule_count !== 1 ? 's' : ''})</div>`;
        html += '</div>';
    } else if (yara.error) {
        html += `<div class="yara-error"><i class="fas fa-info-circle"></i> YARA: ${yara.error}</div>`;
    } else if (yara.info) {
        html += `<div class="yara-info"><i class="fas fa-info-circle"></i> ${yara.info}</div>`;
    }
    
    // Suspicious elements
    if (structure.suspicious_elements && structure.suspicious_elements.length > 0) {
        html += '<h4 style="margin-top: 1.5rem; margin-bottom: 1rem;"><i class="fas fa-exclamation-circle"></i> Suspicious Elements</h4>';
        html += '<div class="pdf-suspicious">';
        structure.suspicious_elements.forEach(element => {
            html += `<div class="suspicious-item"><i class="fas fa-warning"></i> ${element}</div>`;
        });
        html += '</div>';
    }
    
    // Warnings
    if (structure.warnings && structure.warnings.length > 0) {
        html += '<h4 style="margin-top: 1.5rem; margin-bottom: 1rem;"><i class="fas fa-exclamation"></i> Warnings</h4>';
        html += '<div class="pdf-warnings">';
        structure.warnings.forEach(warning => {
            html += `<div class="warning-item"><i class="fas fa-info-circle"></i> ${warning}</div>`;
        });
        html += '</div>';
    }
    
    // PeePDF Analysis
    const peepdf = pdf.peepdf || {};
    if (peepdf.info && Object.keys(peepdf.info).length > 0) {
        html += '<h4 style="margin-top: 1.5rem; margin-bottom: 1rem;"><i class="fas fa-search-plus"></i> PeePDF Analysis</h4>';
        html += '<div class="peepdf-info">';
        
        if (peepdf.info.version) {
            html += `<div class="peepdf-item"><strong>Version:</strong> ${peepdf.info.version}</div>`;
        }
        if (peepdf.info.binary) {
            html += `<div class="peepdf-item"><strong>Binary:</strong> ${peepdf.info.binary}</div>`;
        }
        if (peepdf.info.encrypted) {
            html += `<div class="peepdf-item"><strong>Encrypted:</strong> <span class="badge-warning">${peepdf.info.encrypted}</span></div>`;
        }
        if (peepdf.info.linearized) {
            html += `<div class="peepdf-item"><strong>Linearized:</strong> ${peepdf.info.linearized}</div>`;
        }
        if (peepdf.info.objects) {
            html += `<div class="peepdf-item"><strong>Objects:</strong> ${peepdf.info.objects}</div>`;
        }
        if (peepdf.info.streams) {
            html += `<div class="peepdf-item"><strong>Streams:</strong> ${peepdf.info.streams}</div>`;
        }
        
        html += '</div>';
        
        // PeePDF suspicious elements
        if (peepdf.suspicious_elements && peepdf.suspicious_elements.length > 0) {
            html += '<h5 style="margin-top: 1rem;"><i class="fas fa-exclamation-triangle"></i> PeePDF Findings</h5>';
            html += '<div class="peepdf-suspicious">';
            peepdf.suspicious_elements.forEach(element => {
                html += `<div class="suspicious-item"><i class="fas fa-warning"></i> ${element}</div>`;
            });
            html += '</div>';
        }
    } else if (peepdf.error) {
        html += '<h4 style="margin-top: 1.5rem; margin-bottom: 1rem;"><i class="fas fa-search-plus"></i> PeePDF Analysis</h4>';
        html += `<div class="peepdf-error"><i class="fas fa-info-circle"></i> ${peepdf.error}</div>`;
    }
    
    // Metadata
    const metadata = structure.metadata || {};
    if (Object.keys(metadata).length > 0) {
        html += '<h4 style="margin-top: 1.5rem; margin-bottom: 1rem;"><i class="fas fa-info"></i> PDF Metadata</h4>';
        html += '<div class="pdf-metadata-grid">';
        
        if (metadata.pdf_version) {
            html += `
                <div class="metadata-item">
                    <span class="metadata-label">PDF Version:</span>
                    <span class="metadata-value">${metadata.pdf_version}</span>
                </div>
            `;
        }
        if (metadata.page_count !== undefined) {
            html += `
                <div class="metadata-item">
                    <span class="metadata-label">Page Count:</span>
                    <span class="metadata-value">${metadata.page_count}</span>
                </div>
            `;
        }
        if (metadata.javascript_count) {
            html += `
                <div class="metadata-item">
                    <span class="metadata-label">JavaScript:</span>
                    <span class="metadata-value" style="color: #ff4444;">${metadata.javascript_count} instances</span>
                </div>
            `;
        }
        if (metadata.embedded_files) {
            html += `
                <div class="metadata-item">
                    <span class="metadata-label">Embedded Files:</span>
                    <span class="metadata-value">${metadata.embedded_files}</span>
                </div>
            `;
        }
        if (metadata.auto_action_count) {
            html += `
                <div class="metadata-item">
                    <span class="metadata-label">Auto Actions:</span>
                    <span class="metadata-value" style="color: #ff4444;">${metadata.auto_action_count}</span>
                </div>
            `;
        }
        if (metadata.launch_count) {
            html += `
                <div class="metadata-item">
                    <span class="metadata-label">Launch Actions:</span>
                    <span class="metadata-value" style="color: #cc0000; font-weight: 700;">${metadata.launch_count} (CRITICAL)</span>
                </div>
            `;
        }
        
        html += '</div>';
    }
    
    // PDF Entropy
    if (structure.entropy && Object.keys(structure.entropy).length > 0) {
        const ent = structure.entropy;
        html += '<h4 style="margin-top: 1.5rem; margin-bottom: 1rem;"><i class="fas fa-chart-bar"></i> PDF Entropy</h4>';
        html += '<div class="pdf-entropy-grid">';
        
        if (ent.total !== undefined) {
            html += `
                <div class="entropy-item">
                    <span>Total:</span>
                    <span class="entropy-bar-mini" style="width: ${(ent.total / 8) * 100}%"></span>
                    <span>${ent.total.toFixed(2)}</span>
                </div>
            `;
        }
        if (ent.inside_streams !== undefined) {
            html += `
                <div class="entropy-item">
                    <span>Inside Streams:</span>
                    <span class="entropy-bar-mini" style="width: ${(ent.inside_streams / 8) * 100}%"></span>
                    <span>${ent.inside_streams.toFixed(2)}</span>
                </div>
            `;
        }
        if (ent.outside_streams !== undefined) {
            html += `
                <div class="entropy-item">
                    <span>Outside Streams:</span>
                    <span class="entropy-bar-mini" style="width: ${(ent.outside_streams / 8) * 100}%"></span>
                    <span>${ent.outside_streams.toFixed(2)}</span>
                </div>
            `;
        }
        
        html += '</div>';
    }
    
    return html;
}

// Generate PDF Obfuscation Analysis HTML
function generatePDFObfuscationHTML(obfuscation) {
    let html = '';
    
    const analysis = obfuscation.analysis || {};
    const rawData = obfuscation.raw_data || {};
    
    // Risk Summary
    const riskScore = obfuscation.risk_score || 0;
    const riskLevel = obfuscation.risk_level || 'UNKNOWN';
    const summary = analysis.summary || 'No analysis summary available';
    
    // Determine risk color
    let riskColor = '#4CAF50'; // GREEN
    if (riskLevel === 'CRITICAL') riskColor = '#b71c1c';
    else if (riskLevel === 'HIGH') riskColor = '#f44336';
    else if (riskLevel === 'MEDIUM') riskColor = '#ff9800';
    else if (riskLevel === 'LOW') riskColor = '#ffc107';
    
    html += '<div class="obfuscation-summary" style="margin-bottom: 1.5rem;">';
    html += '<div style="display: flex; justify-content: space-between; align-items: center; background: ' + riskColor + '15; padding: 1.5rem; border-radius: 12px; border-left: 4px solid ' + riskColor + ';">';
    html += '<div>';
    html += '<h4 style="margin: 0 0 0.5rem 0; color: ' + riskColor + ';"><i class="fas fa-exclamation-triangle"></i> Risk Assessment</h4>';
    html += '<p style="margin: 0; color: var(--gray-dark);">' + escapeHtml(summary) + '</p>';
    html += '</div>';
    html += '<div style="text-align: center;">';
    html += '<div style="font-size: 2.5rem; font-weight: 700; color: ' + riskColor + ';">' + riskScore + '</div>';
    html += '<div style="font-size: 1rem; font-weight: 600; color: ' + riskColor + ';">' + riskLevel + '</div>';
    html += '</div>';
    html += '</div>';
    html += '</div>';
    
    const indicators = analysis.indicators || {};
    
    // High-Risk Features
    if (indicators.high_risk_features && indicators.high_risk_features.length > 0) {
        html += '<h4 style="margin-top: 1.5rem; margin-bottom: 1rem;"><i class="fas fa-exclamation-circle" style="color: #f44336;"></i> High-Risk Features Detected</h4>';
        html += '<div style="background: #fff3e0; padding: 1rem; border-radius: 8px; border-left: 4px solid #ff9800; margin-bottom: 1.5rem;">';
        
        indicators.high_risk_features.forEach(feature => {
            html += '<div style="margin-bottom: 1rem; padding: 0.75rem; background: white; border-radius: 6px;">';
            html += '<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">';
            html += '<strong style="color: #d32f2f; font-size: 1.1rem;"><code>' + escapeHtml(feature.feature) + '</code></strong>';
            html += '<span style="background: #d32f2f; color: white; padding: 0.25rem 0.75rem; border-radius: 12px; font-size: 0.85rem; font-weight: 600;">Count: ' + feature.count + '</span>';
            html += '</div>';
            html += '<p style="margin: 0; color: var(--gray-dark); font-size: 0.95rem;"><i class="fas fa-info-circle"></i> ' + escapeHtml(feature.description) + '</p>';
            html += '</div>';
        });
        
        html += '</div>';
    }
    
    // Structural Anomalies
    if (indicators.structural_anomalies && indicators.structural_anomalies.length > 0) {
        html += '<h4 style="margin-top: 1.5rem; margin-bottom: 1rem;"><i class="fas fa-wrench" style="color: #ff5722;"></i> Structural Anomalies</h4>';
        html += '<div style="background: #ffebee; padding: 1rem; border-radius: 8px; border-left: 4px solid #f44336; margin-bottom: 1.5rem;">';
        
        indicators.structural_anomalies.forEach(anomaly => {
            html += '<div style="margin-bottom: 1rem; padding: 0.75rem; background: white; border-radius: 6px;">';
            html += '<strong style="color: #c62828;">' + escapeHtml(anomaly.anomaly) + '</strong>';
            html += '<p style="margin: 0.5rem 0 0 0; font-family: monospace; font-size: 0.9rem; color: var(--gray-medium);">' + escapeHtml(anomaly.details) + '</p>';
            html += '<p style="margin: 0.5rem 0 0 0; color: var(--gray-dark); font-size: 0.95rem;"><i class="fas fa-shield-alt"></i> ' + escapeHtml(anomaly.risk) + '</p>';
            html += '</div>';
        });
        
        html += '</div>';
    }
    
    // Obfuscation Techniques
    if (indicators.obfuscation_techniques && indicators.obfuscation_techniques.length > 0) {
        html += '<h4 style="margin-top: 1.5rem; margin-bottom: 1rem;"><i class="fas fa-mask" style="color: #9c27b0;"></i> Obfuscation Techniques</h4>';
        html += '<div style="background: #f3e5f5; padding: 1rem; border-radius: 8px; border-left: 4px solid #9c27b0; margin-bottom: 1.5rem;">';
        
        indicators.obfuscation_techniques.forEach(tech => {
            html += '<div style="margin-bottom: 1rem; padding: 0.75rem; background: white; border-radius: 6px;">';
            html += '<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">';
            html += '<strong style="color: #7b1fa2;">' + escapeHtml(tech.technique) + '</strong>';
            html += '<span style="background: #9c27b0; color: white; padding: 0.25rem 0.75rem; border-radius: 12px; font-size: 0.85rem;">Count: ' + tech.count + '</span>';
            html += '</div>';
            html += '<p style="margin: 0; color: var(--gray-dark); font-size: 0.95rem;">' + escapeHtml(tech.description) + '</p>';
            html += '</div>';
        });
        
        html += '</div>';
    }
    
    // Suspicious Characteristics
    if (indicators.suspicious_characteristics && indicators.suspicious_characteristics.length > 0) {
        html += '<h4 style="margin-top: 1.5rem; margin-bottom: 1rem;"><i class="fas fa-search" style="color: #ff6f00;"></i> Suspicious Characteristics</h4>';
        html += '<div style="background: #fff8e1; padding: 1rem; border-radius: 8px; border-left: 4px solid #ffa726; margin-bottom: 1.5rem;">';
        
        indicators.suspicious_characteristics.forEach(char => {
            html += '<div style="margin-bottom: 1rem; padding: 0.75rem; background: white; border-radius: 6px;">';
            html += '<strong style="color: #e65100;">' + escapeHtml(char.characteristic) + '</strong>';
            html += '<p style="margin: 0.5rem 0 0 0; font-size: 0.9rem; color: var(--gray-medium);">' + escapeHtml(char.details) + '</p>';
            html += '<p style="margin: 0.5rem 0 0 0; color: var(--gray-dark); font-size: 0.95rem;"><i class="fas fa-exclamation-triangle"></i> ' + escapeHtml(char.concern) + '</p>';
            html += '</div>';
        });
        
        html += '</div>';
    }
    
    // Recommendations
    const recommendations = analysis.recommendations || [];
    if (recommendations.length > 0) {
        html += '<h4 style="margin-top: 1.5rem; margin-bottom: 1rem;"><i class="fas fa-clipboard-list" style="color: #2196F3;"></i> Recommended Actions</h4>';
        html += '<div style="background: #e3f2fd; padding: 1rem; border-radius: 8px; border-left: 4px solid #2196F3; margin-bottom: 1.5rem;">';
        
        recommendations.forEach(rec => {
            let priorityColor = '#4CAF50';
            if (rec.priority === 'CRITICAL') priorityColor = '#d32f2f';
            else if (rec.priority === 'HIGH') priorityColor = '#f44336';
            else if (rec.priority === 'MEDIUM') priorityColor = '#ff9800';
            
            html += '<div style="margin-bottom: 1rem; padding: 0.75rem; background: white; border-radius: 6px;">';
            html += '<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">';
            html += '<strong style="color: #1976d2;">' + escapeHtml(rec.action) + '</strong>';
            html += '<span style="background: ' + priorityColor + '; color: white; padding: 0.25rem 0.75rem; border-radius: 12px; font-size: 0.85rem; font-weight: 600;">' + rec.priority + '</span>';
            html += '</div>';
            html += '<p style="margin: 0; color: var(--gray-dark); font-size: 0.95rem;">' + escapeHtml(rec.details) + '</p>';
            html += '</div>';
        });
        
        html += '</div>';
    }
    
    // Raw PDF Structure Data
    if (rawData.counts && Object.keys(rawData.counts).length > 0) {
        html += '<h4 style="margin-top: 1.5rem; margin-bottom: 1rem;"><i class="fas fa-list"></i> PDF Structure Details</h4>';
        html += '<div style="background: #f5f5f5; padding: 1rem; border-radius: 8px; margin-bottom: 1rem;">';
        
        if (rawData.header) {
            html += '<div style="margin-bottom: 1rem; padding: 0.75rem; background: white; border-radius: 6px;">';
            html += '<strong>PDF Header:</strong> <code>' + escapeHtml(rawData.header) + '</code>';
            html += '</div>';
        }
        
        html += '<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 0.75rem;">';
        
        const counts = rawData.counts;
        Object.keys(counts).sort().forEach(key => {
            const value = counts[key];
            let keyClass = 'normal';
            if (key.startsWith('/JS') || key.startsWith('/JavaScript') || key.startsWith('/Launch') || key.startsWith('/AA') || key.startsWith('/OpenAction')) {
                keyClass = 'critical';
            } else if (key.startsWith('/Encrypt') || key.startsWith('/ObjStm') || key.startsWith('/EmbeddedFile')) {
                keyClass = 'warning';
            }
            
            let bgColor = 'white';
            let textColor = 'var(--gray-dark)';
            if (keyClass === 'critical' && value > 0) {
                bgColor = '#ffebee';
                textColor = '#c62828';
            } else if (keyClass === 'warning' && value > 0) {
                bgColor = '#fff8e1';
                textColor = '#f57c00';
            }
            
            html += '<div style="padding: 0.75rem; background: ' + bgColor + '; border-radius: 6px; display: flex; justify-content: space-between; align-items: center;">';
            html += '<span style="font-weight: 500; color: ' + textColor + ';"><code>' + escapeHtml(key) + '</code></span>';
            html += '<span style="font-weight: 700; color: ' + textColor + ';">' + value + '</span>';
            html += '</div>';
        });
        
        html += '</div>';
        html += '</div>';
    }
    
    return html;
}

// Show Results
function showResults(file, fileType) {
    uploadSection.style.display = 'none';
    warningMessage.style.display = 'none';
    resultsSection.style.display = 'block';
    
    // Populate file info
    document.getElementById('fileName').textContent = file.name;
    document.getElementById('fileSize').textContent = formatFileSize(file.size);
    document.getElementById('fileType').textContent = fileType;
    document.getElementById('uploadDate').textContent = new Date().toLocaleString();
    document.getElementById('fileTypeBadge').textContent = fileType;
}

// Calculate Hashes
async function calculateHashes(file) {
    try {
        const arrayBuffer = await file.arrayBuffer();
        
        // Calculate MD5
        const md5 = await calculateHash(arrayBuffer, 'MD5');
        document.getElementById('md5Hash').textContent = md5;
        
        // Calculate SHA-1
        const sha1 = await calculateHash(arrayBuffer, 'SHA-1');
        document.getElementById('sha1Hash').textContent = sha1;
        
        // Calculate SHA-256
        const sha256 = await calculateHash(arrayBuffer, 'SHA-256');
        document.getElementById('sha256Hash').textContent = sha256;
        
    } catch (error) {
        console.error('Error calculating hashes:', error);
        document.getElementById('md5Hash').textContent = 'Error';
        document.getElementById('sha1Hash').textContent = 'Error';
        document.getElementById('sha256Hash').textContent = 'Error';
    }
}

// Hash Calculation using Web Crypto API
async function calculateHash(arrayBuffer, algorithm) {
    // For MD5, we'll use a simple implementation since Web Crypto doesn't support it
    if (algorithm === 'MD5') {
        return calculateMD5(arrayBuffer);
    }
    
    const hashBuffer = await crypto.subtle.digest(algorithm, arrayBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    return hashHex;
}

// Simple MD5 implementation (for demonstration - in production, use a proper library)
function calculateMD5(arrayBuffer) {
    // This is a placeholder - in production, use a library like crypto-js or spark-md5
    // For now, we'll generate a pseudo-hash for demonstration
    const view = new Uint8Array(arrayBuffer);
    let hash = 0;
    for (let i = 0; i < view.length; i++) {
        hash = ((hash << 5) - hash) + view[i];
        hash = hash & hash;
    }
    return Math.abs(hash).toString(16).padStart(32, '0');
}

// Format File Size
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}

// Back Button
btnBack.addEventListener('click', () => {
    resultsSection.style.display = 'none';
    uploadSection.style.display = 'block';
    fileInput.value = '';
});

// Dismiss Warning
btnDismissWarning.addEventListener('click', () => {
    warningMessage.style.display = 'none';
    uploadSection.style.display = 'block';
    fileInput.value = '';
});

// Copy Hash to Clipboard
document.addEventListener('click', (e) => {
    if (e.target.closest('.btn-copy')) {
        const btn = e.target.closest('.btn-copy');
        const hashType = btn.dataset.hash;
        const hashValue = document.getElementById(`${hashType}Hash`).textContent;
        
        navigator.clipboard.writeText(hashValue).then(() => {
            // Change button appearance
            btn.classList.add('copied');
            btn.innerHTML = '<i class="fas fa-check"></i>';
            
            showNotification('Hash copied to clipboard!', 'success');
            
            // Reset button after 2 seconds
            setTimeout(() => {
                btn.classList.remove('copied');
                btn.innerHTML = '<i class="fas fa-copy"></i>';
            }, 2000);
        }).catch(err => {
            console.error('Failed to copy:', err);
            showNotification('Failed to copy hash', 'error');
        });
    }
});

// Navigate to settings
function navigateToSettings() {
    console.log('Navigate to settings page');
    // Will implement settings page navigation
}

// User Profile Click
const userProfile = document.querySelector('.user-profile');
userProfile.addEventListener('click', () => {
    const dropdown = document.createElement('div');
    dropdown.className = 'user-dropdown';
    dropdown.innerHTML = `
        <div class="dropdown-item" onclick="window.location.href='dashboard.html'">
            <i class="fas fa-th-large"></i> Dashboard
        </div>
        <div class="dropdown-item" onclick="logout()">
            <i class="fas fa-sign-out-alt"></i> Logout
        </div>
    `;
    
    const existingDropdown = document.querySelector('.user-dropdown');
    if (existingDropdown) {
        existingDropdown.remove();
    } else {
        userProfile.appendChild(dropdown);
        
        setTimeout(() => {
            document.addEventListener('click', function closeDropdown(e) {
                if (!userProfile.contains(e.target)) {
                    dropdown.remove();
                    document.removeEventListener('click', closeDropdown);
                }
            });
        }, 0);
    }
});

function logout() {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    localStorage.removeItem('analysisMode');
    window.location.href = '../../index.html';
}

// Notification system
function showNotification(message, type = 'success') {
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.innerHTML = `
        <i class="fas fa-${type === 'success' ? 'check-circle' : type === 'error' ? 'exclamation-circle' : 'info-circle'}"></i>
        <span>${message}</span>
    `;
    
    document.body.appendChild(notification);
    
    // Auto dismiss after 3 seconds
    setTimeout(() => {
        notification.style.animation = 'slideOut 0.3s ease';
        setTimeout(() => {
            notification.remove();
        }, 300);
    }, 3000);
    
    if (!document.getElementById('notification-styles')) {
        const style = document.createElement('style');
        style.id = 'notification-styles';
        style.textContent = `
            .notification {
                position: fixed;
                top: 20px;
                right: 20px;
                background: white;
                padding: 1rem 1.5rem;
                border-radius: 12px;
                box-shadow: 0 8px 24px rgba(0, 0, 0, 0.15);
                display: flex;
                align-items: center;
                gap: 0.75rem;
                z-index: 3000;
                animation: slideIn 0.3s ease;
            }
            
            @keyframes slideIn {
                from {
                    transform: translateX(400px);
                    opacity: 0;
                }
                to {
                    transform: translateX(0);
                    opacity: 1;
                }
            }
            
            @keyframes slideOut {
                from {
                    transform: translateX(0);
                    opacity: 1;
                }
                to {
                    transform: translateX(400px);
                    opacity: 0;
                }
            }
            
            .notification i {
                font-size: 1.5rem;
            }
            
            .notification-success i {
                color: #2e7d32;
            }
            
            .notification-error i {
                color: #c62828;
            }
            
            .notification-info i {
                color: #8519D5;
            }
            
            .user-dropdown {
                position: absolute;
                top: calc(100% + 10px);
                right: 0;
                background: white;
                border-radius: 12px;
                box-shadow: 0 8px 24px rgba(0, 0, 0, 0.15);
                min-width: 200px;
                overflow: hidden;
                animation: dropdownSlide 0.3s ease;
                z-index: 1000;
            }
            
            @keyframes dropdownSlide {
                from {
                    opacity: 0;
                    transform: translateY(-10px);
                }
                to {
                    opacity: 1;
                    transform: translateY(0);
                }
            }
            
            .dropdown-item {
                padding: 1rem 1.5rem;
                display: flex;
                align-items: center;
                gap: 0.75rem;
                cursor: pointer;
                transition: all 0.2s ease;
                color: #333;
            }
            
            .dropdown-item:hover {
                background: #f0f0f0;
            }
        `;
        document.head.appendChild(style);
    }
}

function generateVirusTotalHTML(vt) {
    let html = '';
    
    // Verdict banner
    const riskLevel = vt.risk_level || 'UNKNOWN';
    const verdict = vt.verdict || 'Unknown';
    const detectionRatio = vt.detection_ratio || '0/0';
    
    let bannerClass = 'vt-verdict-clean';
    if (riskLevel === 'CRITICAL') {
        bannerClass = 'vt-verdict-malicious';
    } else if (riskLevel === 'HIGH') {
        bannerClass = 'vt-verdict-high';
    } else if (riskLevel === 'MEDIUM') {
        bannerClass = 'vt-verdict-suspicious';
    }
    
    html += `
        <div class="vt-verdict ${bannerClass}">
            <i class="fas fa-shield-alt"></i>
            <div>
                <strong>${verdict}</strong>
                <p>Detection: ${detectionRatio}</p>
            </div>
            <div class="vt-score">${vt.statistics.malicious}/${vt.statistics.total}</div>
        </div>
    `;
    
    // Statistics
    const stats = vt.statistics;
    html += '<h4 style="margin-top: 1.5rem; margin-bottom: 1rem;"><i class="fas fa-chart-bar"></i> Detection Statistics</h4>';
    html += '<div class="vt-stats-grid">';
    html += `
        <div class="vt-stat-item vt-malicious">
            <i class="fas fa-bug"></i>
            <div>
                <div class="vt-stat-value">${stats.malicious}</div>
                <div class="vt-stat-label">Malicious</div>
            </div>
        </div>
        <div class="vt-stat-item vt-suspicious">
            <i class="fas fa-exclamation-triangle"></i>
            <div>
                <div class="vt-stat-value">${stats.suspicious}</div>
                <div class="vt-stat-label">Suspicious</div>
            </div>
        </div>
        <div class="vt-stat-item vt-undetected">
            <i class="fas fa-check-circle"></i>
            <div>
                <div class="vt-stat-value">${stats.undetected}</div>
                <div class="vt-stat-label">Undetected</div>
            </div>
        </div>
        <div class="vt-stat-item vt-harmless">
            <i class="fas fa-shield-check"></i>
            <div>
                <div class="vt-stat-value">${stats.harmless}</div>
                <div class="vt-stat-label">Harmless</div>
            </div>
        </div>
    `;
    html += '</div>';
    
    // Detections list
    if (vt.detections && vt.detections.length > 0) {
        html += `<h4 style="margin-top: 1.5rem; margin-bottom: 1rem;"><i class="fas fa-list"></i> Detection Details (${vt.detections.length} engines)</h4>`;
        html += '<div class="vt-detections">';
        
        vt.detections.forEach(detection => {
            const categoryClass = detection.category === 'malicious' ? 'vt-det-malicious' : 'vt-det-suspicious';
            html += `
                <div class="vt-detection ${categoryClass}">
                    <div class="vt-det-header">
                        <strong>${detection.engine}</strong>
                        <span class="vt-det-category">${detection.category}</span>
                    </div>
                    <div class="vt-det-result">${detection.result}</div>
                </div>
            `;
        });
        
        html += '</div>';
    }
    
    // File information
    if (vt.file_info) {
        html += '<h4 style="margin-top: 1.5rem; margin-bottom: 1rem;"><i class="fas fa-info-circle"></i> File Information</h4>';
        html += '<div class="vt-file-info">';
        html += `<div class="vt-info-item"><strong>Type:</strong> ${vt.file_info.type}</div>`;
        html += `<div class="vt-info-item"><strong>Size:</strong> ${(vt.file_info.size / 1024).toFixed(2)} KB</div>`;
        if (vt.times_submitted) {
            html += `<div class="vt-info-item"><strong>Times Submitted:</strong> ${vt.times_submitted}</div>`;
        }
        if (vt.reputation !== undefined) {
            html += `<div class="vt-info-item"><strong>Reputation:</strong> ${vt.reputation}</div>`;
        }
        if (vt.file_info.names && vt.file_info.names.length > 0) {
            html += `<div class="vt-info-item"><strong>Known Names:</strong> ${vt.file_info.names.join(', ')}</div>`;
        }
        html += '</div>';
    }
    
    // Scan dates
    if (vt.scan_date) {
        const scanDate = new Date(vt.scan_date * 1000).toLocaleString();
        html += `<div class="vt-scan-date"><i class="fas fa-clock"></i> Last scanned: ${scanDate}</div>`;
    }
    
    return html;
}

// Generate Strings Analysis HTML
function generateStringsAnalysisHTML(strings) {
    let html = '<div class="strings-summary">';
    
    // Summary Statistics
    html += '<div class="strings-stats">';
    html += `<div class="stat-item">
        <span class="stat-label">Total Strings Extracted:</span>
        <span class="stat-value">${strings.total_strings || 0}</span>
    </div>`;
    html += `<div class="stat-item">
        <span class="stat-label">Risk Score:</span>
        <span class="stat-value risk-level-${strings.risk_level?.toLowerCase() || 'low'}">${strings.risk_score || 0} (${strings.risk_level || 'LOW'})</span>
    </div>`;
    html += '</div>';
    
    const indicators = strings.indicators || {};
    
    // Suspicious Commands Section (New - High Priority) with Classification
    if (indicators.suspicious_commands && indicators.suspicious_commands.length > 0) {
        html += '<div class="indicator-section dangerous-section">';
        html += '<h4><i class="fas fa-terminal"></i> Suspicious Commands Detected</h4>';
        html += '<div class="indicator-list">';
        indicators.suspicious_commands.forEach(cmd => {
            // Check if cmd is an object with classification data or just a string
            const cmdString = typeof cmd === 'object' ? cmd.string : cmd;
            const category = typeof cmd === 'object' ? cmd.category : 'UNKNOWN';
            const riskLevel = typeof cmd === 'object' ? cmd.risk_level : 'HIGH';
            const reason = typeof cmd === 'object' ? cmd.reason : 'Suspicious pattern detected';
            
            // Get badge color based on risk level
            let badgeClass = 'command-badge';
            let badgeText = riskLevel;
            if (riskLevel === 'CRITICAL') {
                badgeClass += ' badge-critical';
            } else if (riskLevel === 'HIGH') {
                badgeClass += ' badge-high';
            } else if (riskLevel === 'MEDIUM') {
                badgeClass += ' badge-medium';
            }
            
            // Get category icon
            let categoryIcon = 'fas fa-terminal';
            if (category === 'LOLBIN') categoryIcon = 'fas fa-tools';
            else if (category === 'PERSISTENCE_COMMAND') categoryIcon = 'fas fa-repeat';
            else if (category === 'ENCODED_PAYLOAD') categoryIcon = 'fas fa-lock';
            else if (category === 'NETWORK_TOOL') categoryIcon = 'fas fa-network-wired';
            
            html += `<div class="indicator-item command-item">
                <span class="indicator-icon danger-icon"><i class="${categoryIcon}"></i></span>
                <div class="command-content">
                    <div class="command-header">
                        <span class="command-category">${category.replace(/_/g, ' ')}</span>
                        <span class="${badgeClass}">${badgeText}</span>
                    </div>
                    <span class="command-text">${escapeHtml(cmdString)}</span>
                    <span class="command-reason"><i class="fas fa-info-circle"></i> ${escapeHtml(reason)}</span>
                </div>
            </div>`;
        });
        html += '</div>';
        html += '</div>';
    }
    
    // URLs - Enhanced with clickable links
    if (indicators.urls && indicators.urls.length > 0) {
        html += '<div class="indicator-section url-section">';
        html += '<h4><i class="fas fa-link"></i> URLs Found</h4>';
        html += '<div class="indicator-list">';
        indicators.urls.forEach(url => {
            const urlSafe = escapeHtml(url);
            html += `<div class="indicator-item url-item">
                <span class="indicator-icon"><i class="fas fa-globe"></i></span>
                <a href="${urlSafe}" target="_blank" rel="noopener noreferrer" class="indicator-text url-link">
                    ${urlSafe}
                    <i class="fas fa-external-link-alt"></i>
                </a>
            </div>`;
        });
        html += '</div>';
        html += '</div>';
        
        // VirusTotal URL Results
        if (strings.vt_url_results && strings.vt_url_results.length > 0) {
            html += '<div class="vt-url-section">';
            html += '<h4><i class="fas fa-shield-alt"></i> VirusTotal URL Analysis</h4>';
            strings.vt_url_results.forEach(result => {
                const isMalicious = result.malicious_count > 0;
                html += `<div class="vt-url-result ${isMalicious ? 'malicious' : 'clean'}">
                    <div class="vt-url-header">
                        <span class="vt-url-icon">
                            ${isMalicious ? '<i class="fas fa-exclamation-triangle"></i>' : '<i class="fas fa-check-circle"></i>'}
                        </span>
                        <span class="vt-url-text">${escapeHtml(result.url)}</span>
                    </div>
                    <div class="vt-url-stats">
                        <span class="vt-stat malicious">Malicious: ${result.malicious_count}</span>
                        <span class="vt-stat suspicious">Suspicious: ${result.suspicious_count}</span>
                        <span class="vt-stat clean">Clean: ${result.harmless_count}</span>
                        <span class="vt-stat undetected">Undetected: ${result.undetected_count}</span>
                    </div>
                </div>`;
            });
            html += '</div>';
        }
    }
    
    // IP Addresses - Enhanced with badges
    if (indicators.ip_addresses && indicators.ip_addresses.length > 0) {
        html += '<div class="indicator-section ip-section">';
        html += '<h4><i class="fas fa-network-wired"></i> IP Addresses</h4>';
        html += '<div class="indicator-list">';
        indicators.ip_addresses.forEach(ip => {
            html += `<div class="indicator-item ip-item">
                <span class="indicator-icon"><i class="fas fa-server"></i></span>
                <div class="ip-content">
                    <span class="indicator-text">${escapeHtml(ip)}</span>
                    <span class="ip-badge">Network IOC</span>
                </div>
            </div>`;
        });
        html += '</div>';
        html += '</div>';
    }
    
    // Domains - New dedicated section
    if (indicators.domains && indicators.domains.length > 0) {
        html += '<div class="indicator-section domain-section">';
        html += '<h4><i class="fas fa-globe-americas"></i> Domains Found</h4>';
        html += '<div class="indicator-list">';
        indicators.domains.forEach(domain => {
            html += `<div class="indicator-item domain-item">
                <span class="indicator-icon"><i class="fas fa-sitemap"></i></span>
                <span class="indicator-text">${escapeHtml(domain)}</span>
            </div>`;
        });
        html += '</div>';
        html += '</div>';
    }
    
    // Suspicious API Calls
    if (indicators.suspicious_apis && indicators.suspicious_apis.length > 0) {
        html += '<div class="indicator-section dangerous">';
        html += '<h4><i class="fas fa-exclamation-triangle"></i> Suspicious API Calls</h4>';
        html += '<div class="indicator-list">';
        indicators.suspicious_apis.forEach(api => {
            html += `<div class="indicator-item api-item">
                <span class="indicator-icon"><i class="fas fa-code"></i></span>
                <span class="indicator-text">${escapeHtml(api)}</span>
            </div>`;
        });
        html += '</div>';
        html += '</div>';
    }
    
    // DLL Files
    if (indicators.dll_files && indicators.dll_files.length > 0) {
        html += '<div class="indicator-section">';
        html += '<h4><i class="fas fa-file-code"></i> DLL References</h4>';
        html += '<div class="indicator-list">';
        indicators.dll_files.forEach(dll => {
            html += `<div class="indicator-item dll-item">
                <span class="indicator-icon"><i class="fas fa-cube"></i></span>
                <span class="indicator-text">${escapeHtml(dll)}</span>
            </div>`;
        });
        html += '</div>';
        html += '</div>';
    }
    
    // Registry Keys - Enhanced with warning styling
    if (indicators.registry_keys && indicators.registry_keys.length > 0) {
        html += '<div class="indicator-section registry-section">';
        html += '<h4><i class="fas fa-key"></i> Registry Keys</h4>';
        html += '<div class="indicator-list">';
        indicators.registry_keys.forEach(key => {
            html += `<div class="indicator-item registry-item">
                <span class="indicator-icon"><i class="fas fa-database"></i></span>
                <div class="registry-content">
                    <span class="indicator-text">${escapeHtml(key)}</span>
                    <span class="registry-badge">Registry IOC</span>
                </div>
            </div>`;
        });
        html += '</div>';
        html += '</div>';
    }
    
    // File Paths - Enhanced with folder icon
    if (indicators.file_paths && indicators.file_paths.length > 0) {
        html += '<div class="indicator-section path-section">';
        html += '<h4><i class="fas fa-folder-open"></i> File Paths Detected</h4>';
        html += '<div class="indicator-list">';
        indicators.file_paths.forEach(path => {
            html += `<div class="indicator-item path-item">
                <span class="indicator-icon"><i class="fas fa-folder"></i></span>
                <div class="path-content">
                    <span class="indicator-text">${escapeHtml(path)}</span>
                </div>
            </div>`;
        });
        html += '</div>';
        html += '</div>';
    }
    
    // Email Addresses
    if (indicators.emails && indicators.emails.length > 0) {
        html += '<div class="indicator-section">';
        html += '<h4><i class="fas fa-envelope"></i> Email Addresses</h4>';
        html += '<div class="indicator-list">';
        indicators.emails.forEach(email => {
            html += `<div class="indicator-item email-item">
                <span class="indicator-icon"><i class="fas fa-at"></i></span>
                <span class="indicator-text">${escapeHtml(email)}</span>
            </div>`;
        });
        html += '</div>';
        html += '</div>';
    }
    
    // Check if any indicators were found
    const hasIndicators = (indicators.suspicious_commands && indicators.suspicious_commands.length > 0) ||
                          (indicators.urls && indicators.urls.length > 0) ||
                          (indicators.ip_addresses && indicators.ip_addresses.length > 0) ||
                          (indicators.domains && indicators.domains.length > 0) ||
                          (indicators.suspicious_apis && indicators.suspicious_apis.length > 0) ||
                          (indicators.dll_files && indicators.dll_files.length > 0) ||
                          (indicators.registry_keys && indicators.registry_keys.length > 0) ||
                          (indicators.file_paths && indicators.file_paths.length > 0) ||
                          (indicators.emails && indicators.emails.length > 0);
    
    if (!hasIndicators) {
        html += '<div class="indicator-section">';
        html += '<div style="text-align: center; padding: 2rem; color: var(--gray-medium);">';
        html += '<i class="fas fa-info-circle" style="font-size: 2rem; margin-bottom: 1rem;"></i>';
        html += '<p>No suspicious indicators detected in the extracted strings.</p>';
        html += '<p style="font-size: 0.9rem; margin-top: 0.5rem;">This file appears to contain mostly benign strings.</p>';
        html += '</div>';
        html += '</div>';
    }
    
    html += '</div>';
    return html;
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Display standalone CVSS Risk Card
function displayCVSSCard(data) {
    const cvssCard = document.getElementById('cvssCard');
    const cvssContent = document.getElementById('cvssContent');
    
    if (!cvssCard || !cvssContent) return;
    
    const cvssScore = data.cvss_score;
    const severity = data.severity || 'None';
    const threatLevel = data.threat_level || 'Safe';
    const verdict = data.verdict || 'No threats detected';
    const recommendation = data.recommendation || '';
    
    if (cvssScore === undefined) {
        cvssCard.style.display = 'none';
        return;
    }
    
    // Generate CVSS HTML
    let html = `
        <div class="cvss-risk-box cvss-${severity.toLowerCase()}">
            <div class="cvss-header">
                <i class="fas fa-shield-alt"></i> CVSS Risk Assessment
            </div>
            <div class="cvss-score-display">
                <div class="cvss-score-circle">
                    <div class="cvss-score-value">${cvssScore.toFixed(1)}</div>
                    <div class="cvss-score-max">/10.0</div>
                </div>
                <div class="cvss-details">
                    <div class="cvss-severity">${severity.toUpperCase()}</div>
                    <div class="cvss-threat-level">${threatLevel}</div>
                    <div class="cvss-verdict">${verdict}</div>
                </div>
            </div>
    `;
    
    // Add contributing factors if available
    if (data.contributing_factors && data.contributing_factors.length > 0) {
        html += `
            <div class="cvss-factors">
                <h4><i class="fas fa-list-ul"></i> Threat Indicators</h4>
                <div class="factors-list">
        `;
        
        data.contributing_factors.slice(0, 5).forEach(factor => {
            const indicatorName = factor.indicator.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
            html += `
                <div class="factor-item">
                    <span class="factor-name">${indicatorName}</span>
                    <span class="factor-impact">+${factor.contribution.toFixed(1)} pts</span>
                </div>
            `;
        });
        
        html += `
                </div>
            </div>
        `;
    }
    
    // Add recommendation
    if (recommendation) {
        html += `
            <div class="cvss-recommendation">
                <i class="fas fa-info-circle"></i>
                <span>${recommendation}</span>
            </div>
        `;
    }
    
    html += `</div>`;
    
    cvssContent.innerHTML = html;
    cvssCard.style.display = 'block';
}

// ============= CAPA ANALYSIS HTML GENERATION =============

function generateCapaAnalysisHTML(capaData) {
    if (!capaData || capaData.error) {
        return `<div class="error-message">
            <i class="fas fa-exclamation-triangle"></i>
            <p>Error: ${capaData.error || 'Unknown error occurred during CAPA analysis'}</p>
        </div>`;
    }

    let html = '<div class="capa-analysis-container">';
    
    // File Information Section
    if (capaData.file_info && Object.keys(capaData.file_info).length > 0) {
        html += '<div class="capa-section capa-file-info">';
        html += '<h4><i class="fas fa-file-code"></i> File Information</h4>';
        html += '<div class="info-grid">';
        
        const fileInfoOrder = ['md5', 'sha1', 'sha256', 'analysis', 'os', 'format', 'arch'];
        fileInfoOrder.forEach(key => {
            if (capaData.file_info[key]) {
                html += `
                    <div class="info-item">
                        <span class="info-label">${key.toUpperCase()}:</span>
                        <span class="info-value">${escapeHtml(capaData.file_info[key])}</span>
                    </div>`;
            }
        });
        
        html += '</div></div>';
    }

    // ATT&CK Tactics & Techniques Section
    if (capaData.attack_tactics && capaData.attack_tactics.length > 0) {
        html += '<div class="capa-section capa-attack">';
        html += '<h4><i class="fas fa-crosshairs"></i> MITRE ATT&CK Techniques</h4>';
        html += '<p class="section-description">Identified ATT&CK techniques that this malware may employ</p>';
        html += '<div class="attack-grid">';
        
        capaData.attack_tactics.forEach(item => {
            const attackUrl = item.technique_id ? 
                `https://attack.mitre.org/techniques/${item.technique_id.replace('.', '/')}` : '#';
            
            html += `
                <div class="attack-item">
                    <div class="attack-tactic">
                        <i class="fas fa-shield-alt"></i>
                        <span>${escapeHtml(item.tactic)}</span>
                    </div>
                    <div class="attack-technique">
                        <a href="${attackUrl}" target="_blank" class="technique-link" title="View on MITRE ATT&CK">
                            <span class="technique-name">${escapeHtml(item.technique)}</span>
                            <span class="technique-id">${escapeHtml(item.technique_id)}</span>
                            <i class="fas fa-external-link-alt"></i>
                        </a>
                    </div>
                </div>`;
        });
        
        html += '</div></div>';
    }

    // MBC Objectives & Behaviors Section
    if (capaData.mbc_objectives && capaData.mbc_objectives.length > 0) {
        html += '<div class="capa-section capa-mbc">';
        html += '<h4><i class="fas fa-chess"></i> Malware Behavior Catalog (MBC)</h4>';
        html += '<p class="section-description">Detailed behavioral patterns and objectives</p>';
        html += '<div class="mbc-grid">';
        
        capaData.mbc_objectives.forEach(item => {
            html += `
                <div class="mbc-item">
                    <div class="mbc-objective">
                        <i class="fas fa-bullseye"></i>
                        <span>${escapeHtml(item.objective)}</span>
                    </div>
                    <div class="mbc-behavior">
                        <span class="behavior-name">${escapeHtml(item.behavior)}</span>
                        ${item.mbc_id ? `<span class="mbc-id">[${escapeHtml(item.mbc_id)}]</span>` : ''}
                    </div>
                </div>`;
        });
        
        html += '</div></div>';
    }

    // Capabilities Section (The Star of the Show!)
    if (capaData.capabilities && capaData.capabilities.length > 0) {
        html += '<div class="capa-section capa-capabilities">';
        html += '<h4><i class="fas fa-brain"></i> Detected Capabilities</h4>';
        html += '<p class="section-description">Specific malware capabilities and techniques identified in the binary</p>';
        
        // Group capabilities by namespace
        const groupedCaps = {};
        capaData.capabilities.forEach(cap => {
            const namespace = cap.namespace || 'uncategorized';
            if (!groupedCaps[namespace]) {
                groupedCaps[namespace] = [];
            }
            groupedCaps[namespace].push(cap);
        });
        
        // Sort namespaces alphabetically
        const sortedNamespaces = Object.keys(groupedCaps).sort();
        
        html += '<div class="capabilities-list">';
        
        sortedNamespaces.forEach(namespace => {
            const caps = groupedCaps[namespace];
            
            html += `
                <div class="capability-namespace-group">
                    <div class="namespace-header">
                        <i class="fas fa-folder-open"></i>
                        <span class="namespace-name">${escapeHtml(namespace)}</span>
                        <span class="namespace-count">${caps.length} ${caps.length === 1 ? 'capability' : 'capabilities'}</span>
                    </div>
                    <div class="namespace-capabilities">`;
            
            caps.forEach(cap => {
                html += `
                    <div class="capability-item" onclick="showCapaRule('${escapeHtml(cap.namespace)}', '${escapeHtml(cap.capability)}')">
                        <div class="capability-main">
                            <i class="fas fa-code"></i>
                            <span class="capability-name">${escapeHtml(cap.capability)}</span>
                            ${cap.match_count > 1 ? `<span class="match-count">${cap.match_count} matches</span>` : ''}
                        </div>
                        <div class="capability-action">
                            <span class="view-rule-btn">
                                <i class="fas fa-file-code"></i> View Rule
                            </span>
                        </div>
                    </div>`;
            });
            
            html += `
                    </div>
                </div>`;
        });
        
        html += '</div></div>';
    }

    // Summary statistics
    const attackCount = capaData.attack_tactics ? capaData.attack_tactics.length : 0;
    const mbcCount = capaData.mbc_objectives ? capaData.mbc_objectives.length : 0;
    const capCount = capaData.capabilities ? capaData.capabilities.length : 0;
    
    html += `
        <div class="capa-section capa-summary">
            <h4><i class="fas fa-chart-bar"></i> Analysis Summary</h4>
            <div class="summary-stats">
                <div class="stat-item">
                    <div class="stat-value">${attackCount}</div>
                    <div class="stat-label">ATT&CK Techniques</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">${mbcCount}</div>
                    <div class="stat-label">MBC Behaviors</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">${capCount}</div>
                    <div class="stat-label">Capabilities Detected</div>
                </div>
            </div>
        </div>`;

    html += '</div>';
    return html;
}

// ============= CAPA RULE MODAL FUNCTIONS =============

function showCapaRule(namespace, capabilityName) {
    const modal = document.getElementById('capaRuleModal');
    const modalRuleName = document.getElementById('modalRuleName');
    const modalRuleNamespace = document.getElementById('modalRuleNamespace');
    const modalRuleContent = document.getElementById('modalRuleContent');
    
    // Show modal with loading state
    modalRuleName.textContent = capabilityName;
    modalRuleNamespace.textContent = namespace;
    modalRuleContent.innerHTML = '<div style="text-align: center; padding: 2rem;"><i class="fas fa-spinner fa-spin" style="font-size: 2rem; color: #00d9ff;"></i><p style="margin-top: 1rem;">Loading rule details...</p></div>';
    modal.style.display = 'flex';
    
    // Fetch rule content from backend
    fetch('/api/get-capa-rule', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + localStorage.getItem('token')
        },
        body: JSON.stringify({
            namespace: namespace,
            capability: capabilityName
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success && data.rule_content) {
            // Parse and format YAML into structured display
            const parsedRule = parseCapaYaml(data.rule_content);
            modalRuleContent.innerHTML = generateRuleHTML(parsedRule, data.file_path);
        } else if (data.error && (data.error.includes('not found') || data.error.includes('Rule not found'))) {
            // Handle built-in rules that don't have YAML files
            modalRuleContent.innerHTML = generateBuiltInRuleMessage(capabilityName, namespace);
        } else {
            modalRuleContent.innerHTML = `<div class="error-message"><i class="fas fa-exclamation-circle"></i> <strong>Error:</strong> ${data.error || 'Unable to load rule details'}</div>`;
        }
    })
    .catch(error => {
        modalRuleContent.innerHTML = `<div class="error-message"><i class="fas fa-exclamation-circle"></i> <strong>Error loading rule:</strong> ${error.message}</div>`;
    });
}

function closeCapaRuleModal() {
    const modal = document.getElementById('capaRuleModal');
    modal.style.display = 'none';
}

// Close modal when clicking outside
window.onclick = function(event) {
    const modal = document.getElementById('capaRuleModal');
    if (event.target === modal) {
        closeCapaRuleModal();
    }
}

// Generate message for built-in rules that don't have YAML files
function generateBuiltInRuleMessage(capabilityName, namespace) {
    return `
        <div class="built-in-rule-message">
            <div class="built-in-icon">
                <i class="fas fa-shield-alt"></i>
            </div>
            <div class="built-in-content">
                <h3>Built-In Rule Detected</h3>
                <div class="built-in-details">
                    <div class="built-in-detail-row">
                        <label><i class="fas fa-tag"></i> Capability:</label>
                        <div class="built-in-value">${escapeHtml(capabilityName)}</div>
                    </div>
                    <div class="built-in-detail-row">
                        <label><i class="fas fa-folder"></i> Namespace:</label>
                        <div class="built-in-value">${escapeHtml(namespace)}</div>
                    </div>
                </div>
                <div class="built-in-info">
                    <i class="fas fa-lightbulb"></i>
                    <div class="built-in-info-text">
                        <p><strong>What does this mean?</strong></p>
                        <p>This is a built-in CAPA rule that was successfully detected in the analyzed file. 
                        Built-in rules are core detection patterns integrated directly into the CAPA engine and don't have 
                        separate YAML definition files available for detailed viewing.</p>
                        <p>The detection indicates that the analyzed file exhibits behavior or characteristics matching this capability.</p>
                    </div>
                </div>
                <div class="built-in-status">
                    <i class="fas fa-check-circle"></i>
                    <span>Rule Successfully Matched</span>
                </div>
            </div>
        </div>
    `;
}

// Parse CAPA YAML rule into structured data
function parseCapaYaml(yamlText) {
    const rule = {
        meta: {},
        scopes: [],
        mbc: [],
        attack: [],
        references: [],
        examples: [],
        features: []
    };
    
    const lines = yamlText.split('\n');
    let currentSection = null;
    
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const trimmed = line.trim();
        
        if (!trimmed || trimmed.startsWith('#')) continue;
        
        const indent = line.search(/\S/);
        
        // Detect sections
        if (trimmed === 'rule:') currentSection = 'rule';
        else if (trimmed === 'meta:') currentSection = 'meta';
        else if (trimmed === 'features:') currentSection = 'features';
        else if (trimmed === 'scopes:') currentSection = 'scopes';
        else if (trimmed === 'mbc:') currentSection = 'mbc';
        else if (trimmed === 'att&ck:' || trimmed === 'attack:') currentSection = 'attack';
        else if (trimmed === 'references:') currentSection = 'references';
        else if (trimmed === 'examples:') currentSection = 'examples';
        else if (trimmed === 'authors:') currentSection = 'authors';
        else if (currentSection === 'meta') {
            const match = trimmed.match(/^([\w-]+):\s*(.*)$/);
            if (match) {
                const key = match[1];
                let value = match[2];
                
                // Handle multi-line descriptions and other multi-line values
                if ((key === 'description' || key === 'lib') && value) {
                    // Check if value continues on next lines
                    let j = i + 1;
                    while (j < lines.length) {
                        const nextLine = lines[j];
                        const nextTrimmed = nextLine.trim();
                        const nextIndent = nextLine.search(/\S/);
                        
                        // Continue if next line is indented more than current meta section
                        // and doesn't start a new key or list item
                        if (nextTrimmed && 
                            nextIndent > 2 && 
                            !nextTrimmed.match(/^[\w-]+:/) && 
                            !nextTrimmed.startsWith('-')) {
                            value += ' ' + nextTrimmed;
                            i = j;
                            j++;
                        } else {
                            break;
                        }
                    }
                }
                
                rule.meta[key] = value;
            }
        }
        else if (currentSection === 'scopes' && trimmed.startsWith('-')) {
            rule.scopes.push(trimmed.substring(1).trim());
        }
        else if (currentSection === 'mbc' && trimmed.startsWith('-')) {
            rule.mbc.push(trimmed.substring(1).trim());
        }
        else if (currentSection === 'attack' && trimmed.startsWith('-')) {
            rule.attack.push(trimmed.substring(1).trim());
        }
        else if (currentSection === 'references' && trimmed.startsWith('-')) {
            rule.references.push(trimmed.substring(1).trim());
        }
        else if (currentSection === 'examples' && trimmed.startsWith('-')) {
            rule.examples.push(trimmed.substring(1).trim());
        }
        else if (currentSection === 'authors' && trimmed.startsWith('-')) {
            if (!rule.meta.authors) rule.meta.authors = [];
            rule.meta.authors.push(trimmed.substring(1).trim());
        }
        else if (currentSection === 'features') {
            if (trimmed.startsWith('- ')) {
                const feature = trimmed.substring(2);
                rule.features.push({ type: 'item', value: feature, indent: indent });
            } else if (trimmed.includes(':')) {
                const match = trimmed.match(/^([\w-]+):\s*(.*)$/);
                if (match) {
                    rule.features.push({ type: 'key', key: match[1], value: match[2], indent: indent });
                }
            }
        }
    }
    
    return rule;
}

// Generate beautiful HTML for CAPA rule
function generateRuleHTML(rule, filePath) {
    let html = '<div class="capa-rule-display">';
    
    // Rule metadata header
    html += '<div class="rule-section rule-header">';
    html += `<div class="rule-meta-grid">`;
    
    if (rule.meta.name) {
        html += `<div class="rule-meta-item"><label><i class="fas fa-tag"></i> Rule Name</label><div class="rule-meta-value">${escapeHtml(rule.meta.name)}</div></div>`;
    }
    if (rule.meta.namespace) {
        html += `<div class="rule-meta-item"><label><i class="fas fa-folder"></i> Namespace</label><div class="rule-meta-value">${escapeHtml(rule.meta.namespace)}</div></div>`;
    }
    if (rule.meta.authors && rule.meta.authors.length > 0) {
        html += `<div class="rule-meta-item"><label><i class="fas fa-user"></i> Author(s)</label><div class="rule-meta-value">${rule.meta.authors.map(a => escapeHtml(a)).join(', ')}</div></div>`;
    }
    if (filePath) {
        html += `<div class="rule-meta-item rule-file-path"><label><i class="fas fa-file-code"></i> File Path</label><div class="rule-meta-value"><code>${escapeHtml(filePath)}</code></div></div>`;
    }
    
    html += '</div></div>';
    
    // Description section (if available)
    if (rule.meta.description) {
        html += '<div class="rule-section rule-description-section">';
        html += '<h4 class="rule-section-title"><i class="fas fa-info-circle"></i> Description</h4>';
        html += `<div class="rule-description-text">${escapeHtml(rule.meta.description)}</div>`;
        html += '</div>';
    }
    
    // Scopes
    if (rule.scopes && rule.scopes.length > 0) {
        html += '<div class="rule-section">';
        html += '<h4 class="rule-section-title"><i class="fas fa-crosshairs"></i> Scopes</h4>';
        html += '<div class="rule-badges">';
        rule.scopes.forEach(scope => {
            const cleanScope = scope.split(':')[0].trim();
            html += `<span class="rule-badge scope-badge">${escapeHtml(cleanScope)}</span>`;
        });
        html += '</div></div>';
    }
    
    // MBC Behaviors
    if (rule.mbc && rule.mbc.length > 0) {
        html += '<div class="rule-section">';
        html += '<h4 class="rule-section-title"><i class="fas fa-shield-virus"></i> MBC Malware Behaviors</h4>';
        html += '<div class="rule-technique-list">';
        rule.mbc.forEach(mbc => {
            const match = mbc.match(/^(.+?)\s*\[([A-Z]\d+(?:\.\d+)*)\]/);
            if (match) {
                const name = match[1].trim();
                const id = match[2];
                html += `<div class="rule-technique-item mbc-item">`;
                html += `<span class="technique-id">${escapeHtml(id)}</span>`;
                html += `<span class="technique-name">${escapeHtml(name)}</span>`;
                html += `</div>`;
            } else {
                html += `<div class="rule-technique-item mbc-item"><span class="technique-name">${escapeHtml(mbc)}</span></div>`;
            }
        });
        html += '</div></div>';
    }
    
    // ATT&CK Techniques
    if (rule.attack && rule.attack.length > 0) {
        html += '<div class="rule-section">';
        html += '<h4 class="rule-section-title"><i class="fas fa-bullseye"></i> MITRE ATT&CK Techniques</h4>';
        html += '<div class="rule-technique-list">';
        rule.attack.forEach(attack => {
            const parts = attack.split('::');
            if (parts.length >= 2) {
                const tactic = parts[0].trim();
                const technique = parts[1].trim();
                const match = technique.match(/^(.+?)\s*\[([T]\d+(?:\.\d+)*)\]/);
                if (match) {
                    const name = match[1].trim();
                    const id = match[2];
                    html += `<div class="rule-technique-item attack-item">`;
                    html += `<span class="technique-tactic">${escapeHtml(tactic)}</span>`;
                    html += `<span class="technique-id">${escapeHtml(id)}</span>`;
                    html += `<span class="technique-name">${escapeHtml(name)}</span>`;
                    html += `</div>`;
                } else {
                    html += `<div class="rule-technique-item attack-item"><span class="technique-name">${escapeHtml(attack)}</span></div>`;
                }
            }
        });
        html += '</div></div>';
    }
    
    // References
    if (rule.references && rule.references.length > 0) {
        html += '<div class="rule-section">';
        html += '<h4 class="rule-section-title"><i class="fas fa-link"></i> References</h4>';
        html += '<div class="rule-references">';
        rule.references.forEach(ref => {
            if (ref.startsWith('http://') || ref.startsWith('https://')) {
                html += `<a href="${escapeHtml(ref)}" target="_blank" class="rule-reference-link"><i class="fas fa-external-link-alt"></i> ${escapeHtml(ref)}</a>`;
            } else {
                html += `<div class="rule-reference-text">${escapeHtml(ref)}</div>`;
            }
        });
        html += '</div></div>';
    }
    
    // Examples
    if (rule.examples && rule.examples.length > 0) {
        html += '<div class="rule-section">';
        html += '<h4 class="rule-section-title"><i class="fas fa-file-archive"></i> Example Samples</h4>';
        html += '<div class="rule-examples">';
        rule.examples.forEach(example => {
            html += `<code class="rule-example-hash">${escapeHtml(example)}</code>`;
        });
        html += '</div></div>';
    }
    
    // Features
    if (rule.features && rule.features.length > 0) {
        html += '<div class="rule-section rule-features-section">';
        html += '<h4 class="rule-section-title"><i class="fas fa-code"></i> Detection Features</h4>';
        html += '<div class="rule-features-description">These are the specific indicators that CAPA looks for in the binary:</div>';
        html += '<div class="rule-features-list">';
        
        rule.features.forEach((feature) => {
            const indentLevel = Math.floor(feature.indent / 2);
            
            if (feature.type === 'key') {
                const keyClass = getFeatureKeyClass(feature.key);
                html += `<div class="rule-feature-item" style="margin-left: ${indentLevel * 20}px;">`;
                html += `<span class="feature-key ${keyClass}">${escapeHtml(feature.key)}:</span>`;
                if (feature.value) {
                    html += `<span class="feature-value">${escapeHtml(feature.value)}</span>`;
                }
                html += `</div>`;
            } else if (feature.type === 'item') {
                html += `<div class="rule-feature-item" style="margin-left: ${indentLevel * 20}px;">`;
                html += `<span class="feature-bullet">•</span>`;
                html += `<span class="feature-value">${formatFeatureValue(feature.value)}</span>`;
                html += `</div>`;
            }
        });
        
        html += '</div></div>';
    }
    
    html += '</div>';
    return html;
}

function getFeatureKeyClass(key) {
    const logicalOps = ['or', 'and', 'not', 'optional'];
    const featureTypes = ['string', 'api', 'number', 'bytes', 'mnemonic', 'characteristic', 'match'];
    
    if (logicalOps.includes(key.toLowerCase())) return 'feature-key-logical';
    if (featureTypes.includes(key.toLowerCase())) return 'feature-key-type';
    return 'feature-key-default';
}

function formatFeatureValue(value) {
    // Check if it's a string pattern
    if (value.includes('/') && (value.includes('/i') || value.includes('/s'))) {
        return `<span class="feature-pattern">${escapeHtml(value)}</span>`;
    }
    // Check if it's a hex pattern
    if (value.match(/[0-9A-Fa-f]{2}(\s+[0-9A-Fa-f]{2})+/)) {
        return `<span class="feature-hex">${escapeHtml(value)}</span>`;
    }
    return escapeHtml(value);
}

// Generate PE Structure Analysis HTML
function generatePEStructureHTML(peStructure) {
    let html = '';
    
    // Remove CVSS display from here - it's now standalone
    // Just show the PE structure data
    
    // Imports Analysis
    if (peStructure.imports && !peStructure.imports.error) {
        const imports = peStructure.imports;
        html += '<div class="structure-section imports-section">';
        html += '<h4><i class="fas fa-file-import"></i> Import Table Analysis</h4>';
        
        // Summary stats
        html += '<div class="import-stats">';
        html += `<span class="stat-badge"><i class="fas fa-book"></i> ${imports.dll_count || 0} DLLs</span>`;
        html += `<span class="stat-badge"><i class="fas fa-function"></i> ${imports.total_functions || 0} Functions</span>`;
        html += '</div>';
        
        // Analysis findings
        if (imports.analysis && imports.analysis.findings) {
            imports.analysis.findings.forEach(finding => {
                const severityClass = finding.severity.toLowerCase();
                html += `<div class="finding-box finding-${severityClass}">
                    <div class="finding-header">
                        <i class="fas fa-exclamation-circle"></i>
                        <strong>${escapeHtml(finding.category)}</strong>
                        <span class="severity-badge severity-${severityClass}">${finding.severity}</span>
                    </div>
                    <div class="finding-description">${escapeHtml(finding.description)}</div>
                </div>`;
            });
        }
        
        // Show imported DLLs and functions
        if (imports.imports && Object.keys(imports.imports).length > 0) {
            html += '<div class="imports-list">';
            html += '<div class="imports-header">';
            html += '<h5><i class="fas fa-cubes"></i> Imported Libraries & Functions</h5>';
            html += '<span class="imports-hint"><i class="fas fa-info-circle"></i> Scroll to view all functions</span>';
            html += '</div>';
            
            Object.keys(imports.imports).forEach(dll => {
                const funcs = imports.imports[dll];
                html += `<div class="dll-import">
                    <div class="dll-header">
                        <div class="dll-name"><i class="fas fa-book"></i> ${escapeHtml(dll)}</div>
                        <span class="func-count"><i class="fas fa-function"></i> ${funcs.length} functions</span>
                    </div>
                    <div class="func-list-container">
                        <div class="func-list">`;
                
                // Show ALL functions
                funcs.forEach(func => {
                    html += `<span class="func-name">${escapeHtml(func)}</span>`;
                });
                
                html += '</div></div></div>';
            });
            html += '</div>';
        }
        
        html += '</div>';
    }
    
    // Exports Analysis
    if (peStructure.exports && !peStructure.exports.error) {
        const exports = peStructure.exports;
        html += '<div class="structure-section exports-section">';
        html += '<h4><i class="fas fa-file-export"></i> Export Table Analysis</h4>';
        
        if (exports.analysis) {
            const severityClass = exports.analysis.severity.toLowerCase();
            html += `<div class="finding-box finding-${severityClass}">
                <div class="finding-description">${escapeHtml(exports.analysis.description)}</div>
            </div>`;
        }
        
        if (exports.exports && exports.exports.length > 0) {
            html += '<div class="exports-list">';
            exports.exports.forEach(exp => {
                html += `<span class="export-name">${escapeHtml(exp)}</span>`;
            });
            html += '</div>';
        }
        
        html += '</div>';
    }
    
    // Sections Analysis
    if (peStructure.sections && !peStructure.sections.error) {
        const sections = peStructure.sections;
        html += '<div class="structure-section sections-section">';
        html += '<h4><i class="fas fa-layer-group"></i> Section Permissions Analysis</h4>';
        
        // Analysis findings
        if (sections.analysis && sections.analysis.findings) {
            sections.analysis.findings.forEach(finding => {
                const severityClass = finding.severity.toLowerCase();
                html += `<div class="finding-box finding-${severityClass}">
                    <div class="finding-header">
                        <i class="fas fa-exclamation-circle"></i>
                        <strong>${escapeHtml(finding.category)}</strong>
                        <span class="severity-badge severity-${severityClass}">${finding.severity}</span>
                    </div>
                    <div class="finding-description">${escapeHtml(finding.description)}</div>
                </div>`;
            });
        }
        
        // Show section table
        if (sections.sections && sections.sections.length > 0) {
            html += '<div class="sections-table">';
            html += '<table>';
            html += '<thead><tr><th>Section Name</th><th>Virtual Size</th><th>Permissions</th></tr></thead>';
            html += '<tbody>';
            sections.sections.forEach(section => {
                const perms = section.permissions || 'R';
                const permClass = perms === 'RWX' ? 'perm-rwx' : perms.includes('X') ? 'perm-exec' : perms.includes('W') ? 'perm-write' : 'perm-read';
                html += `<tr>
                    <td class="section-name-cell">${escapeHtml(section.name)}</td>
                    <td class="section-size-cell">0x${section.virtual_size || '0'}</td>
                    <td class="section-perms-cell"><span class="perm-badge ${permClass}">${perms}</span></td>
                </tr>`;
            });
            html += '</tbody></table>';
            html += '</div>';
        }
        
        html += '</div>';
    }
    
    // Resources Analysis
    if (peStructure.resources && !peStructure.resources.error) {
        const resources = peStructure.resources;
        html += '<div class="structure-section resources-section">';
        html += '<h4><i class="fas fa-box-open"></i> Resources Analysis</h4>';
        
        // Analysis findings
        if (resources.findings && resources.findings.length > 0) {
            resources.findings.forEach(finding => {
                const severityClass = finding.severity.toLowerCase();
                html += `<div class="finding-box finding-${severityClass}">
                    <div class="finding-header">
                        <i class="fas fa-exclamation-circle"></i>
                        <strong>${escapeHtml(finding.category)}</strong>
                        <span class="severity-badge severity-${severityClass}">${finding.severity}</span>
                    </div>
                    <div class="finding-description">${escapeHtml(finding.description)}</div>
                </div>`;
            });
        } else if (resources.analysis) {
            // Show general analysis if no specific findings
            const severityClass = resources.analysis.severity.toLowerCase();
            html += `<div class="finding-box finding-${severityClass}">
                <div class="finding-description">${escapeHtml(resources.analysis.description)}</div>
            </div>`;
        }
        
        // Show resource types summary
        if (resources.resources && resources.resources.length > 0) {
            html += '<div class="resources-summary">';
            html += '<h5><i class="fas fa-list"></i> Resource Types Found</h5>';
            html += '<div class="resource-types-grid">';
            resources.resources.forEach(res => {
                html += `<div class="resource-type-item">
                    <span class="resource-type-name">${escapeHtml(res.type)}</span>
                    <span class="resource-count-badge">${res.count}</span>
                </div>`;
            });
            html += '</div></div>';
        }
        
        html += '</div>';
    }
    
    // Timestamps Analysis
    if (peStructure.timestamps && !peStructure.timestamps.error) {
        const timestamps = peStructure.timestamps;
        html += '<div class="structure-section timestamps-section">';
        html += '<h4><i class="fas fa-clock"></i> Timestamps & Signature Analysis</h4>';
        
        // Show signature status prominently
        const signedStatus = timestamps.signed ? 
            '<span class="signature-badge signed"><i class="fas fa-certificate"></i> Digitally Signed</span>' : 
            '<span class="signature-badge unsigned"><i class="fas fa-exclamation-triangle"></i> Unsigned Binary</span>';
        html += `<div class="signature-status">${signedStatus}</div>`;
        
        // Analysis findings
        if (timestamps.findings && timestamps.findings.length > 0) {
            timestamps.findings.forEach(finding => {
                const severityClass = finding.severity.toLowerCase();
                html += `<div class="finding-box finding-${severityClass}">
                    <div class="finding-header">
                        <i class="fas fa-info-circle"></i>
                        <strong>${escapeHtml(finding.category)}</strong>
                        <span class="severity-badge severity-${severityClass}">${finding.severity}</span>
                    </div>
                    <div class="finding-description">${escapeHtml(finding.description)}</div>
                </div>`;
            });
        }
        
        html += '</div>';
    }
    
    // Embedded Payload Discovery (Overlays)
    if (peStructure.overlays && !peStructure.overlays.error) {
        const overlays = peStructure.overlays;
        html += '<div class="structure-section overlays-section">';
        html += '<h4><i class="fas fa-ghost"></i> Embedded Payload Discovery</h4>';
        
        // Show overlay status prominently
        if (overlays.overlay_present) {
            html += `<div class="overlay-status overlay-detected">
                <div class="overlay-status-icon"><i class="fas fa-exclamation-triangle"></i></div>
                <div class="overlay-status-details">
                    <div class="overlay-status-title">Overlay Data Detected</div>
                    <div class="overlay-status-size">${(overlays.overlay_size / 1024).toFixed(2)} KB of data appended after PE sections</div>
                </div>
            </div>`;
        } else {
            html += `<div class="overlay-status overlay-clean">
                <div class="overlay-status-icon"><i class="fas fa-check-circle"></i></div>
                <div class="overlay-status-details">
                    <div class="overlay-status-title">No Overlay Detected</div>
                    <div class="overlay-status-size">All bytes accounted for by PE structure</div>
                </div>
            </div>`;
        }
        
        // Analysis findings
        if (overlays.findings && overlays.findings.length > 0) {
            overlays.findings.forEach(finding => {
                const severityClass = finding.severity.toLowerCase();
                html += `<div class="finding-box finding-${severityClass}">
                    <div class="finding-header">
                        <i class="fas fa-exclamation-circle"></i>
                        <strong>${escapeHtml(finding.category)}</strong>
                        <span class="severity-badge severity-${severityClass}">${finding.severity}</span>
                    </div>
                    <div class="finding-description">${escapeHtml(finding.description)}</div>
                </div>`;
            });
        }
        
        html += '</div>';
    }
    
    return html;
}
