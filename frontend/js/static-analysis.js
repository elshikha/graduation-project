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
    
    // Show CAPA capability analysis for PE and ELF files
    console.log('CAPA analysis data:', data.capa_analysis);
    if ((data.file_type === 'PE' || data.file_type === 'ELF') && data.capa_analysis) {
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
    
    // Show ELF analysis for ELF files
    console.log('ELF analysis data:', data.elf_analysis);
    if (data.file_type === 'ELF' && data.elf_analysis) {
        const elfCard = document.getElementById('elfAnalysisCard');
        const elfInfo = document.getElementById('elfInfo');
        
        if (!data.elf_analysis.error) {
            elfCard.style.display = 'block';
            elfInfo.innerHTML = generateELFAnalysisHTML(data.elf_analysis);
        } else {
            console.error('ELF analysis error:', data.elf_analysis.error);
        }
    } else {
        document.getElementById('elfAnalysisCard').style.display = 'none';
    }
    
    // Show ELF hardening analysis for ELF files
    console.log('ELF hardening data:', data.elf_hardening);
    if (data.file_type === 'ELF' && data.elf_hardening) {
        const hardeningCard = document.getElementById('elfHardeningCard');
        const hardeningInfo = document.getElementById('elfHardeningInfo');
        
        if (!data.elf_hardening.error) {
            hardeningCard.style.display = 'block';
            hardeningInfo.innerHTML = generateELFHardeningHTML(data.elf_hardening);
        } else {
            console.error('ELF hardening error:', data.elf_hardening.error);
        }
    } else {
        document.getElementById('elfHardeningCard').style.display = 'none';
    }
    
    // Show ELF packer analysis for ELF files
    console.log('ELF packer data:', data.elf_packer);
    if (data.file_type === 'ELF' && data.elf_packer) {
        const packerCard = document.getElementById('elfPackerCard');
        const packerInfo = document.getElementById('elfPackerInfo');
        
        if (!data.elf_packer.error) {
            packerCard.style.display = 'block';
            packerInfo.innerHTML = generateELFPackerHTML(data.elf_packer);
        } else {
            console.error('ELF packer error:', data.elf_packer.error);
        }
    } else {
        document.getElementById('elfPackerCard').style.display = 'none';
    }
    
    // Show Office analysis for Office files
    console.log('Office analysis data:', data.office_analysis);
    if (data.file_type === 'Office' && data.office_analysis) {
        const officeCard = document.getElementById('officeAnalysisCard');
        const officeInfo = document.getElementById('officeInfo');
        
        if (!data.office_analysis.error) {
            officeCard.style.display = 'block';
            officeInfo.innerHTML = generateOfficeAnalysisHTML(data.office_analysis);
        } else {
            console.error('Office analysis error:', data.office_analysis.error);
        }
    } else {
        document.getElementById('officeAnalysisCard').style.display = 'none';
    }
    
    // Show Office macro analysis for Office files
    console.log('Office macro data:', data.office_macros);
    if (data.file_type === 'Office' && data.office_macros) {
        const macroCard = document.getElementById('officeMacroCard');
        const macroInfo = document.getElementById('officeMacroInfo');
        
        if (!data.office_macros.error) {
            macroCard.style.display = 'block';
            macroInfo.innerHTML = generateOfficeMacroHTML(data.office_macros);
        } else {
            console.error('Office macro error:', data.office_macros.error);
        }
    } else {
        document.getElementById('officeMacroCard').style.display = 'none';
    }
    
    // Show Office URL analysis for Office files
    console.log('Office URL data:', data.office_urls);
    if (data.file_type === 'Office' && data.office_urls) {
        const urlCard = document.getElementById('officeUrlCard');
        const urlInfo = document.getElementById('officeUrlInfo');
        
        if (!data.office_urls.error) {
            urlCard.style.display = 'block';
            urlInfo.innerHTML = generateOfficeUrlHTML(data.office_urls);
        } else {
            console.error('Office URL error:', data.office_urls.error);
        }
    } else {
        document.getElementById('officeUrlCard').style.display = 'none';
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

// Office Document Analysis Functions - Matching office.py structure
function generateOfficeAnalysisHTML(office) {
    let html = '';
    
    // Get info from the new structure
    const info = office.info || {};
    const metadata = office.metadata || {};
    const score = office.score || 0;
    const verdict = office.verdict || 'SAFE';
    const reasons = office.reasons || [];
    
    // Verdict Banner (matching office.py output style)
    let bannerColor = '#4caf50'; // green
    if (verdict === 'MALICIOUS') bannerColor = '#f44336';
    else if (verdict === 'SUSPICIOUS') bannerColor = '#ff9800';
    
    html += '<div class="office-verdict-banner" style="background: linear-gradient(135deg, ' + bannerColor + '15, ' + bannerColor + '25); border-left: 4px solid ' + bannerColor + '; padding: 1.5rem; border-radius: 12px; margin-bottom: 1.5rem;">';
    html += '<div style="display: flex; justify-content: space-between; align-items: center;">';
    html += '<div>';
    html += '<h3 style="margin: 0; color: ' + bannerColor + ';"><i class="fas ' + (verdict === 'SAFE' ? 'fa-check-circle' : 'fa-exclamation-triangle') + '"></i> ' + verdict + '</h3>';
    html += '<p style="margin: 0.5rem 0 0 0; color: #666;">Risk Score: ' + score + '/10</p>';
    html += '</div>';
    html += '<div style="text-align: center;">';
    html += '<div style="font-size: 2.5rem; font-weight: 700; color: ' + bannerColor + ';">' + score + '</div>';
    html += '<div style="font-size: 0.85rem; color: #666;">SCORE</div>';
    html += '</div>';
    html += '</div>';
    html += '</div>';
    
    // File Identity (TrID Engine style)
    html += '<div class="office-section">';
    html += '<h4 style="margin-bottom: 1rem;"><i class="fas fa-fingerprint"></i> File Identity (TrID Engine)</h4>';
    html += '<div class="office-grid">';
    
    html += '<div class="office-item"><span class="office-label">Filename</span><span class="office-value">' + escapeHtml(info.filename || 'N/A') + '</span></div>';
    html += '<div class="office-item"><span class="office-label">Type</span><span class="office-value">' + escapeHtml(info.trid_type || 'Unknown') + '</span></div>';
    html += '<div class="office-item"><span class="office-label">Magic Bytes</span><span class="office-value" style="font-family: monospace;">' + escapeHtml(info.magic || 'N/A') + '</span></div>';
    html += '<div class="office-item"><span class="office-label">Size</span><span class="office-value">' + (info.size ? info.size.toLocaleString() + ' bytes' : 'N/A') + '</span></div>';
    
    html += '</div></div>';
    
    // Entropy
    const entropy = info.entropy || 0;
    let entropyClass = 'entropy-low';
    let entropyStatus = 'Normal';
    if (entropy >= 7.5) { entropyClass = 'entropy-high'; entropyStatus = 'High (Possibly encrypted/packed)'; }
    else if (entropy >= 6.5) { entropyClass = 'entropy-medium'; entropyStatus = 'Medium'; }
    
    html += '<div class="office-section">';
    html += '<h4 style="margin-bottom: 1rem;"><i class="fas fa-chart-area"></i> Entropy Analysis</h4>';
    html += '<div class="entropy-bar-container">';
    html += '<div class="entropy-bar ' + entropyClass + '" style="width: ' + (entropy * 12.5) + '%;"></div>';
    html += '</div>';
    html += '<p style="font-weight: 600;" class="' + entropyClass + '">' + entropy.toFixed(2) + ' / 8.0 - ' + entropyStatus + '</p>';
    html += '</div>';
    
    // Metadata & File Intelligence
    html += '<div class="office-section">';
    html += '<h4 style="margin-bottom: 1rem;"><i class="fas fa-info-circle"></i> Metadata & File Intelligence</h4>';
    html += '<div class="office-grid">';
    
    const metaFields = [
        {key: 'author', label: 'Author'},
        {key: 'last_modified_by', label: 'Last Modified By'},
        {key: 'created', label: 'Created Date'},
        {key: 'modified', label: 'Modified Date'},
        {key: 'title', label: 'Title'},
        {key: 'subject', label: 'Subject'},
        {key: 'company', label: 'Company'},
        {key: 'application', label: 'Application'}
    ];
    
    metaFields.forEach(field => {
        const value = metadata[field.key];
        if (value && value !== 'N/A') {
            html += '<div class="office-item">';
            html += '<span class="office-label">' + field.label + '</span>';
            html += '<span class="office-value">' + escapeHtml(value) + '</span>';
            html += '</div>';
        }
    });
    
    html += '</div></div>';
    
    // Hashes
    const hashes = info.hashes || {};
    if (hashes.md5 && hashes.md5 !== 'Error') {
        html += '<div class="office-section">';
        html += '<h4 style="margin-bottom: 1rem;"><i class="fas fa-key"></i> Cryptographic Hashes</h4>';
        html += '<div class="hash-list">';
        
        ['md5', 'sha1', 'sha256', 'sha512'].forEach(hashType => {
            if (hashes[hashType] && hashes[hashType] !== 'Error') {
                html += '<div class="hash-item">';
                html += '<span class="hash-label">' + hashType.toUpperCase() + '</span>';
                html += '<code class="hash-value">' + escapeHtml(hashes[hashType]) + '</code>';
                html += '</div>';
            }
        });
        
        html += '</div></div>';
    }
    
    // OLE Sector Map (Olemap)
    const oleMap = office.ole_map || {};
    if (oleMap.sector_size && oleMap.sector_size > 0) {
        html += '<div class="office-section">';
        html += '<h4 style="margin-bottom: 1rem;"><i class="fas fa-database"></i> Sector Map (Olemap)</h4>';
        html += '<div class="office-grid">';
        html += '<div class="office-item"><span class="office-label">Sector Size</span><span class="office-value">' + oleMap.sector_size + ' bytes</span></div>';
        html += '<div class="office-item"><span class="office-label">Total Sectors</span><span class="office-value">' + oleMap.total_sectors + '</span></div>';
        html += '<div class="office-item"><span class="office-label">Slack Space</span><span class="office-value">' + oleMap.slack_space + ' bytes</span></div>';
        html += '</div></div>';
    }
    
    // OLE Stream Timestamps (Oletime)
    const streams = office.streams || [];
    if (streams.length > 0) {
        html += '<div class="office-section">';
        html += '<h4 style="margin-bottom: 1rem;"><i class="fas fa-clock"></i> Stream Timestamps (Oletime)</h4>';
        html += '<table class="office-table" style="width: 100%; border-collapse: collapse;">';
        html += '<thead><tr style="background: #f0f0f0;"><th style="padding: 0.75rem; text-align: left; border-bottom: 2px solid #ddd;">Stream</th><th style="padding: 0.75rem; text-align: left; border-bottom: 2px solid #ddd;">Timestamp</th></tr></thead>';
        html += '<tbody>';
        
        streams.slice(0, 10).forEach(stream => {
            html += '<tr style="border-bottom: 1px solid #eee;">';
            html += '<td style="padding: 0.5rem; font-family: monospace; font-size: 0.85rem;">' + escapeHtml(stream.name || '') + '</td>';
            html += '<td style="padding: 0.5rem; color: #666;">' + escapeHtml(stream.time || '') + '</td>';
            html += '</tr>';
        });
        
        if (streams.length > 10) {
            html += '<tr><td colspan="2" style="padding: 0.5rem; color: #999; text-align: center;">... and ' + (streams.length - 10) + ' more streams</td></tr>';
        }
        
        html += '</tbody></table></div>';
    }
    
    // Detected Threats (Reasons)
    if (reasons.length > 0) {
        html += '<div class="office-section" style="background: #fff8f8; border-color: #ffcdd2;">';
        html += '<h4 style="margin-bottom: 1rem; color: #c62828;"><i class="fas fa-exclamation-triangle"></i> Detected Threats</h4>';
        html += '<ul class="risk-indicator-list">';
        
        reasons.forEach(reason => {
            html += '<li class="risk-indicator"><i class="fas fa-exclamation-circle"></i> ' + escapeHtml(reason) + '</li>';
        });
        
        html += '</ul></div>';
    }
    
    // Forensic Artifacts
    const artifacts = office.artifacts || [];
    if (artifacts.length > 0) {
        html += '<div class="office-section">';
        html += '<h4 style="margin-bottom: 1rem;"><i class="fas fa-search"></i> Forensic Artifacts & Hex Dumps</h4>';
        html += '<table class="office-table" style="width: 100%; border-collapse: collapse;">';
        html += '<thead><tr style="background: #f0f0f0;"><th style="padding: 0.75rem; text-align: left; border-bottom: 2px solid #ddd; width: 150px;">Type</th><th style="padding: 0.75rem; text-align: left; border-bottom: 2px solid #ddd;">Value</th></tr></thead>';
        html += '<tbody>';
        
        artifacts.forEach(artifact => {
            let valueStr = artifact.value || '';
            if (valueStr.length > 80) valueStr = valueStr.substring(0, 77) + '...';
            html += '<tr style="border-bottom: 1px solid #eee;">';
            html += '<td style="padding: 0.5rem; font-weight: 600; color: #333;">' + escapeHtml(artifact.type || 'Unknown') + '</td>';
            html += '<td style="padding: 0.5rem; font-family: monospace; font-size: 0.85rem; word-break: break-all;">' + escapeHtml(valueStr) + '</td>';
            html += '</tr>';
        });
        
        html += '</tbody></table></div>';
    }
    
    // VMonkey Heuristics (Obfuscation)
    const vmonkey = office.vmonkey_heuristics || [];
    if (vmonkey.length > 0) {
        html += '<div class="office-section" style="background: #f3e5f5; border-color: #ce93d8;">';
        html += '<h4 style="margin-bottom: 1rem; color: #7b1fa2;"><i class="fas fa-mask"></i> Heuristic Emulation (VMonkey-Style)</h4>';
        html += '<div class="obfuscation-list">';
        
        vmonkey.forEach(h => {
            html += '<div class="obfuscation-item">';
            html += '<span class="pattern-name">' + escapeHtml(h.pattern || h) + '</span>';
            if (h.count) {
                html += '<span class="pattern-count">Found ' + h.count + ' times</span>';
            }
            html += '</div>';
        });
        
        html += '</div></div>';
    }
    
    return html;
}

function generateOfficeMacroHTML(macros) {
    let html = '';
    
    // Handle both old and new structure
    const hasMacros = macros.has_vba_macros || macros.has_xlm_macros;
    const macroCount = macros.macro_count || 0;
    const autoExec = macros.auto_exec_triggers || [];
    const suspicious = macros.suspicious_keywords || macros.suspicious_functions || [];
    const vmonkey = macros.vmonkey_heuristics || macros.obfuscation_patterns || [];
    const iocs = macros.iocs || [];
    const snippets = macros.macro_snippets || [];
    
    // Calculate status
    let macroStatus = 'CLEAN';
    let statusColor = 'green';
    if (autoExec.length > 0 || vmonkey.length > 0) {
        macroStatus = 'DANGEROUS';
        statusColor = 'red';
    } else if (hasMacros) {
        macroStatus = 'PRESENT';
        statusColor = 'yellow';
    }
    
    // Status banner
    html += '<div class="macro-status-banner status-' + statusColor + '">';
    html += '<div class="macro-status-left">';
    html += '<i class="fas ' + (hasMacros ? 'fa-exclamation-triangle' : 'fa-check-circle') + '"></i>';
    html += '<span class="macro-status-text">' + macroStatus + '</span>';
    html += '</div>';
    html += '<div class="macro-risk-score">';
    html += '<span class="score-value">' + macroCount + '</span>';
    html += '<span class="score-label">Macros Found</span>';
    html += '</div>';
    html += '</div>';
    
    // Macro presence grid
    html += '<div class="macro-section">';
    html += '<h4 style="margin-bottom: 1rem;"><i class="fas fa-code"></i> Macro Detection</h4>';
    html += '<div class="macro-grid">';
    
    html += '<div class="macro-item"><span class="macro-label">VBA Macros</span>';
    html += '<span class="macro-value ' + (macros.has_vba_macros ? 'status-danger' : 'status-safe') + '">';
    html += macros.has_vba_macros ? 'DETECTED' : 'Not Found';
    html += '</span></div>';
    
    html += '<div class="macro-item"><span class="macro-label">XLM Macros (Legacy)</span>';
    html += '<span class="macro-value ' + (macros.has_xlm_macros ? 'status-danger' : 'status-safe') + '">';
    html += macros.has_xlm_macros ? 'DETECTED' : 'Not Found';
    html += '</span></div>';
    
    html += '<div class="macro-item"><span class="macro-label">Macro Count</span>';
    html += '<span class="macro-value">' + macroCount + '</span></div>';
    
    html += '</div></div>';
    
    // Auto-execution triggers
    if (autoExec.length > 0) {
        html += '<div class="macro-section" style="background: #ffebee; border-color: #ef9a9a;">';
        html += '<h4 style="margin-bottom: 1rem; color: #c62828;"><i class="fas fa-play-circle"></i> Auto-Execution Triggers</h4>';
        html += '<div class="trigger-list">';
        
        autoExec.forEach(trigger => {
            html += '<div class="trigger-item danger"><code>' + escapeHtml(trigger) + '</code></div>';
        });
        
        html += '</div></div>';
    }
    
    // Suspicious keywords/functions
    if (suspicious.length > 0) {
        html += '<div class="macro-section" style="background: #fff3e0; border-color: #ffcc80;">';
        html += '<h4 style="margin-bottom: 1rem; color: #e65100;"><i class="fas fa-exclamation-triangle"></i> Suspicious Keywords</h4>';
        html += '<div class="suspicious-list">';
        
        suspicious.forEach(kw => {
            html += '<div class="suspicious-item high"><code>' + escapeHtml(kw) + '</code></div>';
        });
        
        html += '</div></div>';
    }
    
    // VMonkey heuristics
    if (vmonkey.length > 0) {
        html += '<div class="macro-section" style="background: #f3e5f5; border-color: #ce93d8;">';
        html += '<h4 style="margin-bottom: 1rem; color: #7b1fa2;"><i class="fas fa-mask"></i> Obfuscation Patterns</h4>';
        html += '<div class="obfuscation-list">';
        
        vmonkey.forEach(pattern => {
            const patternName = pattern.pattern || pattern;
            const count = pattern.count || 0;
            html += '<div class="obfuscation-item">';
            html += '<span class="pattern-name">' + escapeHtml(patternName) + '</span>';
            if (count > 0) html += '<span class="pattern-count">Count: ' + count + '</span>';
            html += '</div>';
        });
        
        html += '</div></div>';
    }
    
    // IOCs (bad links in macros)
    if (iocs.length > 0) {
        html += '<div class="macro-section" style="background: #ffebee; border-color: #ef9a9a;">';
        html += '<h4 style="margin-bottom: 1rem; color: #c62828;"><i class="fas fa-link"></i> IOCs Found in Macros</h4>';
        html += '<div class="suspicious-url-list">';
        
        iocs.forEach(ioc => {
            html += '<div class="suspicious-url-item">';
            html += '<code class="url-text">' + escapeHtml(ioc.value || ioc) + '</code>';
            if (ioc.verdict) {
                html += '<span class="threat-tag">' + escapeHtml(ioc.verdict) + '</span>';
            }
            html += '</div>';
        });
        
        html += '</div></div>';
    }
    
    // Macro snippets (hex dumps)
    if (snippets.length > 0) {
        html += '<div class="macro-section">';
        html += '<h4 style="margin-bottom: 1rem;"><i class="fas fa-file-code"></i> Macro Code Snippets</h4>';
        
        snippets.forEach(snippet => {
            html += '<div style="background: #f8f9fa; padding: 1rem; border-radius: 8px; margin-bottom: 0.75rem;">';
            html += '<div style="font-weight: 600; margin-bottom: 0.5rem;">' + escapeHtml(snippet.filename || 'Unknown') + ' (' + (snippet.length || 0) + ' bytes)</div>';
            html += '<pre style="background: #1a1a1a; color: #4caf50; padding: 0.75rem; border-radius: 4px; overflow-x: auto; font-size: 0.8rem; margin: 0;">' + escapeHtml(snippet.hex_dump || '') + '</pre>';
            html += '</div>';
        });
        
        html += '</div>';
    }
    
    return html;
}

function generateOfficeUrlHTML(urls) {
    let html = '';
    
    // Handle both old and new structure
    const urlList = urls.urls || urls.extracted_urls || [];
    const totalUrls = urls.total_urls || urlList.length;
    const maliciousCount = urls.malicious_count || urls.malicious_urls || urlList.filter(u => u.status === 'MALICIOUS').length;
    const suspiciousCount = urls.suspicious_count || urls.suspicious_urls || urlList.filter(u => u.status === 'SUSPICIOUS').length;
    
    // Determine status
    let urlStatus = 'CLEAN';
    let statusColor = 'green';
    if (maliciousCount > 0) {
        urlStatus = 'MALICIOUS LINKS';
        statusColor = 'red';
    } else if (suspiciousCount > 0) {
        urlStatus = 'SUSPICIOUS';
        statusColor = 'orange';
    } else if (totalUrls > 0) {
        urlStatus = 'PRESENT';
        statusColor = 'yellow';
    }
    
    // Status banner
    html += '<div class="url-status-banner status-' + statusColor + '">';
    html += '<div class="url-status-left">';
    html += '<i class="fas ' + (maliciousCount > 0 ? 'fa-exclamation-triangle' : suspiciousCount > 0 ? 'fa-exclamation-circle' : 'fa-check-circle') + '"></i>';
    html += '<span class="url-status-text">' + urlStatus + '</span>';
    html += '</div>';
    html += '<div class="url-risk-score">';
    html += '<span class="score-value">' + totalUrls + '</span>';
    html += '<span class="score-label">URLs Found</span>';
    html += '</div>';
    html += '</div>';
    
    // Summary statistics
    html += '<div class="url-section">';
    html += '<h4 style="margin-bottom: 1rem;"><i class="fas fa-chart-bar"></i> URL Statistics</h4>';
    html += '<div class="url-stats">';
    
    html += '<div class="stat-item"><span class="stat-value">' + totalUrls + '</span><span class="stat-label">Total URLs</span></div>';
    html += '<div class="stat-item ' + (maliciousCount > 0 ? 'danger' : '') + '"><span class="stat-value">' + maliciousCount + '</span><span class="stat-label">Malicious</span></div>';
    html += '<div class="stat-item ' + (suspiciousCount > 0 ? 'danger' : '') + '"><span class="stat-value">' + suspiciousCount + '</span><span class="stat-label">Suspicious</span></div>';
    
    html += '</div></div>';
    
    // Group URLs by status
    const maliciousUrls = urlList.filter(u => u.status === 'MALICIOUS');
    const suspiciousUrls = urlList.filter(u => u.status === 'SUSPICIOUS');
    const safeUrls = urlList.filter(u => u.status === 'SAFE');
    
    // Malicious URLs
    if (maliciousUrls.length > 0) {
        html += '<div class="url-section danger-section">';
        html += '<h4 style="margin-bottom: 1rem; color: #c62828;"><i class="fas fa-skull-crossbones"></i> Malicious Links</h4>';
        html += '<div class="suspicious-url-list">';
        
        maliciousUrls.forEach(urlInfo => {
            html += '<div class="suspicious-url-item">';
            html += '<code class="url-text">' + escapeHtml(urlInfo.url) + '</code>';
            html += '<div class="threat-tags">';
            html += '<span class="threat-tag">MALICIOUS</span>';
            if (urlInfo.source) html += '<span class="threat-tag" style="background: #666;">' + escapeHtml(urlInfo.source) + '</span>';
            html += '</div></div>';
        });
        
        html += '</div></div>';
    }
    
    // Suspicious URLs
    if (suspiciousUrls.length > 0) {
        html += '<div class="url-section warning-section">';
        html += '<h4 style="margin-bottom: 1rem; color: #e65100;"><i class="fas fa-exclamation-triangle"></i> Suspicious Links</h4>';
        html += '<div class="suspicious-url-list">';
        
        suspiciousUrls.forEach(urlInfo => {
            html += '<div class="suspicious-url-item" style="background: #fff3e0; border-color: #ffcc80;">';
            html += '<code class="url-text" style="color: #e65100;">' + escapeHtml(urlInfo.url) + '</code>';
            html += '<div class="threat-tags">';
            html += '<span class="threat-tag" style="background: #ff9800;">SUSPICIOUS</span>';
            if (urlInfo.source) html += '<span class="threat-tag" style="background: #666;">' + escapeHtml(urlInfo.source) + '</span>';
            html += '</div></div>';
        });
        
        html += '</div></div>';
    }
    
    // Safe URLs (collapsed by default)
    if (safeUrls.length > 0) {
        html += '<div class="url-section">';
        html += '<h4 style="margin-bottom: 1rem;"><i class="fas fa-link"></i> Other Links (' + safeUrls.length + ')</h4>';
        html += '<div class="hyperlink-list">';
        
        safeUrls.slice(0, 15).forEach(urlInfo => {
            html += '<div class="hyperlink-item">';
            html += '<code>' + escapeHtml(urlInfo.url) + '</code>';
            if (urlInfo.source) html += '<span style="font-size: 0.75rem; color: #999; margin-left: 1rem;">' + escapeHtml(urlInfo.source) + '</span>';
            html += '</div>';
        });
        
        if (safeUrls.length > 15) {
            html += '<div class="more-indicator">... and ' + (safeUrls.length - 15) + ' more links</div>';
        }
        
        html += '</div></div>';
    }
    
    if (totalUrls === 0) {
        html += '<div class="url-section" style="text-align: center; padding: 2rem;">';
        html += '<i class="fas fa-check-circle" style="font-size: 3rem; color: #4caf50; margin-bottom: 1rem;"></i>';
        html += '<p style="color: #666; margin: 0;">No external links found in this document.</p>';
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

// Generate ELF Analysis HTML
function generateELFAnalysisHTML(elf) {
    let html = '';
    
    // Header information
    const header = elf.header || {};
    html += `
        <div class="elf-section">
            <h4><i class="fab fa-linux"></i> ELF Header</h4>
            <div class="elf-header-grid">
                <div class="elf-header-item">
                    <span class="label">Magic:</span>
                    <span class="value mono">${header.magic || 'N/A'}</span>
                </div>
                <div class="elf-header-item">
                    <span class="label">Class:</span>
                    <span class="value">${header.class || 'N/A'}</span>
                </div>
                <div class="elf-header-item">
                    <span class="label">Data:</span>
                    <span class="value">${header.data || 'N/A'}</span>
                </div>
                <div class="elf-header-item">
                    <span class="label">Type:</span>
                    <span class="value">${header.type || 'N/A'}</span>
                </div>
                <div class="elf-header-item">
                    <span class="label">Machine:</span>
                    <span class="value">${header.machine || 'N/A'}</span>
                </div>
                <div class="elf-header-item">
                    <span class="label">Entry Point:</span>
                    <span class="value mono">${header.entry_point || 'N/A'}</span>
                </div>
                <div class="elf-header-item">
                    <span class="label">OS/ABI:</span>
                    <span class="value">${header.os_abi || 'N/A'}</span>
                </div>
                <div class="elf-header-item">
                    <span class="label">Program Headers:</span>
                    <span class="value">${header.program_header_count || 0}</span>
                </div>
                <div class="elf-header-item">
                    <span class="label">Section Headers:</span>
                    <span class="value">${header.section_header_count || 0}</span>
                </div>
            </div>
        </div>
    `;
    
    // File entropy
    if (elf.file_entropy !== undefined) {
        const entropyPct = (elf.file_entropy / 8) * 100;
        const entropyClass = elf.file_entropy >= 7.5 ? 'high' : (elf.file_entropy >= 6.0 ? 'medium' : 'low');
        html += `
            <div class="elf-section">
                <h4><i class="fas fa-chart-bar"></i> File Entropy</h4>
                <div class="entropy-display">
                    <div class="entropy-bar ${entropyClass}">
                        <div class="entropy-fill" style="width: ${entropyPct}%"></div>
                    </div>
                    <span class="entropy-value">${elf.file_entropy.toFixed(4)}/8.0</span>
                    <span class="entropy-status ${entropyClass}">${elf.entropy_status || ''}</span>
                </div>
            </div>
        `;
    }
    
    // Program Headers (Segments) - ELF Structure Analysis matching FullElf.py
    const segments = elf.segments || {};
    if (segments.segments && segments.segments.length > 0) {
        html += `
            <div class="elf-section elf-structure-analysis">
                <h4><i class="fas fa-list-alt"></i> Program Headers</h4>
                <div class="elf-table-wrapper">
                    <table class="elf-table elf-program-headers">
                        <thead>
                            <tr>
                                <th>Type</th>
                                <th>Offset</th>
                                <th>VirtAddr</th>
                                <th>FileSz</th>
                                <th>MemSz</th>
                                <th>Flags</th>
                            </tr>
                        </thead>
                        <tbody>
        `;
        
        segments.segments.forEach(seg => {
            // Determine row class based on flags
            let rowClass = '';
            const flags = seg.flags || '';
            if (flags.includes('R') && flags.includes('W') && flags.includes('E')) {
                rowClass = 'danger-row'; // RWX segment
            } else if (flags.includes('W') && flags.includes('E')) {
                rowClass = 'warning-row'; // WX segment
            }
            
            // Format segment type for display (clean up PT_ prefix if needed)
            let segType = seg.type || '';
            if (typeof segType === 'string' && segType.startsWith('PT_')) {
                // Keep as-is, it's already formatted
            }
            
            html += `
                <tr class="${rowClass}">
                    <td class="mono">${segType}</td>
                    <td class="mono">${seg.offset || '0x0'}</td>
                    <td class="mono" style="font-size: 0.8rem;">${seg.virtual_address || '0x0'}</td>
                    <td>${seg.file_size !== undefined ? seg.file_size.toLocaleString() : '0'}</td>
                    <td>${seg.memory_size !== undefined ? seg.memory_size.toLocaleString() : '0'}</td>
                    <td class="mono ${flags.includes('E') ? 'flag-exec' : ''}">${flags}</td>
                </tr>
            `;
        });
        
        html += '</tbody></table></div>';
        
        // RWX warning
        if (segments.has_rwx) {
            html += `
                <div class="elf-danger" style="margin-top: 1rem;">
                    <i class="fas fa-skull-crossbones"></i>
                    <strong>RWX Segment Detected!</strong>
                    Read-Write-Execute segments are a major security risk and common in shellcode.
                </div>
            `;
        }
        
        html += '</div>';
    }
    
    // Section Headers
    const sections = elf.sections || {};
    if (sections.sections && sections.sections.length > 0) {
        html += `
            <div class="elf-section elf-structure-analysis">
                <h4><i class="fas fa-layer-group"></i> Section Headers</h4>
                <div class="elf-table-wrapper">
                    <table class="elf-table elf-section-headers">
                        <thead>
                            <tr>
                                <th>Name</th>
                                <th>Type</th>
                                <th>Address</th>
                                <th>Offset</th>
                                <th>Size</th>
                                <th>Entropy</th>
                            </tr>
                        </thead>
                        <tbody>
        `;
        
        sections.sections.forEach(sec => {
            const entropyClass = sec.entropy >= 7.0 ? 'danger-row' : (sec.entropy >= 6.0 ? 'warning-row' : '');
            const entropyHighlight = sec.entropy >= 7.0 ? 'entropy-high' : (sec.entropy >= 6.0 ? 'entropy-medium' : '');
            html += `
                <tr class="${entropyClass}">
                    <td class="mono">${sec.name || '<unnamed>'}</td>
                    <td>${sec.type || ''}</td>
                    <td class="mono">${sec.address || '0x0'}</td>
                    <td class="mono">${sec.offset || '0x0'}</td>
                    <td>${sec.size !== undefined ? sec.size.toLocaleString() : 0}</td>
                    <td class="mono ${entropyHighlight}">${sec.entropy ? sec.entropy.toFixed(2) : '0.00'}</td>
                </tr>
            `;
        });
        
        html += '</tbody></table></div>';
        
        // High entropy sections warning
        if (sections.high_entropy_sections && sections.high_entropy_sections.length > 0) {
            html += `
                <div class="elf-warning" style="margin-top: 1rem;">
                    <i class="fas fa-exclamation-triangle"></i>
                    <strong>High Entropy Sections:</strong> 
                    ${sections.high_entropy_sections.map(s => s.name).join(', ')}
                    (possible packing/encryption)
                </div>
            `;
        }
        
        html += '</div>';
    }
    
    // Interpreter
    if (elf.interpreter) {
        html += `
            <div class="elf-info-item">
                <i class="fas fa-terminal"></i>
                <strong>Interpreter:</strong> <code>${elf.interpreter}</code>
            </div>
        `;
    }
    
    // Suspicious imports
    if (elf.suspicious_imports && elf.suspicious_imports.length > 0) {
        html += `
            <div class="elf-section">
                <h4><i class="fas fa-exclamation-circle"></i> Suspicious Imports (${elf.suspicious_imports.length})</h4>
                <div class="suspicious-imports-list">
                    ${elf.suspicious_imports.map(imp => `<span class="suspicious-import">${imp}</span>`).join('')}
                </div>
            </div>
        `;
    }
    
    // Syscalls
    const syscalls = elf.syscalls || {};
    if (syscalls.has_raw_syscalls && syscalls.syscalls_detected) {
        html += `
            <div class="elf-section">
                <h4><i class="fas fa-microchip"></i> Raw Syscalls Detected</h4>
                <ul class="syscall-list">
                    ${syscalls.syscalls_detected.map(sc => `<li>${sc.description}</li>`).join('')}
                </ul>
            </div>
        `;
    }
    
    // Embedded payloads
    if (elf.has_embedded_payloads && elf.embedded_payloads && elf.embedded_payloads.length > 0) {
        html += `
            <div class="elf-danger">
                <i class="fas fa-file-archive"></i>
                <strong>Embedded Payloads Detected:</strong>
                <ul>
                    ${elf.embedded_payloads.map(p => `<li>${p.description}</li>`).join('')}
                </ul>
            </div>
        `;
    }
    
    // URLs
    if (elf.urls && elf.urls.length > 0) {
        html += `
            <div class="elf-section">
                <h4><i class="fas fa-link"></i> Extracted URLs (${elf.url_count})</h4>
                <div class="url-list">
                    ${elf.urls.slice(0, 10).map(url => `<div class="url-item"><code>${url}</code></div>`).join('')}
                </div>
            </div>
        `;
    }
    
    return html;
}

// Generate ELF Hardening Analysis HTML
function generateELFHardeningHTML(hardening) {
    let html = '';
    
    // Security score banner
    const score = hardening.security_score || 0;
    const maxScore = hardening.max_score || 10;
    const status = hardening.status || 'Unknown';
    const statusColor = hardening.status_color || 'yellow';
    
    const scoreClass = score >= 8 ? 'good' : (score >= 5 ? 'medium' : 'poor');
    
    html += `
        <div class="hardening-score ${scoreClass}">
            <div class="score-circle">
                <span class="score-value">${score}</span>
                <span class="score-max">/${maxScore}</span>
            </div>
            <div class="score-label">
                <strong>${status}</strong>
                <p>Security Hardening Score</p>
            </div>
        </div>
    `;
    
    // Hardening checks
    const summary = hardening.summary || {};
    html += '<div class="hardening-checks">';
    
    // RELRO
    const relro = hardening.relro || {};
    const relroClass = relro.level === 'Full' ? 'enabled' : (relro.level === 'Partial' ? 'partial' : 'disabled');
    html += `
        <div class="hardening-item ${relroClass}">
            <div class="check-icon">
                <i class="fas ${relro.level === 'Full' ? 'fa-check-circle' : (relro.level === 'Partial' ? 'fa-exclamation-circle' : 'fa-times-circle')}"></i>
            </div>
            <div class="check-details">
                <strong>RELRO</strong>
                <span class="check-status">${relro.level || 'Unknown'}</span>
                <p class="check-desc">${relro.description || ''}</p>
            </div>
        </div>
    `;
    
    // PIE
    const pie = hardening.pie || {};
    const pieClass = pie.enabled ? 'enabled' : 'disabled';
    html += `
        <div class="hardening-item ${pieClass}">
            <div class="check-icon">
                <i class="fas ${pie.enabled ? 'fa-check-circle' : 'fa-times-circle'}"></i>
            </div>
            <div class="check-details">
                <strong>PIE (ASLR)</strong>
                <span class="check-status">${pie.enabled ? 'Enabled' : 'Disabled'}</span>
                <p class="check-desc">${pie.description || ''}</p>
            </div>
        </div>
    `;
    
    // NX
    const nx = hardening.nx || {};
    const nxClass = nx.enabled ? 'enabled' : 'disabled';
    html += `
        <div class="hardening-item ${nxClass}">
            <div class="check-icon">
                <i class="fas ${nx.enabled ? 'fa-check-circle' : 'fa-times-circle'}"></i>
            </div>
            <div class="check-details">
                <strong>NX (Non-Executable Stack)</strong>
                <span class="check-status">${nx.enabled ? 'Enabled' : 'Disabled'}</span>
                <p class="check-desc">${nx.description || ''}</p>
            </div>
        </div>
    `;
    
    // Stack Canary
    const canary = hardening.stack_canary || {};
    const canaryClass = canary.enabled ? 'enabled' : 'disabled';
    html += `
        <div class="hardening-item ${canaryClass}">
            <div class="check-icon">
                <i class="fas ${canary.enabled ? 'fa-check-circle' : 'fa-times-circle'}"></i>
            </div>
            <div class="check-details">
                <strong>Stack Canary</strong>
                <span class="check-status">${canary.enabled ? 'Present' : 'Not Found'}</span>
                <p class="check-desc">${canary.description || ''}</p>
            </div>
        </div>
    `;
    
    // Fortify
    const fortify = hardening.fortify || {};
    const fortifyClass = fortify.enabled ? 'enabled' : 'disabled';
    html += `
        <div class="hardening-item ${fortifyClass}">
            <div class="check-icon">
                <i class="fas ${fortify.enabled ? 'fa-check-circle' : 'fa-times-circle'}"></i>
            </div>
            <div class="check-details">
                <strong>FORTIFY_SOURCE</strong>
                <span class="check-status">${fortify.enabled ? 'Present' : 'Not Found'}</span>
                <p class="check-desc">${fortify.description || ''}</p>
            </div>
        </div>
    `;
    
    html += '</div>';
    
    // RPATH warning
    const rpath = hardening.rpath || {};
    if (rpath.has_rpath || rpath.has_runpath) {
        html += `
            <div class="elf-warning">
                <i class="fas fa-exclamation-triangle"></i>
                <strong>Custom Library Paths:</strong>
                ${rpath.rpath ? `RPATH: ${rpath.rpath}` : ''}
                ${rpath.runpath ? `RUNPATH: ${rpath.runpath}` : ''}
                <p>This may allow library hijacking attacks.</p>
            </div>
        `;
    }
    
    return html;
}

// Generate ELF Packer Detection HTML
function generateELFPackerHTML(packer) {
    let html = '';
    
    // Packing status banner
    const isPacked = packer.is_packed || false;
    const packersDetected = packer.packers_detected || [];
    
    if (isPacked) {
        html += `
            <div class="packer-detected">
                <i class="fas fa-box"></i>
                <div>
                    <strong>Packing/Obfuscation Detected</strong>
                    ${packersDetected.length > 0 ? `<p>Packers: ${packersDetected.join(', ')}</p>` : ''}
                </div>
            </div>
        `;
    } else {
        html += `
            <div class="packer-clean">
                <i class="fas fa-check-circle"></i>
                <strong>No Packing Detected</strong>
            </div>
        `;
    }
    
    // Indicators
    const indicators = packer.indicators || [];
    if (indicators.length > 0) {
        html += `
            <div class="packer-indicators">
                <h4><i class="fas fa-search"></i> Detection Indicators (${indicators.length})</h4>
                <ul class="indicator-list">
        `;
        
        indicators.forEach(ind => {
            const iconClass = ind.type === 'signature' ? 'fa-fingerprint' : 
                             ind.type === 'high_entropy_region' ? 'fa-chart-line' :
                             ind.type === 'stripped_symbols' ? 'fa-eraser' :
                             ind.type === 'segment_expansion' ? 'fa-expand' :
                             'fa-exclamation-circle';
            
            html += `
                <li class="indicator-item">
                    <i class="fas ${iconClass}"></i>
                    <span>${ind.description || ind.type}</span>
                </li>
            `;
        });
        
        html += '</ul></div>';
    }
    
    // Stripped info
    const stripped = packer.stripped_info || {};
    if (stripped.stripped) {
        html += `
            <div class="elf-warning">
                <i class="fas fa-eraser"></i>
                <strong>Symbols Stripped:</strong> ${stripped.description || 'Symbol tables have been removed'}
            </div>
        `;
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


// ============================================
// RELATIONAL GRAPH & AI REPORT FUNCTIONALITY
// ============================================

// Graph instance
let graphInstance = null;
let currentGraphData = null;

// Initialize button event listeners when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    // Relational Graph Button
    const btnGraph = document.getElementById('btnRelationalGraph');
    if (btnGraph) {
        btnGraph.addEventListener('click', handleRelationalGraph);
    }
    
    // Generate Report Button
    const btnReport = document.getElementById('btnGenerateReport');
    if (btnReport) {
        btnReport.addEventListener('click', handleGenerateReport);
    }
    
    // Modal close buttons
    const closeGraphModal = document.getElementById('closeGraphModal');
    if (closeGraphModal) {
        closeGraphModal.addEventListener('click', () => {
            document.getElementById('graphModal').style.display = 'none';
            if (graphInstance) {
                graphInstance.destroy();
                graphInstance = null;
            }
        });
    }
    
    const closeReportModal = document.getElementById('closeReportModal');
    if (closeReportModal) {
        closeReportModal.addEventListener('click', () => {
            document.getElementById('reportModal').style.display = 'none';
        });
    }
    
    // Copy Report Button
    const btnCopyReport = document.getElementById('btnCopyReport');
    if (btnCopyReport) {
        btnCopyReport.addEventListener('click', copyReportToClipboard);
    }
    
    // Download Report Button
    const btnDownloadReport = document.getElementById('btnDownloadReport');
    if (btnDownloadReport) {
        btnDownloadReport.addEventListener('click', downloadReport);
    }
    
    // Close modals when clicking outside
    document.getElementById('graphModal')?.addEventListener('click', (e) => {
        if (e.target.id === 'graphModal') {
            document.getElementById('graphModal').style.display = 'none';
            if (graphInstance) {
                graphInstance.destroy();
                graphInstance = null;
            }
        }
    });
    
    document.getElementById('reportModal')?.addEventListener('click', (e) => {
        if (e.target.id === 'reportModal') {
            document.getElementById('reportModal').style.display = 'none';
        }
    });
});


// Handle Relational Graph Button Click
async function handleRelationalGraph() {
    const analysisData = window.currentAnalysisData;
    
    if (!analysisData) {
        showNotification('No analysis data available. Please upload a file first.', 'error');
        return;
    }
    
    // Show modal with loading state
    const modal = document.getElementById('graphModal');
    const container = document.getElementById('graphContainer');
    const sidebar = document.getElementById('graphNodeDetails');
    
    modal.style.display = 'flex';
    container.innerHTML = '<div class="report-loading"><div class="spinner"></div><p>Building relational graph...</p></div>';
    sidebar.innerHTML = '<div class="empty-node-state"><i class="fas fa-mouse-pointer"></i><p>Click on a node to see details</p></div>';
    
    try {
        const token = localStorage.getItem('token');
        const response = await fetch('http://localhost:5000/api/generate-graph', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({ analysis_data: analysisData })
        });
        
        const result = await response.json();
        
        if (!result.success) {
            container.innerHTML = `<div class="report-error"><i class="fas fa-exclamation-triangle"></i><h3>Failed to Generate Graph</h3><p>${result.message || 'Unknown error'}</p></div>`;
            return;
        }
        
        currentGraphData = result.graph;
        window.currentGraphData = result.graph;  // Make available for node explanations
        renderGraph(result.graph, container, sidebar);
        
    } catch (error) {
        console.error('Graph generation error:', error);
        container.innerHTML = `<div class="report-error"><i class="fas fa-exclamation-triangle"></i><h3>Error</h3><p>${error.message}</p></div>`;
    }
}


// Render Cytoscape Graph
function renderGraph(graphData, container, sidebar) {
    container.innerHTML = '';
    
    // Add legend
    const legend = document.createElement('div');
    legend.className = 'graph-legend';
    legend.innerHTML = `
        <h4>Risk Level</h4>
        <div class="legend-items">
            <div class="legend-item"><div class="legend-color critical"></div>Critical</div>
            <div class="legend-item"><div class="legend-color high"></div>High</div>
            <div class="legend-item"><div class="legend-color medium"></div>Medium</div>
            <div class="legend-item"><div class="legend-color low"></div>Low/Safe</div>
            <div class="legend-item"><div class="legend-color info"></div>Info</div>
        </div>
    `;
    container.appendChild(legend);
    
    // Add controls
    const controls = document.createElement('div');
    controls.className = 'graph-controls';
    controls.innerHTML = `
        <button class="graph-control-btn" id="graphZoomIn" title="Zoom In"><i class="fas fa-plus"></i></button>
        <button class="graph-control-btn" id="graphZoomOut" title="Zoom Out"><i class="fas fa-minus"></i></button>
        <button class="graph-control-btn" id="graphFit" title="Fit to View"><i class="fas fa-expand"></i></button>
        <button class="graph-control-btn" id="graphCenter" title="Center"><i class="fas fa-crosshairs"></i></button>
    `;
    container.appendChild(controls);
    
    // Risk level to color mapping
    const riskColors = {
        'critical': '#ef4444',
        'high': '#f97316',
        'medium': '#eab308',
        'low': '#22c55e',
        'safe': '#22c55e',
        'info': '#3b82f6'
    };
    
    // Node type to shape mapping - cleaner, more consistent shapes
    const nodeShapes = {
        'file': 'round-rectangle',
        'hash': 'round-rectangle',
        'entropy': 'round-rectangle',
        'risk': 'round-rectangle',
        'indicator_group': 'round-rectangle',
        'indicator': 'round-rectangle',
        'pe_info': 'round-rectangle',
        'elf_info': 'round-rectangle',
        'pdf_info': 'round-rectangle',
        'office_info': 'round-rectangle',
        'sections': 'round-rectangle',
        'section': 'round-rectangle',
        'api_group': 'round-rectangle',
        'api': 'round-rectangle',
        'packer': 'round-rectangle',
        'javascript': 'round-rectangle',
        'auto_action': 'round-rectangle',
        'embedded': 'round-rectangle',
        'obfuscation': 'round-rectangle',
        'security': 'round-rectangle',
        'function_group': 'round-rectangle',
        'function': 'round-rectangle',
        'macro': 'round-rectangle',
        'auto_execute': 'round-rectangle',
        'keywords': 'round-rectangle',
        'urls': 'round-rectangle',
        'capabilities': 'round-rectangle',
        'namespace': 'round-rectangle',
        'capability': 'round-rectangle',
        'virustotal': 'round-rectangle',
        'detection': 'round-rectangle',
        'ips': 'round-rectangle',
        'registry': 'round-rectangle'
    };

    // Node type to icon emoji mapping
    const nodeIcons = {
        'file': '📄',
        'hash': '🔐',
        'entropy': '📊',
        'risk': '⚠️',
        'indicator_group': '🔍',
        'indicator': '🔸',
        'pe_info': '💻',
        'elf_info': '🐧',
        'pdf_info': '📕',
        'office_info': '📎',
        'sections': '📁',
        'section': '📂',
        'api_group': '⚙️',
        'api': '🔧',
        'packer': '📦',
        'javascript': '📜',
        'auto_action': '⚡',
        'embedded': '📎',
        'obfuscation': '🔒',
        'security': '🛡️',
        'function_group': '📋',
        'function': '🔹',
        'macro': '⚠️',
        'auto_execute': '🚀',
        'keywords': '🏷️',
        'urls': '🔗',
        'capabilities': '🎯',
        'namespace': '📂',
        'capability': '✨',
        'virustotal': '🦠',
        'detection': '🚨',
        'ips': '🌐',
        'registry': '📝'
    };
    
    // Prepare elements with icons
    const elements = [
        ...graphData.nodes.map(n => ({
            data: {
                id: n.id,
                label: n.label,
                type: n.type,
                risk: n.risk_level || 'info',
                nodeData: n.data,
                icon: nodeIcons[n.type] || '📌'
            }
        })),
        ...graphData.edges.map(e => ({
            data: {
                id: e.id,
                source: e.source,
                target: e.target,
                label: e.label || e.type
            }
        }))
    ];
    
    // Create Cytoscape instance
    graphInstance = cytoscape({
        container: container,
        elements: elements,
        style: [
            {
                selector: 'node',
                style: {
                    'background-color': '#ffffff',
                    'border-width': 2,
                    'border-color': function(ele) {
                        return riskColors[ele.data('risk')] || '#3b82f6';
                    },
                    'width': 50,
                    'height': 50,
                    'label': function(ele) {
                        return ele.data('icon') + '\n' + ele.data('label');
                    },
                    'color': '#334155',
                    'font-family': 'Inter, sans-serif',
                    'font-size': '9px',
                    'font-weight': '500',
                    'text-valign': 'bottom',
                    'text-halign': 'center',
                    'text-margin-y': 6,
                    'text-wrap': 'wrap',
                    'text-max-width': 100,
                    'text-background-opacity': 0.95,
                    'text-background-color': '#ffffff',
                    'text-background-padding': '4px',
                    'text-background-shape': 'round-rectangle',
                    'shape': 'round-rectangle',
                    'transition-property': 'border-color, border-width, width, height, background-color',
                    'transition-duration': '0.2s',
                    'shadow-blur': 8,
                    'shadow-color': 'rgba(0, 0, 0, 0.1)',
                    'shadow-offset-x': 0,
                    'shadow-offset-y': 2,
                    'shadow-opacity': 1
                }
            },
            {
                selector: 'node[type="file"]',
                style: {
                    'width': 70,
                    'height': 70,
                    'font-size': '11px',
                    'font-weight': '600',
                    'background-color': '#8519d5',
                    'color': '#ffffff',
                    'text-background-color': '#8519d5',
                    'text-background-opacity': 0.9,
                    'border-width': 3,
                    'border-color': '#6b21a8'
                }
            },
            {
                selector: 'node[risk="critical"]',
                style: {
                    'background-color': '#fef2f2',
                    'border-color': '#ef4444'
                }
            },
            {
                selector: 'node[risk="high"]',
                style: {
                    'background-color': '#fff7ed',
                    'border-color': '#f97316'
                }
            },
            {
                selector: 'node[risk="medium"]',
                style: {
                    'background-color': '#fefce8',
                    'border-color': '#eab308'
                }
            },
            {
                selector: 'node[risk="low"], node[risk="safe"]',
                style: {
                    'background-color': '#f0fdf4',
                    'border-color': '#22c55e'
                }
            },
            {
                selector: 'node[risk="info"]',
                style: {
                    'background-color': '#eff6ff',
                    'border-color': '#3b82f6'
                }
            },
            {
                selector: 'edge',
                style: {
                    'width': 1.5,
                    'line-color': '#94a3b8',
                    'target-arrow-color': '#64748b',
                    'target-arrow-shape': 'triangle',
                    'curve-style': 'bezier',
                    'label': 'data(label)',
                    'font-size': '8px',
                    'font-weight': '500',
                    'color': '#475569',
                    'text-rotation': 'autorotate',
                    'text-margin-y': -8,
                    'arrow-scale': 1,
                    'font-family': 'Inter, sans-serif',
                    'text-background-opacity': 0.9,
                    'text-background-color': '#ffffff',
                    'text-background-padding': '2px',
                    'text-background-shape': 'round-rectangle'
                }
            },
            {
                selector: 'node:selected',
                style: {
                    'background-color': '#f3e8ff',
                    'border-color': '#8519d5',
                    'border-width': 3,
                    'shadow-blur': 15,
                    'shadow-color': 'rgba(133, 25, 213, 0.4)',
                    'shadow-opacity': 1
                }
            },
            {
                selector: 'edge:selected',
                style: {
                    'line-color': '#8519d5',
                    'target-arrow-color': '#8519d5',
                    'width': 2.5
                }
            }
        ],
        layout: {
            name: 'cose',
            padding: 50,
            nodeRepulsion: 8000,
            idealEdgeLength: 100,
            edgeElasticity: 100,
            nestingFactor: 1.2,
            gravity: 0.25,
            numIter: 1000,
            animate: true,
            animationDuration: 1000,
            randomize: false
        },
        wheelSensitivity: 0.15,
        minZoom: 0.2,
        maxZoom: 3
    });
    
    // Node click handler
    graphInstance.on('tap', 'node', function(evt) {
        const node = evt.target;
        displayNodeDetails(node, sidebar);
    });
    
    // Control button handlers
    document.getElementById('graphZoomIn')?.addEventListener('click', () => {
        graphInstance.zoom(graphInstance.zoom() * 1.2);
    });
    
    document.getElementById('graphZoomOut')?.addEventListener('click', () => {
        graphInstance.zoom(graphInstance.zoom() / 1.2);
    });
    
    document.getElementById('graphFit')?.addEventListener('click', () => {
        graphInstance.fit(50);
    });
    
    document.getElementById('graphCenter')?.addEventListener('click', () => {
        graphInstance.center();
    });
    
    // Mouse cursor change on hover
    graphInstance.on('mouseover', 'node', () => {
        container.style.cursor = 'pointer';
    });
    
    graphInstance.on('mouseout', 'node', () => {
        container.style.cursor = 'default';
    });
}


// Display Node Details in Sidebar
function displayNodeDetails(node, sidebar) {
    const nodeId = node.id();
    const nodeLabel = node.data('label');
    const nodeType = node.data('type');
    const nodeRisk = node.data('risk');
    const nodeIcon = node.data('icon') || '📌';
    const nodeData = node.data('nodeData') || {};
    
    // Clean the label (remove emoji prefix if present)
    const cleanLabel = nodeLabel.replace(/^[\u{1F300}-\u{1F9FF}][\n\r]*/u, '').trim();
    
    // Format display value helper
    function formatValue(value, key) {
        if (value === null || value === undefined) return 'N/A';
        
        if (Array.isArray(value)) {
            if (value.length === 0) return 'None';
            if (value.length <= 3) return value.join(', ');
            return value.slice(0, 3).join(', ') + ` (+${value.length - 3} more)`;
        }
        
        if (typeof value === 'object') {
            // Special handling for known object types
            if (value.name) return value.name;
            if (value.description) return value.description;
            if (value.value) return value.value;
            
            const keys = Object.keys(value);
            if (keys.length === 0) return 'None';
            if (keys.length <= 2) {
                return keys.map(k => `${k}: ${value[k]}`).join(', ');
            }
            return `${keys.length} properties`;
        }
        
        if (typeof value === 'boolean') {
            return value ? '✓ Yes' : '✗ No';
        }
        
        if (typeof value === 'number') {
            // Format scores nicely
            if (key.toLowerCase().includes('score')) {
                return value.toFixed(1);
            }
            return value.toString();
        }
        
        if (typeof value === 'string') {
            if (value.length > 60) {
                return value.substring(0, 57) + '...';
            }
            return value;
        }
        
        return String(value);
    }
    
    // Pretty label for keys
    function prettyKey(key) {
        return key
            .replace(/_/g, ' ')
            .replace(/([A-Z])/g, ' $1')
            .replace(/^./, str => str.toUpperCase())
            .trim();
    }
    
    let html = `
        <div class="node-detail-card">
            <h3>${nodeIcon} ${escapeHtml(cleanLabel)}</h3>
            <span class="node-type-badge risk-${nodeRisk}">${nodeType.replace(/_/g, ' ').toUpperCase()}</span>
            
            <div class="node-data-list">
                <div class="node-data-item">
                    <span class="node-data-label">Type</span>
                    <span class="node-data-value">${nodeType}</span>
                </div>
                <div class="node-data-item">
                    <span class="node-data-label">Risk Level</span>
                    <span class="node-data-value">${nodeRisk}</span>
                </div>
    `;
    
    // Add additional data items with better formatting
    const skipKeys = ['record', 'full_text', 'full', 'id', 'node_id'];
    for (const [key, value] of Object.entries(nodeData)) {
        if (value !== null && value !== undefined && !skipKeys.includes(key.toLowerCase())) {
            const displayValue = formatValue(value, key);
            const displayKey = prettyKey(key);
            
            html += `
                <div class="node-data-item">
                    <span class="node-data-label">${displayKey}</span>
                    <span class="node-data-value">${escapeHtml(String(displayValue))}</span>
                </div>
            `;
        }
    }
    
    // Show full description if available
    if (nodeData.full_text || nodeData.full) {
        const fullDesc = nodeData.full_text || nodeData.full;
        html += `
            <div class="node-data-item" style="flex-direction: column; gap: 4px;">
                <span class="node-data-label">Description</span>
                <span class="node-data-value" style="text-align: left;">${escapeHtml(String(fullDesc).substring(0, 150))}</span>
            </div>
        `;
    }
    
    html += '</div></div>';
    
    // Get connected edges
    const connectedEdges = node.connectedEdges();
    if (connectedEdges.length > 0) {
        html += `
            <div class="node-detail-card">
                <h3><i class="fas fa-link"></i> Connections (${connectedEdges.length})</h3>
                <div class="node-data-list">
        `;
        
        connectedEdges.forEach(edge => {
            const isSource = edge.source().id() === nodeId;
            const connectedNode = isSource ? edge.target() : edge.source();
            const direction = isSource ? '→' : '←';
            const connectedLabel = connectedNode.data('label')
                .replace(/^[\u{1F300}-\u{1F9FF}][\n\r]*/u, '')
                .trim()
                .substring(0, 25);
            
            html += `
                <div class="node-data-item">
                    <span class="node-data-label">${edge.data('label')}</span>
                    <span class="node-data-value">${direction} ${connectedLabel}</span>
                </div>
            `;
        });
        
        html += '</div></div>';
    }
    
    // Add AI Explanation section
    html += `
        <div class="node-detail-card ai-explanation-card">
            <h3><i class="fas fa-robot"></i> AI Analysis</h3>
            <div id="nodeExplanation" class="node-explanation">
                <button class="btn-explain" onclick="getNodeExplanation('${nodeId}', '${nodeType}', '${cleanLabel}', '${nodeRisk}')">
                    <i class="fas fa-magic"></i> Generate AI Explanation
                </button>
            </div>
        </div>
    `;
    
    sidebar.innerHTML = html;
    
    // Store current node data for explanation
    window.currentNodeForExplanation = {
        id: nodeId,
        type: nodeType,
        label: cleanLabel,
        risk: nodeRisk,
        data: nodeData
    };
}


// Get AI Explanation for a node
async function getNodeExplanation(nodeId, nodeType, nodeLabel, nodeRisk) {
    const explanationDiv = document.getElementById('nodeExplanation');
    const nodeData = window.currentNodeForExplanation?.data || {};
    
    // Show loading state
    explanationDiv.innerHTML = `
        <div class="explanation-loading">
            <div class="spinner-small"></div>
            <span>Analyzing with AI...</span>
        </div>
    `;
    
    try {
        const token = localStorage.getItem('token');
        const response = await fetch('/api/explain-node', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({
                node_id: nodeId,
                node_data: {
                    type: nodeType,
                    label: nodeLabel,
                    risk: nodeRisk,
                    data: nodeData
                },
                graph_data: window.currentGraphData || null
            })
        });
        
        const result = await response.json();
        
        if (result.success && result.explanation) {
            // Display the explanation with markdown formatting
            explanationDiv.innerHTML = `
                <div class="ai-explanation-content">
                    ${marked.parse(result.explanation)}
                </div>
                <button class="btn-explain-refresh" onclick="getNodeExplanation('${nodeId}', '${nodeType}', '${nodeLabel}', '${nodeRisk}')">
                    <i class="fas fa-sync-alt"></i> Regenerate
                </button>
            `;
        } else {
            explanationDiv.innerHTML = `
                <div class="explanation-error">
                    <i class="fas fa-exclamation-triangle"></i>
                    <p>${result.message || 'Failed to generate explanation'}</p>
                    <button class="btn-explain" onclick="getNodeExplanation('${nodeId}', '${nodeType}', '${nodeLabel}', '${nodeRisk}')">
                        <i class="fas fa-redo"></i> Try Again
                    </button>
                </div>
            `;
        }
    } catch (error) {
        console.error('Error getting node explanation:', error);
        explanationDiv.innerHTML = `
            <div class="explanation-error">
                <i class="fas fa-exclamation-triangle"></i>
                <p>Error: ${error.message}</p>
                <button class="btn-explain" onclick="getNodeExplanation('${nodeId}', '${nodeType}', '${nodeLabel}', '${nodeRisk}')">
                    <i class="fas fa-redo"></i> Try Again
                </button>
            </div>
        `;
    }
}


// Handle Generate Report Button Click
async function handleGenerateReport() {
    const analysisData = window.currentAnalysisData;
    
    if (!analysisData) {
        showNotification('No analysis data available. Please upload a file first.', 'error');
        return;
    }
    
    // Show modal with loading state
    const modal = document.getElementById('reportModal');
    const content = document.getElementById('reportContent');
    
    modal.style.display = 'flex';
    content.innerHTML = `
        <div class="report-loading">
            <div class="spinner"></div>
            <p>Generating AI report...</p>
            <p class="report-loading-hint">This may take a moment. Ollama is analyzing the file.</p>
        </div>
    `;
    
    try {
        // First check if Ollama is available
        const ollamaCheck = await fetch('http://localhost:5000/api/check-ollama');
        const ollamaStatus = await ollamaCheck.json();
        
        if (!ollamaStatus.available) {
            content.innerHTML = `
                <div class="report-error">
                    <i class="fas fa-server"></i>
                    <h3>Ollama Not Available</h3>
                    <p>The AI service (Ollama) is not running. Please start Ollama with the llama3.2:3b model and try again.</p>
                    <p style="margin-top: 1rem; font-family: monospace; color: #64748b;">ollama run llama3.2:3b</p>
                    <button class="btn-retry" onclick="handleGenerateReport()">
                        <i class="fas fa-redo"></i> Retry
                    </button>
                </div>
            `;
            return;
        }
        
        const token = localStorage.getItem('token');
        const response = await fetch('http://localhost:5000/api/generate-report', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({ 
                analysis_data: analysisData,
                language: 'english'
            })
        });
        
        const result = await response.json();
        
        if (!result.success) {
            content.innerHTML = `
                <div class="report-error">
                    <i class="fas fa-exclamation-triangle"></i>
                    <h3>Failed to Generate Report</h3>
                    <p>${result.message || 'Unknown error occurred while generating the report.'}</p>
                    <button class="btn-retry" onclick="handleGenerateReport()">
                        <i class="fas fa-redo"></i> Retry
                    </button>
                </div>
            `;
            return;
        }
        
        // Store report for download/copy
        window.currentReport = result.report;
        
        // Render markdown report
        const htmlReport = marked.parse(result.report);
        content.innerHTML = `
            <div class="report-markdown">
                ${htmlReport}
            </div>
            <div style="text-align: center; padding: 2rem; border-top: 1px solid rgba(255,255,255,0.1); margin-top: 2rem;">
                <p style="color: #64748b; font-size: 0.85rem;">
                    Generated by ${result.model_used || 'AI'} at ${new Date(result.generated_at).toLocaleString()}
                </p>
            </div>
        `;
        
        showNotification('AI report generated successfully!', 'success');
        
    } catch (error) {
        console.error('Report generation error:', error);
        content.innerHTML = `
            <div class="report-error">
                <i class="fas fa-exclamation-triangle"></i>
                <h3>Error</h3>
                <p>${error.message}</p>
                <button class="btn-retry" onclick="handleGenerateReport()">
                    <i class="fas fa-redo"></i> Retry
                </button>
            </div>
        `;
    }
}


// Copy Report to Clipboard
function copyReportToClipboard() {
    if (!window.currentReport) {
        showNotification('No report to copy', 'error');
        return;
    }
    
    navigator.clipboard.writeText(window.currentReport).then(() => {
        showNotification('Report copied to clipboard!', 'success');
    }).catch(err => {
        console.error('Copy failed:', err);
        showNotification('Failed to copy report', 'error');
    });
}


// Download Report as Markdown
function downloadReport() {
    if (!window.currentReport) {
        showNotification('No report to download', 'error');
        return;
    }
    
    const analysisData = window.currentAnalysisData || {};
    const filename = analysisData.filename || 'malware_analysis';
    const safeFilename = filename.replace(/[^a-z0-9]/gi, '_').toLowerCase();
    
    const blob = new Blob([window.currentReport], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    
    const a = document.createElement('a');
    a.href = url;
    a.download = `${safeFilename}_report.md`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    
    showNotification('Report downloaded!', 'success');
}
