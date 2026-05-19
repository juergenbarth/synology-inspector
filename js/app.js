/**
 * app.js
 *
 * Main application bootstrap for Synology Inspector.
 *
 * State machine:
 *   'idle'    → file selected/dropped → 'loading'
 *   'loading' → parse success         → 'results'
 *   'loading' → parse error           → 'error'
 *   'results' → reset button          → 'idle'
 *   'error'   → reset button          → 'idle'
 *
 * Depends on (loaded before this file):
 *   i18n.js, xz-decompress.js, tar-parser.js, sqlite-reader.js,
 *   dss-pipeline.js, compliance-engine.js, checks/*.js, compliance-view.js
 */

const YOUTUBE_CHANNEL_URL = 'https://www.youtube.com/@navigio1';

// ── Utilities ─────────────────────────────────────────────────────────────────

function escapeHtml(str) {
    if (typeof str !== 'string') return '';
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function formatFileSize(bytes) {
    if (bytes < 1024)        return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}

// ── App state ─────────────────────────────────────────────────────────────────

let _appPhase     = 'idle';       // 'idle' | 'loading' | 'results' | 'error'
let _parseResult  = null;
let _errorMessage = '';
let _activeTab    = 'security';   // 'security' | 'bestpractices'

// ── Main render ────────────────────────────────────────────────────────────────

function renderApp() {
    updateLangButtons();
    updateContextBar();

    const root = document.getElementById('app');
    if (!root) return;

    if (_appPhase === 'idle') {
        root.innerHTML = renderDropZone();
    } else if (_appPhase === 'loading') {
        root.innerHTML = renderLoadingView();
    } else if (_appPhase === 'results' && _parseResult) {
        const secFindings = runAllChecks(_parseResult.config, _parseResult.tlsProfile, _parseResult);
        const bpFindings  = runAllBestPracticesChecks(_parseResult.config, _parseResult.tlsProfile, _parseResult);
        // Reset view state on every render (covers language switches and tab switches)
        complianceState.severityFilter  = null;
        complianceState.frameworkFilter = null;
        complianceState.expandedIds.clear();
        bpState.expandedIds.clear();
        const isSecTab = _activeTab === 'security';
        root.innerHTML = `
            <div class="results-shell">
                <div class="tab-bar">
                    <button class="tab-btn ${isSecTab ? 'tab-btn--active' : ''}"
                            onclick="switchTab('security')">${t('tabSecurity')}</button>
                    <button class="tab-btn ${!isSecTab ? 'tab-btn--active' : ''}"
                            onclick="switchTab('bestpractices')">${t('tabBestPractices')}</button>
                </div>
                ${isSecTab
                    ? `<div class="compliance-view" id="compliance-view-root">${renderComplianceView(secFindings)}</div>`
                    : `<div class="bestpractices-view" id="bestpractices-view-root">${renderBestPracticesView(bpFindings)}</div>`
                }
            </div>
        `;
    } else if (_appPhase === 'error') {
        root.innerHTML = renderErrorView(_errorMessage);
    }
}

// ── Context bar ────────────────────────────────────────────────────────────────

function updateContextBar() {
    const bar = document.getElementById('context-bar');
    if (!bar) return;

    if (_appPhase === 'results' && _parseResult) {
        const { info, config, fileName, fileSize } = _parseResult;
        const version = info.dsm_majorversion
            ? `${info.dsm_majorversion}.${info.dsm_minorversion || '0'} (Build ${info.dsm_buildnumber || '?'})`
            : '—';
        const model   = info.unique
            ? info.unique.replace(/^synology_[^_]+_/, '').toUpperCase()
            : '—';
        let hostname = '—';
        try { hostname = JSON.parse(config?.get('NETWORK_GENERAL_config') || '{}')?.config?.server_name || '—'; } catch (_) {}

        bar.className = 'context-bar';
        bar.innerHTML = `
            <div class="context-item">
                <span class="context-label">${t('labelFileName')}</span>
                <span class="context-value">${escapeHtml(fileName)}</span>
            </div>
            <div class="context-item">
                <span class="context-label">${t('labelFileSize')}</span>
                <span class="context-value">${formatFileSize(fileSize)}</span>
            </div>
            <div class="context-item">
                <span class="context-label">${t('labelDSMVersion')}</span>
                <span class="context-value">${escapeHtml(version)}</span>
            </div>
            <div class="context-item">
                <span class="context-label">${t('labelModel')}</span>
                <span class="context-value">${escapeHtml(model)}</span>
            </div>
            <div class="context-item">
                <span class="context-label">${t('labelHostname')}</span>
                <span class="context-value">${escapeHtml(hostname)}</span>
            </div>
            <div class="context-actions">
                ${window.JKLP_PDF_EXPORT ? `
                <button class="fd-button fd-button--ghost pdf-export-btn"
                        onclick="${_activeTab === 'bestpractices' ? 'exportBPToPDF()' : 'exportToPDF()'}">
                    <svg width="14" height="14" viewBox="0 0 16 16" fill="none" aria-hidden="true">
                        <path d="M3 12h10M8 2v8M5 7l3 3 3-3" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>
                    </svg>
                    ${t('btnExportPDF')}
                </button>` : ''}
                <button class="fd-button fd-button--ghost" onclick="resetApp()">
                    ${t('btnNewFile')}
                </button>
            </div>
        `;
    } else {
        bar.className = 'context-bar context-bar--hidden';
        bar.innerHTML = '';
    }
}

// ── Drop zone ─────────────────────────────────────────────────────────────────

function renderDropZone() {
    return `
        <div class="drop-zone-container"
             ondragover="onDragOver(event)"
             ondragleave="onDragLeave(event)"
             ondrop="onDrop(event)">
            <div class="drop-zone" id="drop-zone"
                 onclick="document.getElementById('file-input').click()">
                <div class="drop-zone-icon">
                    <svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24"
                         fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
                        <polyline points="17 8 12 3 7 8"/>
                        <line x1="12" y1="3" x2="12" y2="15"/>
                    </svg>
                </div>
                <div class="drop-zone-title">${t('dropTitle')}</div>
                <div class="drop-zone-or">${t('dropOr')} <span class="drop-zone-browse">${t('dropBrowse')}</span></div>
                <div class="drop-zone-formats">${t('dropFormats')}</div>
                <div class="drop-zone-privacy">
                    <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24"
                         fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
                        <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
                    </svg>
                    ${t('dropPrivacy')}
                </div>
            </div>
            ${renderDisclaimer('drop-zone-disclaimer')}
            <button class="about-inline-btn" onclick="showAbout()">
                <svg width="13" height="13" viewBox="0 0 16 16" fill="none" aria-hidden="true">
                    <circle cx="8" cy="8" r="7.25" stroke="currentColor" stroke-width="1.5"/>
                    <rect x="7.25" y="6.5" width="1.5" height="5" rx=".75" fill="currentColor"/>
                    <rect x="7.25" y="4" width="1.5" height="1.5" rx=".75" fill="currentColor"/>
                </svg>
                ${t('aboutBtn')}
            </button>
        </div>
        <input type="file" id="file-input" accept=".dss"
               style="display:none" onchange="onFileInputChange(event)">
    `;
}

// ── Loading view ───────────────────────────────────────────────────────────────

function renderLoadingView() {
    return `
        <div class="loading-view">
            <div class="loading-spinner"></div>
            <div class="loading-title">${t('loading')}</div>
            <div class="loading-hint">${t('loadingHint')}</div>
        </div>
    `;
}

// ── Error view ─────────────────────────────────────────────────────────────────

function renderErrorView(message) {
    return `
        <div class="error-view">
            <div class="error-icon">⚠</div>
            <div class="error-title">${t('errUnknown')}</div>
            <div class="error-message">${escapeHtml(message)}</div>
            <button class="fd-button fd-button--emphasized" onclick="resetApp()">
                ${t('btnNewFile')}
            </button>
        </div>
    `;
}

// ── File processing ────────────────────────────────────────────────────────────

function processFile(file) {
    if (!file) return;

    _appPhase = 'loading';
    renderApp();

    parseDSSFile(file)
        .then(result => {
            _parseResult = result;
            _appPhase    = 'results';
            renderApp();
        })
        .catch(err => {
            _errorMessage = err.message || String(err);
            _appPhase     = 'error';
            renderApp();
        });
}

function resetApp() {
    _appPhase     = 'idle';
    _parseResult  = null;
    _errorMessage = '';
    _activeTab    = 'security';
    renderApp();
}

function switchTab(tab) {
    _activeTab = tab;
    renderApp();
}

// ── Drag & drop event handlers ─────────────────────────────────────────────────

function onDragOver(event) {
    event.preventDefault();
    event.stopPropagation();
    document.getElementById('drop-zone')?.classList.add('drop-zone--active');
}

function onDragLeave(event) {
    event.preventDefault();
    // Only remove the class if we actually left the container (not a child element)
    if (!event.currentTarget.contains(event.relatedTarget)) {
        document.getElementById('drop-zone')?.classList.remove('drop-zone--active');
    }
}

function onDrop(event) {
    event.preventDefault();
    event.stopPropagation();
    document.getElementById('drop-zone')?.classList.remove('drop-zone--active');
    const file = event.dataTransfer?.files?.[0];
    if (file) processFile(file);
}

function onFileInputChange(event) {
    const file = event.target?.files?.[0];
    if (file) processFile(file);
}

// ── About ──────────────────────────────────────────────────────────────────────

function _renderAboutContent() {
    const ytIcon = `
        <svg class="about-yt-icon" width="32" height="22" viewBox="0 0 32 22" fill="none" aria-hidden="true">
            <rect width="32" height="22" rx="5" fill="#FF0000"/>
            <polygon points="13,6 13,16 22,11" fill="white"/>
        </svg>`;
    const arrowIcon = `
        <svg class="about-yt-arrow" width="14" height="14" viewBox="0 0 16 16" fill="none" aria-hidden="true">
            <path d="M3 8h10M9 4l4 4-4 4" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>`;
    return `
        <div class="about-header">
            <img class="about-logo" src="img/logo-jklp.png" alt="JKLP Consulting">
            <div>
                <div class="about-tool-name">
                    Synology Inspector
                    <span class="about-tool-version">v1.0</span>
                </div>
                <div class="about-maker">${t('aboutMaker')}</div>
            </div>
        </div>
        <p class="about-desc">${t('aboutDesc')}</p>
        <a class="about-yt-link" href="${YOUTUBE_CHANNEL_URL}" target="_blank" rel="noopener noreferrer">
            ${ytIcon}
            <div class="about-yt-text">
                <span class="about-yt-name">${t('aboutChannelName')}</span>
                <span class="about-yt-sub">${t('aboutChannelDesc')}</span>
            </div>
            ${arrowIcon}
        </a>
        <a class="about-web-link" href="https://jklp.io" target="_blank" rel="noopener noreferrer">
            <svg class="about-web-icon" width="20" height="20" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                <circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="1.6"/>
                <path d="M2 12h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" stroke="currentColor" stroke-width="1.6"/>
            </svg>
            <div class="about-yt-text">
                <span class="about-yt-name">${t('aboutWebsiteName')}</span>
                <span class="about-yt-sub">${t('aboutWebsiteDesc')}</span>
            </div>
            ${arrowIcon}
        </a>
        <div class="about-badges">
            <span class="about-badge">${t('aboutBadgeFree')}</span>
            <span class="about-badge">${t('aboutBadgeOS')}</span>
            <span class="about-badge">${t('aboutBadgePrivacy')}</span>
        </div>
    `;
}

function showAbout() {
    const modal = document.getElementById('about-modal');
    const content = document.getElementById('about-modal-content');
    if (!modal || !content) return;
    content.innerHTML = _renderAboutContent();
    modal.classList.remove('about-modal-overlay--hidden');
    document.addEventListener('keydown', _aboutKeyHandler);
}

function closeAbout() {
    const modal = document.getElementById('about-modal');
    if (modal) modal.classList.add('about-modal-overlay--hidden');
    document.removeEventListener('keydown', _aboutKeyHandler);
}

function _aboutKeyHandler(e) {
    if (e.key === 'Escape') closeAbout();
}

// ── Language button state ──────────────────────────────────────────────────────

function updateLangButtons() {
    const lang = getCurrentLanguage();
    document.querySelectorAll('.lang-btn').forEach(btn => {
        btn.classList.toggle('lang-btn--active', btn.dataset.lang === lang);
    });
}

// ── Bootstrap ─────────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
    renderApp();
});
