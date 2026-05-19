/**
 * bestpractices-view.js
 *
 * Renders the Best Practices dashboard.
 * Simplified layout — no security score or framework filters.
 *
 * Depends on: compliance-view.js (SEVERITY_COLOR, renderDisclaimer),
 *             compliance-engine.js, i18n.js, app.js (escapeHtml)
 */

// ── View state ────────────────────────────────────────────────────────────────

const bpState = {
    expandedIds: new Set(),
};

function toggleBPExpanded(id) {
    if (bpState.expandedIds.has(id)) {
        bpState.expandedIds.delete(id);
    } else {
        bpState.expandedIds.add(id);
    }
    rerenderBestPractices();
}

let _cachedBPFindings = null;

function rerenderBestPractices() {
    if (!_cachedBPFindings) return;
    const el = document.getElementById('bestpractices-view-root');
    if (!el) return;
    const scrollArea = el.querySelector('.findings-scroll-area');
    const scrollTop  = scrollArea ? scrollArea.scrollTop : 0;
    el.innerHTML     = renderBestPracticesView(_cachedBPFindings);
    const newScroll  = el.querySelector('.findings-scroll-area');
    if (newScroll) newScroll.scrollTop = scrollTop;
}

// ── Top-level renderer ────────────────────────────────────────────────────────

/**
 * Render the full best practices dashboard into a string of HTML.
 * @param {Object[]} findings  All BP findings (fail + pass)
 * @returns {string}
 */
function renderBestPracticesView(findings) {
    _cachedBPFindings = findings;

    const failFindings = findings.filter(f => f.status === 'fail');
    const passFindings = findings.filter(f => f.status === 'pass');

    const issueCount  = failFindings.length;
    const headerColor = issueCount === 0 ? '#256f3a' : issueCount <= 3 ? '#b44f00' : '#aa0808';

    return `
        <div class="bp-header">
            <div class="bp-header-left">
                <div class="bp-title">${t('bpViewTitle')}</div>
                <div class="bp-subtitle">
                    <span class="bp-issue-count" style="color:${headerColor}">${issueCount}</span>
                    <span class="bp-issue-label">${issueCount === 1 ? t('findingSingular') : t('findingPlural')}</span>
                </div>
            </div>
        </div>
        <div class="findings-scroll-area">
            ${_renderBPFindingsByCategory(failFindings)}
            ${_renderBPPassedSection(passFindings)}
            ${renderDisclaimer()}
        </div>
    `;
}

// ── Finding card ──────────────────────────────────────────────────────────────

function _renderBPFindingCard(f) {
    const isExpanded  = bpState.expandedIds.has(f.id);
    const stripeColor = SEVERITY_COLOR[f.severity] || '#64748b';
    const sevLabel    = t('severity' + f.severity.charAt(0).toUpperCase() + f.severity.slice(1));

    const body = isExpanded ? `
        <div class="finding-body">
            ${f.description ? `<p class="finding-description">${escapeHtml(f.description)}</p>` : ''}
            ${f.affectedItems && f.affectedItems.length > 0 ? `
                <div class="finding-section">
                    <div class="finding-section-title">${t('labelAffected')}</div>
                    <ul class="finding-affected-list">
                        ${f.affectedItems.map(i => `<li>${escapeHtml(i)}</li>`).join('')}
                    </ul>
                </div>
            ` : ''}
            ${f.remediation ? `
                <div class="finding-section finding-section--remediation">
                    <div class="finding-section-title">${t('labelRemediation')}</div>
                    <p class="finding-remediation">${escapeHtml(f.remediation)}</p>
                </div>
            ` : ''}
        </div>
    ` : '';

    return `
        <div class="finding-card" style="--stripe-color: ${stripeColor}">
            <div class="finding-stripe"></div>
            <div class="finding-card-content">
                <div class="finding-header" onclick="toggleBPExpanded('${f.id}')">
                    <div class="finding-header-main">
                        <span class="severity-pill severity-pill--${f.severity}">${sevLabel}</span>
                    </div>
                    <div class="finding-title">${escapeHtml(f.title)}</div>
                    <div class="finding-meta"></div>
                    <span class="finding-toggle ${isExpanded ? 'finding-toggle--open' : ''}">▶</span>
                </div>
                ${body}
            </div>
        </div>
    `;
}

// ── Grouped findings ──────────────────────────────────────────────────────────

function _renderBPFindingsByCategory(findings) {
    if (findings.length === 0) {
        return `
            <div class="findings-empty-state">
                <div class="findings-empty-icon">✓</div>
                <div class="findings-empty-title">${t('bpNoIssuesTitle')}</div>
                <div class="findings-empty-sub">${t('bpNoIssuesSub')}</div>
            </div>
        `;
    }

    const order   = [];
    const grouped = {};
    for (const f of findings) {
        if (!grouped[f.category]) { grouped[f.category] = []; order.push(f.category); }
        grouped[f.category].push(f);
    }

    return order.map(cat => {
        const catF     = grouped[cat];
        const n        = catF.length;
        const topColor = SEVERITY_COLOR[catF[0].severity] || SEVERITY_COLOR.info;
        const issueText = n === 1 ? t('issueCount') : t('issuesCount', n);
        return `
            <div class="category-group">
                <div class="category-header" style="--cat-color: ${topColor}">
                    <span class="category-header-name">${escapeHtml(cat)}</span>
                    <span class="category-header-count">${issueText}</span>
                </div>
                <div class="category-findings">
                    ${catF.map(_renderBPFindingCard).join('')}
                </div>
            </div>
        `;
    }).join('');
}

// ── Passed section ────────────────────────────────────────────────────────────

function _renderBPPassedSection(passFindings) {
    if (passFindings.length === 0) return '';

    const cards = passFindings.map(f => `
        <div class="finding-card finding-card--pass" style="--stripe-color: #34d399">
            <div class="finding-stripe"></div>
            <div class="finding-card-content">
                <div class="finding-header finding-header--pass">
                    <div class="finding-header-main">
                        <span class="severity-pill severity-pill--pass">${t('severityPass')}</span>
                        <span class="finding-category">${escapeHtml(f.category)}</span>
                    </div>
                    <div class="finding-title finding-title--pass">${escapeHtml(f.title)}</div>
                </div>
            </div>
        </div>
    `).join('');

    return `
        <div class="passed-section">
            <div class="passed-section-header">
                ${t('passedChecks')} <span class="passed-count">${passFindings.length}</span>
            </div>
            <div class="passed-list">${cards}</div>
        </div>
    `;
}
