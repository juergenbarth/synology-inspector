/**
 * check-websecurity.js
 *
 * DSM web interface hardening checks:
 *   1. CSRF protection disabled          (medium)
 *   2. iFrame embedding not blocked      (medium)
 *   3. Session IP binding disabled       (medium)
 *
 * All three settings live in the SECURITY_ config key —
 * a JSON array of SYNO.Core.Security.* API response objects.
 */

/**
 * Extract the two relevant DSM security data objects from the SECURITY_ blob.
 *
 * @param {Map<string,string>} config
 * @returns {{ dsmSecurity: Object|null, dsmEmbedSecurity: Object|null }}
 */
function parseDsmSecurityBlob(config) {
    const securityRaw = config.get('SECURITY_');
    let dsmSecurity      = null;
    let dsmEmbedSecurity = null;

    if (!securityRaw) return { dsmSecurity, dsmEmbedSecurity };

    try {
        const apiResponses = JSON.parse(securityRaw);
        for (const apiResponse of apiResponses) {
            if (apiResponse.api === 'SYNO.Core.Security.DSM') {
                dsmSecurity = apiResponse.result?.data ?? null;
            } else if (apiResponse.api === 'SYNO.Core.Security.DSM.Embed') {
                dsmEmbedSecurity = apiResponse.result?.data ?? null;
            }
        }
    } catch (_) {}

    return { dsmSecurity, dsmEmbedSecurity };
}

function checkWebSecurity(config, _tlsProfile) {
    const findings = [];
    const { dsmSecurity, dsmEmbedSecurity } = parseDsmSecurityBlob(config);

    // ── CSRF protection ───────────────────────────────────────────────────────
    if (dsmSecurity !== null) {
        const csrfEnabled = dsmSecurity.enable_csrf_protection === true;

        if (csrfEnabled) {
            findings.push({
                id:          'syn-csrf-on',
                title:       t('checkCSRFPassTitle'),
                description: '',
                severity:    'info',
                status:      'pass',
                category:    t('catAuth'),
                frameworks:  [fwRef('CIS', '16.6'), fwRef('NIST', 'SI-10'), fwRef('ISO', 'A.8.26')],
                affectedItems: [],
                remediation: '',
            });
        } else {
            findings.push({
                id:          'syn-csrf-off',
                title:       t('checkCSRFFailTitle'),
                description: t('checkCSRFDesc'),
                severity:    'medium',
                status:      'fail',
                category:    t('catAuth'),
                frameworks:  [fwRef('CIS', '16.6'), fwRef('NIST', 'SI-10'), fwRef('ISO', 'A.8.26')],
                affectedItems: [t('checkCSRFAffected')],
                remediation: t('checkCSRFRemediation'),
            });
        }
    }

    // ── iFrame embedding ──────────────────────────────────────────────────────
    if (dsmEmbedSecurity !== null) {
        const iframeBlocked = dsmEmbedSecurity.enable_block === true;

        if (iframeBlocked) {
            findings.push({
                id:          'syn-iframe-blocked',
                title:       t('checkIFramePassTitle'),
                description: '',
                severity:    'info',
                status:      'pass',
                category:    t('catAuth'),
                frameworks:  [fwRef('CIS', '16.6'), fwRef('NIST', 'SI-10'), fwRef('ISO', 'A.8.26')],
                affectedItems: [],
                remediation: '',
            });
        } else {
            findings.push({
                id:          'syn-iframe-allowed',
                title:       t('checkIFrameFailTitle'),
                description: t('checkIFrameDesc'),
                severity:    'medium',
                status:      'fail',
                category:    t('catAuth'),
                frameworks:  [fwRef('CIS', '16.6'), fwRef('NIST', 'SI-10'), fwRef('ISO', 'A.8.26')],
                affectedItems: [t('checkIFrameAffected')],
                remediation: t('checkIFrameRemediation'),
            });
        }
    }

    // ── Session IP binding ────────────────────────────────────────────────────
    // skip_ip_checking = true means DSM no longer verifies that requests in a
    // session come from the same IP as the login → session hijacking is easier.
    if (dsmSecurity !== null) {
        const ipCheckingSkipped = dsmSecurity.skip_ip_checking === true;

        if (!ipCheckingSkipped) {
            findings.push({
                id:          'syn-ip-check-on',
                title:       t('checkIPCheckPassTitle'),
                description: '',
                severity:    'info',
                status:      'pass',
                category:    t('catAuth'),
                frameworks:  [fwRef('NIST', 'AC-17'), fwRef('ISO', 'A.8.5')],
                affectedItems: [],
                remediation: '',
            });
        } else {
            findings.push({
                id:          'syn-ip-check-off',
                title:       t('checkIPCheckFailTitle'),
                description: t('checkIPCheckDesc'),
                severity:    'medium',
                status:      'fail',
                category:    t('catAuth'),
                frameworks:  [fwRef('NIST', 'AC-17'), fwRef('ISO', 'A.8.5')],
                affectedItems: [t('checkIPCheckAffected')],
                remediation: t('checkIPCheckRemediation'),
            });
        }
    }

    return findings;
}

COMPLIANCE_CHECKS.push(checkWebSecurity);
