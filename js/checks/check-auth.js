/**
 * check-auth.js
 *
 * Authentication and access hardening checks:
 *   1. Auto-block not configured   (medium)
 *   2. HTTPS redirect disabled     (medium)
 *   3. HSTS not enabled            (low)
 */

function checkAuth(config, _tlsProfile) {
    const findings = [];

    // ── Auto-block ────────────────────────────────────────────────────────────
    // AutoBlock_attempts > 0 means the feature is configured with an attempt limit.
    // A value of 0 or missing key means auto-block is effectively off.
    const autoBlockAttempts = parseInt(config.get('AutoBlock_attempts') || '0', 10);
    const autoBlockMinutes  = parseInt(config.get('AutoBlock_attemptMin') || '0', 10);

    if (autoBlockAttempts > 0 && autoBlockMinutes > 0) {
        findings.push({
            id:          'syn-autoblock-on',
            title:       t('checkAutoBlockPassTitle'),
            description: '',
            severity:    'info',
            status:      'pass',
            category:    t('catAuth'),
            frameworks:  [fwRef('CIS', '4.10'), fwRef('NIST', 'AC-7'), fwRef('ISO', 'A.8.5')],
            affectedItems: [],
            remediation: '',
        });
    } else {
        findings.push({
            id:          'syn-autoblock-off',
            title:       t('checkAutoBlockFailTitle'),
            description: t('checkAutoBlockDesc'),
            severity:    'medium',
            status:      'fail',
            category:    t('catAuth'),
            frameworks:  [fwRef('CIS', '4.10'), fwRef('NIST', 'AC-7'), fwRef('ISO', 'A.8.5'), fwRef('PCI', 'Req.8.3.4')],
            affectedItems: [t('checkAutoBlockAffected')],
            remediation: t('checkAutoBlockRemediation'),
        });
    }

    // ── HTTPS redirect ────────────────────────────────────────────────────────
    // w3_redirectHTTPS = 'yes' means DSM automatically redirects HTTP → HTTPS.
    const httpsRedirect = config.get('w3_redirectHTTPS');

    if (httpsRedirect === 'yes') {
        findings.push({
            id:          'syn-https-redirect-on',
            title:       t('checkHTTPSRedirectPassTitle'),
            description: '',
            severity:    'info',
            status:      'pass',
            category:    t('catAuth'),
            frameworks:  [fwRef('CIS', '9.5'), fwRef('NIST', 'SC-8'), fwRef('ISO', 'A.8.24')],
            affectedItems: [],
            remediation: '',
        });
    } else {
        findings.push({
            id:          'syn-https-redirect-off',
            title:       t('checkHTTPSRedirectFailTitle'),
            description: t('checkHTTPSRedirectDesc'),
            severity:    'medium',
            status:      'fail',
            category:    t('catAuth'),
            frameworks:  [fwRef('CIS', '9.5'), fwRef('NIST', 'SC-8'), fwRef('ISO', 'A.8.24'), fwRef('PCI', 'Req.4.2.1')],
            affectedItems: [t('checkHTTPSRedirectAffected')],
            remediation: t('checkHTTPSRedirectRemediation'),
        });
    }

    // ── HSTS ─────────────────────────────────────────────────────────────────
    // w3_runsyshsts = 'yes' means HTTP Strict Transport Security is active.
    const hsts = config.get('w3_runsyshsts');

    if (hsts === 'yes') {
        findings.push({
            id:          'syn-hsts-on',
            title:       t('checkHSTSPassTitle'),
            description: '',
            severity:    'info',
            status:      'pass',
            category:    t('catAuth'),
            frameworks:  [fwRef('CIS', '9.5'), fwRef('NIST', 'SC-8')],
            affectedItems: [],
            remediation: '',
        });
    } else {
        findings.push({
            id:          'syn-hsts-off',
            title:       t('checkHSTSFailTitle'),
            description: t('checkHSTSDesc'),
            severity:    'low',
            status:      'fail',
            category:    t('catAuth'),
            frameworks:  [fwRef('CIS', '9.5'), fwRef('NIST', 'SC-8'), fwRef('ISO', 'A.8.24')],
            affectedItems: [t('checkHSTSAffected')],
            remediation: t('checkHSTSRemediation'),
        });
    }

    return findings;
}

COMPLIANCE_CHECKS.push(checkAuth);
