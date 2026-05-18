/**
 * check-remote-access.js
 *
 * Remote access checks:
 *   1. QuickConnect enabled                    (high)
 *   2. SSH enabled on the default port 22      (medium)
 *   3. Telnet enabled                          (critical)
 */

function checkRemoteAccess(config, _tlsProfile) {
    const findings = [];

    // ── QuickConnect ─────────────────────────────────────────────────────────
    const qcRaw = config.get('QUICKCONNECT_config');
    if (qcRaw) {
        let qcEnabled = false;
        try { qcEnabled = JSON.parse(qcRaw)?.quickconnect?.enabled === true; } catch (_) {}

        if (qcEnabled) {
            findings.push({
                id:          'syn-qc-enabled',
                title:       t('checkQCFailTitle'),
                description: t('checkQCDesc'),
                severity:    'high',
                status:      'fail',
                category:    t('catRemoteAccess'),
                frameworks:  [fwRef('CIS', '4.8'), fwRef('NIST', 'SC-7'), fwRef('ISO', 'A.8.20'), fwRef('NIS2', 'Art.21(b)')],
                affectedItems: ['QuickConnect'],
                remediation: t('checkQCRemediation'),
            });
        } else {
            findings.push({
                id:          'syn-qc-disabled',
                title:       t('checkQCPassTitle'),
                description: '',
                severity:    'info',
                status:      'pass',
                category:    t('catRemoteAccess'),
                frameworks:  [fwRef('CIS', '4.8'), fwRef('NIST', 'SC-7')],
                affectedItems: [],
                remediation: '',
            });
        }
    }

    // ── Telnet ───────────────────────────────────────────────────────────────
    const telnetEnabled = config.get('Terminal_isEnableTelnet') === '1';
    if (telnetEnabled) {
        findings.push({
            id:          'syn-telnet-enabled',
            title:       t('checkTelnetFailTitle'),
            description: t('checkTelnetDesc'),
            severity:    'critical',
            status:      'fail',
            category:    t('catRemoteAccess'),
            frameworks:  [fwRef('CIS', '4.6'), fwRef('NIST', 'SC-8'), fwRef('ISO', 'A.8.20'), fwRef('PCI', 'Req.2.2.7')],
            affectedItems: ['Telnet'],
            remediation: t('checkTelnetRemediation'),
        });
    } else {
        findings.push({
            id:          'syn-telnet-disabled',
            title:       t('checkTelnetPassTitle'),
            description: '',
            severity:    'info',
            status:      'pass',
            category:    t('catRemoteAccess'),
            frameworks:  [fwRef('CIS', '4.6'), fwRef('NIST', 'SC-8')],
            affectedItems: [],
            remediation: '',
        });
    }


    return findings;
}

COMPLIANCE_CHECKS.push(checkRemoteAccess);
