/**
 * check-network.js
 *
 * Network perimeter security checks:
 *   1. DoS protection not enabled on all interfaces  (medium)
 */

function checkNetwork(config, _tlsProfile) {
    const findings = [];

    // ── DoS protection ────────────────────────────────────────────────────────
    // DOS_config: JSON object mapping /etc/fw_security/<iface>.conf → INI content.
    // Each INI block contains dos_protect_enable=yes|no.
    const dosConfigRaw = config.get('DOS_config');
    const unprotectedInterfaces = [];
    let dosConfigAvailable = false;

    if (dosConfigRaw) {
        try {
            const dosConfig = JSON.parse(dosConfigRaw);
            dosConfigAvailable = true;
            for (const [confFilePath, iniContent] of Object.entries(dosConfig)) {
                const interfaceName = confFilePath
                    .replace('/etc/fw_security/', '')
                    .replace('.conf', '');
                if (!iniContent.includes('dos_protect_enable=yes')) {
                    unprotectedInterfaces.push(interfaceName);
                }
            }
        } catch (_) {}
    }

    if (dosConfigAvailable) {
        if (unprotectedInterfaces.length === 0) {
            findings.push({
                id:          'syn-dos-protected',
                title:       t('checkDoSPassTitle'),
                description: '',
                severity:    'info',
                status:      'pass',
                category:    t('catNetwork'),
                frameworks:  [fwRef('NIST', 'SC-5'), fwRef('ISO', 'A.8.20'), fwRef('NIS2', 'Art.21(e)')],
                affectedItems: [],
                remediation: '',
            });
        } else {
            findings.push({
                id:          'syn-dos-incomplete',
                title:       t('checkDoSFailTitle'),
                description: t('checkDoSDesc'),
                severity:    'medium',
                status:      'fail',
                category:    t('catNetwork'),
                frameworks:  [fwRef('NIST', 'SC-5'), fwRef('ISO', 'A.8.20'), fwRef('NIS2', 'Art.21(e)')],
                affectedItems: unprotectedInterfaces,
                remediation: t('checkDoSRemediation'),
            });
        }
    }

    return findings;
}

COMPLIANCE_CHECKS.push(checkNetwork);
