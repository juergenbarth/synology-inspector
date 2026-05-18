/**
 * check-maintenance.js
 *
 * Maintenance and infrastructure security checks:
 *   1. Automatic configuration backup not configured  (medium)
 *   2. SMB signing disabled                           (medium)
 */

function checkMaintenance(config, _tlsProfile, parseResult) {
    const findings            = [];
    const autoBackupConfigured = parseResult?.autoBackupConfigured ?? false;

    // ── Auto config backup ────────────────────────────────────────────────────
    if (!autoBackupConfigured) {
        findings.push({
            id:          'syn-no-config-backup',
            title:       t('checkConfigBackupFailTitle'),
            description: t('checkConfigBackupDesc'),
            severity:    'medium',
            status:      'fail',
            category:    t('catMaintenance'),
            frameworks:  [fwRef('CIS', '12.2'), fwRef('NIST', 'CP-9')],
            affectedItems: [],
            remediation: t('checkConfigBackupRemediation'),
        });
    } else {
        findings.push({
            id:          'syn-config-backup-ok',
            title:       t('checkConfigBackupPassTitle'),
            description: '',
            severity:    'info',
            status:      'pass',
            category:    t('catMaintenance'),
            frameworks:  [fwRef('CIS', '12.2')],
            affectedItems: [],
            remediation: '',
        });
    }

    // ── SMB signing ───────────────────────────────────────────────────────────
    if (config.get('CIFS_Enable_Server_Signing') !== '1') {
        findings.push({
            id:          'syn-smb-no-signing',
            title:       t('checkSMBSigningFailTitle'),
            description: t('checkSMBSigningDesc'),
            severity:    'medium',
            status:      'fail',
            category:    t('catMaintenance'),
            frameworks:  [fwRef('CIS', '9.4'), fwRef('NIST', 'SC-8'), fwRef('ISO', 'A.8.24')],
            affectedItems: ['SMB'],
            remediation: t('checkSMBSigningRemediation'),
        });
    } else {
        findings.push({
            id:          'syn-smb-signing-ok',
            title:       t('checkSMBSigningPassTitle'),
            description: '',
            severity:    'info',
            status:      'pass',
            category:    t('catMaintenance'),
            frameworks:  [fwRef('CIS', '9.4'), fwRef('NIST', 'SC-8')],
            affectedItems: [],
            remediation: '',
        });
    }

    return findings;
}

COMPLIANCE_CHECKS.push(checkMaintenance);
