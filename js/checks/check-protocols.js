/**
 * check-protocols.js
 *
 * Network protocol security checks:
 *   1. SMBv1 enabled       (critical)
 *   2. NTLMv1 auth enabled (high)
 *   3. FTP anonymous access enabled (high)
 *   4. FTP without TLS enabled      (medium)
 */

function checkProtocols(config, _tlsProfile) {
    const findings = [];

    // ── SMBv1 ────────────────────────────────────────────────────────────────
    // CIFS_Min_Protocol: 'SMB1' / 'NT1' = SMBv1 allowed; 'SMB2' / 'SMB3' = secure
    const minProto  = (config.get('CIFS_Min_Protocol') || 'SMB2').toUpperCase();
    const smb1On    = (minProto === 'SMB1' || minProto === 'NT1');

    if (smb1On) {
        findings.push({
            id:          'syn-smb1-enabled',
            title:       t('checkSMB1FailTitle'),
            description: t('checkSMB1Desc'),
            severity:    'critical',
            status:      'fail',
            category:    t('catProtocols'),
            frameworks:  [fwRef('CIS', '9.4'), fwRef('NIST', 'CM-7'), fwRef('ISO', 'A.8.20'), fwRef('PCI', 'Req.12.3.3')],
            affectedItems: ['SMBv1 / CIFS'],
            remediation: t('checkSMB1Remediation'),
        });
    } else {
        findings.push({
            id:          'syn-smb1-disabled',
            title:       t('checkSMB1PassTitle'),
            description: '',
            severity:    'info',
            status:      'pass',
            category:    t('catProtocols'),
            frameworks:  [fwRef('CIS', '9.4'), fwRef('NIST', 'CM-7')],
            affectedItems: [],
            remediation: '',
        });
    }

    // ── NTLMv1 authentication ─────────────────────────────────────────────────
    const ntlmv1On = config.get('CIFS_Enable_NTLMv1_Auth') === '1';
    if (ntlmv1On) {
        findings.push({
            id:          'syn-ntlmv1-enabled',
            title:       t('checkNTLMv1FailTitle'),
            description: t('checkNTLMv1Desc'),
            severity:    'high',
            status:      'fail',
            category:    t('catProtocols'),
            frameworks:  [fwRef('CIS', '9.4'), fwRef('NIST', 'IA-3'), fwRef('ISO', 'A.8.20'), fwRef('PCI', 'Req.12.3.3')],
            affectedItems: ['NTLMv1 authentication'],
            remediation: t('checkNTLMv1Remediation'),
        });
    } else {
        findings.push({
            id:          'syn-ntlmv1-disabled',
            title:       t('checkNTLMv1PassTitle'),
            description: '',
            severity:    'info',
            status:      'pass',
            category:    t('catProtocols'),
            frameworks:  [fwRef('CIS', '9.4'), fwRef('NIST', 'IA-3')],
            affectedItems: [],
            remediation: '',
        });
    }

    // ── FTP anonymous access ──────────────────────────────────────────────────
    const ftpOn     = config.get('FTP_isEnableFTP') === '1';
    const ftpAnonOn = config.get('FTP_isEnableAnon') === '1';

    if (ftpAnonOn) {
        findings.push({
            id:          'syn-ftp-anon',
            title:       t('checkFTPAnonFailTitle'),
            description: t('checkFTPAnonDesc'),
            severity:    'high',
            status:      'fail',
            category:    t('catProtocols'),
            frameworks:  [fwRef('CIS', '9.2'), fwRef('NIST', 'CM-7'), fwRef('ISO', 'A.8.3'), fwRef('PCI', 'Req.2.2.7')],
            affectedItems: ['FTP anonymous login'],
            remediation: t('checkFTPAnonRemediation'),
        });
    }

    // ── FTP without TLS ───────────────────────────────────────────────────────
    // FTP_isEnableSSL: '0' = disabled, '1' = optional, '2' = required
    const ftpSslVal = parseInt(config.get('FTP_isEnableSSL') || '0', 10);
    const ftpSslOn  = ftpSslVal >= 1;

    if (ftpOn && !ftpSslOn) {
        findings.push({
            id:          'syn-ftp-no-tls',
            title:       t('checkFTPTLSFailTitle'),
            description: t('checkFTPTLSDesc'),
            severity:    'medium',
            status:      'fail',
            category:    t('catProtocols'),
            frameworks:  [fwRef('CIS', '9.2'), fwRef('NIST', 'SC-8'), fwRef('ISO', 'A.8.24')],
            affectedItems: ['FTP (unencrypted)'],
            remediation: t('checkFTPTLSRemediation'),
        });
    } else if (ftpOn && ftpSslOn) {
        findings.push({
            id:          'syn-ftp-tls-on',
            title:       t('checkFTPTLSPassTitle'),
            description: '',
            severity:    'info',
            status:      'pass',
            category:    t('catProtocols'),
            frameworks:  [fwRef('CIS', '9.2'), fwRef('NIST', 'SC-8'), fwRef('ISO', 'A.8.24')],
            affectedItems: [],
            remediation: '',
        });
    }

    return findings;
}

COMPLIANCE_CHECKS.push(checkProtocols);
