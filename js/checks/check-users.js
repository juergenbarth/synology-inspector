/**
 * check-users.js
 *
 * User account security checks:
 *   1. Default admin account active                     (high)
 *   2. Password policy not enforced                     (high)
 *   3. Password minimum length below 12                 (medium)
 *   4. Password special characters not required         (low)
 *   5. Common password check disabled                   (low)
 *   6. Administrators group members                     (info)
 */

function checkUsers(config, _tlsProfile, parseResult) {
    const findings    = [];
    const users       = parseResult?.users       || [];
    const adminMembers = parseResult?.adminMembers || [];

    // ── Default admin account disabled ────────────────────────────────────────
    // expire: -1 = active (never expires), 1 = disabled
    const adminUser   = users.find(u => u.name === 'admin' || u.uid === 1024);
    const adminActive = adminUser ? adminUser.expire === -1 : false;

    if (adminActive) {
        findings.push({
            id:          'syn-admin-active',
            title:       t('checkAdminActiveFailTitle'),
            description: t('checkAdminActiveDesc'),
            severity:    'high',
            status:      'fail',
            category:    t('catUsers'),
            frameworks:  [fwRef('CIS', '4.7'), fwRef('NIST', 'AC-2'), fwRef('ISO', 'A.8.3')],
            affectedItems: ['admin'],
            remediation: t('checkAdminActiveRemediation'),
        });
    } else {
        findings.push({
            id:          'syn-admin-disabled',
            title:       t('checkAdminActivePassTitle'),
            description: '',
            severity:    'info',
            status:      'pass',
            category:    t('catUsers'),
            frameworks:  [fwRef('CIS', '4.7'), fwRef('NIST', 'AC-2')],
            affectedItems: [],
            remediation: '',
        });
    }

    // ── Password policy ───────────────────────────────────────────────────────
    const policyEnabled = config.get('Passwdstrength_isApplyPasswdRule') === '1';

    if (!policyEnabled) {
        findings.push({
            id:          'syn-pwd-policy-disabled',
            title:       t('checkPwdPolicyDisabledFailTitle'),
            description: t('checkPwdPolicyDisabledDesc'),
            severity:    'high',
            status:      'fail',
            category:    t('catUsers'),
            frameworks:  [fwRef('CIS', '4.10'), fwRef('NIST', 'AC-7'), fwRef('ISO', 'A.8.5'), fwRef('PCI', 'Req.8.3.4')],
            affectedItems: [],
            remediation: t('checkPwdPolicyDisabledRemediation'),
        });
    } else {
        // Min length
        const minLengthEnabled = config.get('Passwdstrength_isEnableMinLength') === '1';
        const minLength        = minLengthEnabled ? parseInt(config.get('Passwdstrength_minLength') || '0', 10) : 0;

        if (!minLengthEnabled || minLength < 12) {
            findings.push({
                id:          'syn-pwd-length-weak',
                title:       t('checkPwdLengthFailTitle'),
                description: t('checkPwdLengthDesc', minLength || 0),
                severity:    'medium',
                status:      'fail',
                category:    t('catUsers'),
                frameworks:  [fwRef('CIS', '4.10'), fwRef('ISO', 'A.8.5'), fwRef('PCI', 'Req.8.3.4')],
                affectedItems: [],
                remediation: t('checkPwdLengthRemediation'),
            });
        } else {
            findings.push({
                id:          'syn-pwd-length-ok',
                title:       t('checkPwdLengthPassTitle'),
                description: '',
                severity:    'info',
                status:      'pass',
                category:    t('catUsers'),
                frameworks:  [fwRef('CIS', '4.10'), fwRef('ISO', 'A.8.5')],
                affectedItems: [],
                remediation: '',
            });
        }

        // Special characters
        if (config.get('Passwdstrength_isIncludeSpecialChar') !== '1') {
            findings.push({
                id:          'syn-pwd-no-special',
                title:       t('checkPwdSpecialFailTitle'),
                description: t('checkPwdSpecialDesc'),
                severity:    'low',
                status:      'fail',
                category:    t('catUsers'),
                frameworks:  [fwRef('NIST', 'AC-7'), fwRef('ISO', 'A.8.5')],
                affectedItems: [],
                remediation: t('checkPwdSpecialRemediation'),
            });
        } else {
            findings.push({
                id:          'syn-pwd-special-ok',
                title:       t('checkPwdSpecialPassTitle'),
                description: '',
                severity:    'info',
                status:      'pass',
                category:    t('catUsers'),
                frameworks:  [fwRef('ISO', 'A.8.5')],
                affectedItems: [],
                remediation: '',
            });
        }

        // Common password check
        if (config.get('Passwdstrength_isExcloudCommon') !== '1') {
            findings.push({
                id:          'syn-pwd-no-common-check',
                title:       t('checkPwdCommonFailTitle'),
                description: t('checkPwdCommonDesc'),
                severity:    'low',
                status:      'fail',
                category:    t('catUsers'),
                frameworks:  [fwRef('NIST', 'AC-7'), fwRef('ISO', 'A.8.5')],
                affectedItems: [],
                remediation: t('checkPwdCommonRemediation'),
            });
        } else {
            findings.push({
                id:          'syn-pwd-common-ok',
                title:       t('checkPwdCommonPassTitle'),
                description: '',
                severity:    'info',
                status:      'pass',
                category:    t('catUsers'),
                frameworks:  [fwRef('ISO', 'A.8.5')],
                affectedItems: [],
                remediation: '',
            });
        }
    }

    // ── Administrators group members (always info) ─────────────────────────────
    if (adminMembers.length > 0) {
        findings.push({
            id:          'syn-admin-group-members',
            title:       t('checkAdminGroupTitle'),
            description: t('checkAdminGroupDesc'),
            severity:    'info',
            status:      'pass',
            category:    t('catUsers'),
            frameworks:  [fwRef('CIS', '4.7'), fwRef('NIST', 'AC-2'), fwRef('ISO', 'A.8.3')],
            affectedItems: adminMembers,
            remediation: '',
        });
    }

    return findings;
}

COMPLIANCE_CHECKS.push(checkUsers);
