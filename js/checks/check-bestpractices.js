/**
 * check-bestpractices.js
 *
 * Operational best-practice checks (non-security, do NOT affect security score):
 *   SMB:      Transfer Log off, Strict Allocate on, AIO Read on, Multichannel on,
 *             Cross-share symlinks off
 *   Services: AFP deprecated
 *   Storage:  Fast Clone (btrfs only)
 *   Updates:  Notify-only setting
 *   Scheduler: Recycle Bin cleanup task
 */

function checkBestPractices(config, _tlsProfile, parseResult) {
    const findings       = [];
    const schedulerTasks = parseResult?.schedulerTasks || [];
    const hasBtrfs       = parseResult?.hasBtrfs       ?? false;

    // ── SMB: Transfer Log ─────────────────────────────────────────────────────
    // Transfer log should be OFF (0) for performance; ON (1) = FAIL
    if (config.get('CIFS_Enable_Transfer_Log') === '1') {
        findings.push({
            id:          'bp-smb-transfer-log-on',
            title:       t('bpCheckTransferLogFailTitle'),
            description: t('bpCheckTransferLogDesc'),
            severity:    'low',
            status:      'fail',
            category:    t('catBPSMB'),
            frameworks:  [],
            affectedItems: ['CIFS_Enable_Transfer_Log'],
            remediation: t('bpCheckTransferLogRemediation'),
        });
    } else {
        findings.push({
            id:          'bp-smb-transfer-log-off',
            title:       t('bpCheckTransferLogPassTitle'),
            description: '',
            severity:    'info',
            status:      'pass',
            category:    t('catBPSMB'),
            frameworks:  [],
            affectedItems: [],
            remediation: '',
        });
    }

    // ── SMB: Strict Allocate ──────────────────────────────────────────────────
    // Should be ON (1) = "do not reserve disk space" = better performance
    if (config.get('CIFS_Strict_Allocate') !== '1') {
        findings.push({
            id:          'bp-smb-no-strict-allocate',
            title:       t('bpCheckStrictAllocateFailTitle'),
            description: t('bpCheckStrictAllocateDesc'),
            severity:    'low',
            status:      'fail',
            category:    t('catBPSMB'),
            frameworks:  [],
            affectedItems: [],
            remediation: t('bpCheckStrictAllocateRemediation'),
        });
    } else {
        findings.push({
            id:          'bp-smb-strict-allocate-ok',
            title:       t('bpCheckStrictAllocatePassTitle'),
            description: '',
            severity:    'info',
            status:      'pass',
            category:    t('catBPSMB'),
            frameworks:  [],
            affectedItems: [],
            remediation: '',
        });
    }

    // ── SMB: Asynchronous Read ────────────────────────────────────────────────
    if (config.get('CIFS_Enable_AIO_Read') !== '1') {
        findings.push({
            id:          'bp-smb-no-aio',
            title:       t('bpCheckAIOReadFailTitle'),
            description: t('bpCheckAIOReadDesc'),
            severity:    'low',
            status:      'fail',
            category:    t('catBPSMB'),
            frameworks:  [],
            affectedItems: [],
            remediation: t('bpCheckAIOReadRemediation'),
        });
    } else {
        findings.push({
            id:          'bp-smb-aio-ok',
            title:       t('bpCheckAIOReadPassTitle'),
            description: '',
            severity:    'info',
            status:      'pass',
            category:    t('catBPSMB'),
            frameworks:  [],
            affectedItems: [],
            remediation: '',
        });
    }

    // ── SMB: Multichannel ─────────────────────────────────────────────────────
    if (config.get('CIFS_Enable_Multichannel') !== '1') {
        findings.push({
            id:          'bp-smb-no-multichannel',
            title:       t('bpCheckMultichannelFailTitle'),
            description: t('bpCheckMultichannelDesc'),
            severity:    'low',
            status:      'fail',
            category:    t('catBPSMB'),
            frameworks:  [],
            affectedItems: [],
            remediation: t('bpCheckMultichannelRemediation'),
        });
    } else {
        findings.push({
            id:          'bp-smb-multichannel-ok',
            title:       t('bpCheckMultichannelPassTitle'),
            description: '',
            severity:    'info',
            status:      'pass',
            category:    t('catBPSMB'),
            frameworks:  [],
            affectedItems: [],
            remediation: '',
        });
    }

    // ── SMB: Cross-share symlinks ─────────────────────────────────────────────
    // CIFS_Symlinks: '1' = symlinks may cross share boundaries (path traversal risk)
    //                '0' or absent = constrained within share (safe)
    if (config.get('CIFS_Symlinks') === '1') {
        findings.push({
            id:          'bp-smb-cross-share-symlinks',
            title:       t('bpCheckSymlinksFailTitle'),
            description: t('bpCheckSymlinksDesc'),
            severity:    'low',
            status:      'fail',
            category:    t('catBPSMB'),
            frameworks:  [],
            affectedItems: [],
            remediation: t('bpCheckSymlinksRemediation'),
        });
    } else {
        findings.push({
            id:          'bp-smb-cross-share-symlinks-ok',
            title:       t('bpCheckSymlinksPassTitle'),
            description: '',
            severity:    'info',
            status:      'pass',
            category:    t('catBPSMB'),
            frameworks:  [],
            affectedItems: [],
            remediation: '',
        });
    }

    // ── AFP: deprecated service ───────────────────────────────────────────────
    if (config.get('AFP_isEnableAFP') === '1') {
        findings.push({
            id:          'bp-afp-enabled',
            title:       t('bpCheckAFPFailTitle'),
            description: t('bpCheckAFPDesc'),
            severity:    'medium',
            status:      'fail',
            category:    t('catBPStorage'),
            frameworks:  [],
            affectedItems: ['AFP'],
            remediation: t('bpCheckAFPRemediation'),
        });
    } else {
        findings.push({
            id:          'bp-afp-disabled',
            title:       t('bpCheckAFPPassTitle'),
            description: '',
            severity:    'info',
            status:      'pass',
            category:    t('catBPStorage'),
            frameworks:  [],
            affectedItems: [],
            remediation: '',
        });
    }

    // ── Fast Clone — only relevant when btrfs is in use ───────────────────────
    if (hasBtrfs) {
        if (config.get('ADV_isEnableReflinkCopy') !== '1') {
            findings.push({
                id:          'bp-no-fast-clone',
                title:       t('bpCheckFastCloneFailTitle'),
                description: t('bpCheckFastCloneDesc'),
                severity:    'medium',
                status:      'fail',
                category:    t('catBPStorage'),
                frameworks:  [],
                affectedItems: [],
                remediation: t('bpCheckFastCloneRemediation'),
            });
        } else {
            findings.push({
                id:          'bp-fast-clone-ok',
                title:       t('bpCheckFastClonePassTitle'),
                description: '',
                severity:    'info',
                status:      'pass',
                category:    t('catBPStorage'),
                frameworks:  [],
                affectedItems: [],
                remediation: '',
            });
        }
    }

    // ── DSM update setting: notify only ───────────────────────────────────────
    let updateType = null;
    try {
        const raw = config.get('UPDATE_setting_v4');
        if (raw) updateType = JSON.parse(raw)?.autoupdate_type || null;
    } catch (_) {}

    if (updateType !== null) {
        if (updateType !== 'notify') {
            findings.push({
                id:          'bp-update-auto',
                title:       t('bpCheckUpdateNotifyFailTitle'),
                description: t('bpCheckUpdateNotifyDesc'),
                severity:    'medium',
                status:      'fail',
                category:    t('catBPUpdates'),
                frameworks:  [],
                affectedItems: [],
                remediation: t('bpCheckUpdateNotifyRemediation'),
            });
        } else {
            findings.push({
                id:          'bp-update-notify-ok',
                title:       t('bpCheckUpdateNotifyPassTitle'),
                description: '',
                severity:    'info',
                status:      'pass',
                category:    t('catBPUpdates'),
                frameworks:  [],
                affectedItems: [],
                remediation: '',
            });
        }
    }

    // ── Recycle Bin cleanup task ──────────────────────────────────────────────
    const hasRecycleTask = schedulerTasks.some(
        task => task.app === 'SYNO.SDS.TaskScheduler.Recycle' && task.state === 'enabled'
    );

    if (!hasRecycleTask) {
        findings.push({
            id:          'bp-no-recycle-task',
            title:       t('bpCheckRecycleTaskFailTitle'),
            description: t('bpCheckRecycleTaskDesc'),
            severity:    'low',
            status:      'fail',
            category:    t('catBPScheduler'),
            frameworks:  [],
            affectedItems: [],
            remediation: t('bpCheckRecycleTaskRemediation'),
        });
    } else {
        findings.push({
            id:          'bp-recycle-task-ok',
            title:       t('bpCheckRecycleTaskPassTitle'),
            description: '',
            severity:    'info',
            status:      'pass',
            category:    t('catBPScheduler'),
            frameworks:  [],
            affectedItems: [],
            remediation: '',
        });
    }

    return findings;
}

BEST_PRACTICES_CHECKS.push(checkBestPractices);
