/**
 * i18n.js — internationalisation for Synology Inspector
 *
 * Usage:
 *   t('key')           — returns the translated string for the active language
 *   setLanguage('de')  — switches to German (persisted in localStorage)
 *
 * Languages: 'en' (default), 'de'
 */

(function () {
    'use strict';

    const STRINGS = {
        en: {
            // ── UI chrome ────────────────────────────────────────────────────
            appTitle:        'Synology Inspector',
            appVersion:      'v1.0',
            appSubtitle:     'JKLP CONSULTING · SECURITY AUDIT',

            // ── Drop zone ────────────────────────────────────────────────────
            dropTitle:       'Drop your Synology .dss backup here',
            dropOr:          'or',
            dropBrowse:      'browse for file',
            dropFormats:     'Supported: Synology configuration backup (.dss) — DSM 7+',
            dropPrivacy:     'This file is processed entirely in your browser. Nothing is sent to any server.',

            // ── States ────────────────────────────────────────────────────────
            loading:         'Analysing backup…',
            loadingHint:     'Decompressing and parsing — this may take a few seconds.',
            btnNewFile:      'Analyse another file',
            btnExportPDF:    'Export PDF',
            pdfReportTitle:  'Security Assessment Report',
            pdfAnalysedOn:   'Analysed on',
            pdfIssues:       'Findings',

            // ── Errors ────────────────────────────────────────────────────────
            errFileRead:     'Could not read file',
            errDecompress:   'Failed to decompress backup (is this a valid .dss file?)',
            errNoDb:         'No configuration database found in backup',
            errParse:        'Failed to parse backup',
            errUnknown:      'An unexpected error occurred',

            // ── Context bar ────────────────────────────────────────────────────
            labelFileName:   'File',
            labelFileSize:   'Size',
            labelDSMVersion: 'DSM',
            labelModel:      'Model',
            labelHostname:   'Hostname',

            // ── Compliance view ────────────────────────────────────────────────
            complianceTitle:     'Security Assessment',
            filterAll:           'All',
            filterFailed:        'Issues only',
            labelFindings:       'Findings',
            labelAffected:       'Affected',
            labelRemediation:    'Remediation',
            labelFrameworks:     'References',
            labelNoFindings:     'No issues found.',

            // ── Severity labels ────────────────────────────────────────────────
            severityCritical:    'Critical',
            severityHigh:        'High',
            severityMedium:      'Medium',
            severityLow:         'Low',
            severityInfo:        'Info',

            // ── Verdicts ──────────────────────────────────────────────────────
            verdictStrong:       'Strong Security Posture',
            verdictGood:         'Good Security Posture',
            verdictAcceptable:   'Acceptable — Improvements Recommended',
            verdictImprove:      'Needs Improvement',
            verdictExposure:     'Significant Exposure',
            verdictCritical:     'Critical — Immediate Action Required',

            // ── Tab bar ───────────────────────────────────────────────────────
            tabSecurity:         'Security Check',
            tabBestPractices:    'Best Practices',

            // ── Best Practices view ───────────────────────────────────────────
            bpViewTitle:         'Best Practices Assessment',
            bpNoIssuesTitle:     'All Best-Practice Checks Passed',
            bpNoIssuesSub:       'Your configuration follows all recommended best practices.',

            // ── Categories ────────────────────────────────────────────────────
            catRemoteAccess:     'Remote Access',
            catProtocols:        'Protocols',
            catAuth:             'Authentication',
            catUsers:            'User Accounts',
            catMaintenance:      'Maintenance',
            catBPSMB:            'SMB Performance',
            catBPStorage:        'File Services & Storage',
            catBPUpdates:        'Update Management',
            catBPScheduler:      'Task Scheduler',

            // ── check-remote-access.js ─────────────────────────────────────────
            checkQCFailTitle:    'QuickConnect Is Enabled',
            checkQCPassTitle:    'QuickConnect Is Disabled',
            checkQCDesc:         'QuickConnect routes connections through Synology\'s relay servers, creating a permanent inbound pathway into the NAS that bypasses your network perimeter. Even with port forwarding disabled, QuickConnect exposes management interfaces to the internet.',
            checkQCRemediation:  'Disable QuickConnect in Control Panel › External Access › QuickConnect.',

            checkTelnetFailTitle: 'Telnet Is Enabled',
            checkTelnetPassTitle: 'Telnet Is Disabled',
            checkTelnetDesc:      'Telnet transmits all data — including credentials — in plain text. Any network observer or man-in-the-middle can intercept passwords and session content. Telnet has been superseded by SSH for all remote shell access.',
            checkTelnetRemediation: 'Disable Telnet in Control Panel › Terminal & SNMP › Terminal.',

            // ── check-protocols.js ─────────────────────────────────────────────
            checkSMB1FailTitle:  'SMBv1 Is Allowed',
            checkSMB1PassTitle:  'SMBv1 Is Disabled',
            checkSMB1Desc:       'SMBv1 is a 1980s-era protocol with no encryption, no integrity checking, and no modern authentication. It is the vector for EternalBlue (WannaCry, NotPetya) and numerous other critical exploits. All modern clients support SMB2 or SMB3.',
            checkSMB1Remediation: 'Set the minimum SMB protocol to SMB2 or higher in Control Panel › File Services › SMB.',

            checkNTLMv1FailTitle: 'NTLMv1 Authentication Is Enabled',
            checkNTLMv1PassTitle: 'NTLMv1 Authentication Is Disabled',
            checkNTLMv1Desc:      'NTLMv1 is a cryptographically weak authentication protocol vulnerable to Pass-the-Hash attacks and NTLM relay attacks. NTLMv2 should be the minimum, and Kerberos preferred where possible.',
            checkNTLMv1Remediation: 'Disable NTLMv1 in Control Panel › File Services › SMB › Advanced Settings.',

            checkFTPAnonFailTitle: 'FTP Anonymous Access Is Enabled',
            checkFTPAnonDesc:      'Anonymous FTP allows any user to connect without credentials. This exposes shared files to the internet without authentication and can be abused for data exfiltration.',
            checkFTPAnonRemediation: 'Disable anonymous FTP access in Control Panel › File Services › FTP › FTP service.',

            checkFTPTLSFailTitle: 'FTP Is Operating Without TLS',
            checkFTPTLSPassTitle: 'FTP Is Using TLS Encryption',
            checkFTPTLSDesc:      'Plain FTP transmits credentials and file content in clear text. Anyone on the network path can intercept passwords and data. Use FTPS (FTP over TLS) or switch to SFTP (SSH File Transfer Protocol) instead.',
            checkFTPTLSRemediation: 'Enable FTPS in Control Panel › File Services › FTP › Enable FTP SSL/TLS encryption.',

            // ── check-auth.js ──────────────────────────────────────────────────
            checkAutoBlockFailTitle: 'Automatic Account Blocking Is Not Configured',
            checkAutoBlockPassTitle: 'Automatic Account Blocking Is Active',
            checkAutoBlockDesc:      'Without account blocking, attackers can attempt unlimited password combinations against DSM and all enabled services. Even a modest rate of attempts can eventually succeed against weak passwords.',
            checkAutoBlockAffected:  'All DSM login services',
            checkAutoBlockRemediation: 'Enable auto block in Control Panel › Security › Account › Enable auto block. Configure a low attempt count (e.g., 5 attempts in 2 minutes).',

            checkHTTPSRedirectFailTitle: 'HTTP Does Not Redirect to HTTPS',
            checkHTTPSRedirectPassTitle: 'HTTP Automatically Redirects to HTTPS',
            checkHTTPSRedirectDesc:      'Without HTTPS redirect, the DSM web interface and any reverse-proxied applications can be accessed over unencrypted HTTP. This exposes credentials and session tokens to network eavesdropping.',
            checkHTTPSRedirectAffected:  'DSM web interface (HTTP port)',
            checkHTTPSRedirectRemediation: 'Enable HTTPS redirect in Control Panel › Login Portal › DSM › Enable HTTPS redirect.',

            checkHSTSFailTitle: 'HTTP Strict Transport Security (HSTS) Is Not Enabled',
            checkHSTSPassTitle: 'HTTP Strict Transport Security (HSTS) Is Active',
            checkHSTSDesc:      'Without HSTS, browsers may allow users to bypass TLS certificate warnings or accept downgrade attacks. HSTS instructs browsers to always connect via HTTPS for a defined period.',
            checkHSTSAffected:  'DSM web interface',
            checkHSTSRemediation: 'Enable HSTS in Control Panel › Login Portal › DSM › Enable HTTP Strict Transport Security (HSTS).',

            // ── check-users.js ─────────────────────────────────────────────────
            checkAdminActiveFailTitle:  'Default Admin Account Is Active',
            checkAdminActivePassTitle:  'Default Admin Account Is Disabled',
            checkAdminActiveDesc:       'The built-in "admin" account is active. Synology recommends disabling it and using a named personal account for administration. The default admin name is a predictable brute-force target.',
            checkAdminActiveRemediation: 'Disable the admin account: Control Panel › User & Group › select "admin" › Edit › Deactivate this account.',

            checkAdminGroupTitle:       'Administrators Group Members',
            checkAdminGroupDesc:        'The following accounts have administrator privileges. Review this list regularly and ensure only authorised personnel retain admin access. Remove service accounts or any accounts that no longer require elevated privileges.',

            checkPwdPolicyDisabledFailTitle: 'Password Policy Is Not Enforced',
            checkPwdPolicyDisabledDesc:      'No password strength rules are applied. Users can set arbitrarily simple passwords, making all accounts highly vulnerable to brute-force and credential-stuffing attacks.',
            checkPwdPolicyDisabledRemediation: 'Enable password strength rules: Control Panel › User & Group › Advanced › Password Settings › Apply password strength rules.',

            checkPwdLengthFailTitle:    'Minimum Password Length Is Below Recommended Threshold',
            checkPwdLengthPassTitle:    'Minimum Password Length Meets Recommended Threshold',
            checkPwdLengthDesc:         'The current minimum password length ({0} characters) is below the recommended minimum of 12. Short passwords are significantly easier to crack by brute-force or dictionary attacks.',
            checkPwdLengthRemediation:  'Increase the minimum password length to at least 12 characters: Control Panel › User & Group › Advanced › Password Settings.',

            checkPwdSpecialFailTitle:   'Password Policy Does Not Require Special Characters',
            checkPwdSpecialPassTitle:   'Password Policy Requires Special Characters',
            checkPwdSpecialDesc:        'Requiring at least one special character significantly increases password entropy and resistance to dictionary attacks.',
            checkPwdSpecialRemediation: 'Enable "Include special characters" in the password strength settings: Control Panel › User & Group › Advanced › Password Settings.',

            checkPwdCommonFailTitle:    'Common Password Check Is Not Enabled',
            checkPwdCommonPassTitle:    'Common Password Check Is Active',
            checkPwdCommonDesc:         'Without a common password check, users may set easily-guessable passwords such as "Password1!" that technically meet complexity rules but offer minimal real-world security.',
            checkPwdCommonRemediation:  'Enable "Exclude commonly used passwords" in the password strength settings: Control Panel › User & Group › Advanced › Password Settings.',

            // ── check-maintenance.js ───────────────────────────────────────────
            checkConfigBackupFailTitle: 'Automatic Configuration Backup Is Not Configured',
            checkConfigBackupPassTitle: 'Automatic Configuration Backup Is Configured',
            checkConfigBackupDesc:      'Without a scheduled configuration backup, a hardware failure, ransomware attack, or misconfiguration could make recovery difficult or impossible. Synology DSM supports automated backups to a local share.',
            checkConfigBackupRemediation: 'Configure automatic configuration backup: Control Panel › Update & Restore › Configuration Backup › Back Up Configuration.',

            checkSMBSigningFailTitle:   'SMB Signing Is Disabled',
            checkSMBSigningPassTitle:   'SMB Signing Is Enabled',
            checkSMBSigningDesc:        'SMB signing ensures that network packets have not been tampered with in transit. Without it, the NAS is vulnerable to NTLM relay attacks and man-in-the-middle attacks against SMB connections, allowing attackers to intercept and modify file traffic.',
            checkSMBSigningRemediation: 'Enable SMB signing: Control Panel › File Services › SMB › Advanced Settings › Enable SMB signing.',

            // ── check-bestpractices.js ─────────────────────────────────────────
            bpCheckTransferLogPassTitle:        'SMB Transfer Log Is Disabled',
            bpCheckTransferLogFailTitle:        'SMB Transfer Log Is Enabled',
            bpCheckTransferLogDesc:             'Logging every SMB file operation generates significant I/O overhead and disk usage on production servers. Disable transfer logging unless actively required for compliance or troubleshooting.',
            bpCheckTransferLogRemediation:      'Disable transfer log: Control Panel › File Services › SMB › Advanced Settings › Enable transfer log.',

            bpCheckStrictAllocatePassTitle:     'File Space Pre-allocation Is Disabled',
            bpCheckStrictAllocateFailTitle:     'File Space Pre-allocation Is Enabled',
            bpCheckStrictAllocateDesc:          '"Do not reserve disk space when creating files" improves write performance by using sparse file allocation instead of pre-allocating the full file size on disk. Pre-allocation can significantly slow write-heavy workloads.',
            bpCheckStrictAllocateRemediation:   'Disable strict allocation: Control Panel › File Services › SMB › Advanced Settings › Do not reserve disk space when creating files.',

            bpCheckAIOReadPassTitle:            'Asynchronous SMB Read Is Enabled',
            bpCheckAIOReadFailTitle:            'Asynchronous SMB Read Is Disabled',
            bpCheckAIOReadDesc:                 'Asynchronous read (AIO) allows the server to process multiple SMB read requests concurrently, significantly improving throughput for multi-client workloads.',
            bpCheckAIOReadRemediation:          'Enable async read: Control Panel › File Services › SMB › Advanced Settings › Enable asynchronous read.',

            bpCheckMultichannelPassTitle:       'SMB Multichannel Is Enabled',
            bpCheckMultichannelFailTitle:       'SMB Multichannel Is Disabled',
            bpCheckMultichannelDesc:            'SMB3 Multichannel allows clients with multiple network adapters to aggregate all available interfaces simultaneously, dramatically increasing throughput and providing automatic network failover.',
            bpCheckMultichannelRemediation:     'Enable SMB Multichannel: Control Panel › File Services › SMB › Advanced Settings › Enable SMB3 Multichannel.',

            bpCheckAFPPassTitle:                'AFP Service Is Disabled',
            bpCheckAFPFailTitle:                'AFP Service Is Enabled',
            bpCheckAFPDesc:                     'Apple Filing Protocol (AFP) is deprecated and has been removed from macOS Ventura and later. Modern Macs connect via SMB3. Running AFP adds unnecessary attack surface and maintenance overhead without benefit for current Apple clients.',
            bpCheckAFPRemediation:              'Disable AFP: Control Panel › File Services › AFP › uncheck "Enable AFP service".',

            bpCheckFastClonePassTitle:          'File Fast Clone (Reflink) Is Enabled',
            bpCheckFastCloneFailTitle:          'File Fast Clone (Reflink) Is Disabled',
            bpCheckFastCloneDesc:               'Fast Clone uses btrfs reflinks to create instant, space-efficient file copies without duplicating data on disk. This is a major performance feature for virtual machine storage, Docker volumes, and backup workflows.',
            bpCheckFastCloneRemediation:        'Enable File Fast Clone: Control Panel › File Services › Advanced › Enable file fast clone.',

            bpCheckUpdateNotifyPassTitle:       'DSM Updates Are Set to Notify Only',
            bpCheckUpdateNotifyFailTitle:       'DSM Updates Are Not Set to Notify Only',
            bpCheckUpdateNotifyDesc:            'Automatic DSM updates can cause unplanned downtime and introduce incompatibilities with installed packages or running containers. "Notify only" mode ensures you remain in full control of when updates are applied.',
            bpCheckUpdateNotifyRemediation:     'Change update setting to "Notify me, then let me decide": Control Panel › Update & Restore › DSM Update.',

            bpCheckRecycleTaskPassTitle:        'Recycle Bin Cleanup Task Is Configured',
            bpCheckRecycleTaskFailTitle:        'No Recycle Bin Cleanup Task Found',
            bpCheckRecycleTaskDesc:             'Without a scheduled recycle bin cleanup, deleted files accumulate indefinitely. This silently consumes disk space and can trigger unexpected storage alerts on production NAS systems.',
            bpCheckRecycleTaskRemediation:      'Create a scheduled task to empty the recycle bin: Control Panel › Task Scheduler › Create › Scheduled Task › Recycle Bin.',

            // ── Compliance view UI ─────────────────────────────────────────────
            frameworksLabel:         'Frameworks',
            clearFiltersBtn:         'Clear',
            clearAllFiltersBtn:      'Clear all filters',
            findingPlural:           'issues',
            findingSingular:         'issue',
            filteredBy:              'filtered by',
            ofTotal:                 'of',
            noFindingsTitle:         'No Issues Found',
            noFindingsSub:           'All security checks passed.',
            issueCount:              '1 issue',
            issuesCount:             '{0} issues',
            severityPass:            'Pass',
            passedChecks:            'Passed checks',
            affectedItems:           'Affected items',
            howToFix:                'How to fix',

            // ── About ──────────────────────────────────────────────────────────
            aboutBtn:         'About this tool',
            aboutMaker:       'JKLP CONSULTING · SECURITY AUDIT',
            aboutDesc:        'Synology Inspector analyses Synology DSM configuration backups (.dss) directly in your browser — no data is ever uploaded. It checks your NAS configuration against security best practices and common compliance frameworks.',
            aboutChannelName: 'JKLP Consulting',
            aboutChannelDesc: 'Security audits, NAS hardening guides, and IT security for SMEs.',
            aboutWebsiteName: 'jklp.io',
            aboutWebsiteDesc: 'Book a security consultation',
            aboutBadgeFree:   'Free for personal use',
            aboutBadgeOS:     'Source available',
            aboutBadgePrivacy:'No data leaves your browser',

            // ── Disclaimer ─────────────────────────────────────────────────────
            disclaimerTitle:  'Important Notice',
            disclaimerItem1:  'This tool provides automated analysis as technical guidance only and does not replace a professional security audit.',
            disclaimerItem2:  'It makes no claim to completeness or correctness.',
            disclaimerItem3:  'Results serve as technical orientation only and do not constitute professional security advice.',
            disclaimerItem4:  'The mapping to compliance frameworks is for technical orientation only and does not constitute certification or legal assessment.',
            disclaimerItem5:  'The tool analyses backups in read-only mode and makes no changes to your Synology NAS.',
            disclaimerFooter: 'Use at your own risk.',
        },

        de: {
            // ── Compliance view UI ─────────────────────────────────────────────
            frameworksLabel:         'Frameworks',
            clearFiltersBtn:         'Zurücksetzen',
            clearAllFiltersBtn:      'Alle Filter zurücksetzen',
            findingPlural:           'Befunde',
            findingSingular:         'Befund',
            filteredBy:              'gefiltert nach',
            ofTotal:                 'von',
            noFindingsTitle:         'Keine Befunde gefunden',
            noFindingsSub:           'Alle Sicherheitsprüfungen bestanden.',
            issueCount:              '1 Befund',
            issuesCount:             '{0} Befunde',
            severityPass:            'OK',
            passedChecks:            'Bestandene Prüfungen',
            affectedItems:           'Betroffene Elemente',
            howToFix:                'So beheben',

            // ── About ──────────────────────────────────────────────────────────
            aboutBtn:         'Über dieses Tool',
            aboutMaker:       'JKLP CONSULTING · SICHERHEITSAUDIT',
            aboutDesc:        'Synology Inspector analysiert Synology DSM-Konfigurationssicherungen (.dss) direkt im Browser – ohne Datenübertragung. Er prüft die NAS-Konfiguration gegen Sicherheits-Best-Practices und gängige Compliance-Frameworks.',
            aboutChannelName: 'JKLP Consulting',
            aboutChannelDesc: 'Security-Audits, NAS-Hardening-Guides und IT-Sicherheit für KMU.',
            aboutWebsiteName: 'jklp.io',
            aboutWebsiteDesc: 'Beratungsgespräch buchen',
            aboutBadgeFree:   'Kostenlos für Privatnutzung',
            aboutBadgeOS:     'Quellcode einsehbar',
            aboutBadgePrivacy:'Keine Daten verlassen Ihren Browser',

            // ── Disclaimer ─────────────────────────────────────────────────────
            disclaimerTitle:  'Wichtiger Hinweis',
            disclaimerItem1:  'Dieses Tool bietet eine automatisierte Analyse als technische Orientierungshilfe und ersetzt kein professionelles Security Audit.',
            disclaimerItem2:  'Es erhebt keinen Anspruch auf Vollständigkeit oder Korrektheit.',
            disclaimerItem3:  'Ergebnisse liefern technische Anhaltspunkte, ersetzen jedoch keine professionelle Sicherheitsberatung.',
            disclaimerItem4:  'Die Zuordnung zu Compliance-Frameworks dient ausschließlich der technischen Orientierung und stellt keine Zertifizierung oder rechtliche Bewertung dar.',
            disclaimerItem5:  'Das Tool analysiert Backups ausschließlich lesend und nimmt keine Änderungen an Ihrem Synology NAS vor.',
            disclaimerFooter: 'Benutzung auf eigene Gefahr.',

            // ── UI chrome ────────────────────────────────────────────────────
            appTitle:        'Synology Inspector',
            appVersion:      'v1.0',
            appSubtitle:     'JKLP CONSULTING · SICHERHEITSAUDIT',

            // ── Drop zone ────────────────────────────────────────────────────
            dropTitle:       'Synology .dss-Backup hier ablegen',
            dropOr:          'oder',
            dropBrowse:      'Datei auswählen',
            dropFormats:     'Unterstützt: Synology Konfigurationssicherung (.dss) – DSM 7+',
            dropPrivacy:     'Die Datei wird ausschließlich im Browser verarbeitet. Es werden keine Daten an einen Server übertragen.',

            // ── States ────────────────────────────────────────────────────────
            loading:         'Backup wird analysiert…',
            loadingHint:     'Dekomprimierung und Analyse — dies kann einige Sekunden dauern.',
            btnNewFile:      'Weitere Datei analysieren',
            btnExportPDF:    'PDF exportieren',
            pdfReportTitle:  'Sicherheitsbericht',
            pdfAnalysedOn:   'Analysiert am',
            pdfIssues:       'Befunde',

            // ── Errors ────────────────────────────────────────────────────────
            errFileRead:     'Datei konnte nicht gelesen werden',
            errDecompress:   'Dekomprimierung fehlgeschlagen (ist dies eine gültige .dss-Datei?)',
            errNoDb:         'Keine Konfigurationsdatenbank im Backup gefunden',
            errParse:        'Backup konnte nicht analysiert werden',
            errUnknown:      'Ein unerwarteter Fehler ist aufgetreten',

            // ── Context bar ────────────────────────────────────────────────────
            labelFileName:   'Datei',
            labelFileSize:   'Größe',
            labelDSMVersion: 'DSM',
            labelModel:      'Modell',
            labelHostname:   'Hostname',

            // ── Compliance view ────────────────────────────────────────────────
            complianceTitle:     'Sicherheitsbewertung',
            filterAll:           'Alle',
            filterFailed:        'Nur Befunde',
            labelFindings:       'Befunde',
            labelAffected:       'Betroffen',
            labelRemediation:    'Behebung',
            labelFrameworks:     'Referenzen',
            labelNoFindings:     'Keine Befunde gefunden.',

            // ── Severity labels ────────────────────────────────────────────────
            severityCritical:    'Kritisch',
            severityHigh:        'Hoch',
            severityMedium:      'Mittel',
            severityLow:         'Niedrig',
            severityInfo:        'Info',

            // ── Verdicts ──────────────────────────────────────────────────────
            verdictStrong:       'Starke Sicherheitslage',
            verdictGood:         'Gute Sicherheitslage',
            verdictAcceptable:   'Akzeptabel – Verbesserungen empfohlen',
            verdictImprove:      'Verbesserungsbedarf',
            verdictExposure:     'Erhebliches Risiko',
            verdictCritical:     'Kritisch – Sofortiger Handlungsbedarf',

            // ── Tab bar ───────────────────────────────────────────────────────
            tabSecurity:         'Sicherheitsprüfung',
            tabBestPractices:    'Best Practices',

            // ── Best Practices view ───────────────────────────────────────────
            bpViewTitle:         'Best-Practices-Bewertung',
            bpNoIssuesTitle:     'Alle Best-Practice-Prüfungen bestanden',
            bpNoIssuesSub:       'Ihre Konfiguration entspricht allen empfohlenen Best Practices.',

            // ── Categories ────────────────────────────────────────────────────
            catRemoteAccess:     'Fernzugriff',
            catProtocols:        'Protokolle',
            catAuth:             'Authentifizierung',
            catUsers:            'Benutzerkonten',
            catMaintenance:      'Wartung',
            catBPSMB:            'SMB-Performance',
            catBPStorage:        'Dateidienste & Speicher',
            catBPUpdates:        'Update-Verwaltung',
            catBPScheduler:      'Aufgabenplaner',

            // ── check-remote-access.js ─────────────────────────────────────────
            checkQCFailTitle:    'QuickConnect ist aktiviert',
            checkQCPassTitle:    'QuickConnect ist deaktiviert',
            checkQCDesc:         'QuickConnect leitet Verbindungen über die Relay-Server von Synology, wodurch ein dauerhafter eingehender Pfad zum NAS entsteht, der Ihr Netzwerkperimeter umgeht. Auch ohne Port-Weiterleitungen werden Verwaltungsschnittstellen dem Internet zugänglich gemacht.',
            checkQCRemediation:  'QuickConnect deaktivieren: Systemsteuerung › Externer Zugriff › QuickConnect.',

            checkTelnetFailTitle: 'Telnet ist aktiviert',
            checkTelnetPassTitle: 'Telnet ist deaktiviert',
            checkTelnetDesc:      'Telnet überträgt alle Daten einschließlich Anmeldedaten im Klartext. Jeder Netzwerkbeobachter kann Passwörter und Sitzungsinhalte mitlesen. SSH ist der sichere Ersatz für alle Remote-Shell-Zugriffe.',
            checkTelnetRemediation: 'Telnet deaktivieren: Systemsteuerung › Terminal & SNMP › Terminal.',

            // ── check-protocols.js ─────────────────────────────────────────────
            checkSMB1FailTitle:  'SMBv1 ist erlaubt',
            checkSMB1PassTitle:  'SMBv1 ist deaktiviert',
            checkSMB1Desc:       'SMBv1 ist ein veraltetes Protokoll aus den 1980er Jahren ohne Verschlüsselung oder Integritätsprüfung. Es ist der Angriffsvektor für EternalBlue (WannaCry, NotPetya). Alle modernen Clients unterstützen SMB2 oder SMB3.',
            checkSMB1Remediation: 'Mindest-SMB-Version auf SMB2 oder höher setzen: Systemsteuerung › Dateidienste › SMB.',

            checkNTLMv1FailTitle: 'NTLMv1-Authentifizierung ist aktiviert',
            checkNTLMv1PassTitle: 'NTLMv1-Authentifizierung ist deaktiviert',
            checkNTLMv1Desc:      'NTLMv1 ist ein kryptografisch schwaches Authentifizierungsprotokoll, das für Pass-the-Hash- und NTLM-Relay-Angriffe anfällig ist. NTLMv2 ist das Minimum, Kerberos wird bevorzugt.',
            checkNTLMv1Remediation: 'NTLMv1 deaktivieren: Systemsteuerung › Dateidienste › SMB › Erweiterte Einstellungen.',

            checkFTPAnonFailTitle: 'FTP-Anonymzugriff ist aktiviert',
            checkFTPAnonDesc:      'Anonymer FTP-Zugriff erlaubt Verbindungen ohne Anmeldedaten. Dies macht freigegebene Dateien ohne Authentifizierung zugänglich und kann zur Datenexfiltration missbraucht werden.',
            checkFTPAnonRemediation: 'Anonymen FTP-Zugriff deaktivieren: Systemsteuerung › Dateidienste › FTP.',

            checkFTPTLSFailTitle: 'FTP läuft ohne TLS',
            checkFTPTLSPassTitle: 'FTP verwendet TLS-Verschlüsselung',
            checkFTPTLSDesc:      'FTP ohne TLS überträgt Anmeldedaten und Dateiinhalte im Klartext. Jeder auf dem Netzwerkpfad kann Passwörter und Daten mitlesen. FTPS oder SFTP sollte stattdessen verwendet werden.',
            checkFTPTLSRemediation: 'FTPS aktivieren: Systemsteuerung › Dateidienste › FTP › FTP SSL/TLS-Verschlüsselung aktivieren.',

            // ── check-auth.js ──────────────────────────────────────────────────
            checkAutoBlockFailTitle: 'Automatische Kontosperrung ist nicht konfiguriert',
            checkAutoBlockPassTitle: 'Automatische Kontosperrung ist aktiv',
            checkAutoBlockDesc:      'Ohne Kontosperrung können Angreifer unbegrenzte Passwortversuche gegen DSM und alle aktivierten Dienste starten. Bereits eine moderate Versuchsrate kann bei schwachen Passwörtern erfolgreich sein.',
            checkAutoBlockAffected:  'Alle DSM-Anmeldedienste',
            checkAutoBlockRemediation: 'Automatische Sperrung aktivieren: Systemsteuerung › Sicherheit › Konto › Automatische Sperrung aktivieren. Niedrige Schwellenwerte konfigurieren (z. B. 5 Versuche in 2 Minuten).',

            checkHTTPSRedirectFailTitle: 'HTTP leitet nicht auf HTTPS um',
            checkHTTPSRedirectPassTitle: 'HTTP leitet automatisch auf HTTPS um',
            checkHTTPSRedirectDesc:      'Ohne HTTPS-Weiterleitung kann die DSM-Weboberfläche unverschlüsselt über HTTP aufgerufen werden. Dies ermöglicht das Abfangen von Anmeldedaten und Sitzungstoken.',
            checkHTTPSRedirectAffected:  'DSM-Weboberfläche (HTTP-Port)',
            checkHTTPSRedirectRemediation: 'HTTPS-Weiterleitung aktivieren: Systemsteuerung › Anmeldeportal › DSM › HTTPS-Weiterleitung aktivieren.',

            checkHSTSFailTitle: 'HTTP Strict Transport Security (HSTS) ist nicht aktiviert',
            checkHSTSPassTitle: 'HTTP Strict Transport Security (HSTS) ist aktiv',
            checkHSTSDesc:      'Ohne HSTS können Browser TLS-Zertifikatswarnungen umgehen oder Downgrade-Angriffe akzeptieren. HSTS weist Browser an, für einen definierten Zeitraum ausschließlich HTTPS zu verwenden.',
            checkHSTSAffected:  'DSM-Weboberfläche',
            checkHSTSRemediation: 'HSTS aktivieren: Systemsteuerung › Anmeldeportal › DSM › HTTP Strict Transport Security (HSTS) aktivieren.',

            // ── check-users.js ─────────────────────────────────────────────────
            checkAdminActiveFailTitle:  'Standard-Admin-Konto ist aktiv',
            checkAdminActivePassTitle:  'Standard-Admin-Konto ist deaktiviert',
            checkAdminActiveDesc:       'Das integrierte "admin"-Konto ist aktiv. Synology empfiehlt, es zu deaktivieren und stattdessen ein persönliches benanntes Konto für die Administration zu verwenden. Der standardisierte Kontoname ist ein vorhersehbares Ziel für Brute-Force-Angriffe.',
            checkAdminActiveRemediation: 'Admin-Konto deaktivieren: Systemsteuerung › Benutzer & Gruppe › "admin" auswählen › Bearbeiten › Dieses Konto deaktivieren.',

            checkAdminGroupTitle:       'Mitglieder der Administratorengruppe',
            checkAdminGroupDesc:        'Die folgenden Konten haben Administratorrechte. Überprüfen Sie diese Liste regelmäßig und stellen Sie sicher, dass nur autorisierte Personen Adminzugriff haben. Entfernen Sie Dienstkonten und Konten, die keine erhöhten Rechte mehr benötigen.',

            checkPwdPolicyDisabledFailTitle: 'Kennwortrichtlinie ist nicht aktiviert',
            checkPwdPolicyDisabledDesc:      'Es werden keine Kennwortstärkeregeln angewendet. Benutzer können beliebig einfache Kennwörter setzen, was alle Konten für Brute-Force- und Credential-Stuffing-Angriffe anfällig macht.',
            checkPwdPolicyDisabledRemediation: 'Kennwortstärkeregeln aktivieren: Systemsteuerung › Benutzer & Gruppe › Erweitert › Kennworteinstellungen › Kennwortstärkeregeln anwenden.',

            checkPwdLengthFailTitle:    'Minimale Kennwortlänge liegt unter dem empfohlenen Schwellenwert',
            checkPwdLengthPassTitle:    'Minimale Kennwortlänge entspricht dem empfohlenen Schwellenwert',
            checkPwdLengthDesc:         'Die aktuelle Mindestkennwortlänge ({0} Zeichen) liegt unter dem empfohlenen Minimum von 12. Kurze Kennwörter sind deutlich einfacher durch Brute-Force- oder Wörterbuchangriffe zu knacken.',
            checkPwdLengthRemediation:  'Mindestkennwortlänge auf mindestens 12 Zeichen erhöhen: Systemsteuerung › Benutzer & Gruppe › Erweitert › Kennworteinstellungen.',

            checkPwdSpecialFailTitle:   'Kennwortrichtlinie erfordert keine Sonderzeichen',
            checkPwdSpecialPassTitle:   'Kennwortrichtlinie erfordert Sonderzeichen',
            checkPwdSpecialDesc:        'Die Anforderung mindestens eines Sonderzeichens erhöht die Kennwort-Entropie und die Resistenz gegen Wörterbuchangriffe erheblich.',
            checkPwdSpecialRemediation: '"Sonderzeichen einschließen" in den Kennwortstärkeeinstellungen aktivieren: Systemsteuerung › Benutzer & Gruppe › Erweitert › Kennworteinstellungen.',

            checkPwdCommonFailTitle:    'Prüfung auf gängige Kennwörter ist nicht aktiviert',
            checkPwdCommonPassTitle:    'Prüfung auf gängige Kennwörter ist aktiv',
            checkPwdCommonDesc:         'Ohne Prüfung auf gängige Kennwörter können Benutzer leicht erratbare Kennwörter wie "Passwort1!" setzen, die technisch die Komplexitätsregeln erfüllen, aber in der Praxis kaum Sicherheit bieten.',
            checkPwdCommonRemediation:  '"Häufig verwendete Kennwörter ausschließen" in den Kennwortstärkeeinstellungen aktivieren: Systemsteuerung › Benutzer & Gruppe › Erweitert › Kennworteinstellungen.',

            // ── check-maintenance.js ───────────────────────────────────────────
            checkConfigBackupFailTitle: 'Automatische Konfigurationssicherung ist nicht konfiguriert',
            checkConfigBackupPassTitle: 'Automatische Konfigurationssicherung ist konfiguriert',
            checkConfigBackupDesc:      'Ohne geplante Konfigurationssicherung kann ein Hardwareausfall, Ransomware-Angriff oder eine Fehlkonfiguration die Wiederherstellung erheblich erschweren oder unmöglich machen. DSM unterstützt automatische Sicherungen auf einer lokalen Freigabe.',
            checkConfigBackupRemediation: 'Automatische Konfigurationssicherung einrichten: Systemsteuerung › Aktualisierung & Wiederherstellung › Konfigurationssicherung.',

            checkSMBSigningFailTitle:   'SMB-Signierung ist deaktiviert',
            checkSMBSigningPassTitle:   'SMB-Signierung ist aktiviert',
            checkSMBSigningDesc:        'SMB-Signierung stellt sicher, dass Netzwerkpakete während der Übertragung nicht manipuliert wurden. Ohne Signierung ist das NAS anfällig für NTLM-Relay-Angriffe und Man-in-the-Middle-Angriffe auf SMB-Verbindungen.',
            checkSMBSigningRemediation: 'SMB-Signierung aktivieren: Systemsteuerung › Dateidienste › SMB › Erweiterte Einstellungen › SMB-Signierung aktivieren.',

            // ── check-bestpractices.js ─────────────────────────────────────────
            bpCheckTransferLogPassTitle:        'SMB Transfer-Log ist deaktiviert',
            bpCheckTransferLogFailTitle:        'SMB Transfer-Log ist aktiviert',
            bpCheckTransferLogDesc:             'Das Protokollieren jeder SMB-Dateioperation erzeugt erheblichen I/O-Overhead und Festplattenverbrauch auf Produktionsservern. Deaktivieren Sie Transfer-Logging, sofern es nicht für Compliance oder Fehleranalyse benötigt wird.',
            bpCheckTransferLogRemediation:      'Transfer-Log deaktivieren: Systemsteuerung › Dateidienste › SMB › Erweiterte Einstellungen › Transfer-Log aktivieren.',

            bpCheckStrictAllocatePassTitle:     'Speicherplatzvorreservierung ist deaktiviert',
            bpCheckStrictAllocateFailTitle:     'Speicherplatzvorreservierung ist aktiviert',
            bpCheckStrictAllocateDesc:          '"Keinen Speicherplatz beim Erstellen von Dateien reservieren" verbessert die Schreibleistung durch Verwendung von Sparse-File-Zuweisung statt Vorab-Allokation der vollen Dateigröße. Vorab-Allokation kann schreibintensive Workloads erheblich verlangsamen.',
            bpCheckStrictAllocateRemediation:   'Strikte Allokation deaktivieren: Systemsteuerung › Dateidienste › SMB › Erweiterte Einstellungen › Keinen Speicherplatz beim Erstellen von Dateien reservieren.',

            bpCheckAIOReadPassTitle:            'Asynchrones SMB-Lesen ist aktiviert',
            bpCheckAIOReadFailTitle:            'Asynchrones SMB-Lesen ist deaktiviert',
            bpCheckAIOReadDesc:                 'Asynchrones Lesen (AIO) ermöglicht es dem Server, mehrere SMB-Leseanfragen gleichzeitig zu verarbeiten, was den Durchsatz bei Multi-Client-Workloads erheblich verbessert.',
            bpCheckAIOReadRemediation:          'Asynchrones Lesen aktivieren: Systemsteuerung › Dateidienste › SMB › Erweiterte Einstellungen › Asynchrones Lesen aktivieren.',

            bpCheckMultichannelPassTitle:       'SMB Multichannel ist aktiviert',
            bpCheckMultichannelFailTitle:       'SMB Multichannel ist deaktiviert',
            bpCheckMultichannelDesc:            'SMB3 Multichannel ermöglicht Clients mit mehreren Netzwerkadaptern, alle verfügbaren Schnittstellen gleichzeitig zu nutzen, was den Durchsatz erheblich steigert und automatisches Netzwerk-Failover bietet.',
            bpCheckMultichannelRemediation:     'SMB Multichannel aktivieren: Systemsteuerung › Dateidienste › SMB › Erweiterte Einstellungen › SMB3 Multichannel aktivieren.',

            bpCheckAFPPassTitle:                'AFP-Dienst ist deaktiviert',
            bpCheckAFPFailTitle:                'AFP-Dienst ist aktiviert',
            bpCheckAFPDesc:                     'Apple Filing Protocol (AFP) ist veraltet und wurde ab macOS Ventura entfernt. Moderne Macs verbinden sich über SMB3. Das Ausführen von AFP erzeugt unnötige Angriffsfläche und Wartungsaufwand ohne Nutzen für aktuelle Apple-Clients.',
            bpCheckAFPRemediation:              'AFP deaktivieren: Systemsteuerung › Dateidienste › AFP › "AFP-Dienst aktivieren" deaktivieren.',

            bpCheckFastClonePassTitle:          'File Fast Clone (Reflink) ist aktiviert',
            bpCheckFastCloneFailTitle:          'File Fast Clone (Reflink) ist deaktiviert',
            bpCheckFastCloneDesc:               'Fast Clone nutzt btrfs-Reflinks, um sofortige, platzsparende Dateikopien ohne Datenduplizierung zu erstellen. Dies ist ein entscheidendes Performance-Feature für VM-Storage, Docker-Volumes und Backup-Workflows.',
            bpCheckFastCloneRemediation:        'File Fast Clone aktivieren: Systemsteuerung › Dateidienste › Erweitert › Datei-Fast-Clone aktivieren.',

            bpCheckUpdateNotifyPassTitle:       'DSM-Updates sind auf "Nur benachrichtigen" eingestellt',
            bpCheckUpdateNotifyFailTitle:       'DSM-Updates sind nicht auf "Nur benachrichtigen" eingestellt',
            bpCheckUpdateNotifyDesc:            'Automatische DSM-Updates können ungeplante Ausfallzeiten verursachen und Inkompatibilitäten mit installierten Paketen oder laufenden Containern einführen. Der Modus "Nur benachrichtigen" stellt sicher, dass Sie die volle Kontrolle behalten.',
            bpCheckUpdateNotifyRemediation:     'Update-Einstellung ändern: Systemsteuerung › Aktualisierung & Wiederherstellung › DSM-Aktualisierung › "Benachrichtigen und selbst entscheiden".',

            bpCheckRecycleTaskPassTitle:        'Papierkorb-Bereinigungsaufgabe ist konfiguriert',
            bpCheckRecycleTaskFailTitle:        'Keine Papierkorb-Bereinigungsaufgabe gefunden',
            bpCheckRecycleTaskDesc:             'Ohne geplante Papierkorbleerung häufen sich gelöschte Dateien unbegrenzt an. Dies verbraucht stillschweigend Festplattenplatz und kann zu unerwarteten Speicheralarmen auf Produktionssystemen führen.',
            bpCheckRecycleTaskRemediation:      'Geplante Aufgabe zur Papierkorbleerung erstellen: Systemsteuerung › Aufgabenplaner › Erstellen › Geplante Aufgabe › Papierkorb.',

        },
    };

    // ── Runtime ────────────────────────────────────────────────────────────────

    let _lang = localStorage.getItem('syno-inspector-lang') || 'en';

    window.t = function (key, ...args) {
        let str = (STRINGS[_lang] && STRINGS[_lang][key]) ||
                  (STRINGS['en']  && STRINGS['en'][key])  ||
                  key;
        args.forEach((arg, i) => { str = str.replace(`{${i}}`, arg); });
        return str;
    };

    window.setLanguage = function (lang) {
        if (!STRINGS[lang]) return;
        _lang = lang;
        localStorage.setItem('syno-inspector-lang', lang);
        document.documentElement.lang = lang;
        // Update active button state
        document.querySelectorAll('.lang-btn').forEach(btn => {
            btn.classList.toggle('lang-btn--active', btn.dataset.lang === lang);
        });
        if (typeof renderApp === 'function') renderApp();
    };

    window.getCurrentLanguage = function () { return _lang; };
}());
