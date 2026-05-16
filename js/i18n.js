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

            // ── Categories ────────────────────────────────────────────────────
            catRemoteAccess:     'Remote Access',
            catProtocols:        'Protocols',
            catAuth:             'Authentication',

            // ── check-remote-access.js ─────────────────────────────────────────
            checkQCFailTitle:    'QuickConnect Is Enabled',
            checkQCPassTitle:    'QuickConnect Is Disabled',
            checkQCDesc:         'QuickConnect routes connections through Synology\'s relay servers, creating a permanent inbound pathway into the NAS that bypasses your network perimeter. Even with port forwarding disabled, QuickConnect exposes management interfaces to the internet.',
            checkQCRemediation:  'Disable QuickConnect in Control Panel › External Access › QuickConnect.',

            checkTelnetFailTitle: 'Telnet Is Enabled',
            checkTelnetPassTitle: 'Telnet Is Disabled',
            checkTelnetDesc:      'Telnet transmits all data — including credentials — in plain text. Any network observer or man-in-the-middle can intercept passwords and session content. Telnet has been superseded by SSH for all remote shell access.',
            checkTelnetRemediation: 'Disable Telnet in Control Panel › Terminal & SNMP › Terminal.',

            checkSSHPortFailTitle:  'SSH Is Using the Default Port (22)',
            checkSSHPortPassTitle:  'SSH Is Using a Non-Default Port',
            checkSSHPortDesc:       'SSH on port 22 is targeted by automated scanners and brute-force bots within minutes of exposure. Moving to a non-standard port significantly reduces automated attack noise, though it does not replace strong authentication.',
            checkSSHPortRemediation: 'Change the SSH port in Control Panel › Terminal & SNMP › Terminal. Choose a port above 1024 not used by other services.',

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
            findingPlural:           'Probleme',
            findingSingular:         'Problem',
            filteredBy:              'gefiltert nach',
            ofTotal:                 'von',
            noFindingsTitle:         'Keine Probleme gefunden',
            noFindingsSub:           'Alle Sicherheitsprüfungen bestanden.',
            issueCount:              '1 Problem',
            issuesCount:             '{0} Probleme',
            severityPass:            'OK',
            passedChecks:            'Bestandene Prüfungen',

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
            filterFailed:        'Nur Probleme',
            labelFindings:       'Befunde',
            labelAffected:       'Betroffen',
            labelRemediation:    'Behebung',
            labelFrameworks:     'Referenzen',
            labelNoFindings:     'Keine Probleme gefunden.',

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

            // ── Categories ────────────────────────────────────────────────────
            catRemoteAccess:     'Fernzugriff',
            catProtocols:        'Protokolle',
            catAuth:             'Authentifizierung',

            // ── check-remote-access.js ─────────────────────────────────────────
            checkQCFailTitle:    'QuickConnect ist aktiviert',
            checkQCPassTitle:    'QuickConnect ist deaktiviert',
            checkQCDesc:         'QuickConnect leitet Verbindungen über die Relay-Server von Synology, wodurch ein dauerhafter eingehender Pfad zum NAS entsteht, der Ihr Netzwerkperimeter umgeht. Auch ohne Port-Weiterleitungen werden Verwaltungsschnittstellen dem Internet zugänglich gemacht.',
            checkQCRemediation:  'QuickConnect deaktivieren: Systemsteuerung › Externer Zugriff › QuickConnect.',

            checkTelnetFailTitle: 'Telnet ist aktiviert',
            checkTelnetPassTitle: 'Telnet ist deaktiviert',
            checkTelnetDesc:      'Telnet überträgt alle Daten einschließlich Anmeldedaten im Klartext. Jeder Netzwerkbeobachter kann Passwörter und Sitzungsinhalte mitlesen. SSH ist der sichere Ersatz für alle Remote-Shell-Zugriffe.',
            checkTelnetRemediation: 'Telnet deaktivieren: Systemsteuerung › Terminal & SNMP › Terminal.',

            checkSSHPortFailTitle:  'SSH verwendet den Standardport (22)',
            checkSSHPortPassTitle:  'SSH verwendet einen nicht standardmäßigen Port',
            checkSSHPortDesc:       'SSH auf Port 22 wird von automatisierten Scannern und Brute-Force-Bots innerhalb von Minuten angegriffen. Ein nicht standardmäßiger Port reduziert automatisierte Angriffe deutlich, ersetzt aber keine starke Authentifizierung.',
            checkSSHPortRemediation: 'SSH-Port ändern: Systemsteuerung › Terminal & SNMP › Terminal. Einen Port über 1024 wählen, der nicht von anderen Diensten belegt ist.',

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
