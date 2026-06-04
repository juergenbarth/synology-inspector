# Synology Inspector

**Browser-based security audit tool for Synology DSM configuration backups.**

Synology Inspector analyses `.dss` backup files exported from Synology DiskStation Manager (DSM 7+) and checks your NAS configuration against security best practices and common compliance frameworks — entirely in your browser, with no data ever leaving your device.

---

## Features

- **Security checks** across Remote Access, Network, Protocols, Authentication, User Accounts, and Maintenance
- **Best Practices checks** for SMB performance, file services, updates, and task scheduler
- **Framework references** — CIS Controls, NIST SP 800-53, ISO 27001, NIS2, PCI DSS
- **Security score** with letter grade (A–F) and verdict
- **Filter by severity** — Critical, High, Medium, Low
- **EN / DE** — full English and German UI
- **100% client-side** — no server, no telemetry, no internet connection required
- **Source available** — every line of code is open to inspection before use

## Members

YouTube channel members receive an extended version with **PDF export** — a branded, print-ready security assessment report.

→ [youtube.com/@navigio1](https://www.youtube.com/@navigio1)

---

## How to Use

1. **Download** the latest release ZIP and unpack it
2. **Open** `index.html` in your browser (works from `file://` — no web server needed)
3. **Drop** your `.dss` backup file onto the upload area
4. **Review** the findings

### Exporting a Synology DSM backup

In DSM: **Control Panel → Update & Restore → Configuration Backup → Back Up Configuration**

The exported file has a `.dss` extension.

---

## Privacy

Your backup file is processed entirely within your browser using client-side JavaScript and WebAssembly. No data is transmitted to any server — not even anonymised telemetry. The tool works fully offline.

You are encouraged to review the source code before use.

---

## Supported DSM Versions

DSM 7.0 and later. DSM 6.x is not supported.

---

## Security Checks

| Category | Check | Severity |
|---|---|---|
| Remote Access | QuickConnect enabled | High |
| Remote Access | SSH enabled | Medium |
| Remote Access | Telnet enabled | Critical |
| Network Security | DoS protection not enabled on all interfaces | Medium |
| Protocols | SMBv1 allowed | Critical |
| Protocols | NTLMv1 authentication enabled | High |
| Protocols | FTP anonymous access enabled | High |
| Protocols | FTP without TLS | Medium |
| Authentication | Automatic account blocking not configured | Medium |
| Authentication | HTTP does not redirect to HTTPS | Medium |
| Authentication | HSTS not enabled | Low |
| Authentication | CSRF protection not enabled | Medium |
| Authentication | DSM can be embedded in iFrames | Medium |
| Authentication | Session IP binding disabled | Medium |
| User Accounts | Default admin account active | High |
| User Accounts | Password policy not enforced | High |
| User Accounts | Minimum password length below 12 | Medium |
| User Accounts | Special characters not required | Low |
| User Accounts | Common password check disabled | Low |
| Maintenance | Automatic configuration backup not configured | Medium |
| Maintenance | SMB signing disabled | Medium |

## Best Practice Checks

| Category | Check |
|---|---|
| SMB Performance | Transfer log enabled |
| SMB Performance | File space pre-allocation enabled |
| SMB Performance | Asynchronous SMB read disabled |
| SMB Performance | SMB Multichannel disabled |
| SMB Performance | Cross-share symlinks enabled |
| File Services & Storage | AFP service enabled (deprecated) |
| File Services & Storage | File Fast Clone disabled (btrfs only) |
| Update Management | DSM updates not set to notify-only |
| Task Scheduler | No recycle bin cleanup task configured |

---

## License

Source Available — free for personal, non-commercial use.  
Commercial use requires written permission. See [LICENSE](LICENSE) for details.

© 2025–2026 Jürgen Barth, JKLP Consulting

---

## About

**JKLP Consulting** provides security audits, NAS hardening, and IT security advisory for small and medium-sized businesses.

- Website: [jklp.io](https://jklp.io)
- YouTube: [@navigio1](https://www.youtube.com/@navigio1)
- Contact: [contact@jklp.io](mailto:contact@jklp.io)
