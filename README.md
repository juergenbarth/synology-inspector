# Synology Inspector

**Browser-based security audit tool for Synology DSM configuration backups.**

Synology Inspector analyses `.dss` backup files exported from Synology DiskStation Manager (DSM 7+) and checks your NAS configuration against security best practices and common compliance frameworks — entirely in your browser, with no data ever leaving your device.

---

## Features

- **Security checks** across Remote Access, Protocols, and Authentication
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

| Category | Check |
|---|---|
| Remote Access | QuickConnect enabled |
| Remote Access | Telnet enabled |
| Remote Access | SSH on default port 22 |
| Protocols | SMBv1 allowed |
| Protocols | NTLMv1 authentication enabled |
| Protocols | FTP anonymous access enabled |
| Protocols | FTP without TLS |
| Authentication | Automatic account blocking not configured |
| Authentication | HTTP does not redirect to HTTPS |
| Authentication | HSTS not enabled |

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
