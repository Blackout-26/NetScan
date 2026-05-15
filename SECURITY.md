# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.x | ✅ |

## Reporting a Vulnerability

If you discover a security vulnerability in NetScan, please report it responsibly.

**Do not** open a public GitHub issue for security vulnerabilities.

**Do** open a [GitHub Security Advisory](https://github.com/Blackout-26/NetScan/security/advisories/new) or contact the maintainer directly.

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

You can expect a response within 72 hours.

## Security Considerations for Deployment

- NetScan requires Nmap which needs elevated privileges for OS detection
- The `.env` file contains secrets — never commit it to version control
- NetScan currently runs on HTTP — for sensitive environments, place it behind a reverse proxy with TLS
- Only deploy NetScan on networks you own or have authorisation to scan
