# Changelog

## 0.1.1

- Fix completed scans being rejected when the HA host does not appear in Nmap ARP results.
- Use current OS interface addresses as evidence that the HA host's addresses are occupied.
- Preserve multiple local IPv4 addresses and show a local-host label when no name is published.
- Keep safeguards for empty, incomplete, failed and cancelled scans.
- Add scan-start and completion diagnostics; derive CI/package versions from app configuration.

## 0.1.0

- Initial experimental Home Assistant OS app with Ingress and local IPv4 ARP discovery.
- DNS/mDNS naming, MAC/vendor information and persistent device history.
- Hebrew responsive UI, address map, device/free/range tables, custom names and CSV export.
- Preserve previous results on incomplete, empty, failed or cancelled scans.
