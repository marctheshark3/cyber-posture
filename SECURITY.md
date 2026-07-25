# Security Policy

## Reporting

If you find a vulnerability in **cyber-posture** itself, open a GitHub Security Advisory or private report on the repository.

## What this tool is not

- Not a replacement for EDR/MDM.
- Not a guarantee of host compromise detection (especially kernel rootkits).
- Scan output may contain network topology — treat reports as sensitive.

## Supply chain

Release images are built on GitHub Actions and published to GHCR. Prefer pinned version tags over `edge` in production.
