# Security Policy

## Reporting

If you find a vulnerability in **cyber-posture** itself, open a GitHub Security Advisory or private report on the repository.

## What this tool is not

- Not a replacement for EDR/MDM.
- Not a guarantee of host compromise detection (especially kernel rootkits).
- Scan output may contain network topology — treat reports as sensitive.

## Supply chain

Release images are built on GitHub Actions and published to GHCR. Prefer verified image digests for deployment. Workflow actions are pinned to reviewed commit SHAs and releases require the regression suite. Review dependency updates regularly.

New report/state files use mode 0600 and atomic replacement; new managed directories use 0700. Existing historical files and directories need separate permission review. Local state is not tamper-proof against the account running the scanner. Send important alerts to an independently protected system.
