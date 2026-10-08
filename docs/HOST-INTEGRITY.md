# Host integrity checks

Run the native CLI separately as each workstation user whose persistence you want to monitor.
Running as root checks root's home and crontab; it does not automatically check every user's
SSH keys or user services. This tool supports Linux; WSL checks the Linux environment,
not the Windows host. Use native endpoint protection for Windows and macOS.

## Coverage and results

Quick checks inspect ld.so.preload, readable processes, executable payloads in temporary
storage, user SSH keys, crontab, user systemd files, PATH permissions and established
connections. Quick temporary-directory walks are limited to three directory levels and
sample findings; deep scans walk further. Permission failures appear in coverage.

Each report includes the target scope, per-check status, and `complete`. A complete
scan means the declared checks completed; it is not proof that the machine is clean.
Checks report `passed`, `finding`, `failed` or `skipped`. Before an approved persistence
baseline exists, drift comparison is explicitly skipped and coverage is incomplete.
Required checks that fail or are
skipped make the result incomplete. A missing optional Docker CLI is shown separately
in exposure coverage. External LAN/WAN reachability requires testing from another device.

Exit code **0** means the scan completed, including when it found a threat. Exit code
**2** means an error or incomplete coverage. Inspect JSON `summary` for finding severity.
Automation must monitor both scan findings and scan/job failures.

## Baselines and alerts

```bash
cyber-posture integrity
# Review the current keys, jobs, unit files, ownership and permissions first:
cyber-posture integrity --update-baseline
```

Persistence baselines record absence as well as presence, so the first new SSH key or cron
job is detected. Unit contents, drop-ins and enablement links are hashed, including ownership
and permissions. Unit checks honor XDG settings and data directories and include persistent
`user.control` settings. Legacy key/unit baselines require explicit review and migration. Only
baseline after an intentional, reviewed change. Failed persistence checks and unresolved
HIGH/CRITICAL non-drift findings prevent approval. A baseline does not suppress alerts.

Alert state is separate from approved baselines and from the latest report. `--quiet`
prints the first HIGH/CRITICAL result, changes in evidence, recovery, and a reminder after
24 hours if a finding remains. Quick, deep and ClamAV jobs maintain separate notification
history. Invalid or future-dated alert history cannot suppress current HIGH/CRITICAL results.
Exposure `--full --quiet` forces a notification. Output is stdout/stderr; configure
and test your own delivery mechanism. No webhook, email or chat message is sent by this tool.

`--no-write` creates no scan reports, baselines, alert records or state directories; it is
incompatible with `--update-baseline`. Scan commands sharing output are locked against
concurrent writes. State/report files are replaced atomically with mode 0600; new managed
directories use 0700. Review permissions on existing directories and older reports separately.
Serve reports only through an authenticated service with deliberately granted read access.

## Deep scans

```bash
sudo ./scripts/install-malware-tools.sh
cyber-posture integrity --deep
cyber-posture integrity --clam /path/to/review
```

Deep scans request chkrootkit, rkhunter, debsums and ClamAV. Tools may require an appropriately
privileged native run; missing tools and permission failures are incomplete coverage, not
clean results. ClamAV reports clean only after a successful scan that actually examined files.
Its file/archive size limits still apply. clamscan rejects signature databases older than
seven days; an older scanner without this option reports a failure and needs upgrading.
For clamdscan, configure and monitor the daemon's signature updates separately.
Keep signatures updated with freshclam. The installer
does not approve rkhunter properties or disable existing ClamAV daemons.

Exposure scans collect current quick evidence in memory. They never reuse a cached quick
result as current evidence after a failure. Prior deep-tool HIGH/CRITICAL findings remain
visible with their date; a saved deep result older than eight days, or an incomplete deep
result, triggers a coverage alert. Invalid saved reports and reports for a different host also
make deep coverage incomplete; valid threat evidence from the current host remains visible.
Rerun deep checks to resolve that state.

## Docker limitations

The host helper mounts /etc and temporary directories read-only under /host and shares
host PID/network namespaces. It does not mount host homes, cron spools, the package database,
or the Docker socket. Host SSH/cron/systemd/PATH/package checks are explicitly skipped and
the result is incomplete (exit 2). Run those checks natively on the host.

Profiles control `tmp_allow_prefixes` and `clam_paths`. Temporary exclusions match complete
path components, not lookalike prefixes. Command-line matches are reported as PID/pattern
without raw arguments, and HTTP response bodies are omitted. Reports still contain sensitive
paths, topology and evidence; local baselines are not tamper-proof against an attacker with
control of the same account. Keep important alerts and approved baseline copies off-host.
