# Host integrity layer

## Quick (no root, ~1s)

- `/etc/ld.so.preload`
- Userland processes with kernel-thread names + real `/proc/pid/exe`
- Miner / bind-shell cmdline patterns
- ELF/shebang executables under `/tmp` `/var/tmp` `/dev/shm`
- `~/.ssh/authorized_keys`, user crontab, systemd --user unit drift vs baseline
- World-writable PATH entries
- Suspicious ESTABLISHED remote ports

## Deep (optional packages)

```bash
sudo ./scripts/install-malware-tools.sh
cyber-posture integrity --deep
```

- chkrootkit, rkhunter, debsums, clamscan
- freshclam timer enabled; clamd **off** unless `--with-daemon`

## Baselining

```bash
cyber-posture integrity --update-baseline
cyber-posture scan --update-baseline
```

After you add an SSH key or systemd unit on purpose, re-baseline or you will get HIGH drift alerts.

## False positives

- debsums “missing file” on incomplete vendor images (e.g. some NVIDIA metapackages) → INFO, not malware.
- Container runtime scratch files under `/tmp` — extend `tmp_allow_prefixes` in your profile.
