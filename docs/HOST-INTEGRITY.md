# Host integrity layer

See also the wiki concept on spark; this is the portable summary.

## Quick (no root, ~1s)

- `/etc/ld.so.preload`
- Userland processes with kernel-thread names + real `/proc/pid/exe`
- Miner / bind-shell cmdline patterns
- ELF/shebang executables under `/tmp` `/var/tmp` `/dev/shm`
- `~/.ssh/authorized_keys`, user crontab, systemd --user unit drift vs baseline
- World-writable PATH entries
- Weak miner-ish ESTABLISHED remote ports

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
