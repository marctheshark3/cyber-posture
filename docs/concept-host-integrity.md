---
title: "Host integrity and malware defense"
aliases: [malware scan, trojan worm rootkit host checks, clamav rkhunter]
visibility: private
tags: [security, cyber, malware, integrity, private]
sources:
  - "[[wiki/concepts/cyber-posture]]"
created: 2026-07-24
last_compiled: 2026-07-24
compiled_by: tron
confidence: 0.85
---

# Host integrity and malware defense

Defense-in-depth for `spark-adb4` beyond network exposure. Complements [[wiki/concepts/cyber-posture]].

## Threat model (this house stack)

| Class | How it shows up here | Primary control |
|-------|----------------------|-----------------|
| **Worm / remote exploit** | Exposed service → lateral on LAN | Loopback binds, ufw, no WAN forwards ([[wiki/concepts/cyber-posture]]) |
| **Trojan / supply chain** | Bad pip/npm/deb, malicious script, nerd-sniped binary | Trusted sources, debsums, scoped ClamAV |
| **Rootkit** | `ld.so.preload`, fake kernel procs, hide-pid | IoC scanner, rkhunter/chkrootkit, live USB if confirmed |
| **Miner / reverse shell** | Suspicious cmdline, odd ESTABLISHED ports | Process/cmdline + ss checks |
| **Persistence** | Extra SSH keys, cron, systemd --user units | Hash baselines + delta alerts |

Linux malware volume is lower than Windows, but **DGX + always-on hub + Redroid + LLM** is a high-value target on a LAN that is **not** a trust boundary.

Research-backed stack (home/lab, not enterprise EDR):

1. **Reduce surface first** (already primary) — most “malware wins” start as open services.  
2. **Host integrity / IoCs** — free, fast, no daemon RAM fight with vLLM.  
3. **Signature AV (ClamAV)** — on-demand for Downloads/tmp; avoid full-disk always-on on 121 GiB GPU box unless Marc opts in (`--with-daemon`).  
4. **Rootkit hunters** — weekly rkhunter + chkrootkit (expect false positives).  
5. **Package integrity** — `debsums -s` after upgrades.  
6. **Optional later** — AIDE FIM, Lynis audit score, fail2ban on SSH, unattended-upgrades.

## Tooling (Rage)

| Piece | Path |
|-------|------|
| Integrity scanner | `~/.hermes/profiles/tron/scripts/cyber-host-integrity-scan.py` |
| Quiet / deep wrappers | `cyber-host-integrity-quiet.sh`, `cyber-host-integrity-deep.sh` |
| Optional package install | `sudo bash …/cyber-malware-tools-install.sh` |
| State | `~/.hermes/profiles/tron/state/cyber-posture/host-integrity/` |
| Report MD | `wiki/outputs/cyber-posture/host-integrity.md` |
| Merged into exposure | `cyber-posture-scan.py` → `/security/cyber` + `/ops` cyber blade |

### Commands

```bash
# Quick IoCs + persistence baselines (~1s)
python3 ~/.hermes/profiles/tron/scripts/cyber-host-integrity-scan.py
python3 ~/.hermes/profiles/tron/scripts/cyber-host-integrity-scan.py --update-baseline

# After sudo install of packages:
python3 ~/.hermes/profiles/tron/scripts/cyber-host-integrity-scan.py --deep
python3 ~/.hermes/profiles/tron/scripts/cyber-host-integrity-scan.py --clam
# optional paths:
python3 …/cyber-host-integrity-scan.py --clam ~/Downloads /tmp

# Exposure scan merges quick integrity automatically
python3 ~/.hermes/profiles/tron/scripts/cyber-posture-scan.py
```

### What quick mode checks (no root)

- `/etc/ld.so.preload` present → CRITICAL  
- Fake kernel-thread names with a real `/proc/pid/exe` → CRITICAL  
- Miner/bind-shell cmdline patterns → HIGH  
- ELF/shebang executables under `/tmp` `/var/tmp` `/dev/shm` (Redroid data excluded) → HIGH/MEDIUM  
- `authorized_keys`, user crontab, systemd --user unit set **hash drift** vs baseline → HIGH  
- World-writable PATH dirs → HIGH  
- Weak miner-ish ESTABLISHED remote ports → MEDIUM  
- Tooling gap INFO until ClamAV/rkhunter installed  

### What deep / clam adds (after install)

- `chkrootkit -q`, `rkhunter --check`, `debsums -s`  
- ClamAV recursive on Downloads, Trash, tmp, shm (size-capped)

## Cadence

| Job | Schedule | Channel |
|-----|----------|---------|
| Host integrity quiet | every 6h (with exposure delta) | `#cyber-alerts` on fp change |
| Host integrity deep | weekly Sun ~10:30 | `#cyber-ops` if attention |
| Exposure delta | every 6h | existing |
| Weekly agent review | Sun 11:00 | includes malware backlog |

## Install (Marc sudo once)

```bash
sudo bash ~/.hermes/profiles/tron/scripts/cyber-malware-tools-install.sh
# optional clamd (RAM):  … --with-daemon
```

Then re-baseline:

```bash
python3 ~/.hermes/profiles/tron/scripts/cyber-host-integrity-scan.py --deep --update-baseline
python3 ~/.hermes/profiles/tron/scripts/cyber-posture-scan.py --update-baseline
```

## What this is not

- Not enterprise EDR (CrowdStrike/Falcon).  
- Not a substitute for backups / secrets rotation if CRITICAL IoC fires.  
- Rootkits can lie to a running kernel — confirmed CRITICAL → live USB offline inspect.  
- ClamAV will not catch novel Linux implants; IoC + least exposure still win.

## Related

- [[wiki/concepts/cyber-posture]]
- [[wiki/concepts/cyber-hardening-backlog]]
- [[wiki/guides/cyber-posture-ops]]
- Skill: `cyber-posture`
