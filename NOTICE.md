# Third-party notices

This product (`cyber-posture`) is released under the **MIT License** (see `LICENSE`).

The Docker image and optional host install may bundle or invoke third-party tools.
Their licenses apply to those components themselves.

## Bundled in the container image (Ubuntu packages)

| Component | Upstream | Typical license |
|-----------|----------|-----------------|
| Python 3 | python.org / Debian | PSF |
| iproute2 (`ss`) | kernel.org | GPL-2.0 |
| ClamAV | clamav.net | GPL-2.0 |
| rkhunter | rkhunter.sourceforge.net | GPL-2.0 |
| chkrootkit | chkrootkit.org | BSD-style / GPL (upstream) |
| debsums | Debian | GPL-2.0+ |
| Lynis | cisofy.com | GPL-3.0 |
| Ubuntu base | Canonical | various (Ubuntu intellectual property policy) |

Install source packages on Ubuntu with `apt-get source <pkg>` for full texts.
Debian/Ubuntu license files on a running image live under `/usr/share/doc/*/copyright`.

## Not bundled (optional host)

- Docker Engine (when you mount `docker.sock`) — Apache-2.0
- systemd, ufw — GPL-2.0 (host)

## Trademark

ClamAV®, NVIDIA®, Ubuntu® and other marks belong to their owners. Use of names is for identification only.

## SPDX

- Package license: `MIT`
- Recommended SPDX for redistributed image docs: `MIT AND GPL-2.0-or-later AND GPL-3.0-or-later` (aggregate)
