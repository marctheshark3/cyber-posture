# Workstation, Docker and home/lab hardening

## Turning findings into repairs

Start with one workstation and preserve a tested recovery path. Review each finding's
evidence and coverage before deciding whether to repair a service or document expected
activity. A bound socket does not establish remote reachability, and a process name alone
does not establish trust. Permission failures remain incomplete checks.

1. Restrict unauthenticated administration first. Confirm physical-device clients before
   changing a service to loopback. For a human-only tool, authenticated SSH forwarding can
   provide remote access without publishing another application port.
2. Review SSH keys and the effective VPN access policy. Match key fingerprints through a
   trusted source and retain a verified access path before revoking a key.
3. Test container restrictions with disposable data before changing production workloads.
   Check existing data ownership as well as startup: root-created files can prevent a
   non-root container from saving data. Back up data before ownership migrations.
4. Verify intended access from another device, then review persistence and approve only
   intentional baseline changes. Keep private inventories and deployment policy outside
   the public scanner repository; see [the multi-host workflow](MULTI-HOST.md).

## Access and network boundaries

Maintain an inventory of your workstations, Docker hosts, router, cameras and other IoT
devices. Record the owner, update policy, exposed services and backup location for each.
Separate trusted workstations, lab workloads, IoT/cameras and guest devices with VLANs or
an isolated guest network. Restrict traffic between segments to required services.

Use phishing-resistant MFA for important accounts, especially email, remote access,
source control and backups. Use separate administrative accounts. Enable disk encryption
and OS-native endpoint protection, and keep operating systems, browsers and router firmware
updated. This Linux scanner does not replace endpoint protection for other operating systems.

Prefer loopback binds plus an authenticated reverse proxy or a VPN with restricted access
rules for private APIs and dashboards. A VPN IP address alone does not establish trust.
The scanner recognizes tailnet bindings from local Tailscale interfaces; it never treats
all 100.x addresses as trusted. Required authentication is checked per protected endpoint.
Public health endpoints must be explicitly labeled `auth: public` in the profile.

## Previewing firewall changes

The helpers preview their proposed rules by default. They preserve existing rules, create
root-only backups before applying, and attempt restoration if a UFW command fails. They
never reset UFW, restart unrelated services, or add blanket allowances for Docker or a VPN.

```bash
# Preview SSH access on the VPN interface. Set your actual SSH port.
./scripts/harden-host.sh --interface tailscale0 --ssh-port 22

# Preview a LAN rule scoped to a particular administrator device.
./scripts/harden-host.sh --interface eth0 --ssh-port 2222 --ssh-from 192.168.10.20/32

# After reviewing the preview, apply the intended settings from a recoverable session.
sudo ./scripts/harden-host.sh --interface tailscale0 --ssh-port 22 --apply

# Hub access is restricted to the selected interface and port.
./scripts/fix-hub-access.sh --interface tailscale0 --port 9093
./scripts/fix-hub-access.sh --interface eth0 --from 192.168.10.20/32 --port 9093
```

Replace interface names, addresses and ports with your own. Before applying, retain console
access and verify how you will reconnect. Existing broad allow rules remain and need separate
review. A successful command does not prove remote access still works: test from a second
device, then use the printed rollback command if needed. Backups are under
`/var/backups/cyber-posture/`; either helper accepts `--rollback BACKUP_DIRECTORY` as root.

Review VPN firewall behavior separately. In its default Linux netfilter mode, Tailscale
evaluates its rules early and accepts permitted tailnet traffic. A UFW deny default or an
interface-specific allow rule does not establish that other tailnet access is restricted.
Use the effective tailnet policy to limit users/devices and ports. Grants are additive, so
an existing broad grant must also be reviewed when adding a narrower one. See
[Tailscale netfilter modes](https://tailscale.com/docs/reference/netfilter-modes) and
[grants syntax](https://tailscale.com/docs/reference/syntax/grants).

## Docker hosts

Bind private published ports explicitly, for example `127.0.0.1:8080:8080`. Check both IPv4
and IPv6. Test from another machine on each relevant network segment; a connection from the
host to its own IP does not validate the incoming firewall path. Docker-published ports may
bypass UFW filtering; apply rules appropriate to Docker's configured firewall backend.
See [Docker's firewall documentation](https://docs.docker.com/engine/network/packet-filtering-firewalls/).

For application containers, use an unprivileged user, drop unneeded capabilities, enable
`no-new-privileges`, and use a read-only filesystem where supported. Avoid Docker socket
mounts. A `:ro` socket mount does not restrict API operations. Pin deployment images by digest
and review updates regularly. The scanner helper follows these restrictions but still shares
host networking and processes for collection; inspect only trusted images.

## Recovery and monitoring

Keep an offline or immutable backup of important workstation data and service configuration.
Record backup credentials separately from the machines being backed up and regularly test
restoration. Forward critical logs and alerts to another trusted system. Configure a heartbeat
that notices missed scheduled scans and test both failure and alert delivery paths. The CLI
only prints notifications; delivery must be configured in your environment.

If compromise is suspected, isolate the affected machine, preserve evidence, revoke exposed
credentials from a trusted device and rebuild from trusted media when necessary. Re-establish
baselines only after review. These priorities follow [CISA's ransomware prevention and recovery
guidance](https://www.cisa.gov/stopransomware/ransomware-guide).

## Verification after changes

Run `cyber-posture scan`, inspect coverage and findings, and independently verify intended
network access. Approve an integrity baseline only after reviewing intentional persistence
changes. Exposure baselines are inventory snapshots and never waive vulnerabilities.
