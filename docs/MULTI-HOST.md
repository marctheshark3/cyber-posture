# Multi-host deployment

cyber-posture runs locally on each Linux machine. Each host has its own policy,
user persistence baseline, scan history and reports. The public project provides
the scanner and generic examples; operators supply their own inventory and
deployment workflow. No private repository or hosted account is required to use it.

## Public tool and private operations

| Location | Contents |
| --- | --- |
| This public repository | Scanner code, validated profile format, tests, generic examples and deployment documentation |
| An operator's private configuration repository | Stable machine IDs, trusted connection aliases, assigned policies, pinned scanner revisions, schedules and deployment records |
| Each host, outside its source checkout | Installed policy, approved persistence baseline, latest reports and alert history |
| Private monitoring storage | Received scan summaries, collection failures, last-seen times and reviewed findings |
| A credential store | Authentication material for deployment and alert delivery |

Keep real host profiles, network addresses, inventories and scan output out of
this public checkout. Private profiles can live under
`~/.config/cyber-posture/`, or another directory selected with `CYBER_CONFIG_DIR`.
Keep credentials out of profile files and source control. The scanner prints
notifications to stdout/stderr; delivery and fleet aggregation are separate
operator integrations.

## Rollout sequence

1. Make the tested scanner revision available on one selected Linux machine.
   A source clone alone does not install a CLI, start a job or validate the host.
   Confirm which checkout the installed `cyber-posture` command resolves to.
2. Validate the policy with `cyber-posture paths`, then run
   `cyber-posture scan --no-write`. Start with a generic policy or an explicitly
   reviewed host policy. First-run unknown listeners are review items; identify
   their owners before deciding which services belong in the policy.
3. Review failed/skipped coverage and HIGH/CRITICAL findings. A user scan may lack
   firewall/process visibility. Use separate privileged read-only checks where
   needed, and test intended LAN/VPN reachability from another device.
4. Review that user's SSH keys, cron jobs and systemd files before explicitly
   approving persistence with `cyber-posture integrity --update-baseline`.
   Approval can fail while unresolved non-drift HIGH/CRITICAL findings remain.
5. Install the reviewed policy and schedule in private deployment automation.
   Verify a fresh run, finding delivery, failure delivery and stale-host detection.
6. Repeat on other hosts with their own policies and baselines. Use small rollout
   batches and retain the previous reviewed code/configuration for recovery.

Generic profiles are deliberately small. Browser/media UDP sockets, discovery
traffic and temporary development executables need context on a workstation.
Keep policy decisions tied to the machine's intended role; avoid accepting every
observed port or automatically approving a scan as a baseline.

## Local paths and profiles

Install the CLI from the selected checkout with `./install.sh`. The default policy
is `~/.config/cyber-posture/config.yaml`; a named profile uses a matching filename:

```bash
cyber-posture init-config --profile example-lab
# Edit ~/.config/cyber-posture/example-lab.yaml for this host before use.
cyber-posture --profile example-lab paths
cyber-posture --profile example-lab scan --no-write
```

The `default` profile covers SSH and common local system services. `example-lab`
is a generic LLM/camera example requiring local review. A named profile must exist;
it never silently falls back to an unrelated `config.yaml`.

Paths can be supplied through `CYBER_CONFIG_DIR`, `CYBER_STATE_DIR` and
`CYBER_REPORT_DIR`. Use separate state roots for different machines, users, and
native/container scopes. Profiles on the same user/state root share persistence
and alert history, so a profile name alone does not isolate state.

Never distribute a shared persistence baseline to the fleet. Keep approved
off-host copies associated with the original machine, user and installation.
Review baseline validity after a reimage or account change.

## Scheduling and private collection

Choose local scheduled jobs and a private collector that fit the environment.
Existing trusted SSH access can support deployment and report retrieval without
opening a new network-facing scanner endpoint. Preserve host-key verification.

A starting schedule is quick exposure/integrity checks every six hours and deep
checks weekly on machines with suitable tools and capacity. Small lab devices
can use a lighter schedule and explicitly report unavailable deep coverage.
If using systemd timers, calendar catch-up and randomized start delays can help
with powered-off workstations and shared load; see the
[systemd timer manual](https://www.freedesktop.org/software/systemd/man/latest/systemd.timer.html).

Every private collection attempt should record:

- Stable machine ID, intended login user, scanner revision and policy revision.
- Collection time, reported scan time, target scope and scan exit status.
- `complete`, per-check coverage, severity counts and finding fingerprint.
- Transport/configuration errors and time since the last successful report.

Exit **0** means the declared scan completed, including when threats were found.
Exit **2** means incomplete coverage or an error. Read finding severities separately.
A missing, stale or invalid report needs its own monitoring status. Silent
`--quiet` output is not proof that a scheduled job ran or that an alert was delivered.

The latest native exposure JSON is `last-scan.json` under the resolved state root;
integrity reports are under `host-integrity/`. Preserve stdout/stderr and the exit
status even when no valid report was produced. Protect collected reports with
restricted permissions and authenticated access; configure retention privately.

## Upgrades

Pin a reviewed commit or release and its corresponding policy version in private
deployment configuration. Run `make test` before promoting changes. Verify native
behavior on a pilot before upgrading other machines. Updates to a source checkout
do not replace a separately installed checkout or image.

Validate existing profiles with the new CLI before enabling jobs. Supported service
`auth` values are `required`, `public`, `n/a`, `unknown` and `keyish`; HTTP probe
policies use `required`, `public` or `observe`. Unsupported legacy labels require
an explicit policy decision, rather than an automatic security exemption.
Legacy SSH/systemd baselines may require reviewed migration to capture ownership,
permissions and unit contents. See [host integrity behavior](HOST-INTEGRITY.md).

## Coverage across different systems

Use native Linux runs for host/user persistence and Docker inventory. Running as
root inspects root's own home and cron, so monitor each intended user's persistence
separately. The container helper has partial host visibility and returns incomplete
coverage; it complements native inspection.

Docker-published ports require external reachability checks because Docker's
forwarding rules can bypass UFW's incoming rules. See
[Docker's firewall documentation](https://docs.docker.com/engine/network/packet-filtering-firewalls/).
Routers, switches and IoT devices need separate configuration, firmware and network
reviews. They are not automatically covered by a workstation scan.

Windows and macOS need native endpoint protection and their own checks. A WSL2 run
inspects its Linux environment, not the Windows host.
