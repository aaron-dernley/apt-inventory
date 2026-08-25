# apt-inventory

A [swamp](https://github.com/swamp-club/swamp) model (`@aaronge/apt-inventory`) that
observes APT package state and produces versioned, queryable data about what
is installed and what is pending. Observation and reporting only — it does
not replace `unattended-upgrades`, and does not do package pinning, repo
management, or `dpkg` surgery.

## OS/architecture support

**This only works on Debian and Debian-derivative Linux systems** (Debian,
Ubuntu, Raspberry Pi OS, etc. — anything with `dpkg-query` and `apt-get`).

It will **not** work on:

- RHEL/Fedora/CentOS (`dnf`/`yum`), Arch (`pacman`), Alpine (`apk`)
- macOS or Windows

Developed and verified against:

- **Debian GNU/Linux 13 (trixie)**
- **arm64/aarch64** (Raspberry Pi 5 Model B Rev 1.1, 8GB)

It is expected to work unmodified on other Debian-family distros/releases and
other architectures, but the `dpkg-query`/`apt-get` output parsing has only
been hand-verified on the above. If you port this to a distro where the apt
archive's security suite isn't literally `stable-security` (see "Security
update classification" below), you'll need to update `securityOrigin` and
re-verify against real output before trusting the data.

## Status

| Phase | Description | Status |
|---|---|---|
| 1 | `query` / `listUpgradable` (read-only, no privileges) | Done |
| 2 | `apt-report` workflow over versioned data | Done |
| 3 | `refresh` (needs root) | Done |
| 4 | `install` / `remove` (needs root, gated) | Done |
| 5 | `scanVulnerabilities` (debsecan, CVE cross-check); widened install/remove sudoers | Done |

Scheduling `apt-report` to actually run daily (via `swamp serve`) is deliberately
on hold until this has been exercised for a while — see "Scheduling" below.

## Privileges

`query` and `listUpgradable` need no privileges. `refresh` needs root, granted
via a narrow sudoers entry (approved by the user before being applied, per the
spec — this isn't a call the agent makes alone):

```
# /etc/sudoers.d/swamp-apt (mode 0440, root:root)
aaronge ALL=(root) NOPASSWD: /usr/bin/apt-get update -qq
```

This grants NOPASSWD for exactly that one invocation — nothing else gains
root.

`install`/`remove` (Phase 4) also need root. **Initially** (per the build
order's "only after Phase 1-3 have run reliably for a while" guidance not
really being satisfied yet) these were scoped to a fixed 3-package sudoers
allowlist. **As of Phase 5, sudoers is a wildcard** — the actual restriction
moved into the model code instead (see "install / remove" below):

```
# /etc/sudoers.d/swamp-apt-install (mode 0440, root:root)
Defaults!/usr/bin/apt-get env_keep += "DEBIAN_FRONTEND"
aaronge ALL=(root) NOPASSWD: /usr/bin/apt-get install -y -qq *
aaronge ALL=(root) NOPASSWD: /usr/bin/apt-get remove -y -qq *
```

The `Defaults!/usr/bin/apt-get env_keep` line lets `DEBIAN_FRONTEND` pass
through sudo's `env_reset` for this one binary specifically — without it, the
`noninteractive` frontend setting would be silently dropped. This is a
mechanical requirement of the command working correctly, not an additional
privilege grant on its own.

This was a deliberate, explicit tradeoff (user-approved): sudoers alone can
only do static text matching — it has no way to express "only packages with
verified security fixes," so a real allowlist-by-package-name approach could
never generalize beyond whatever's pending *today*. Moving enforcement into
the model code (which can read `apt-local`'s own data) means the actual
security boundary is dynamic and verifiable, not a static list that goes
stale. `remove` has no equivalent "verified safe" concept, so it's a
straight wildcard with no code-level gate — same trust level as running
`apt-get remove` by hand.

## Model type

- Type: `@aaronge/apt-inventory`, instance: `apt-local`
- Source: `extensions/models/apt.ts`
- Tests: `extensions/models/apt_test.ts` (`~/.swamp/deno/deno test extensions/models/apt_test.ts`)
- **System dependency**: `debsecan` (for `scanVulnerabilities`) — not installed
  by default on Debian; `sudo apt-get install debsecan` once, out-of-band
  (this is one-time host setup, not something swamp mediates per-run). Needs
  network access to fetch its vulnerability database.
- Global args: `securityOrigin` (default `stable-security`), `timeout`
  (default `120000`ms), `suite` (default `trixie` — passed to debsecan's
  `--suite`; unlike `securityOrigin`, this **does** need updating on release
  upgrade)

## Reporting

`extensions/reports/apt_delta.ts` (`@aaronge/apt-inventory-delta`) is a
model-scope report attached by default to `@aaronge/apt-inventory`. It fires
automatically after `query`/`listUpgradable` and computes installed/upgradable/
security counts plus the delta versus the previous version of each resource —
persisted as `report-aaronge-apt-inventory-delta{,-json}` data on the model
instance, retrievable via `swamp report get @aaronge/apt-inventory-delta
--model apt-local`.

The `workflows/workflow-apt-report.yaml` workflow ties it together:

1. **`collect`** — runs `listUpgradable` and `query` on `apt-local` (they
   serialize on the model's lock rather than truly running in parallel, since
   both target the same instance — not a problem at this scale).
2. **`report`** — a `command/shell` step (model `apt-report-printer`) that
   prints the counts/deltas via CEL expressions reading the delta report's
   JSON attributes.
3. **`alert`** — an `assert` step that fails the run when
   `data.latest("apt-local", "upgradable").attributes.securityCount > 0`. A
   failed run is the v1 notification mechanism.

Verified end-to-end against the real machine, including re-runs to confirm
version history, delta computation, `swamp data query 'attributes.securityCount
> 0'` returning rows, and the `alert` job genuinely failing the workflow run
when security updates are pending (a real OpenSSL security update surfaced
during Phase 3 testing — see below).

## Security update classification

**`securityOrigin`'s default is `stable-security`, not a codename.** This
correction came from a real bug caught during Phase 3 testing: this machine's
`/etc/apt/sources.list.d/debian.sources` configures `Suites: trixie-security`,
but apt does not report that string back — real `Inst` line output showed
`Debian-Security:13/stable-security`, so a codename-based default (the
spec's original assumption) would silently classify every real security
update as non-security. `stable-security` is also the *more* durable choice
long-term: it doesn't change across codenames/releases as long as the machine
tracks the `stable` suite, whereas a codename-based substring would need
updating on every release upgrade and would never actually match in the
meantime.

## install / remove

Both are idempotent: `remove(package)` no-ops if the package is already
absent. `install(package, version?)` no-ops if already at the target
version — target being the requested `version` if given, or (if omitted)
whatever's already installed, as long as nothing verified is pending. Both
always re-snapshot and write a fresh `installed` resource afterward, whether
or not anything actually changed.

**`install`'s real safety boundary lives in the code, not sudoers** (sudoers
is a wildcard as of Phase 5 — see "Privileges" above). Before any actual
mutation, `install` reads `apt-local`'s own latest `upgradable` resource and
refuses unless the requested package+version is present there with
`isSecurity: true` — i.e. a real, currently pending, apt-classified security
update. Anything else (a package with no pending update, a non-security
pending upgrade, an arbitrary version that doesn't match the verified
candidate) is refused with a clear error, regardless of what sudoers would
technically allow. This is a deliberate narrowing from Phase 4's original
"install any package" behavior to "apply verified pending security updates
only" — the tradeoff that makes a wildcard sudoers grant safe.

Live-verified on this machine:

- No-op paths confirmed fast (~100ms, vs. several seconds for a real
  `apt-get` call): `install` for an already-installed, never-pending package
  (`bash`); `remove` for an already-absent package (`cowsay`); and `install`
  re-run for a package that *was* a pending security update but has since
  been fixed and dropped out of `upgradable` (`openssl`, after being patched
  — confirms the gate doesn't turn "already applied" into an error).
- **The gate actually refuses what it should**: `install --input
  package=cowsay` (no pending update) failed with `"Refusing to install
  cowsay: not a currently pending security update..."` even though sudoers'
  wildcard would technically permit the underlying `apt-get` call.
- Real mutation path: `install` with `package: openssl, version:
  3.5.7-1~deb13u2` (a genuinely verified pending security update at the
  time) ran `sudo apt-get install -y -qq openssl=3.5.7-1~deb13u2`, which apt
  resolved into upgrading all three related packages (`openssl`,
  `libssl3t64`, `openssl-provider-legacy`) in one transaction. Confirmed via
  direct `dpkg-query` afterward, and via `listUpgradable` dropping to
  `count: 0, securityCount: 0`.
- `remove`'s real mutation path (an actual uninstall) was not exercised live —
  there was no package worth safely removing on this machine to test with.
  The code is structurally symmetric with `install`'s verified mutation path.

## Vulnerability scanning (debsecan)

`scanVulnerabilities` (read-only, no privileges — debsecan itself needs no
root) runs `debsecan --suite <suite> --format detail` against installed
packages and writes the `vulnerabilities` resource: every CVE debsecan knows
about for currently installed packages, whether a fix is available for the
configured `suite`, and — critically — an independent `actuallyFixed` check.

**Why the independent check exists: debsecan produces real false positives
on this machine.** Raspberry Pi OS rebuilds packages with its own version
suffixes (e.g. `+rpt2+deb13u2`), which debsecan's vulnerability database
doesn't understand — it compares against upstream Debian's fixed version
string and calls it vulnerable even when `dpkg --compare-versions` confirms
the installed (rebuilt) version is already newer. Verified concretely on
this machine with two different packages: `cups` (2.4.10-3+rpt2+deb13u2 vs.
debsecan's claimed fix 2.4.10-3+deb13u2) and `gstreamer1.0-plugins-bad`
(1.26.2-3+rpt3+deb13u2 vs. 1.26.2-3+deb13u3) — both already patched per
dpkg, both flagged as vulnerable by debsecan alone. A live full scan on this
machine found **347 debsecan "fix available" entries, all 347 of which** are
false positives per `actuallyFixed` (0 `actionableCount`).

Because of this, `install`'s safety gate (above) deliberately does **not**
use `scanVulnerabilities`/debsecan data directly — it's anchored to apt's
own `upgradable`/`isSecurity` classification, which is inherently
version-comparison-aware and doesn't share this false-positive class.
`scanVulnerabilities` is enrichment/reporting data (including CVEs with no
fix available yet at all, which apt-based observation can never see), not
an install gate.

## Scheduling

`apt-report` runs 3x daily — 06:00, 12:00, 20:00 (`trigger: schedule: "0
6,12,20 * * *"` in `workflows/workflow-apt-report.yaml`), via `swamp serve`
running as a systemd service:

```
# /etc/systemd/system/swamp-serve.service
[Unit]
Description=swamp serve (apt-inventory)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=aaronge
Group=aaronge
Environment=HOME=/home/aaronge
WorkingDirectory=/home/aaronge/Repositories/apt-inventory
ExecStart=/usr/local/bin/swamp serve --repo-dir /home/aaronge/Repositories/apt-inventory
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

`systemctl enable --now swamp-serve.service`. Runs as `aaronge` (not root) —
this matters because `refresh`/`install`/`remove`'s `sudo` calls are keyed to
the `aaronge` sudoers entries; running the service as root would sidestep
those entries entirely. `HOME=/home/aaronge` is set explicitly per the
gotcha `swamp help serve` calls out directly (scheduled runs fail with
`"Unknown model type"` without it, since swamp resolves extensions relative
to `$HOME/.swamp`). Binds to `127.0.0.1:9090` only (the default) — no need
for network exposure or auth just to run a local schedule.

Verified after starting the service: `swamp workflow trigger get apt-report`
shows the effective schedule as `"0 6,12,20 * * *"`; the service's own
startup log confirms `Registered schedule for workflow "apt-report": "0
6,12,20 * * *"` and `Scheduled execution service started with 1 schedules`;
`systemctl is-enabled` confirms it'll survive a reboot.

**Changing the schedule requires a `swamp-serve` restart** — schedules are
registered at server startup, not live-reloaded from the workflow file.
After editing `trigger.schedule`, run `sudo systemctl restart
swamp-serve.service` and re-check `swamp workflow trigger get apt-report`.

**Not verified**: whether the cron expression is interpreted in the system's
local timezone (`Europe/London`) or UTC — the manual doesn't document this
either way. Worth confirming once the first real 06:00 run lands; if it
fires at the wrong wall-clock hour, adjust the cron hour field accordingly.

## Day-to-day operation

A small toolkit in `~/.local/bin/` (outside this repo — personal machine
tooling, not part of the swamp extension) makes this genuinely low-effort to
live with day to day:

| Command | Does |
|---|---|
| `apt-status` | One-shot status: is `swamp-serve` up, recent run history (with failure reasons), the latest report, and whether anything security-relevant is pending right now. Works from any directory. |
| `apt-monitor` | Opens a `foot` terminal window that auto-refreshes `apt-status` every 30s — a live dashboard you can just glance at. Independent of any shell session; close the window whenever. |
| `apt-off` | Stops `swamp-serve` **and** disables it (won't restart on reboot either). The single "turn it off" command. |
| `apt-on` | Re-enables and restarts `swamp-serve`. The single "turn it back on" command. |

`~/.bashrc` also exports `SWAMP_SERVE_URL=ws://127.0.0.1:9090`, so any plain
`swamp` command (`swamp data query ...`, `swamp report get ...`, etc.) works
from any directory too — no more `cd`-ing into the repo or remembering
`--repo-dir`.

**Storage footprint** (checked directly, given the Pi's limited space): the
`.swamp/data` directory is a few MB and bounded by each resource's
`garbageCollection` cap — it will not grow unboundedly. The systemd journal
(covering `swamp-serve`'s own logs, among everything else on the machine) is
in the single-digit MB range and self-vacuums old entries by default. Neither
is a real concern against 16GB free.

**Reproducing the toolkit** (e.g. after a fresh SD card):

```bash
# ~/.local/bin/apt-status — one-shot status check
#!/bin/bash
set -euo pipefail
export SWAMP_SERVE_URL="${SWAMP_SERVE_URL:-ws://127.0.0.1:9090}"

echo "=== swamp-serve service ==="
systemctl is-active swamp-serve 2>&1 || true

echo
echo "=== recent apt-report runs ==="
swamp workflow history search --json \
  | python3 -c "
import json, sys
d = json.load(sys.stdin)
for r in d.get('results', [])[:5]:
    status = r.get('status')
    started = r.get('startedAt', '?')
    trigger = r.get('triggerSource', '?')
    line = f\"{started}  {status:10}  ({trigger})\"
    if status == 'failed':
        line += f\"  -> {r.get('failedStep')}: {r.get('failureReason')}\"
    print(line)
"

echo
echo "=== latest report ==="
swamp report get @aaronge/apt-inventory-delta --model apt-local --markdown

echo
echo "=== pending security updates right now ==="
swamp data query 'attributes.securityCount > 0' --json \
  | python3 -c "
import json, sys
d = json.load(sys.stdin)
if d.get('total', 0) == 0:
    print('none')
else:
    print(f\"{d['total']} record(s) — run: swamp data get apt-local upgradable --json\")
"
```

```bash
# ~/.local/bin/apt-monitor — friendly live dashboard window
#!/bin/bash
set -euo pipefail
setsid foot -T "apt-inventory monitor" watch -n 30 -c apt-status >/dev/null 2>&1 &
disown
echo "Opened. Close the window whenever you don't need it — it's independent of this shell."
```

```bash
# ~/.local/bin/apt-off — stop and disable the schedule
#!/bin/bash
set -euo pipefail
sudo systemctl disable --now swamp-serve.service
echo "swamp-serve stopped and disabled. Scheduled apt-report runs will not happen until you run 'apt-on'."
```

```bash
# ~/.local/bin/apt-on — re-enable and start the schedule
#!/bin/bash
set -euo pipefail
sudo systemctl enable --now swamp-serve.service
sleep 1
swamp workflow trigger get apt-report --json
echo "swamp-serve running and enabled. Scheduled apt-report runs: 06:00, 12:00, 20:00 daily."
```

All four need `chmod +x`, and `~/.local/bin` needs to be on `$PATH` (already
the case on this machine).
