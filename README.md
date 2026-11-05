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

`apt-report` is scheduled 3x daily under `swamp serve`. See "Scheduling"
below.

## Privileges

**Note on scope**: the sudoers rules below assume the account running
`swamp serve` (`aaronge` on this Pi) has *only* the grants shown here. If that account has any
broader pre-existing sudo access (check with `sudo -l`), this scoping isn't
a hard boundary — any process running as that account already has whatever
that broader access allows, independent of anything below. Worth verifying
on whatever machine you deploy this to.

`query` and `listUpgradable` need no privileges. `refresh` needs root, granted
via a narrow sudoers entry (approved by the user before being applied, per the
spec — this isn't a call the agent makes alone):

```
# /etc/sudoers.d/swamp-apt (mode 0440, root:root)
aaronge ALL=(root) NOPASSWD: /usr/bin/apt-get update -qq
```

`install` runs through a root-owned wrapper script rather than calling
`apt-get` directly, so its own safety check can't be bypassed by anything
that isn't going through that exact script:

```
# /etc/sudoers.d/swamp-apt-install (mode 0440, root:root)
Defaults!/usr/bin/apt-get env_keep += "DEBIAN_FRONTEND"
aaronge ALL=(root) NOPASSWD: /usr/local/sbin/apt-security-install
aaronge ALL=(root) NOPASSWD: /usr/bin/apt-get remove -y -qq *
```

```bash
# /usr/local/sbin/apt-security-install (mode 0755, root:root — NOT writable
# by aaronge or any non-root account; verified directly)
#!/bin/bash
set -euo pipefail
readonly SECURITY_ORIGIN="stable-security"
readonly APT_GET=/usr/bin/apt-get
PACKAGE="${1:-}"; VERSION="${2:-}"
[ -n "$PACKAGE" ] && [ -n "$VERSION" ] || { echo "Usage: apt-security-install <package> <version>" >&2; exit 2; }

MATCH=""
while IFS= read -r line; do
  case "$line" in "Inst "*) ;; *) continue ;; esac
  read -r _inst pkg rest <<<"$line"
  [ "$pkg" = "$PACKAGE" ] && { MATCH="$rest"; break; }
done < <("$APT_GET" -s -qq dist-upgrade)

[ -n "$MATCH" ] || { echo "Refusing: ${PACKAGE} is not currently a pending apt upgrade." >&2; exit 1; }
case "$MATCH" in *"($VERSION "*) ;; *) echo "Refusing: version mismatch." >&2; exit 1 ;; esac
case "$MATCH" in *"$SECURITY_ORIGIN"*) ;; *) echo "Refusing: not a security-origin upgrade." >&2; exit 1 ;; esac

exec env DEBIAN_FRONTEND=noninteractive "$APT_GET" install -y -qq "${PACKAGE}=${VERSION}"
```

Why a wrapper rather than a wildcard + code-level check (the original Phase 5
design): sudoers can only do static text matching — it can't express "only
packages with verified security fixes," and a check living purely in swamp's
own TypeScript only ever runs when something goes *through* swamp. Anything
else invoking `sudo apt-get install` directly would skip that check entirely.
Moving the verification into the thing sudoers actually grants access to (a
script, not raw `apt-get`) means the check runs no matter what invokes it,
and can't be disabled by editing it, since the calling account can't write to
it. `remove` has no equivalent "verified safe" concept, so it's a straight
wildcard with no code-level gate — same trust level as running `apt-get
remove` by hand (a choice made explicitly, not by default).

The `Defaults!/usr/bin/apt-get env_keep` line lets `DEBIAN_FRONTEND` pass
through sudo's `env_reset` for `remove`'s direct `apt-get` invocation — the
wrapper doesn't need it, since its own internal `env DEBIAN_FRONTEND=...`
happens after sudo has already elevated, not through another sudo call.

## Model type

- Type: `@aaronge/apt-inventory`, instance: `apt-local`
- Source: `extensions/models/apt.ts`
- Tests: `~/.swamp/deno/deno test extensions/` — `apt_test.ts` (parsers:
  dpkg-query, apt-get simulation, debsecan detail), `apt_install_test.ts`
  (`decideInstallAction`, the pure safety-gate decision function `install`'s
  `execute` delegates to — extracted specifically so the gate's branching is
  unit-testable without mocking subprocesses), `../reports/apt_delta_test.ts`
  (the delta report). 24 tests total.
- All methods and the report log at `info` level on entry/completion via
  `context.logger` (added during the adversarial review pass below — this
  wasn't there through Phase 1-5, verified live and via the swamp CLI's own
  `--log-level info` output).
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

The workflow ships in the package as `@aaronge/apt-report` (listed under
`workflows:` in `manifest.yaml`), so `swamp extension pull
@aaronge/apt-inventory` installs it alongside the model. It expects a model
instance named `apt-local`; its `report` step's `command/shell` model
(`apt-report-printer`) is created automatically on first run.

`apt-report` runs 3x daily — 06:00, 12:00, 20:00 (`trigger: schedule: "0
6,12,20 * * *"` in `workflows/workflow-apt-report.yaml`). `trigger.schedule`
only fires while a `swamp serve` is running for the repo the workflow is
pulled into. Change the cadence without editing the package with
`swamp workflow trigger set @aaronge/apt-report --schedule "..."`, or a
`triggers:` entry in the serve's `serve.yaml`.

On this Pi it runs in the single ops repo,
[`rpi-metrics-bridge`](https://github.com/aaron-dernley/rpi-metrics-bridge).
Since 2026-11-05 that repo's one `swamp serve` runs every scheduled
`@aaronge/*` workflow. It's the systemd user unit `swamp-serve.service`
(installed with `swamp serve daemon enable --config serve.yaml`, linger on
so it starts at boot), bound to `127.0.0.1:9090`, running one scheduled
workflow at a time. See that repo's README and
`docs/swamp-ops-best-practices.md`. Before then, this repo had its own
system-level `swamp-serve.service` running `swamp serve` for apt-report
alone. That unit was removed.

The serve runs as `aaronge`, not root. This matters because
`refresh`/`install`/`remove`'s `sudo` calls are keyed to the `aaronge`
sudoers entries above; running as root would sidestep them entirely. The
unit swamp generates sets `SWAMP_HOME` and `SWAMP_CONFIG_DIR`, without
which scheduled runs fail with `"Unknown model type"`.

Verify with `swamp workflow trigger get @aaronge/apt-report` from the ops
repo. The serve's startup log (`journalctl --user -u swamp-serve`) also
shows `Registered schedule for workflow "@aaronge/apt-report": "0 6,12,20 *
* *"`. Schedules from workflow files are registered at serve startup, so
after changing a workflow's own `trigger.schedule`, restart the serve
(`systemctl --user restart swamp-serve`). `serve.yaml` overrides are
picked up by `swamp serve reload` because the ops serve runs with
`hot-reload: true`.

**Not verified**: whether the cron expression is interpreted in the system's
local timezone (`Europe/London`) or UTC — the manual doesn't document this
either way. The serve's health snapshot reports its `timeZone`; if a run
fires at the wrong wall-clock hour, adjust the cron hour field accordingly.

## Day-to-day operation

A small toolkit in `~/.local/bin/` (outside this repo — personal machine
tooling, not part of the swamp extension) makes this low-effort to live
with day to day. Because one serve now runs every scheduled workflow on
the Pi, `apt-on`/`apt-off` control all of them, not just apt-report.

| Command | Does |
|---|---|
| `apt-status` | One-shot status: is the ops `swamp-serve` up, recent apt-report run history (with failure reasons), the latest report, and whether anything security-relevant is pending right now. Works from any directory. |
| `apt-monitor` | Opens a `foot` terminal window that auto-refreshes `apt-status` every 30s — a live dashboard you can just glance at. Independent of any shell session; close the window whenever. |
| `apt-off` | Stops the ops `swamp-serve` **and** disables it (won't restart on reboot either). Pauses every scheduled `@aaronge/*` workflow. |
| `apt-on` | Re-enables and restarts the ops `swamp-serve`. |

`~/.bashrc` maps the ops repo to `ws://127.0.0.1:9090` in its
`SWAMP_SERVE_REPOS` table, so plain `swamp` commands run inside
`rpi-metrics-bridge` go through the serve. `apt-status` sets
`SWAMP_SERVE_URL` itself, so it works from any directory.

**Storage footprint:** an extension's per-resource `garbageCollection` cap
is only enforced when something applies it: `autoGc: true` in
`.swamp.yaml` (at write time) or a manual `swamp data gc`. Without either,
versions accumulate without limit. That happened in the ops repo, where
2.85M stale versions (41.6 GB) built up from per-minute runs until a
manual GC on 2026-11-05. The ops repo now sets `autoGc: true` plus
`garbageCollection.automatic`, which runs an hourly retention pass under
serve.

**Reproducing the toolkit** (e.g. after a fresh SD card):

```bash
# ~/.local/bin/apt-status — one-shot status check
#!/bin/bash
# Quick status check for apt-inventory, served by the ops repo (rpi-metrics-bridge).
set -euo pipefail
export SWAMP_SERVE_URL="${SWAMP_SERVE_URL:-ws://127.0.0.1:9090}"

echo "=== swamp-serve service ==="
systemctl --user is-active swamp-serve 2>&1 || true

echo
echo "=== recent apt-report runs ==="
swamp workflow history search --json \
  | python3 -c "
import json, sys
d = json.load(sys.stdin)
# The ops serve runs every @aaronge/* workflow, so keep only apt-report's.
runs = [r for r in d.get('results', [])
        if (r.get('workflowName') or r.get('workflow') or '').endswith('apt-report')]
for r in runs[:5]:
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
# Opens a foot terminal window with a live-refreshing apt-inventory dashboard.
set -euo pipefail
setsid foot -T "apt-inventory monitor" watch -n 30 -c apt-status >/dev/null 2>&1 &
disown
echo "Opened. Close the window whenever you don't need it — it's independent of this shell."
```

```bash
# ~/.local/bin/apt-off — stop and disable the ops serve
#!/bin/bash
# Stops the Pi's ops swamp serve now AND disables it, so it won't come back
# after a reboot. That pauses EVERY scheduled @aaronge/* workflow, not just
# apt-report, since one serve runs them all.
set -euo pipefail
systemctl --user disable --now swamp-serve.service
echo "Ops swamp-serve stopped and disabled. No scheduled workflows (apt-report included) will run until you run 'apt-on'."
```

```bash
# ~/.local/bin/apt-on — re-enable and start the ops serve
#!/bin/bash
# Turns the Pi's ops swamp serve back on (rpi-metrics-bridge, user service
# installed by `swamp serve daemon enable`). apt-report is one of its
# scheduled workflows, alongside every other @aaronge/* schedule.
set -euo pipefail
systemctl --user enable --now swamp-serve.service
sleep 1
SWAMP_SERVE_URL=ws://127.0.0.1:9090 swamp workflow trigger get @aaronge/apt-report --json
echo "Ops swamp-serve running and enabled. Scheduled apt-report runs: 06:00, 12:00, 20:00 daily."
```

All four need `chmod +x`, and `~/.local/bin` needs to be on `$PATH` (already
the case on this machine).
