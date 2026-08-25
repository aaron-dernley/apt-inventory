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
| 4 | `install` / `remove` (needs root, gated) | Optional, not started |

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
root. `install`/`remove` (Phase 4, optional, not built) would need their own
explicit approval and their own narrowly-scoped sudoers lines if pursued.

## Model type

- Type: `@aaronge/apt-inventory`, instance: `apt-local`
- Source: `extensions/models/apt.ts`
- Tests: `extensions/models/apt_test.ts` (`~/.swamp/deno/deno test extensions/models/apt_test.ts`)

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

## Scheduling

Not wired up yet — deliberately held off until Phase 1/2 have been running
reliably for a while. `swamp serve` is the mechanism (it evaluates every
workflow's `trigger.schedule` cron field and fires it — scheduling does *not*
work via external cron; `swamp serve` must be running continuously, e.g. as a
systemd service, for a daily run to actually happen). Notably, if `swamp serve`
runs as a systemd service, its unit must set `HOME` explicitly, or scheduled
runs fail with `"Unknown model type"`.
