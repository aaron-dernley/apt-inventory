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

`install`/`remove` (Phase 4) also need root, and — since the build order's
"only after Phase 1-3 have run reliably for a while" guidance hadn't really
been satisfied yet when this was built — were deliberately scoped to a fixed
allowlist of packages (the 3 real pending security updates at the time) rather
than a general wildcard, per explicit user approval:

```
# /etc/sudoers.d/swamp-apt-install (mode 0440, root:root)
Defaults!/usr/bin/apt-get env_keep += "DEBIAN_FRONTEND"
aaronge ALL=(root) NOPASSWD: /usr/bin/apt-get install -y -qq openssl
aaronge ALL=(root) NOPASSWD: /usr/bin/apt-get install -y -qq libssl3t64
aaronge ALL=(root) NOPASSWD: /usr/bin/apt-get install -y -qq openssl-provider-legacy
aaronge ALL=(root) NOPASSWD: /usr/bin/apt-get install -y -qq openssl=3.5.7-1~deb13u2
aaronge ALL=(root) NOPASSWD: /usr/bin/apt-get install -y -qq libssl3t64=3.5.7-1~deb13u2
aaronge ALL=(root) NOPASSWD: /usr/bin/apt-get install -y -qq openssl-provider-legacy=3.5.7-1~deb13u2
aaronge ALL=(root) NOPASSWD: /usr/bin/apt-get remove -y -qq openssl
aaronge ALL=(root) NOPASSWD: /usr/bin/apt-get remove -y -qq libssl3t64
aaronge ALL=(root) NOPASSWD: /usr/bin/apt-get remove -y -qq openssl-provider-legacy
```

The `Defaults!/usr/bin/apt-get env_keep` line lets `DEBIAN_FRONTEND` pass
through sudo's `env_reset` for this one binary specifically — without it, the
`noninteractive` frontend setting would be silently dropped. This is a
mechanical requirement of the already-approved command working correctly, not
an additional privilege grant on its own.

**This allowlist only covers these 3 packages.** `install`/`remove` on any
other package will fail with a sudo permission error until the sudoers file
is extended — that's intentional, not a bug. The model code itself is fully
generic (`install(package, version?)` / `remove(package)`); the restriction to
these specific packages lives entirely in sudoers, not in the TypeScript, so
widening it later is a sudoers edit, not a code change.

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

## install / remove

Both are idempotent: `install(package, version?)` checks current state via
the same `dpkg-query` path `query` uses, and no-ops (no `apt-get` call at all)
if the package is already present — at the requested version if one was
given, any version otherwise. `remove(package)` no-ops if the package is
already absent. Both always re-snapshot and write a fresh `installed`
resource afterward, whether or not anything actually changed.

Live-verified on this machine:

- No-op paths confirmed fast (~100ms, vs. several seconds for a real
  `apt-get` call) for both `install` (package already present, no version
  requested) and `remove` (package already absent).
- Real mutation path: `install` with `package: openssl, version:
  3.5.7-1~deb13u2` genuinely ran `sudo apt-get install -y -qq
  openssl=3.5.7-1~deb13u2`, which apt resolved into upgrading all three
  pending packages (`openssl`, `libssl3t64`, `openssl-provider-legacy`) in one
  transaction. Confirmed via direct `dpkg-query` afterward, and via
  `listUpgradable` dropping to `count: 0, securityCount: 0` — the tool
  correctly observed its own mutation.
- `remove`'s real mutation path (an actual uninstall) was not exercised live —
  there was no package worth safely removing on this machine to test with.
  The code is structurally symmetric with `install`'s verified mutation path.

## Scheduling

Not wired up yet — deliberately held off until Phase 1/2 have been running
reliably for a while. `swamp serve` is the mechanism (it evaluates every
workflow's `trigger.schedule` cron field and fires it — scheduling does *not*
work via external cron; `swamp serve` must be running continuously, e.g. as a
systemd service, for a daily run to actually happen). Notably, if `swamp serve`
runs as a systemd service, its unit must set `HOME` explicitly, or scheduled
runs fail with `"Unknown model type"`.
