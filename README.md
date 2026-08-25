# apt-inventory

A [swamp](https://github.com/swamp-club/swamp) model (`@aaronge/apt`) that
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
been hand-verified on the above. If you port this to another distro or
codename, update `securityOrigin` (the security-update classification substring
changes with the release codename) and re-verify the parser against real
output before trusting the data.

## Status

| Phase | Description | Status |
|---|---|---|
| 1 | `query` / `listUpgradable` (read-only, no privileges) | Done |
| 2 | `apt-report` workflow over versioned data | In progress |
| 3 | `refresh` (needs root) | Not started — requires a sudoers decision, see below |
| 4 | `install` / `remove` (needs root, gated) | Optional, not started |

## Privileges

`query` and `listUpgradable` need no privileges. `refresh`/`install`/`remove`
(Phase 3/4) need root, which a non-interactive swamp workflow can't prompt
for — that requires either a narrow `/etc/sudoers.d/swamp-apt` entry or running
the whole workflow under sudo. **Neither is implemented without explicit
user approval first** — this machine is intended to become the household DNS
server, and widening its sudo surface is not this model's call to make alone.

## Model type

- Type: `@aaronge/apt`, instance: `apt-local`
- Source: `extensions/models/apt.ts`
- Tests: `extensions/models/apt_test.ts` (`~/.swamp/deno/deno test extensions/models/apt_test.ts`)
