import { assertEquals } from "jsr:@std/assert@1";
import { parseAptSimulation, parseDebsecanDetail, parseDpkgQuery } from "./apt.ts";

const NOTE_BANNER = `NOTE: This is only a simulation!
      apt-get needs root privileges for real execution.
      Keep also in mind that locking is deactivated,
      so don't depend on the relevance to the real current situation!`;

Deno.test("parseAptSimulation - zero upgradable packages, banner only", () => {
  const result = parseAptSimulation(NOTE_BANNER, "trixie-security");
  assertEquals(result, []);
});

Deno.test("parseAptSimulation - epoch version in current and candidate", () => {
  const stdout = `${NOTE_BANNER}
Inst bash-completion [1:2.16.0-7] (1:2.16.1-1 Debian:13.7/stable [all])
Conf bash-completion (1:2.16.1-1 Debian:13.7/stable [all])`;
  const result = parseAptSimulation(stdout, "trixie-security");
  assertEquals(result, [
    {
      name: "bash-completion",
      currentVersion: "1:2.16.0-7",
      candidateVersion: "1:2.16.1-1",
      origin: "Debian:13.7/stable",
      isSecurity: false,
    },
  ]);
});

Deno.test("parseAptSimulation - new dependency has null currentVersion", () => {
  const stdout = `${NOTE_BANNER}
Inst cowsay (3.03+dfsg2-8 Debian:13.6/stable [all])
Conf cowsay (3.03+dfsg2-8 Debian:13.6/stable [all])`;
  const result = parseAptSimulation(stdout, "trixie-security");
  assertEquals(result, [
    {
      name: "cowsay",
      currentVersion: null,
      candidateVersion: "3.03+dfsg2-8",
      origin: "Debian:13.6/stable",
      isSecurity: false,
    },
  ]);
});

Deno.test("parseAptSimulation - real Debian security origin matches 'stable-security', not the codename", () => {
  // Verified against real apt-get output on this machine (Debian 13
  // "trixie"): despite sources.list configuring the suite as
  // `trixie-security`, apt reports the origin as `Debian-Security:13/stable-security`
  // — the codename never appears. `securityOrigin`'s default must be
  // "stable-security", not a codename-based value, or every real security
  // update on this machine silently classifies as non-security.
  const stdout = `${NOTE_BANNER}
Inst openssl [3.5.6-1~deb13u2+rpt1] (3.5.7-1~deb13u2 Debian-Security:13/stable-security [arm64])`;
  const result = parseAptSimulation(stdout, "stable-security");
  assertEquals(result.length, 1);
  assertEquals(result[0].isSecurity, true);
});

Deno.test("parseAptSimulation - classifies security origin via substring match", () => {
  const stdout = `${NOTE_BANNER}
Inst curl [8.14.0-1] (8.14.0-1+deb13u1 Debian-Security:13/trixie-security [arm64])`;
  const result = parseAptSimulation(stdout, "trixie-security");
  assertEquals(result.length, 1);
  assertEquals(result[0].isSecurity, true);
  assertEquals(result[0].origin, "Debian-Security:13/trixie-security");
});

Deno.test("parseAptSimulation - ignores Conf/Remv/blank lines", () => {
  const stdout = `${NOTE_BANNER}
Remv old-package [1.0-1]
Conf some-package (2.0-1 Debian:13/stable [all])

Inst real-upgrade [1.0-1] (2.0-1 Debian:13/stable [all])`;
  const result = parseAptSimulation(stdout, "trixie-security");
  assertEquals(result.length, 1);
  assertEquals(result[0].name, "real-upgrade");
});

Deno.test("parseDpkgQuery - keeps only install ok installed, splits on tabs not regex", () => {
  const stdout = [
    "bash-completion\t1:2.16.0-7\tall\tinstall ok installed",
    "some-removed-pkg\t1.0-1\tamd64\tdeinstall ok config-files",
    "libfoo\t2.3.4-1~bpo13+1\tarm64\tinstall ok installed",
  ].join("\n") + "\n";

  const result = parseDpkgQuery(stdout);
  assertEquals(result, [
    { name: "bash-completion", version: "1:2.16.0-7", arch: "all" },
    { name: "libfoo", version: "2.3.4-1~bpo13+1", arch: "arm64" },
  ]);
});

Deno.test("parseDpkgQuery - empty input yields empty array", () => {
  assertEquals(parseDpkgQuery(""), []);
});

// The debsecan fixtures below are real output captured on this machine
// (Debian 13 trixie, arm64) via `debsecan --suite trixie --format detail`.

Deno.test("parseDebsecanDetail - no fix available (no trailing suite-fix line)", () => {
  const stdout = `CVE-2026-54369
  acl before version 2.4.0 contains a symlink traversal vulnerability in ...
  installed: acl 2.3.2-2+b1
             (built from acl 2.3.2-2)
  fixed in unstable: acl 2.4.0-1 (source package)`;

  const result = parseDebsecanDetail(stdout);
  assertEquals(result, [
    {
      cve: "CVE-2026-54369",
      package: "acl",
      installedVersion: "2.3.2-2+b1",
      fixedVersions: [],
      fixAvailableInSuite: false,
    },
  ]);
});

Deno.test("parseDebsecanDetail - fix available, multiple branch versions", () => {
  const stdout = `CVE-2025-58060 (fixed)
  OpenPrinting CUPS is an open source printing system for Linux and othe ...
  installed: cups 2.4.10-3+rpt2+deb13u2
             (built from cups 2.4.10-3+rpt2+deb13u2)
  fixed in unstable: cups 2.4.10-4 (source package)
  fixed on branch:   cups 2.3.3op2-3+deb11u10 (source package)
  fixed on branch:   cups 2.4.10-3+deb13u1 (source package)
  fixed on branch:   cups 2.4.10-3+deb13u2 (source package)
  fixed on branch:   cups 2.4.2-3+deb12u9 (source package)
  fix is available for the selected suite (trixie)`;

  const result = parseDebsecanDetail(stdout);
  assertEquals(result, [
    {
      cve: "CVE-2025-58060",
      package: "cups",
      installedVersion: "2.4.10-3+rpt2+deb13u2",
      fixedVersions: [
        "2.3.3op2-3+deb11u10",
        "2.4.10-3+deb13u1",
        "2.4.10-3+deb13u2",
        "2.4.2-3+deb12u9",
      ],
      fixAvailableInSuite: true,
    },
  ]);
});

Deno.test("parseDebsecanDetail - multi-package CVE produces one entry per block", () => {
  const stdout = `CVE-2026-3184
  A flaw was found in util-linux. Improper hostname canonicalization in  ...
  installed: bsdextrautils 2.41.5-0+deb13u1
             (built from util-linux 2.41.5-0+deb13u1)
  fixed in unstable: util-linux 2.42-1 (source package)
  fixed on branch:   util-linux 2.42~rc1-1 (source package)

CVE-2026-3184
  A flaw was found in util-linux. Improper hostname canonicalization in  ...
  installed: bsdutils 1:2.41.5-0+deb13u1
             (built from util-linux 2.41.5-0+deb13u1)
  fixed in unstable: util-linux 2.42-1 (source package)
  fixed on branch:   util-linux 2.42~rc1-1 (source package)`;

  const result = parseDebsecanDetail(stdout);
  assertEquals(result.length, 2);
  assertEquals(result[0].package, "bsdextrautils");
  assertEquals(result[1].package, "bsdutils");
  assertEquals(result[1].installedVersion, "1:2.41.5-0+deb13u1");
});

Deno.test("parseDebsecanDetail - empty input yields empty array", () => {
  assertEquals(parseDebsecanDetail(""), []);
});
