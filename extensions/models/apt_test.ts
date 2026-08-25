import { assertEquals } from "jsr:@std/assert@1";
import { parseAptSimulation, parseDpkgQuery } from "./apt.ts";

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
