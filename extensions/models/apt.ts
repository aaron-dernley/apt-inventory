/**
 * Observes APT package state on a Debian/apt-based Linux host and produces
 * versioned, queryable data about what is installed and what is pending.
 *
 * Scope: Debian and Debian-derivative systems only (relies on `dpkg-query`
 * and `apt-get`). Developed and verified against Debian 13 "trixie" on
 * arm64 (Raspberry Pi 5). Will not work on non-apt distros (RHEL/Fedora,
 * Arch, Alpine), nor on macOS/Windows.
 *
 * This model observes and reports. It deliberately does not replace
 * `unattended-upgrades` — Debian's own tooling remains responsible for
 * actually applying security updates.
 *
 * @module
 */
// extensions/models/apt.ts
import { z } from "npm:zod@4";

const GlobalArgsSchema = z.object({
  securityOrigin: z.string().default("trixie-security").describe(
    "Substring matched against the origin field in `Inst` lines to classify " +
      "an upgrade as security-relevant. Configurable because the codename " +
      "changes on release upgrade (e.g. trixie -> forky).",
  ),
  timeout: z.number().positive().default(120000).describe(
    "Timeout in milliseconds for apt/dpkg subprocess calls. Apt operations " +
      "over a slow link (e.g. a Pi on wifi) can be genuinely slow.",
  ),
});

type GlobalArgs = z.infer<typeof GlobalArgsSchema>;

const InstalledPackageSchema = z.object({
  name: z.string().describe("Package name (dpkg ${Package})."),
  version: z.string().describe(
    "Installed version string, verbatim from dpkg. May contain an epoch " +
      "(e.g. `1:2.16.0-7`), tildes, and plus signs.",
  ),
  arch: z.string().describe("Package architecture (dpkg ${Architecture}), e.g. arm64, all."),
});

const InstalledSchema = z.object({
  packages: z.array(InstalledPackageSchema).describe(
    "All packages currently in `install ok installed` state.",
  ),
  count: z.number().describe("Number of installed packages."),
  capturedAt: z.iso.datetime().describe("ISO8601 timestamp when this snapshot was taken."),
});

const UpgradablePackageSchema = z.object({
  name: z.string().describe("Package name."),
  currentVersion: z.string().nullable().describe(
    "Currently installed version, or null if this package has no current " +
      "version (i.e. it is a new dependency being pulled in, not an upgrade " +
      "of an already-installed package).",
  ),
  candidateVersion: z.string().describe("Version apt would install."),
  origin: z.string().describe(
    "Origin/archive string apt reports for the candidate, e.g. " +
      "`Debian-Security:13/stable-security`.",
  ),
  isSecurity: z.boolean().describe(
    "True when `origin` contains the model's configured `securityOrigin` substring.",
  ),
});

const UpgradableSchema = z.object({
  packages: z.array(UpgradablePackageSchema).describe(
    "Packages apt would install/upgrade in a dist-upgrade, parsed from `Inst` lines.",
  ),
  count: z.number().describe("Total number of upgradable/pending packages."),
  securityCount: z.number().describe("Number of those packages classified as security-relevant."),
  capturedAt: z.iso.datetime().describe("ISO8601 timestamp when this snapshot was taken."),
});

/** Runs a subprocess, capturing stdout/stderr separately, honoring `timeout`. */
async function runCommand(
  cmd: string,
  args: string[],
  timeoutMs: number,
): Promise<{ stdout: string; stderr: string; code: number }> {
  const command = new Deno.Command(cmd, {
    args,
    stdout: "piped",
    stderr: "piped",
  });
  const child = command.spawn();

  const timeout = setTimeout(() => {
    try {
      child.kill();
    } catch {
      // already exited
    }
  }, timeoutMs);

  try {
    const output = await child.output();
    return {
      stdout: new TextDecoder().decode(output.stdout),
      stderr: new TextDecoder().decode(output.stderr),
      code: output.code,
    };
  } finally {
    clearTimeout(timeout);
  }
}

/** Parses `dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${Status}\n'` output. */
export function parseDpkgQuery(stdout: string): z.infer<typeof InstalledPackageSchema>[] {
  const packages: z.infer<typeof InstalledPackageSchema>[] = [];
  for (const line of stdout.split("\n")) {
    if (line.length === 0) continue;
    // Tab-split, not regex over the whole line — versions contain colons
    // (epochs), tildes, and plus signs.
    const parts = line.split("\t");
    if (parts.length < 4) continue;
    const [name, version, arch, status] = parts;
    if (status !== "install ok installed") continue;
    packages.push({ name, version, arch });
  }
  return packages;
}

/**
 * Parses `apt-get -s -qq dist-upgrade` output. Only lines starting with
 * `Inst ` are meaningful; everything else (the simulation NOTE banner,
 * `Conf`/`Remv` lines, blank lines) is ignored. The NOTE banner is emitted
 * on stdout (verified against real output), so filtering must happen by
 * line prefix rather than by discarding a stream.
 *
 * Line shape: `Inst <package> [<current-version>] (<candidate-version> <origin>) [extras]`
 * A package with no `[current-version]` bracket is a new dependency pulled
 * in, not an upgrade of something already installed.
 */
export function parseAptSimulation(
  stdout: string,
  securityOrigin: string,
): z.infer<typeof UpgradablePackageSchema>[] {
  const results: z.infer<typeof UpgradablePackageSchema>[] = [];
  const instLineRe = /^Inst (\S+) (?:\[([^\]]+)\] )?\(([^)]+)\)/;

  for (const line of stdout.split("\n")) {
    if (!line.startsWith("Inst ")) continue;
    const match = instLineRe.exec(line);
    if (!match) continue;

    const [, name, currentVersion, parenContents] = match;
    // parenContents is like "3.03+dfsg2-8 Debian:13.6/stable [all]" —
    // candidate version is the first token, origin is everything up to an
    // optional trailing "[arch]" bracket.
    const archBracketMatch = /^(.*?)\s*\[[^\]]*\]$/.exec(parenContents);
    const withoutArch = archBracketMatch ? archBracketMatch[1] : parenContents;
    const firstSpace = withoutArch.indexOf(" ");
    const candidateVersion = firstSpace === -1 ? withoutArch : withoutArch.slice(0, firstSpace);
    const origin = firstSpace === -1 ? "" : withoutArch.slice(firstSpace + 1).trim();

    results.push({
      name,
      currentVersion: currentVersion ?? null,
      candidateVersion,
      origin,
      isSecurity: origin.includes(securityOrigin),
    });
  }

  return results;
}

/** Model definition for observing APT package inventory and pending upgrades. */
export const model = {
  type: "@aaronge/apt-inventory",
  version: "2026.08.25.1",
  globalArguments: GlobalArgsSchema,
  resources: {
    "installed": {
      description: "Snapshot of installed packages, per `dpkg-query`.",
      schema: InstalledSchema,
      lifetime: "infinite" as const,
      garbageCollection: 30,
    },
    "upgradable": {
      description: "Packages apt would upgrade/install right now, per `apt-get -s -qq dist-upgrade`.",
      schema: UpgradableSchema,
      lifetime: "infinite" as const,
      garbageCollection: 100,
    },
  },
  methods: {
    query: {
      description: "Reads currently installed packages via dpkg-query (read-only, no privileges).",
      arguments: z.object({}),
      execute: async (
        _args: Record<string, never>,
        context: {
          globalArgs: GlobalArgs;
          writeResource: (
            specName: string,
            name: string,
            data: Record<string, unknown>,
          ) => Promise<{ name: string }>;
        },
      ) => {
        const { stdout, code } = await runCommand(
          "dpkg-query",
          ["-W", "-f=${Package}\t${Version}\t${Architecture}\t${Status}\n"],
          context.globalArgs.timeout,
        );

        if (code !== 0) {
          throw new Error(`dpkg-query exited with code ${code}`);
        }

        const packages = parseDpkgQuery(stdout);

        const handle = await context.writeResource("installed", "installed", {
          packages,
          count: packages.length,
          capturedAt: new Date().toISOString(),
        });

        return { dataHandles: [handle] };
      },
    },
    listUpgradable: {
      description: "Simulates a dist-upgrade via apt-get -s (no root, no system change) and classifies pending packages, including security relevance.",
      arguments: z.object({}),
      execute: async (
        _args: Record<string, never>,
        context: {
          globalArgs: GlobalArgs;
          writeResource: (
            specName: string,
            name: string,
            data: Record<string, unknown>,
          ) => Promise<{ name: string }>;
        },
      ) => {
        const { stdout, code } = await runCommand(
          "apt-get",
          ["-s", "-qq", "dist-upgrade"],
          context.globalArgs.timeout,
        );

        // A non-zero exit code must never write a resource — a silent
        // empty result here would look identical to "system fully
        // patched", which is exactly the wrong thing to be wrong about.
        if (code !== 0) {
          throw new Error(`apt-get -s -qq dist-upgrade exited with code ${code}`);
        }

        const packages = parseAptSimulation(stdout, context.globalArgs.securityOrigin);
        const securityCount = packages.filter((p) => p.isSecurity).length;

        const handle = await context.writeResource("upgradable", "upgradable", {
          packages,
          count: packages.length,
          securityCount,
          capturedAt: new Date().toISOString(),
        });

        return { dataHandles: [handle] };
      },
    },
  },
};
