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
  securityOrigin: z.string().default("stable-security").describe(
    "Substring matched against the origin field in `Inst` lines to classify " +
      "an upgrade as security-relevant. Despite sources.list configuring the " +
      "suite as e.g. `trixie-security`, apt reports the archive's own " +
      "published Suite in Inst lines, which reads like " +
      "`Debian-Security:13/stable-security` — NOT the codename (verified " +
      "against real apt-get output on Debian 13). `stable-security` is the " +
      "durable substring: it doesn't change across codenames/releases as " +
      "long as the machine tracks the `stable` suite, unlike a codename-based " +
      "match which would never fire.",
  ),
  timeout: z.number().positive().default(120000).describe(
    "Timeout in milliseconds for apt/dpkg subprocess calls. Apt operations " +
      "over a slow link (e.g. a Pi on wifi) can be genuinely slow.",
  ),
  suite: z.string().default("trixie").describe(
    "Debian release codename passed to debsecan's --suite flag. Unlike " +
      "securityOrigin, this DOES need updating on release upgrade — debsecan " +
      "wants the codename (e.g. `trixie`), not `stable`.",
  ),
});

type GlobalArgs = z.infer<typeof GlobalArgsSchema>;

const InstallArgsSchema = z.object({
  package: z.string().describe("Package name to install."),
  version: z.string().optional().describe(
    "Exact version to install (e.g. `1:2.3.4-1`). If the package is already " +
      "at this version, no-ops. Otherwise, install only ever proceeds if " +
      "this package+version is a currently pending, apt-verified security " +
      "update (per the latest `upgradable` resource's isSecurity flag) — " +
      "if given, it must match that update's candidateVersion exactly. If " +
      "omitted, the version is inferred from that same pending security " +
      "update (or, if already installed and nothing is pending, no-ops).",
  ),
});

const RemoveArgsSchema = z.object({
  package: z.string().describe("Package name to remove."),
});

const InstalledPackageSchema = z.object({
  name: z.string().describe("Package name (dpkg ${Package})."),
  version: z.string().describe(
    "Installed version string, verbatim from dpkg. May contain an epoch " +
      "(e.g. `1:2.16.0-7`), tildes, and plus signs.",
  ),
  arch: z.string().describe(
    "Package architecture (dpkg ${Architecture}), e.g. arm64, all.",
  ),
});

const InstalledSchema = z.object({
  packages: z.array(InstalledPackageSchema).describe(
    "All packages currently in `install ok installed` state.",
  ),
  count: z.number().describe("Number of installed packages."),
  capturedAt: z.iso.datetime().describe(
    "ISO8601 timestamp when this snapshot was taken.",
  ),
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
  securityCount: z.number().describe(
    "Number of those packages classified as security-relevant.",
  ),
  capturedAt: z.iso.datetime().describe(
    "ISO8601 timestamp when this snapshot was taken.",
  ),
});

const VulnerabilitySchema = z.object({
  cve: z.string().describe("CVE identifier, e.g. `CVE-2025-58060`."),
  package: z.string().describe(
    "Installed binary package name debsecan reports as affected.",
  ),
  installedVersion: z.string().describe(
    "Installed version debsecan compared against.",
  ),
  fixedVersions: z.array(z.string()).describe(
    "Fix versions debsecan lists across Debian branches/releases for this CVE's source package.",
  ),
  fixAvailableInSuite: z.boolean().describe(
    "True when debsecan's own report says a fix is available for the configured `suite`.",
  ),
  actuallyFixed: z.boolean().describe(
    "True when `dpkg --compare-versions` shows installedVersion is already >= at least one " +
      "listed fixedVersion. Exists because debsecan's vulnerability database does not " +
      "understand vendor-rebuild version suffixes (e.g. Raspberry Pi OS's `+rptN`) — verified " +
      "on this machine, where every currently fix-available debsecan entry is actually already " +
      "patched per dpkg's own comparison. Only fixAvailableInSuite && !actuallyFixed is a real, " +
      "currently actionable vulnerability.",
  ),
});

const VulnerabilitiesSchema = z.object({
  vulnerabilities: z.array(VulnerabilitySchema).describe(
    "Known CVEs debsecan reports against currently installed packages.",
  ),
  count: z.number().describe("Total vulnerability/package entries reported."),
  actionableCount: z.number().describe(
    "fixAvailableInSuite && !actuallyFixed — real, currently-fixable vulnerabilities.",
  ),
  falsePositiveCount: z.number().describe(
    "fixAvailableInSuite && actuallyFixed — debsecan flagged these, but dpkg's own version " +
      "comparison shows they're already patched (see actuallyFixed).",
  ),
  capturedAt: z.iso.datetime().describe(
    "ISO8601 timestamp when this scan was taken.",
  ),
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
export function parseDpkgQuery(
  stdout: string,
): z.infer<typeof InstalledPackageSchema>[] {
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
    const candidateVersion = firstSpace === -1
      ? withoutArch
      : withoutArch.slice(0, firstSpace);
    const origin = firstSpace === -1
      ? ""
      : withoutArch.slice(firstSpace + 1).trim();

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

/**
 * Parses `debsecan --suite <suite> --format detail` output. Blocks are
 * separated by blank lines; each starts with a `CVE-...` header (optionally
 * suffixed ` (fixed)` — both forms appear regardless of `--only-fixed`, so
 * this doesn't require that flag), followed by an `installed: <pkg>
 * <version>` line and zero or more `fixed on branch:   <src> <version>`
 * lines. A trailing `fix is available for the selected suite (<suite>)`
 * line — present 1:1 with the ` (fixed)` header suffix, verified against
 * real output — is the fixAvailableInSuite signal.
 */
export function parseDebsecanDetail(
  stdout: string,
): Omit<z.infer<typeof VulnerabilitySchema>, "actuallyFixed">[] {
  const results: Omit<z.infer<typeof VulnerabilitySchema>, "actuallyFixed">[] =
    [];

  for (const block of stdout.split("\n\n")) {
    const cveMatch = /^(CVE-\S+)/.exec(block);
    const installedMatch = /^ {2}installed: (\S+) (\S+)/m.exec(block);
    if (!cveMatch || !installedMatch) continue;

    const [, cve] = cveMatch;
    const [, pkg, installedVersion] = installedMatch;

    const fixedVersions = [
      ...block.matchAll(/^ {2}fixed on branch:\s+\S+ (\S+)/gm),
    ]
      .map((m) => m[1]);
    const fixAvailableInSuite = /^ {2}fix is available for the selected suite/m
      .test(block);

    results.push({
      cve,
      package: pkg,
      installedVersion,
      fixedVersions,
      fixAvailableInSuite,
    });
  }

  return results;
}

type WriteResource = (
  specName: string,
  name: string,
  data: Record<string, unknown>,
) => Promise<{ name: string }>;

type Logger = { info: (msg: string, props?: Record<string, unknown>) => void };

/** Snapshots installed packages via dpkg-query and writes the `installed` resource. */
async function captureInstalled(
  timeoutMs: number,
  writeResource: WriteResource,
  logger?: Logger,
) {
  logger?.info("Snapshotting installed packages via dpkg-query");
  const { stdout, stderr, code } = await runCommand(
    "dpkg-query",
    ["-W", "-f=${Package}\t${Version}\t${Architecture}\t${Status}\n"],
    timeoutMs,
  );

  if (code !== 0) {
    throw new Error(`dpkg-query exited with code ${code}: ${stderr}`);
  }

  const packages = parseDpkgQuery(stdout);

  const handle = await writeResource("installed", "installed", {
    packages,
    count: packages.length,
    capturedAt: new Date().toISOString(),
  });
  logger?.info("Captured {count} installed packages", {
    count: packages.length,
  });
  return handle;
}

/**
 * Looks up a single package's installed version, or null if absent.
 * dpkg-query exits non-zero when a package is entirely unknown to dpkg —
 * that's an expected "not installed" outcome here, not a failure, so only
 * the parsed stdout is trusted, not the exit code.
 */
async function getInstalledVersion(
  pkg: string,
  timeoutMs: number,
): Promise<string | null> {
  const { stdout } = await runCommand(
    "dpkg-query",
    ["-W", "-f=${Package}\t${Version}\t${Architecture}\t${Status}\n", pkg],
    timeoutMs,
  );
  const packages = parseDpkgQuery(stdout);
  return packages.length > 0 ? packages[0].version : null;
}

export type InstallDecision =
  | { action: "noop" }
  | { action: "refuse"; reason: string }
  | { action: "install"; targetVersion: string };

/**
 * Pure decision logic for `install` — kept separate from `execute` so it's
 * directly unit-testable without mocking subprocesses. This is the actual
 * safety gate referenced throughout this file: given the package's current
 * installed version and its (if any) pending `upgradable` entry, decide
 * whether to no-op, refuse, or proceed, and with which target version.
 */
export function decideInstallAction(
  args: { package: string; version?: string },
  current: string | null,
  pendingEntry: z.infer<typeof UpgradablePackageSchema> | null,
): InstallDecision {
  const targetVersion = args.version ?? pendingEntry?.candidateVersion ?? null;

  // Already satisfied (or nothing verified is pending and we're not being
  // asked for a specific version) — a pure no-op never needs the checks
  // below, since nothing is being mutated.
  if (
    current !== null && (targetVersion === null || current === targetVersion)
  ) {
    return { action: "noop" };
  }

  // About to actually mutate the system — this is the safety gate. Sudoers
  // permits *any* package via the wrapper script; this check (mirrored,
  // tamper-resistantly, inside the wrapper itself) is what actually
  // restricts install to verified security updates.
  if (!pendingEntry || !pendingEntry.isSecurity) {
    return {
      action: "refuse",
      reason:
        `Refusing to install ${args.package}${
          args.version ? `=${args.version}` : ""
        }: not a currently pending security update per apt-local's own ` +
        `listUpgradable data. Run listUpgradable first, or use apt-get ` +
        `directly for non-security installs.`,
    };
  }
  if (args.version && args.version !== pendingEntry.candidateVersion) {
    return {
      action: "refuse",
      reason: `Requested version ${args.version} does not match the verified ` +
        `security update version ${pendingEntry.candidateVersion} for ${args.package}.`,
    };
  }

  return { action: "install", targetVersion: pendingEntry.candidateVersion };
}

/** True when `a` is dpkg-version-comparison >= `b`. */
async function versionAtLeast(
  a: string,
  b: string,
  timeoutMs: number,
): Promise<boolean> {
  const { code } = await runCommand(
    "dpkg",
    ["--compare-versions", a, "ge", b],
    timeoutMs,
  );
  return code === 0;
}

/** Model definition for observing APT package inventory and pending upgrades. */
export const model = {
  type: "@aaronge/apt-inventory",
  version: "2026.08.25.5",
  globalArguments: GlobalArgsSchema,
  reports: ["@aaronge/apt-inventory-delta"],
  resources: {
    "installed": {
      description: "Snapshot of installed packages, per `dpkg-query`.",
      schema: InstalledSchema,
      lifetime: "infinite" as const,
      garbageCollection: 30,
    },
    "upgradable": {
      description:
        "Packages apt would upgrade/install right now, per `apt-get -s -qq dist-upgrade`.",
      schema: UpgradableSchema,
      lifetime: "infinite" as const,
      garbageCollection: 100,
    },
    "vulnerabilities": {
      description:
        "Known CVEs against installed packages, per `debsecan`, cross-checked against dpkg's own version comparison to filter out vendor-rebuild false positives.",
      schema: VulnerabilitiesSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
  },
  methods: {
    query: {
      description:
        "Reads currently installed packages via dpkg-query (read-only, no privileges).",
      arguments: z.object({}),
      execute: async (
        _args: Record<string, never>,
        context: {
          globalArgs: GlobalArgs;
          writeResource: WriteResource;
          logger: Logger;
        },
      ) => {
        const handle = await captureInstalled(
          context.globalArgs.timeout,
          context.writeResource,
          context.logger,
        );
        return { dataHandles: [handle] };
      },
    },
    listUpgradable: {
      description:
        "Simulates a dist-upgrade via apt-get -s (no root, no system change) and classifies pending packages, including security relevance.",
      arguments: z.object({}),
      execute: async (
        _args: Record<string, never>,
        context: {
          globalArgs: GlobalArgs;
          writeResource: WriteResource;
          logger: Logger;
        },
      ) => {
        context.logger.info("Simulating dist-upgrade via apt-get -s");
        const { stdout, stderr, code } = await runCommand(
          "apt-get",
          ["-s", "-qq", "dist-upgrade"],
          context.globalArgs.timeout,
        );

        // A non-zero exit code must never write a resource — a silent
        // empty result here would look identical to "system fully
        // patched", which is exactly the wrong thing to be wrong about.
        if (code !== 0) {
          throw new Error(
            `apt-get -s -qq dist-upgrade exited with code ${code}: ${stderr}`,
          );
        }

        const packages = parseAptSimulation(
          stdout,
          context.globalArgs.securityOrigin,
        );
        const securityCount = packages.filter((p) => p.isSecurity).length;

        const handle = await context.writeResource("upgradable", "upgradable", {
          packages,
          count: packages.length,
          securityCount,
          capturedAt: new Date().toISOString(),
        });

        context.logger.info(
          "listUpgradable complete: {count} pending, {securityCount} security-relevant",
          { count: packages.length, securityCount },
        );
        return { dataHandles: [handle] };
      },
    },
    refresh: {
      description:
        "Refreshes apt's package lists via `sudo apt-get update -qq` (root required; apt lists only, no other system changes). Produces no resource — run listUpgradable/query afterward to see updated state.",
      arguments: z.object({}),
      execute: async (
        _args: Record<string, never>,
        context: { globalArgs: GlobalArgs; logger: Logger },
      ) => {
        context.logger.info(
          "Refreshing apt package lists (sudo apt-get update -qq)",
        );
        const { code, stderr } = await runCommand(
          "sudo",
          ["apt-get", "update", "-qq"],
          context.globalArgs.timeout,
        );

        if (code !== 0) {
          throw new Error(
            `sudo apt-get update -qq exited with code ${code}: ${stderr}`,
          );
        }

        context.logger.info("Package lists refreshed");
        return { dataHandles: [] };
      },
    },
    install: {
      description:
        "Installs a package via the root-owned `/usr/local/sbin/apt-security-install` " +
        "wrapper (sudoers grants this with no argument restriction). This method's own " +
        "check below is a fast first-pass for a friendly error message — the real, " +
        "tamper-resistant enforcement is inside the wrapper itself, which independently " +
        "re-verifies via a fresh live apt-get simulation (not any file this account can " +
        "write) that the package+version is a genuine pending security update, regardless " +
        "of what invokes it. Idempotent: no-ops if already satisfied. Produces a fresh " +
        "`installed` snapshot either way.",
      arguments: InstallArgsSchema,
      execute: async (
        args: z.infer<typeof InstallArgsSchema>,
        context: {
          globalArgs: GlobalArgs;
          writeResource: WriteResource;
          readResource: (
            instanceName: string,
            version?: number,
          ) => Promise<Record<string, unknown> | null>;
          logger: Logger;
        },
      ) => {
        context.logger.info("install requested for {package}", {
          package: args.package,
          version: args.version ?? "(unspecified)",
        });

        const current = await getInstalledVersion(
          args.package,
          context.globalArgs.timeout,
        );

        const upgradableData = await context.readResource("upgradable") as
          | z.infer<typeof UpgradableSchema>
          | null;
        const pendingEntry =
          upgradableData?.packages.find((p) => p.name === args.package) ?? null;

        const decision = decideInstallAction(args, current, pendingEntry);

        if (decision.action === "noop") {
          context.logger.info("install: {package} already satisfied, no-op", {
            package: args.package,
          });
          const handle = await captureInstalled(
            context.globalArgs.timeout,
            context.writeResource,
            context.logger,
          );
          return { dataHandles: [handle] };
        }

        if (decision.action === "refuse") {
          throw new Error(decision.reason);
        }

        context.logger.info(
          "install: {package} verified as a pending security update, installing {version}",
          { package: args.package, version: decision.targetVersion },
        );
        const { code, stderr } = await runCommand(
          "sudo",
          [
            "/usr/local/sbin/apt-security-install",
            args.package,
            decision.targetVersion,
          ],
          context.globalArgs.timeout,
        );

        if (code !== 0) {
          throw new Error(
            `apt-security-install ${args.package} ${decision.targetVersion} exited with ` +
              `code ${code}: ${stderr}`,
          );
        }

        context.logger.info("install: {package} installed successfully", {
          package: args.package,
        });
        const handle = await captureInstalled(
          context.globalArgs.timeout,
          context.writeResource,
          context.logger,
        );
        return { dataHandles: [handle] };
      },
    },
    remove: {
      description:
        "Removes a package via `sudo DEBIAN_FRONTEND=noninteractive apt-get remove -y -qq` (root required; sudoers grants this for any package — no analogous safety gate to install's, since there's no equivalent notion of a 'verified safe' removal). Idempotent: no-ops if already absent. Produces a fresh `installed` snapshot either way.",
      arguments: RemoveArgsSchema,
      execute: async (
        args: z.infer<typeof RemoveArgsSchema>,
        context: {
          globalArgs: GlobalArgs;
          writeResource: WriteResource;
          logger: Logger;
        },
      ) => {
        context.logger.info("remove requested for {package}", {
          package: args.package,
        });
        const current = await getInstalledVersion(
          args.package,
          context.globalArgs.timeout,
        );

        if (current === null) {
          context.logger.info("remove: {package} already absent, no-op", {
            package: args.package,
          });
        } else {
          const { code, stderr } = await runCommand(
            "sudo",
            [
              "DEBIAN_FRONTEND=noninteractive",
              "apt-get",
              "remove",
              "-y",
              "-qq",
              args.package,
            ],
            context.globalArgs.timeout,
          );

          if (code !== 0) {
            throw new Error(
              `apt-get remove ${args.package} exited with code ${code}: ${stderr}`,
            );
          }
          context.logger.info("remove: {package} removed successfully", {
            package: args.package,
          });
        }

        const handle = await captureInstalled(
          context.globalArgs.timeout,
          context.writeResource,
          context.logger,
        );
        return { dataHandles: [handle] };
      },
    },
    scanVulnerabilities: {
      description:
        "Runs debsecan against installed packages and cross-checks its fix-available claims against dpkg's own version comparison — debsecan's database doesn't understand vendor rebuild suffixes (e.g. Raspberry Pi OS's `+rptN`), which produces false positives (verified on this machine: every current fix-available entry is one). Read-only, no privileges (debsecan itself needs no root).",
      arguments: z.object({}),
      execute: async (
        _args: Record<string, never>,
        context: {
          globalArgs: GlobalArgs;
          writeResource: WriteResource;
          logger: Logger;
        },
      ) => {
        context.logger.info("Running debsecan --suite {suite}", {
          suite: context.globalArgs.suite,
        });
        const { stdout, stderr, code } = await runCommand(
          "debsecan",
          ["--suite", context.globalArgs.suite, "--format", "detail"],
          context.globalArgs.timeout,
        );

        if (code !== 0) {
          throw new Error(`debsecan exited with code ${code}: ${stderr}`);
        }

        const parsed = parseDebsecanDetail(stdout);

        const vulnerabilities: z.infer<typeof VulnerabilitySchema>[] = [];
        for (const entry of parsed) {
          let actuallyFixed = false;
          if (entry.fixAvailableInSuite) {
            for (const fixedVersion of entry.fixedVersions) {
              if (
                await versionAtLeast(
                  entry.installedVersion,
                  fixedVersion,
                  context.globalArgs.timeout,
                )
              ) {
                actuallyFixed = true;
                break;
              }
            }
          }
          vulnerabilities.push({ ...entry, actuallyFixed });
        }

        const actionableCount =
          vulnerabilities.filter((v) =>
            v.fixAvailableInSuite && !v.actuallyFixed
          ).length;
        const falsePositiveCount =
          vulnerabilities.filter((v) =>
            v.fixAvailableInSuite && v.actuallyFixed
          ).length;

        const handle = await context.writeResource(
          "vulnerabilities",
          "vulnerabilities",
          {
            vulnerabilities,
            count: vulnerabilities.length,
            actionableCount,
            falsePositiveCount,
            capturedAt: new Date().toISOString(),
          },
        );

        context.logger.info(
          "scanVulnerabilities complete: {count} entries, {actionableCount} actionable, {falsePositiveCount} false positives",
          {
            count: vulnerabilities.length,
            actionableCount,
            falsePositiveCount,
          },
        );
        return { dataHandles: [handle] };
      },
    },
  },
};
