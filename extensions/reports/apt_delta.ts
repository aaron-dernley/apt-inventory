/**
 * Summarizes @aaronge/apt-inventory package/upgrade counts and the delta
 * since the previous snapshot of each resource.
 *
 * Model-scope: fires after query and after listUpgradable. Each firing reads
 * the freshest available "installed" and "upgradable" data at that moment via
 * dataRepository, so whichever of the two methods finishes last in a given
 * workflow run produces the fully up-to-date report (apt-get's dist-upgrade
 * simulation is the slower of the two, so in practice it fires last).
 *
 * @module
 */
// extensions/reports/apt_delta.ts

interface DataMetadata {
  version: number;
}

interface DataRepository {
  findByName: (
    type: string,
    modelId: string,
    dataName: string,
    version?: number,
  ) => Promise<DataMetadata | null>;
  getContent: (
    type: string,
    modelId: string,
    dataName: string,
    version?: number,
  ) => Promise<Uint8Array | null>;
}

interface Snapshot {
  count: number;
  securityCount?: number;
}

async function latestTwoVersions(
  dataRepository: DataRepository,
  modelType: string,
  modelId: string,
  dataName: string,
): Promise<{ current: Snapshot | null; previous: Snapshot | null }> {
  const currentMeta = await dataRepository.findByName(modelType, modelId, dataName);
  if (!currentMeta) return { current: null, previous: null };

  const readVersion = async (version: number) => {
    const raw = await dataRepository.getContent(modelType, modelId, dataName, version);
    if (!raw) return null;
    return JSON.parse(new TextDecoder().decode(raw)) as Snapshot;
  };

  const current = await readVersion(currentMeta.version);
  const previous = currentMeta.version > 1 ? await readVersion(currentMeta.version - 1) : null;

  return { current, previous };
}

function formatDelta(delta: number): string {
  if (delta === 0) return "no change";
  return delta > 0 ? `+${delta}` : `${delta}`;
}

/** Report definition summarizing apt-inventory counts and run-over-run deltas. */
export const report = {
  name: "@aaronge/apt-inventory-delta",
  description:
    "Total upgradable, security-relevant, and installed package counts, with the delta since the previous run.",
  scope: "model",
  labels: ["apt", "inventory"],
  execute: async (
    context: {
      modelType: string;
      modelId: string;
      dataRepository: DataRepository;
    },
  ) => {
    const upgradable = await latestTwoVersions(
      context.dataRepository,
      context.modelType,
      context.modelId,
      "upgradable",
    );
    const installed = await latestTwoVersions(
      context.dataRepository,
      context.modelType,
      context.modelId,
      "installed",
    );

    if (!upgradable.current || !installed.current) {
      return { markdown: "No apt-inventory data yet.", json: {} };
    }

    const installedDelta = installed.current.count - (installed.previous?.count ?? installed.current.count);
    const upgradableDelta = upgradable.current.count - (upgradable.previous?.count ?? upgradable.current.count);
    const securityDelta = (upgradable.current.securityCount ?? 0) -
      (upgradable.previous?.securityCount ?? upgradable.current.securityCount ?? 0);

    const hasHistory = upgradable.previous !== null;

    const markdown = [
      "# apt-inventory report",
      "",
      `- **Installed packages**: ${installed.current.count} (${formatDelta(installedDelta)} vs previous run)`,
      `- **Upgradable packages**: ${upgradable.current.count} (${formatDelta(upgradableDelta)} vs previous run)`,
      `- **Security-relevant upgrades**: ${upgradable.current.securityCount ?? 0} (${
        formatDelta(securityDelta)
      } vs previous run)`,
      ...(hasHistory ? [] : ["", "_(first run — no prior snapshot to compare against)_"]),
    ].join("\n");

    return {
      markdown,
      json: {
        installedCount: installed.current.count,
        installedDelta,
        upgradableCount: upgradable.current.count,
        upgradableDelta,
        securityCount: upgradable.current.securityCount ?? 0,
        securityDelta,
        hasHistory,
      },
    };
  },
};
