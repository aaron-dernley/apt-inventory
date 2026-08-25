import { assertEquals, assertStringIncludes } from "jsr:@std/assert@1";
import { createReportTestContext } from "jsr:@swamp-club/swamp-testing@0.20260824.32";
import { report } from "./apt_delta.ts";

function artifact(
  modelType: string,
  modelId: string,
  name: string,
  version: number,
  attrs: Record<string, unknown>,
) {
  const content = new TextEncoder().encode(JSON.stringify(attrs));
  return {
    modelType,
    modelId,
    data: {
      name,
      kind: "resource" as const,
      dataId: `${name}-${version}`,
      version,
      size: content.length,
      contentType: "application/json",
    },
    content,
  };
}

Deno.test("apt-delta report - computes deltas when a previous version exists", async () => {
  const modelType = "@aaronge/apt-inventory";
  const modelId = "apt-local";

  const { context } = createReportTestContext({
    scope: "model",
    modelType,
    modelId,
    methodName: "listUpgradable",
    executionStatus: "succeeded",
    dataHandles: [],
    // The test-context mock resolves findByName's "latest" (no explicit
    // version) to the first array entry matching (type, modelId, name) —
    // unlike the real dataRepository, it does not sort by version. Seed the
    // intended "current" snapshot first per name so findByName resolves it;
    // getContent(..., explicit version) then correctly fetches "previous".
    dataArtifacts: [
      artifact(modelType, modelId, "upgradable", 2, { count: 5, securityCount: 3 }),
      artifact(modelType, modelId, "upgradable", 1, { count: 2, securityCount: 1 }),
      artifact(modelType, modelId, "installed", 2, { count: 1899 }),
      artifact(modelType, modelId, "installed", 1, { count: 1890 }),
    ],
  });

  const result = await report.execute(context as Parameters<typeof report.execute>[0]);

  assertEquals(result.json, {
    installedCount: 1899,
    installedDelta: 9,
    upgradableCount: 5,
    upgradableDelta: 3,
    securityCount: 3,
    securityDelta: 2,
    hasHistory: true,
  });
  assertStringIncludes(result.markdown, "Installed packages**: 1899 (+9 vs previous run)");
  assertStringIncludes(result.markdown, "Upgradable packages**: 5 (+3 vs previous run)");
  assertStringIncludes(result.markdown, "Security-relevant upgrades**: 3 (+2 vs previous run)");
});

Deno.test("apt-delta report - first run has no prior snapshot", async () => {
  const modelType = "@aaronge/apt-inventory";
  const modelId = "apt-local";

  const { context } = createReportTestContext({
    scope: "model",
    modelType,
    modelId,
    methodName: "listUpgradable",
    executionStatus: "succeeded",
    dataHandles: [],
    dataArtifacts: [
      artifact(modelType, modelId, "upgradable", 1, { count: 0, securityCount: 0 }),
      artifact(modelType, modelId, "installed", 1, { count: 1899 }),
    ],
  });

  const result = await report.execute(context as Parameters<typeof report.execute>[0]);

  assertEquals(result.json.hasHistory, false);
  assertEquals(result.json.upgradableDelta, 0);
  assertStringIncludes(result.markdown, "first run — no prior snapshot to compare against");
});

Deno.test("apt-delta report - zero deltas read as 'no change'", async () => {
  const modelType = "@aaronge/apt-inventory";
  const modelId = "apt-local";

  const { context } = createReportTestContext({
    scope: "model",
    modelType,
    modelId,
    methodName: "query",
    executionStatus: "succeeded",
    dataHandles: [],
    dataArtifacts: [
      artifact(modelType, modelId, "upgradable", 2, { count: 0, securityCount: 0 }),
      artifact(modelType, modelId, "upgradable", 1, { count: 0, securityCount: 0 }),
      artifact(modelType, modelId, "installed", 2, { count: 1899 }),
      artifact(modelType, modelId, "installed", 1, { count: 1899 }),
    ],
  });

  const result = await report.execute(context as Parameters<typeof report.execute>[0]);
  assertStringIncludes(result.markdown, "Installed packages**: 1899 (no change vs previous run)");
});
