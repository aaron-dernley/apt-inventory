import { assertEquals } from "jsr:@std/assert@1";
import { decideInstallAction } from "./apt.ts";

function pendingEntry(overrides: {
  name: string;
  currentVersion?: string | null;
  candidateVersion: string;
  origin?: string;
  isSecurity: boolean;
}) {
  return {
    currentVersion: null,
    origin: overrides.isSecurity
      ? "Debian-Security:13/stable-security"
      : "Debian:13/stable",
    ...overrides,
  };
}

Deno.test("decideInstallAction - no-op when already at the requested version", () => {
  const decision = decideInstallAction(
    { package: "foo", version: "1.2.3" },
    "1.2.3",
    null,
  );
  assertEquals(decision, { action: "noop" });
});

Deno.test("decideInstallAction - no-op when installed and nothing verified is pending (no version requested)", () => {
  const decision = decideInstallAction({ package: "bash" }, "5.2-6", null);
  assertEquals(decision, { action: "noop" });
});

Deno.test("decideInstallAction - no-op re-running install after the update was already applied", () => {
  // openssl was pending, got installed, and has since dropped out of
  // `upgradable` entirely (this is the real scenario hit during Phase 5
  // testing: re-running install must not turn "already done" into an error).
  const decision = decideInstallAction(
    { package: "openssl" },
    "3.5.7-1~deb13u2",
    null,
  );
  assertEquals(decision, { action: "noop" });
});

Deno.test("decideInstallAction - refuses a package with no pending update at all", () => {
  const decision = decideInstallAction({ package: "cowsay" }, null, null);
  assertEquals(decision.action, "refuse");
  if (decision.action === "refuse") {
    assertEquals(
      decision.reason.includes("not a currently pending security update"),
      true,
    );
  }
});

Deno.test("decideInstallAction - refuses a pending but non-security update", () => {
  const entry = pendingEntry({
    name: "foo",
    candidateVersion: "1.1",
    isSecurity: false,
  });
  const decision = decideInstallAction({ package: "foo" }, "1.0", entry);
  assertEquals(decision.action, "refuse");
  if (decision.action === "refuse") {
    assertEquals(
      decision.reason.includes("not a currently pending security update"),
      true,
    );
  }
});

Deno.test("decideInstallAction - refuses when requested version doesn't match the verified update", () => {
  const entry = pendingEntry({
    name: "foo",
    candidateVersion: "1.1",
    isSecurity: true,
  });
  const decision = decideInstallAction(
    { package: "foo", version: "9.9.9" },
    "1.0",
    entry,
  );
  assertEquals(decision.action, "refuse");
  if (decision.action === "refuse") {
    assertEquals(
      decision.reason.includes("does not match the verified security update"),
      true,
    );
  }
});

Deno.test("decideInstallAction - proceeds for a verified pending security update (version inferred)", () => {
  const entry = pendingEntry({
    name: "foo",
    candidateVersion: "1.1",
    isSecurity: true,
  });
  const decision = decideInstallAction({ package: "foo" }, "1.0", entry);
  assertEquals(decision, { action: "install", targetVersion: "1.1" });
});

Deno.test("decideInstallAction - proceeds for a verified pending security update (version explicit and matching)", () => {
  const entry = pendingEntry({
    name: "foo",
    candidateVersion: "1.1",
    isSecurity: true,
  });
  const decision = decideInstallAction(
    { package: "foo", version: "1.1" },
    "1.0",
    entry,
  );
  assertEquals(decision, { action: "install", targetVersion: "1.1" });
});

Deno.test("decideInstallAction - proceeds for a never-installed package pulled in as a fresh security dependency", () => {
  // currentVersion null on the upgradable entry means apt would pull this
  // in fresh (not upgrade an existing install) — install must still work
  // for that case, as long as it's a verified security-classified entry.
  const entry = pendingEntry({
    name: "new-dep",
    candidateVersion: "2.0",
    isSecurity: true,
  });
  const decision = decideInstallAction({ package: "new-dep" }, null, entry);
  assertEquals(decision, { action: "install", targetVersion: "2.0" });
});
