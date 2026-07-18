import assert from "node:assert/strict";
import test from "node:test";

import { runCommand, type CommandDependencies } from "../src/index";

const LEASE_ID = "0123456789abcdef0123456789abcdef";

function dependencies() {
  const calls = { check: 0, demo: 0, recover: [] as string[] };
  const lines: string[] = [];
  const deps: CommandDependencies = {
    check: async () => { calls.check += 1; },
    demo: async () => { calls.demo += 1; },
    recoverStaleLock: async (expectedLeaseId) => { calls.recover.push(expectedLeaseId); },
    log: (line = "") => { lines.push(line); },
  };
  return { calls, lines, deps };
}

test("stale-lock recovery routes exactly one unchanged lease ID and nothing else", async () => {
  const fixture = dependencies();
  const exitCode = await runCommand(["recover-stale-lock", LEASE_ID], fixture.deps);
  assert.equal(exitCode, 0);
  assert.deepEqual(fixture.calls, { check: 0, demo: 0, recover: [LEASE_ID] });
  assert.match(fixture.lines.join("\n"), new RegExp(LEASE_ID));
});

for (const args of [
  ["recover-stale-lock"],
  ["recover-stale-lock", "not-a-lease-id"],
  ["recover-stale-lock", LEASE_ID.toUpperCase()],
  ["recover-stale-lock", LEASE_ID, "extra"],
] as const) {
  test(`recovery rejects invalid arity: ${args.join(" ")}`, async () => {
    const fixture = dependencies();
    await assert.rejects(runCommand([...args], fixture.deps), /npm run recover-stale-lock -- <expectedLeaseId>/);
    assert.deepEqual(fixture.calls, { check: 0, demo: 0, recover: [] });
  });
}

test("help exposes chain commands and read-only attestation surfaces", async () => {
  const fixture = dependencies();
  assert.equal(await runCommand([], fixture.deps), 0);
  const output = fixture.lines.join("\n");
  assert.match(output, /npm run demo/);
  assert.match(output, /npm run check/);
  assert.match(output, /npm run recover-stale-lock/);
  assert.match(output, /npm run attestation-status/);
  assert.match(output, /npm run attestation-verify-repository/);
  assert.doesNotMatch(output, /create-collection|register-skill|register-derivative/);
});

test("attestation commands receive parsed machine-readable options without Story construction", async () => {
  const fixture = dependencies();
  const calls: unknown[] = [];
  fixture.deps.attestation = async (command, options) => { calls.push({ command, options }); };
  assert.equal(await runCommand(["attestation-status"], fixture.deps, {
    artifactHash: `0x${"0".repeat(64)}`,
    json: true,
  }), 0);
  assert.deepEqual(calls, [{
    command: "attestation-status",
    options: { artifactHash: `0x${"0".repeat(64)}`, json: true },
  }]);
  assert.deepEqual(fixture.calls, { check: 0, demo: 0, recover: [] });
});

for (const retired of ["create-collection", "register-skill", "register-derivative"] as const) {
  test(`retired ${retired} route stays rejected`, async () => {
    const fixture = dependencies();
    assert.equal(await runCommand([retired], fixture.deps), 1);
    assert.deepEqual(fixture.calls, { check: 0, demo: 0, recover: [] });
  });
}
