import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import test from "node:test";

import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";

import { loadLocalCheckoutMap, type AttestationConfigFileSystem } from "../src/attestation-config";
import {
  canonicalChallengeEventStatement,
  challengeEventStatementHash,
  reduceAttestationEvents,
  type ChallengeOpenedEvent,
  type RegistrationSubject,
} from "../src/attestations";
import { ExecGitReader } from "../src/attestation-git";
import { runCommand, type CommandDependencies } from "../src/index";
import { renderTopLevelError } from "../src/terminal";

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

const UNSAFE_TERMINAL = /[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u2028-\u202e\u2066-\u206f]/u;

async function rejected(operation: Promise<unknown>): Promise<unknown> {
  try {
    await operation;
  } catch (error) {
    return error;
  }
  assert.fail("expected operation to reject");
}

function assertSafeTopLevelError(error: unknown): string {
  const rendered = renderTopLevelError(error);
  assert.ok(rendered.startsWith('✗ "'));
  assert.ok(rendered.endsWith('"'));
  assert.doesNotMatch(rendered, UNSAFE_TERMINAL);
  assert.equal(rendered.split("\n").length, 1);
  return rendered;
}

test("terminal errors deterministically escape quotes, slashes, controls, bidi, and unpaired surrogates", () => {
  const message = "quote\" slash\\ c0\u0000 ansi\u001b c1\u0085\u009b bidi\u061c\u200e\u200f\u202a\u202e\u2066\u2069\u206f line\u2028\u2029 high\ud800 low\udfff";
  const rendered = assertSafeTopLevelError(new Error(message));
  for (const token of [
    '\\"', "\\\\", "\\u0000", "\\u001b", "\\u0085", "\\u009b", "\\u061c",
    "\\u200e", "\\u200f", "\\u2028", "\\u2029", "\\u202a", "\\u202e",
    "\\u2066", "\\u2069", "\\u206f", "\\ud800", "\\udfff",
  ]) assert.ok(rendered.includes(token), token);
});

test("top-level CLI stderr is one escaped line with no leading blank line", () => {
  const result = spawnSync(process.execPath, ["--import", "tsx", "src/index.ts", "check", "extra"], {
    cwd: new URL("..", import.meta.url),
    encoding: "utf8",
    env: { ...process.env, HTTP_PROXY: "", HTTPS_PROXY: "", ALL_PROXY: "" },
  });
  assert.notEqual(result.status, 0);
  assert.equal(result.stdout, "");
  assert.ok(result.stderr.startsWith('✗ "'));
  assert.ok(!result.stderr.startsWith("\n"));
  assert.equal(result.stderr.trimEnd().split("\n").length, 1);
});

test("real config-path, duplicate-event, and Git-stderr failures use safe top-level rendering", async () => {
  const hostilePath = "/outside/config-\"\\\n\u001b\u0085\u202e\ud800.json";
  const missing = Object.assign(new Error("missing"), { code: "ENOENT" });
  const fs: AttestationConfigFileSystem = {
    realpath: async (path) => path,
    openNoFollow: async () => { throw missing; },
    currentUid: () => 1,
  };
  const configError = await rejected(loadLocalCheckoutMap({
    env: { PHASE0_ATTESTATION_CHECKOUTS_FILE: hostilePath },
    phase0Root: "/phase0",
    referencedCheckoutKeys: [],
    fs,
  }));
  const renderedConfigError = assertSafeTopLevelError(configError);
  assert.ok(renderedConfigError.includes("repository snapshot mapping unavailable"));
  assert.ok(renderedConfigError.includes('\\"'));
  assert.ok(renderedConfigError.includes("\\\\"));
  assert.ok(renderedConfigError.includes("\\u001b"));
  assert.ok(renderedConfigError.includes("\\u0085"));
  assert.ok(renderedConfigError.includes("\\u202e"));
  assert.ok(renderedConfigError.includes("\\ud800"));

  const challenged = privateKeyToAccount(generatePrivateKey());
  const challenger = privateKeyToAccount(generatePrivateKey());
  const challengedIp = `0x${"a".repeat(40)}` as const;
  const challengerIp = `0x${"b".repeat(40)}` as const;
  const baseSubjects: RegistrationSubject[] = [
    {
      registrationId: `eip155:1315:${challengedIp}`,
      ipId: challengedIp,
      wallet: challenged.address.toLowerCase() as `0x${string}`,
      artifactHash: `0x${"1".repeat(64)}`,
      declaredParentIpIds: [],
    },
    {
      registrationId: `eip155:1315:${challengerIp}`,
      ipId: challengerIp,
      wallet: challenger.address.toLowerCase() as `0x${string}`,
      artifactHash: `0x${"2".repeat(64)}`,
      declaredParentIpIds: [],
    },
  ];
  const hostileEventId = "event-\"\\\n\u001b\u0085\u202e\ud800";
  const unsigned = {
    type: "challenge_opened" as const,
    eventId: hostileEventId,
    sequence: 1,
    occurredAt: "2026-07-18T12:00:00.000Z",
    conflictId: "conflict-duplicate-event",
    challengedRegistrationId: baseSubjects[0].registrationId,
    challengerRegistrationId: baseSubjects[1].registrationId,
    challengerWallet: baseSubjects[1].wallet,
    evidenceUris: ["https://example.com/evidence"],
    reason: "misattributed_creator" as const,
    statementHash: `0x${"0".repeat(64)}` as `0x${string}`,
    signature: "0x00" as `0x${string}`,
  };
  const statementHash = challengeEventStatementHash(unsigned);
  const event: ChallengeOpenedEvent = {
    ...unsigned,
    statementHash,
    signature: await challenger.signMessage({
      message: canonicalChallengeEventStatement({ ...unsigned, statementHash }),
    }),
  };
  const duplicateError = await rejected(reduceAttestationEvents([
    event,
    { ...event, sequence: 2 },
  ], { baseSubjects }));
  const renderedDuplicateError = assertSafeTopLevelError(duplicateError);
  assert.ok(renderedDuplicateError.includes("duplicate attestation event ID"));
  assert.ok(renderedDuplicateError.includes("\\u001b"));
  assert.ok(renderedDuplicateError.includes("\\u0085"));
  assert.ok(renderedDuplicateError.includes("\\u202e"));
  assert.ok(renderedDuplicateError.includes("\\ud800"));

  const gitPath = "/definitely/missing-\"\\\n\u001b\u0085\u202e";
  const gitError = await rejected(new ExecGitReader().remoteUrl(gitPath, "origin"));
  const renderedGitError = assertSafeTopLevelError(gitError);
  assert.ok(renderedGitError.includes("offline Git verification failed"));
  assert.ok(renderedGitError.includes("\\u000a"));
  assert.ok(renderedGitError.includes('\\"'));
  assert.ok(renderedGitError.includes("\\\\"));
});
