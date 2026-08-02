#!/usr/bin/env node

import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import {
  buildEvidenceBundle,
  EvidenceError,
  verifyEvidenceBundle,
} from '../src/evidence-bundle.mjs';
import { canonicalJson, sha256 } from '../src/kernel/canonical.mjs';
import {
  runSpendControlProcessAcceptance,
  SPEND_CONTROL_PROCESS_CHILD_NAMES,
  SPEND_CONTROL_PROCESS_EXPECTED_EXIT_CODES,
  SPEND_CONTROL_PROCESS_INVARIANT_IDS,
} from './lib/spend-control-process-runner.mjs';

const PACKAGE_ROOT = path.resolve(import.meta.dirname, '..');
const REPOSITORY_ROOT = path.resolve(PACKAGE_ROOT, '../..');
const PI_EXECUTABLE = path.join(PACKAGE_ROOT, 'node_modules', '.bin', 'pi');
const BASE_SEPOLIA = 'eip155:84532';
const BASE_SEPOLIA_USDC = '0x036cbd53842c5426634e7929541ec2318f3dcf7e';
const RAW_HASH = /^[0-9a-f]{64}$/u;
const PREFIXED_HASH = /^sha256:[0-9a-f]{64}$/u;
const COMMIT = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u;

export class EvidenceRunnerError extends Error {
  constructor(code, message, options) {
    super(message, options);
    this.name = 'EvidenceRunnerError';
    this.code = code;
  }
}

function fail(code, message, cause) {
  throw new EvidenceRunnerError(code, message, cause ? { cause } : undefined);
}

function canonicalAbsolute(value, code, label) {
  if (typeof value !== 'string' || !path.isAbsolute(value)
      || path.resolve(value) !== value || value.includes('\0')) {
    fail(code, `${label} must be one canonical absolute path`);
  }
  return value;
}

function pathIsInside(candidate, parent) {
  const relative = path.relative(parent, candidate);
  return relative === ''
    || (relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative));
}

function entryExists(destination, code, label) {
  try {
    fs.lstatSync(destination);
    return true;
  } catch (cause) {
    if (cause?.code === 'ENOENT') return false;
    fail(code, `${label} could not be inspected`, cause);
  }
}

function validateAbsentDestination(value, pathCode, existsCode, label) {
  const destination = canonicalAbsolute(value, pathCode, label);
  const parent = path.dirname(destination);
  let realParent;
  try { realParent = fs.realpathSync(parent); } catch (cause) {
    fail(pathCode, `${label} parent must already exist`, cause);
  }
  let parentStat;
  try { parentStat = fs.lstatSync(parent); } catch (cause) {
    fail(pathCode, `${label} parent could not be inspected`, cause);
  }
  if (realParent !== parent || !parentStat.isDirectory() || parentStat.isSymbolicLink()) {
    fail(pathCode, `${label} parent must be one real directory`);
  }
  if (entryExists(destination, pathCode, label)) {
    fail(existsCode, `${label} must not already exist`);
  }
  return destination;
}

function validateOfflineDestinations(outputDirectory, anchorOutput) {
  const output = validateAbsentDestination(
    outputDirectory,
    'EVIDENCE_OUTPUT_PATH',
    'EVIDENCE_OUTPUT_EXISTS',
    'evidence output',
  );
  const anchor = validateAbsentDestination(
    anchorOutput,
    'EVIDENCE_ANCHOR_PATH',
    'EVIDENCE_ANCHOR_EXISTS',
    'external anchor output',
  );
  if (pathIsInside(anchor, output)) {
    fail('EVIDENCE_ANCHOR_PATH', 'external anchor must be outside the evidence bundle');
  }
  return Object.freeze({ outputDirectory: output, anchorOutput: anchor });
}

function fsyncDirectory(directory) {
  const descriptor = fs.openSync(
    directory,
    fs.constants.O_RDONLY | (fs.constants.O_DIRECTORY ?? 0) | (fs.constants.O_NOFOLLOW ?? 0),
  );
  try { fs.fsyncSync(descriptor); } finally { fs.closeSync(descriptor); }
}

function writeExternalAnchor(destination, manifestSha256) {
  if (typeof manifestSha256 !== 'string' || !RAW_HASH.test(manifestSha256)) {
    fail('EVIDENCE_ANCHOR_VALUE', 'external anchor must be one raw SHA-256 digest');
  }
  let descriptor;
  try {
    descriptor = fs.openSync(
      destination,
      fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL
        | (fs.constants.O_NOFOLLOW ?? 0),
      0o600,
    );
    const before = fs.fstatSync(descriptor, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n || (before.mode & 0o7777n) !== 0o600n
        || before.uid !== BigInt(process.getuid())) {
      fail('EVIDENCE_ANCHOR_AUTHORITY', 'external anchor file authority is invalid');
    }
    fs.writeFileSync(descriptor, `${manifestSha256}\n`, { encoding: 'utf8' });
    fs.fsyncSync(descriptor);
    const after = fs.fstatSync(descriptor, { bigint: true });
    const destinationStat = fs.lstatSync(destination, { bigint: true });
    if (destinationStat.isSymbolicLink() || after.dev !== before.dev || after.ino !== before.ino
        || destinationStat.dev !== before.dev || destinationStat.ino !== before.ino
        || after.nlink !== 1n || (after.mode & 0o7777n) !== 0o600n
        || after.size !== 65n) {
      fail('EVIDENCE_ANCHOR_AUTHORITY', 'external anchor changed while it was written');
    }
  } catch (cause) {
    if (cause instanceof EvidenceRunnerError) throw cause;
    if (cause?.code === 'EEXIST' || cause?.code === 'ELOOP') {
      fail('EVIDENCE_ANCHOR_EXISTS', 'external anchor output must not exist', cause);
    }
    fail('EVIDENCE_ANCHOR_WRITE', 'external anchor could not be written safely', cause);
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
  fsyncDirectory(path.dirname(destination));
}

function createAuthorityDirectory() {
  const directory = fs.realpathSync(
    fs.mkdtempSync(path.join(os.tmpdir(), 'pi-wielder-evidence-authority-')),
  );
  fs.chmodSync(directory, 0o700);
  return directory;
}

function readGitState() {
  let commit;
  let status;
  try {
    commit = execFileSync(
      'git',
      ['-C', REPOSITORY_ROOT, 'rev-parse', 'HEAD'],
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] },
    ).trim();
    status = execFileSync(
      'git',
      ['-C', REPOSITORY_ROOT, 'status', '--porcelain=v1', '--untracked-files=normal'],
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] },
    );
  } catch (cause) {
    fail('EVIDENCE_GIT_STATE', 'offline Git state could not be read', cause);
  }
  if (!COMMIT.test(commit)) fail('EVIDENCE_GIT_STATE', 'offline Git commit is invalid');
  return Object.freeze({ commit, dirty: status.length > 0 });
}

function validateAcceptanceOutput(result) {
  if (!result || typeof result !== 'object' || Array.isArray(result)
      || typeof result.cleanup !== 'function') {
    fail('EVIDENCE_ACCEPTANCE_RESULT', 'process acceptance did not return its public result');
  }
  const { summary, evidenceInput } = result;
  if (!summary || typeof summary !== 'object' || Array.isArray(summary)
      || summary.mode !== 'offline-deterministic'
      || summary.piVersion !== '0.80.6' || summary.x402Version !== 2
      || summary.network !== BASE_SEPOLIA || summary.isolation !== 'simulated'
      || summary.tests !== SPEND_CONTROL_PROCESS_INVARIANT_IDS.length
      || summary.passed !== SPEND_CONTROL_PROCESS_INVARIANT_IDS.length
      || summary.liveCdp !== 'not-run'
      || summary.testnetTransaction !== 'not-run') {
    fail('EVIDENCE_ACCEPTANCE_FAILED', 'offline process acceptance did not pass every gate');
  }
  if (!evidenceInput || typeof evidenceInput !== 'object' || Array.isArray(evidenceInput)
      || !Array.isArray(evidenceInput.acceptance?.invariants)
      || evidenceInput.acceptance.invariants.length !== summary.tests
      || evidenceInput.acceptance.invariants.some((item, index) => item?.passed !== true
        || item.id !== SPEND_CONTROL_PROCESS_INVARIANT_IDS[index]
        || !PREFIXED_HASH.test(item.evidenceHash ?? ''))
      || evidenceInput.freshVerification?.authorityEventChain !== true
      || evidenceInput.freshVerification?.projection !== true
      || evidenceInput.freshVerification?.receipts !== true
      || evidenceInput.privilegedReport !== null
      || !Array.isArray(evidenceInput.events) || evidenceInput.events.length < 1
      || !Array.isArray(evidenceInput.receiptPublicKeys)
      || evidenceInput.receiptPublicKeys.length < 1
      || evidenceInput.wallet?.provider !== 'deterministic'
      || !PREFIXED_HASH.test(evidenceInput.wallet?.walletIdHash ?? '')
      || !PREFIXED_HASH.test(evidenceInput.policyHash ?? '')
      || !PREFIXED_HASH.test(evidenceInput.routeMapHash ?? '')
      || !PREFIXED_HASH.test(evidenceInput.configHash ?? '')) {
    fail('EVIDENCE_ACCEPTANCE_RESULT', 'process acceptance evidence is incomplete or unverified');
  }
  const acceptance = evidenceInput.acceptance;
  const exits = acceptance.processExitCodes;
  if (!exits || typeof exits !== 'object' || Array.isArray(exits)
      || canonicalJson(Object.keys(exits).sort())
        !== canonicalJson([...SPEND_CONTROL_PROCESS_CHILD_NAMES].sort())
      || SPEND_CONTROL_PROCESS_CHILD_NAMES.some((name) => (
        exits[name] !== SPEND_CONTROL_PROCESS_EXPECTED_EXIT_CODES[name]
      ))) {
    fail('EVIDENCE_ACCEPTANCE_RESULT', 'process acceptance child exits did not match policy');
  }
  const rawSettlementIds = acceptance.rawSettlementTransactionIds;
  const normalizedTransactionIds = acceptance.transactionIds;
  if (!Array.isArray(rawSettlementIds) || rawSettlementIds.length === 0
      || !Array.isArray(normalizedTransactionIds)
      || rawSettlementIds.some((value) => typeof value !== 'string'
        || !/^0x[0-9a-f]{64}$/u.test(value))
      || normalizedTransactionIds.some((value) => typeof value !== 'string'
        || !/^0x[0-9a-f]{64}$/u.test(value))
      || new Set(rawSettlementIds).size !== rawSettlementIds.length
      || new Set(normalizedTransactionIds).size !== normalizedTransactionIds.length) {
    fail('EVIDENCE_ACCEPTANCE_RESULT', 'process acceptance transaction authority was reused');
  }
  const piApprovalResume = acceptance.piApprovalResume;
  if (!piApprovalResume || typeof piApprovalResume !== 'object'
      || Array.isArray(piApprovalResume)
      || ['tool', 'model'].some((kind) => {
        const entry = piApprovalResume[kind];
        const expected = {
          firstAttempt: {
            pendingObserved: true,
            exitedBeforeOperatorApproval: true,
            signerDelta: 0,
            paidRequestDelta: 0,
            outputObserved: kind === 'tool'
              ? 'PI_APPROVAL_REQUIRED'
              : 'approval-required-error',
            processExitCode: kind === 'tool' ? 0 : 1,
          },
          operatorApprovalStatus: 200,
          secondAttempt: {
            sameRequestFingerprint: true,
            signerDelta: 1,
            paidRequestDelta: 1,
            duplicatePaymentSignatureDelta: 0,
            outputObserved: 'PI_WALLET_OK',
            processExitCode: 0,
          },
        };
        return !entry || typeof entry !== 'object' || Array.isArray(entry)
          || canonicalJson(entry) !== canonicalJson(expected);
      })) {
    fail('EVIDENCE_ACCEPTANCE_RESULT', 'pinned Pi approval resumption was not proven');
  }
  const projections = evidenceInput.sessionProjections;
  const authorityReceipts = evidenceInput.authorityReceipts;
  if (!Array.isArray(projections) || projections.length === 0
      || !Array.isArray(authorityReceipts) || authorityReceipts.length === 0
      || projections.some((bundle) => !PREFIXED_HASH.test(bundle?.projectionHash ?? '')
        || !PREFIXED_HASH.test(bundle?.projection?.sessionHash ?? '')
        || bundle.projection.eventHeadHash !== projections[0]?.projection?.eventHeadHash
        || !Array.isArray(bundle.projection.signedReceipts))
      || projections.some((bundle, index) => index > 0
        && projections[index - 1].projection.sessionHash
          .localeCompare(bundle.projection.sessionHash) >= 0)) {
    fail('EVIDENCE_ACCEPTANCE_RESULT', 'process acceptance projections are incomplete');
  }
  const partition = projections.flatMap(({ projection }) => projection.signedReceipts);
  const receiptOrder = (left, right) => left.intentId.localeCompare(right.intentId)
    || left.revision - right.revision || left.id.localeCompare(right.id);
  const sortedPartition = [...partition].sort(receiptOrder);
  const sortedAuthorityReceipts = [...authorityReceipts].sort(receiptOrder);
  if (new Set(partition.map(({ receiptHash }) => receiptHash)).size !== partition.length
      || canonicalJson(sortedPartition) !== canonicalJson(sortedAuthorityReceipts)) {
    fail('EVIDENCE_ACCEPTANCE_RESULT', 'process acceptance receipt partition is incomplete');
  }
  const receiptEvents = evidenceInput.events.filter(({ eventType }) => (
    eventType === 'receipt.issued'
  ));
  const receiptByHash = new Map(authorityReceipts.map((receipt) => [receipt.receiptHash, receipt]));
  if (receiptEvents.length !== authorityReceipts.length
      || receiptEvents.some((event) => (
        receiptByHash.get(event.receiptHash)?.signature !== event.receiptSignature
      ))) {
    fail('EVIDENCE_ACCEPTANCE_RESULT', 'process acceptance receipt events are incomplete');
  }
  return Object.freeze({ summary, evidenceInput, cleanup: result.cleanup });
}

function signedProjectionSetHash(signedProjections) {
  return sha256(canonicalJson({
    schemaVersion: 1,
    domain: 'wallet-kernel.signed-projection-set.v1',
    signedProjections,
  }));
}

function identityHashes(identityBindings) {
  const kernel = identityBindings?.kernel;
  const agent = identityBindings?.agent;
  if (!kernel || !agent) {
    fail('EVIDENCE_ACCEPTANCE_RESULT', 'process acceptance omitted identity bindings');
  }
  return Object.freeze({
    kernelIdentityHash: sha256(canonicalJson({
      domain: 'wallet-kernel.kernel-identity.v1',
      kernelUid: kernel.uid,
      kernelGid: kernel.gid,
    })),
    agentIdentityHash: sha256(canonicalJson({
      domain: 'wallet-kernel.agent-identity.v1',
      agentUid: agent.uid,
      agentGid: agent.gid,
    })),
  });
}

function offlineManifestInput({ evidenceInput, summary, git, createdAt }) {
  const identities = identityHashes(evidenceInput.identityBindings);
  return {
    schemaVersion: 2,
    createdAt,
    mode: 'offline-deterministic',
    git,
    runtime: { nodeVersion: process.version, piVersion: summary.piVersion },
    protocol: {
      x402Version: summary.x402Version,
      network: summary.network,
      asset: BASE_SEPOLIA_USDC,
    },
    wallet: evidenceInput.wallet,
    isolation: {
      status: 'simulated',
      preflightDigest: null,
      ...identities,
    },
    deployment: {
      status: 'simulated',
      releaseManifestDigest: null,
      releaseTreeHash: null,
      serviceArtifactsHash: null,
      systemdEffectiveConfigHash: null,
    },
    inputs: {
      policyHash: evidenceInput.policyHash,
      routeMapHash: evidenceInput.routeMapHash,
      configHash: evidenceInput.configHash,
    },
    source: {
      authorityEventHeadHash: evidenceInput.sessionProjections[0].projection.eventHeadHash,
      signedProjectionHash: signedProjectionSetHash(evidenceInput.sessionProjections),
      receiptKeys: evidenceInput.receiptPublicKeys,
    },
    status: {
      liveCdp: 'not-run',
      walletFunded: 'not-run',
      testnetTransaction: 'not-run',
    },
    identityBindings: evidenceInput.identityBindings,
    privilegedReport: null,
    signedProjections: evidenceInput.sessionProjections,
  };
}

export function parseRunEvidenceArguments(argv) {
  if (!Array.isArray(argv) || argv.length < 2 || argv.length % 2 !== 0) {
    fail('EVIDENCE_RUN_ARGUMENTS', 'run-evidence requires explicit option/value pairs');
  }
  const options = {};
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    const value = argv[index + 1];
    if (!['--mode', '--output', '--anchor-output'].includes(name)
        || Object.hasOwn(options, name) || typeof value !== 'string' || value.length === 0) {
      fail('EVIDENCE_RUN_ARGUMENTS', 'run-evidence arguments are invalid or duplicated');
    }
    options[name] = value;
  }
  if (options['--mode'] === 'base-sepolia-testnet') {
    if (Object.keys(options).length !== 1) {
      fail('EVIDENCE_RUN_ARGUMENTS', 'testnet mode does not accept developer output paths');
    }
    return Object.freeze({ mode: 'base-sepolia-testnet' });
  }
  if (options['--mode'] !== 'offline-deterministic' || Object.keys(options).length !== 3
      || !options['--output'] || !options['--anchor-output']) {
    fail('EVIDENCE_RUN_ARGUMENTS', 'offline mode requires output and external anchor paths');
  }
  return Object.freeze({
    mode: 'offline-deterministic',
    outputDirectory: canonicalAbsolute(
      path.resolve(options['--output']),
      'EVIDENCE_RUN_ARGUMENTS',
      'evidence output',
    ),
    anchorOutput: canonicalAbsolute(
      path.resolve(options['--anchor-output']),
      'EVIDENCE_RUN_ARGUMENTS',
      'external anchor output',
    ),
  });
}

export async function runOfflineEvidence({ outputDirectory, anchorOutput }, dependencies = {}) {
  const destinations = validateOfflineDestinations(outputDirectory, anchorOutput);
  const runAcceptance = dependencies.runAcceptance ?? runSpendControlProcessAcceptance;
  const buildBundle = dependencies.buildBundle ?? buildEvidenceBundle;
  const verifyBundle = dependencies.verifyBundle ?? verifyEvidenceBundle;
  const gitState = dependencies.gitState ?? readGitState;
  const now = dependencies.now ?? (() => new Date().toISOString());
  const authorityDirectory = (dependencies.createAuthorityDirectory ?? createAuthorityDirectory)();
  const removeAuthorityDirectory = dependencies.removeAuthorityDirectory
    ?? ((directory) => fs.rmSync(directory, { recursive: true, force: true }));
  const piExecutable = dependencies.piExecutable ?? PI_EXECUTABLE;
  const nodeExecutable = dependencies.nodeExecutable ?? fs.realpathSync(process.execPath);
  let cleanup = async () => {};
  let primaryError = null;
  try {
    const raw = await runAcceptance({ authorityDirectory, piExecutable, nodeExecutable });
    if (typeof raw?.cleanup === 'function') cleanup = raw.cleanup;
    const accepted = validateAcceptanceOutput(raw);
    cleanup = accepted.cleanup;
    const built = buildBundle({
      outputDirectory: destinations.outputDirectory,
      manifestInput: offlineManifestInput({
        evidenceInput: accepted.evidenceInput,
        summary: accepted.summary,
        git: gitState(),
        createdAt: now(),
      }),
      events: accepted.evidenceInput.events,
      receipts: accepted.evidenceInput.authorityReceipts,
    });
    if (!built || typeof built.manifestSha256 !== 'string'
        || !RAW_HASH.test(built.manifestSha256)) {
      fail('EVIDENCE_BUILD_RESULT', 'evidence builder did not return an external anchor');
    }
    const verified = verifyBundle(destinations.outputDirectory, {
      expectedManifestSha256: built.manifestSha256,
    });
    if (verified?.valid !== true || verified.mode !== 'offline-deterministic'
        || verified.manifestSha256 !== built.manifestSha256) {
      fail('EVIDENCE_VERIFY_RESULT', 'fresh evidence verification did not match its anchor');
    }
    writeExternalAnchor(destinations.anchorOutput, built.manifestSha256);
    return verified;
  } catch (error) {
    primaryError = error;
    throw error;
  } finally {
    let finalizationError = null;
    try { await cleanup(); } catch (error) { finalizationError = error; }
    try { removeAuthorityDirectory(authorityDirectory); } catch (error) {
      if (finalizationError === null) finalizationError = error;
    }
    if (primaryError === null && finalizationError !== null) {
      fail('EVIDENCE_CLEANUP', 'temporary process authority could not be removed', finalizationError);
    }
  }
}

export async function runEvidence(options, dependencies = {}) {
  if (options?.mode === 'offline-deterministic') {
    return await runOfflineEvidence(options, dependencies);
  }
  if (options?.mode === 'base-sepolia-testnet') {
    // No live Kernel-side orchestration API is available in this slice. Staying
    // not-run here prevents credentials or a funded wallet from being mistaken
    // for authorization and prevents construction of any real adapter.
    fail(
      'EVIDENCE_TESTNET_NOT_RUN',
      'Base Sepolia evidence remains not-run until the privileged live runner is installed',
    );
  }
  fail('EVIDENCE_RUN_ARGUMENTS', 'evidence mode is invalid');
}

function publicError(error, mode = null) {
  const code = error instanceof EvidenceRunnerError || error instanceof EvidenceError
    || (typeof error?.code === 'string' && /^[A-Z][A-Z0-9_]{0,127}$/u.test(error.code))
    ? error.code
    : 'EVIDENCE_RUN_INTERNAL';
  return canonicalJson({
    code,
    mode: mode ?? 'unknown',
    status: 'not-run',
    valid: false,
  });
}

export async function main(argv = process.argv.slice(2)) {
  let options = null;
  try {
    options = parseRunEvidenceArguments(argv);
    process.stdout.write(`${canonicalJson(await runEvidence(options))}\n`);
    return 0;
  } catch (error) {
    process.stderr.write(`${publicError(error, options?.mode ?? null)}\n`);
    return error?.code === 'EVIDENCE_RUN_ARGUMENTS'
      || error?.code === 'EVIDENCE_TESTNET_NOT_RUN' ? 2 : 1;
  }
}

const invokedPath = process.argv[1] ? pathToFileURL(path.resolve(process.argv[1])).href : null;
if (invokedPath === import.meta.url) process.exitCode = await main();
