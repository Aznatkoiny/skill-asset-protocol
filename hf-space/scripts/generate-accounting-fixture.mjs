import { createHash, randomUUID } from 'node:crypto';
import {
  mkdir,
  open,
  readFile,
  rename,
  unlink,
} from 'node:fs/promises';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';

import {
  allocateExternalGross,
  allocateInternalGross,
  formatUsdc,
} from '../../prototype/atomic-money.mjs';

const SCRIPT_DIRECTORY = dirname(fileURLToPath(import.meta.url));
const FIXTURE_PATH = join(SCRIPT_DIRECTORY, '..', 'shared', 'public-demo-allocation.json');

const SCENARIOS = Object.freeze([
  Object.freeze({
    id: 'intra-org',
    allocationKind: 'internal_invocation_award',
    status: 'terminal_product_spike',
    label: 'Intra-org — employer-funded internal Invocation award',
    policy: 'internal_award',
  }),
  Object.freeze({
    id: 'education',
    allocationKind: 'external_royalty_claim',
    status: 'deferred',
    label: 'Education — deferred after free re-authoring dominated the tested model',
    policy: 'LRP',
  }),
  Object.freeze({
    id: 'marketplace',
    allocationKind: 'external_royalty_claim',
    status: 'phase_3_optionality',
    label: 'Marketplace — Phase-3 optionality',
    policy: 'LRP',
  }),
]);
const COMMON_INPUT = Object.freeze({
  grossAtomic: 250000n,
  executionCostAtomic: 50000n,
  refundReserveAtomic: 0n,
});
const EXTERNAL_INPUT = Object.freeze({
  ...COMMON_INPUT,
  settlementCostAtomic: 0n,
  protocolFeeBps: 250,
});
const INTERNAL_INPUT = Object.freeze({
  ...COMMON_INPUT,
  protocolFeeAtomic: 6250n,
});
const EXTERNAL_SKILLS = Object.freeze({
  'derived-skill': Object.freeze({
    parentIds: Object.freeze(['source-skill']),
    inheritBps: 1500,
    holders: Object.freeze([Object.freeze({ recipientId: 'derived-creator', bps: 10000 })]),
  }),
  'source-skill': Object.freeze({
    parentIds: Object.freeze([]),
    inheritBps: 0,
    holders: Object.freeze([Object.freeze({ recipientId: 'source-creator', bps: 10000 })]),
  }),
});

function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function jsonSafe(value) {
  if (typeof value === 'bigint') return value.toString();
  if (Array.isArray(value)) return value.map(jsonSafe);
  if (value && typeof value === 'object') {
    const output = {};
    for (const [key, child] of Object.entries(value)) output[key] = jsonSafe(child);
    return output;
  }
  if (value === null || ['string', 'number', 'boolean'].includes(typeof value)) return value;
  throw new TypeError(`unsupported fixture value type: ${typeof value}`);
}

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.keys(value).sort().map((key) => [key, canonicalize(value[key])]),
    );
  }
  return value;
}

export function canonicalFixtureBytes(fixture) {
  return `${JSON.stringify(canonicalize(fixture), null, 2)}\n`;
}

function sameJournalEntry(candidate, actual) {
  if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) return false;
  const expectedKeys = ['amountAtomic', 'category', 'creditAccountId', 'debitAccountId'];
  const keys = Object.keys(candidate).sort();
  if (keys.length !== expectedKeys.length
      || keys.some((key, index) => key !== expectedKeys[index])) return false;
  return candidate.category === actual.category
    && candidate.debitAccountId === actual.debitAccountId
    && candidate.creditAccountId === actual.creditAccountId
    && candidate.amountAtomic === actual.amountAtomic;
}

export function serializeKernelAllocation(
  allocation,
  { expectedGrossDebitAccountId, journalEntries = allocation?.journalEntries } = {},
) {
  if (!allocation || typeof allocation !== 'object' || Array.isArray(allocation)) {
    throw new TypeError('kernel allocation must be an object');
  }
  if (!Array.isArray(allocation.journalEntries) || !Array.isArray(journalEntries)) {
    throw new TypeError('kernel allocation must contain journalEntries');
  }
  if (typeof expectedGrossDebitAccountId !== 'string' || !expectedGrossDebitAccountId) {
    throw new TypeError('expected gross debit account must be non-empty');
  }
  if (journalEntries.length !== allocation.journalEntries.length
      || journalEntries.some((entry, index) => (
        !sameJournalEntry(entry, allocation.journalEntries[index])
      ))) {
    throw new TypeError('supplied entries are not the kernel-returned journal');
  }
  const gross = allocation.grossAtomic;
  if (typeof gross !== 'bigint') throw new TypeError('kernel grossAtomic must be bigint');
  let total = 0n;
  for (const entry of journalEntries) {
    if (entry.debitAccountId !== expectedGrossDebitAccountId) {
      throw new TypeError('kernel journal has an unexpected gross-source debit account');
    }
    if (typeof entry.creditAccountId !== 'string' || !entry.creditAccountId
        || typeof entry.category !== 'string' || !entry.category
        || typeof entry.amountAtomic !== 'bigint' || entry.amountAtomic < 0n) {
      throw new TypeError('kernel journal entry is malformed');
    }
    total += entry.amountAtomic;
  }
  if (total !== gross) throw new TypeError('kernel journal does not conserve gross');
  return deepFreeze(jsonSafe(allocation));
}

function scenarioFromAllocation(definition, allocation, expectedGrossDebitAccountId) {
  const serialized = serializeKernelAllocation(allocation, { expectedGrossDebitAccountId });
  const isInternal = definition.allocationKind === 'internal_invocation_award';
  const topLevel = {
    id: definition.id,
    label: definition.label,
    status: definition.status,
    policy: definition.policy,
    allocationKind: definition.allocationKind,
    accountingLabel: 'generated from prototype/atomic-money.mjs; synthetic accounting illustration',
    implementationNote: isInternal
      ? 'Illustrative until the internal-award amendment becomes canonical.'
      : 'External Royalty-claim allocation generated by the shared accounting kernel.',
    settlementNote: 'Credited allocation shown; withdrawal and on-chain settlement are not implemented in this demo.',
    expectedGrossDebitAccountId,
    grossAtomic: serialized.grossAtomic,
    grossUsdc: formatUsdc(allocation.grossAtomic),
    executionCostAtomic: serialized.executionCostAtomic,
    executionCostUsdc: formatUsdc(allocation.executionCostAtomic),
    settlementCostAtomic: isInternal ? null : serialized.settlementCostAtomic,
    settlementCostUsdc: isInternal ? null : formatUsdc(allocation.settlementCostAtomic),
    protocolFeeAtomic: serialized.protocolFeeAtomic,
    protocolFeeUsdc: formatUsdc(allocation.protocolFeeAtomic),
    refundReserveAtomic: serialized.refundReserveAtomic,
    refundReserveUsdc: formatUsdc(allocation.refundReserveAtomic),
    royaltyPoolAtomic: isInternal ? null : serialized.royaltyPoolAtomic,
    royaltyPoolUsdc: isInternal ? null : formatUsdc(allocation.royaltyPoolAtomic),
    invocationAwardAtomic: isInternal ? serialized.invocationAwardAtomic : null,
    invocationAwardUsdc: isInternal ? formatUsdc(allocation.invocationAwardAtomic) : null,
    journalEntryDisplayUsdc: allocation.journalEntries.map((entry) => formatUsdc(entry.amountAtomic)),
    conservationEquation: isInternal
      ? 'grossAtomic = executionCostAtomic + protocolFeeAtomic + refundReserveAtomic + invocationAwardAtomic'
      : 'grossAtomic = executionCostAtomic + settlementCostAtomic + protocolFeeAtomic + refundReserveAtomic + royaltyPoolAtomic',
    allocation: serialized,
  };
  return deepFreeze(topLevel);
}

function externalAllocation() {
  return allocateExternalGross({
    ...EXTERNAL_INPUT,
    leafSkillId: 'derived-skill',
    skills: EXTERNAL_SKILLS,
  });
}

export function buildFixture() {
  const quotedExternal = externalAllocation();
  if (quotedExternal.protocolFeeAtomic !== 6250n) {
    throw new Error('shared kernel did not derive the expected protocol fee');
  }
  const internal = allocateInternalGross({
    ...INTERNAL_INPUT,
    protocolFeeAtomic: quotedExternal.protocolFeeAtomic,
    recipientId: 'employee-creator',
  });
  const education = externalAllocation();
  const marketplace = externalAllocation();
  for (const allocation of [education, marketplace]) {
    if (allocation.protocolFeeAtomic !== 6250n || allocation.royaltyPoolAtomic !== 193750n) {
      throw new Error('shared external kernel returned unexpected derived amounts');
    }
  }
  if (internal.invocationAwardAtomic !== 193750n) {
    throw new Error('shared internal kernel returned an unexpected Invocation award');
  }

  const withoutHash = {
    schemaVersion: 1,
    evidenceStatus: 'synthetic_accounting_illustration',
    generatedBy: 'hf-space/scripts/generate-accounting-fixture.mjs',
    corePath: 'prototype/atomic-money.mjs',
    defaultScenarioId: 'intra-org',
    inputs: jsonSafe({
      common: COMMON_INPUT,
      external: EXTERNAL_INPUT,
      internal: INTERNAL_INPUT,
      externalSkills: EXTERNAL_SKILLS,
    }),
    scenarios: [
      scenarioFromAllocation(SCENARIOS[0], internal, 'employer:invocation-gross'),
      scenarioFromAllocation(SCENARIOS[1], education, 'wielder:external-gross'),
      scenarioFromAllocation(SCENARIOS[2], marketplace, 'wielder:external-gross'),
    ],
  };
  const fixtureSha256 = `sha256:${createHash('sha256')
    .update(canonicalFixtureBytes(withoutHash))
    .digest('hex')}`;
  return deepFreeze({ ...withoutHash, fixtureSha256 });
}

async function writeFully(fileHandle, bytes) {
  let offset = 0;
  while (offset < bytes.length) {
    const { bytesWritten } = await fileHandle.write(bytes, offset, bytes.length - offset, offset);
    if (bytesWritten <= 0) throw new Error('short write while generating fixture');
    offset += bytesWritten;
  }
}

async function atomicWrite(path, bytes) {
  await mkdir(dirname(path), { recursive: true });
  const temporaryPath = `${path}.tmp-${process.pid}-${randomUUID()}`;
  let handle;
  try {
    handle = await open(temporaryPath, 'wx', 0o600);
    await writeFully(handle, bytes);
    await handle.sync();
    await handle.close();
    handle = undefined;
    await rename(temporaryPath, path);
  } catch (error) {
    if (handle) await handle.close().catch(() => {});
    await unlink(temporaryPath).catch(() => {});
    throw error;
  }
}

export async function main(argv = process.argv.slice(2)) {
  if (argv.length !== 1 || !['--write', '--check'].includes(argv[0])) {
    throw new TypeError('usage: generate-accounting-fixture.mjs --write|--check');
  }
  const expected = Buffer.from(canonicalFixtureBytes(buildFixture()), 'utf8');
  if (argv[0] === '--write') {
    await atomicWrite(FIXTURE_PATH, expected);
    return;
  }
  const actual = await readFile(FIXTURE_PATH).catch(() => null);
  if (!actual || !actual.equals(expected)) {
    throw new Error('public demo accounting fixture drift');
  }
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  main().catch((error) => {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  });
}
