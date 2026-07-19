import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { assertExecutionQuote } from './execution-economics.mjs';

const TERMINAL_EXECUTION = new Set(['succeeded', 'failed', 'cancelled']);
const CHECKOUT_ROOT = fs.realpathSync(fileURLToPath(new URL('../../../', import.meta.url)));
const LEASE_ID = /^[0-9a-f]{32}$/;
const waitCell = new Int32Array(new SharedArrayBuffer(4));
const NOFOLLOW = fs.constants.O_NOFOLLOW ?? 0;

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalize(value[key])]));
  }
  return value;
}

export const canonicalJson = (value) => JSON.stringify(canonicalize(value));
const same = (left, right) => canonicalJson(left) === canonicalJson(right);
const copy = (value) => structuredClone(value);

function requireText(value, label) {
  const text = String(value ?? '').trim();
  if (!text) throw new Error(`${label} must be non-empty`);
  return text;
}

function requireAtomicString(value, label) {
  if (typeof value !== 'string') throw new Error(`${label} must be a string`);
  const text = requireText(value, label);
  if (!/^(0|[1-9]\d*)$/.test(text)) {
    throw new Error(`${label} must be a canonical non-negative atomic string`);
  }
  return text;
}

function canonicalHex(value, bytes, label) {
  const text = requireText(value, label);
  if (!new RegExp(`^0x[0-9a-fA-F]{${bytes * 2}}$`).test(text)) {
    throw new Error(`${label} must be a ${bytes}-byte hex identifier`);
  }
  return text.toLowerCase();
}

const canonicalAddress = (value, label) => canonicalHex(value, 20, label);
const canonicalBytes32 = (value, label) => canonicalHex(value, 32, label);

function exactKeys(value, expected, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  if (!same(Object.keys(value).sort(), [...expected].sort())) {
    throw new Error(`${label} has unexpected fields`);
  }
}

function safePersistentPath(input, label) {
  if (!path.isAbsolute(input ?? '')) throw new Error(`${label} must be an explicit absolute path`);
  const lexical = path.resolve(input);
  const lexicalParent = path.dirname(lexical);
  const realParent = fs.realpathSync(lexicalParent);
  if (realParent !== lexicalParent) throw new Error(`${label} must not traverse a symlinked directory`);
  const candidate = path.join(realParent, path.basename(lexical));
  const relative = path.relative(CHECKOUT_ROOT, candidate);
  if (relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative))) {
    throw new Error(`${label} must be outside the repository checkout`);
  }
  if (fs.existsSync(candidate)) {
    const stat = fs.lstatSync(candidate);
    if (stat.isSymbolicLink() || !stat.isFile()) {
      throw new Error(`${label} must be a regular non-symlink file`);
    }
    if ((stat.mode & 0o777) !== 0o600) throw new Error(`${label} permissions must be exactly 0600`);
    if (fs.realpathSync(candidate) !== candidate) throw new Error(`${label} must be canonical`);
  }
  return candidate;
}

function fsyncDirectory(directory) {
  const descriptor = fs.openSync(directory, 'r');
  try { fs.fsyncSync(descriptor); } finally { fs.closeSync(descriptor); }
}

function writeAll(descriptor, bytes) {
  let offset = 0;
  while (offset < bytes.byteLength) {
    const written = fs.writeSync(descriptor, bytes, offset, bytes.byteLength - offset, null);
    if (!Number.isSafeInteger(written) || written <= 0) throw new Error('journal write made no progress');
    offset += written;
  }
}

function readPrivateFile(filePath, label) {
  const descriptor = fs.openSync(filePath, fs.constants.O_RDONLY | NOFOLLOW);
  try {
    const stat = fs.fstatSync(descriptor);
    if (!stat.isFile() || (stat.mode & 0o777) !== 0o600) {
      throw new Error(`${label} must be a regular file with mode exactly 0600`);
    }
    return fs.readFileSync(descriptor, 'utf8');
  } finally {
    fs.closeSync(descriptor);
  }
}

function validateLeaseOwner(value) {
  exactKeys(value, ['leaseId', 'hostname', 'pid', 'startedAtUtc'], 'journal lock owner');
  if (!LEASE_ID.test(value.leaseId)) throw new Error('journal lock owner lease ID is malformed');
  requireText(value.hostname, 'journal lock owner hostname');
  if (!Number.isSafeInteger(value.pid) || value.pid <= 0) throw new Error('journal lock owner PID is malformed');
  if (!Number.isFinite(Date.parse(value.startedAtUtc))
      || new Date(value.startedAtUtc).toISOString() !== value.startedAtUtc) {
    throw new Error('journal lock owner start time is malformed');
  }
}

function readLeaseOwner(lockPath) {
  let bytes;
  try {
    bytes = readPrivateFile(lockPath, 'journal lock');
  } catch (error) {
    if (error.code === 'ENOENT') throw new Error('journal lock does not exist', { cause: error });
    throw error;
  }
  if (!bytes.endsWith('\n')) throw new Error('journal lock owner must end with one newline');
  let owner;
  try { owner = JSON.parse(bytes); } catch (error) {
    throw new Error('journal lock owner is malformed', { cause: error });
  }
  validateLeaseOwner(owner);
  return { owner, bytes };
}

function processIsAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    if (error.code === 'ESRCH') return false;
    if (error.code === 'EPERM') {
      throw new Error(`cannot prove PID ${pid} is absent: process probe returned EPERM`, { cause: error });
    }
    throw new Error(`cannot prove PID ${pid} is absent`, { cause: error });
  }
}

function restoreOrRetainClaim(lockPath, claimPath) {
  try {
    fs.linkSync(claimPath, lockPath);
  } catch (error) {
    if (error.code === 'EEXIST') return `retained at ${claimPath}`;
    throw new Error(`unable to restore claimed journal lock; retained at ${claimPath}`, { cause: error });
  }
  fs.unlinkSync(claimPath);
  fsyncDirectory(path.dirname(lockPath));
  return 'restored';
}

function claimAndRemoveLease(lockPath, {
  expectedLeaseId,
  expectedBytes,
  mismatchMessage,
  hooks = {},
}) {
  const claimPath = `${lockPath}.${process.pid}.${crypto.randomUUID()}.claim`;
  fs.renameSync(lockPath, claimPath);
  hooks.afterLeaseClaim?.(claimPath);
  let observed = null;
  let validationError = null;
  try { observed = readLeaseOwner(claimPath); } catch (error) { validationError = error; }
  if (validationError || !observed
      || observed.owner.leaseId !== expectedLeaseId
      || observed.bytes !== expectedBytes) {
    const disposition = restoreOrRetainClaim(lockPath, claimPath);
    throw new Error(`${mismatchMessage}; claimed owner was ${disposition}`, {
      cause: validationError ?? undefined,
    });
  }
  fs.unlinkSync(claimPath);
  fsyncDirectory(path.dirname(lockPath));
}

function acquireLease(lockPath, hooks = {}, timeoutMs = 5_000) {
  const owner = {
    leaseId: crypto.randomBytes(16).toString('hex'),
    hostname: os.hostname(),
    pid: process.pid,
    startedAtUtc: new Date().toISOString(),
  };
  const bytes = `${JSON.stringify(owner)}\n`;
  const deadline = Date.now() + timeoutMs;
  fs.mkdirSync(path.dirname(lockPath), { recursive: true });
  while (true) {
    let descriptor = null;
    try {
      descriptor = fs.openSync(
        lockPath,
        fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | NOFOLLOW,
        0o600,
      );
      writeAll(descriptor, Buffer.from(bytes));
      fs.fsyncSync(descriptor);
      fs.closeSync(descriptor);
      fsyncDirectory(path.dirname(lockPath));
      hooks.afterLeaseCreated?.(lockPath, owner);
      return { owner, bytes };
    } catch (error) {
      if (descriptor != null) {
        try { fs.closeSync(descriptor); } catch { /* already closed */ }
      }
      if (error.code !== 'EEXIST') {
        // Never read-then-unlink here: the pathname may already belong to a
        // replacement owner. A partially acquired lease remains fail-closed
        // and can be removed only through exact-ID stale recovery.
        throw error;
      }
      const existing = readLeaseOwner(lockPath);
      const alive = existing.owner.hostname === os.hostname()
        ? (hooks.isProcessAlive ?? processIsAlive)(existing.owner.pid)
        : true;
      if (typeof alive !== 'boolean') throw new Error('journal lock process probe returned no boolean proof');
      if (!alive) {
        throw new Error(
          `journal lock is stale for PID ${existing.owner.pid}, lease ${existing.owner.leaseId}; explicit recovery is required`,
        );
      }
      if (Date.now() >= deadline) {
        throw new Error(
          `timed out acquiring journal lock held by host ${existing.owner.hostname}, PID ${existing.owner.pid}, lease ${existing.owner.leaseId}`,
        );
      }
      Atomics.wait(waitCell, 0, 0, 10);
    }
  }
}

function withLease(lockPath, operation, hooks = {}) {
  const lease = acquireLease(lockPath, hooks);
  try {
    return operation(lease.owner);
  } finally {
    claimAndRemoveLease(lockPath, {
      expectedLeaseId: lease.owner.leaseId,
      expectedBytes: lease.bytes,
      mismatchMessage: `journal lease CAS failed for ${lease.owner.leaseId}`,
      hooks,
    });
  }
}

export function receiptKeyId(publicKey) {
  const keyObject = publicKey?.type === 'public' ? publicKey : crypto.createPublicKey(publicKey);
  return `sha256:${crypto.createHash('sha256')
    .update(keyObject.export({ type: 'spki', format: 'der' }))
    .digest('hex')}`;
}

function normalizeReceiptSigner(signer, { requirePersistent = false } = {}) {
  if (!signer || typeof signer !== 'object' || typeof signer.signHash !== 'function') {
    throw new Error('receipt signer must provide signHash');
  }
  if (signer.algorithm !== 'Ed25519') {
    throw new Error("receipt signer algorithm must be 'Ed25519'");
  }
  let publicKey;
  try {
    publicKey = crypto.createPublicKey(signer.publicKeyPem);
  } catch (error) {
    throw new Error('receipt signer must provide a valid public key', { cause: error });
  }
  if (publicKey.asymmetricKeyType !== 'ed25519') {
    throw new Error('receipt signer public key must be Ed25519');
  }
  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const keyId = receiptKeyId(publicKey);
  if (signer.keyId !== keyId) {
    throw new Error('receipt signer key ID must be the SPKI-derived SHA-256 identifier');
  }
  if (requirePersistent && signer.persistent !== true) {
    throw new Error('persistent journal refuses an ephemeral receipt signer');
  }
  return Object.freeze({
    algorithm: 'Ed25519',
    publicKeyPem,
    keyId,
    persistent: signer.persistent === true,
    signHash: (hashHex) => signer.signHash.call(signer, hashHex),
  });
}

function verifyHashSignature(hashHex, signature, publicKey) {
  if (!/^[0-9a-f]{64}$/.test(String(hashHex ?? '')) || typeof signature !== 'string') return false;
  const signatureBytes = Buffer.from(signature, 'base64');
  if (signatureBytes.length !== 64 || signatureBytes.toString('base64') !== signature) return false;
  try {
    return crypto.verify(null, Buffer.from(hashHex, 'hex'), publicKey, signatureBytes);
  } catch {
    return false;
  }
}

export function createReceiptSigner(keys = {}, { persistent = false } = {}) {
  const pair = keys.privateKey && keys.publicKey
    ? { privateKey: keys.privateKey, publicKey: keys.publicKey }
    : crypto.generateKeyPairSync('ed25519');
  const publicKeyPem = pair.publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const keyId = receiptKeyId(pair.publicKey);
  return normalizeReceiptSigner({
    algorithm: 'Ed25519',
    publicKeyPem,
    keyId,
    persistent,
    signHash(hashHex) {
      return crypto.sign(null, Buffer.from(hashHex, 'hex'), pair.privateKey).toString('base64');
    },
  });
}

export function loadOrCreateReceiptSigner(keyPath) {
  const canonicalKeyPath = safePersistentPath(keyPath, 'persistent receipt key');
  return withLease(`${canonicalKeyPath}.lock`, () => {
    let privateKey;
    if (fs.existsSync(canonicalKeyPath)) {
      privateKey = crypto.createPrivateKey(readPrivateFile(canonicalKeyPath, 'persistent receipt key'));
    } else {
      const pair = crypto.generateKeyPairSync('ed25519');
      privateKey = pair.privateKey;
      const temporary = `${canonicalKeyPath}.${process.pid}.${crypto.randomUUID()}.tmp`;
      const descriptor = fs.openSync(
        temporary,
        fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | NOFOLLOW,
        0o600,
      );
      try {
        writeAll(descriptor, Buffer.from(privateKey.export({ type: 'pkcs8', format: 'pem' })));
        fs.fsyncSync(descriptor);
      } finally {
        fs.closeSync(descriptor);
      }
      fs.renameSync(temporary, canonicalKeyPath);
      fsyncDirectory(path.dirname(canonicalKeyPath));
    }
    return createReceiptSigner(
      { privateKey, publicKey: crypto.createPublicKey(privateKey) },
      { persistent: true },
    );
  });
}

export function verifySignedReceipt(bundle, { publicKeyPem, keyId }) {
  try {
    if (bundle?.algorithm !== 'Ed25519' || bundle.keyId !== keyId) return false;
    const expectedHash = crypto.createHash('sha256').update(canonicalJson(bundle.receipt)).digest('hex');
    if (bundle.receiptHash !== expectedHash) return false;
    const publicKey = crypto.createPublicKey(publicKeyPem);
    return publicKey.asymmetricKeyType === 'ed25519'
      && verifyHashSignature(expectedHash, bundle.signature, publicKey);
  } catch {
    return false;
  }
}

const EVENT_DATA_KEYS = Object.freeze({
  'invocation.requested': ['invocationId', 'mode', 'skill', 'requestHash', 'creatorId', 'beneficiaryId'],
  'payment.offered': ['quote'],
  'payment.authorization_verified': ['verifiedPaymentHash'],
  'payment.signed': ['settlementReference', 'payer'],
  'payment.settled': ['settlementReference', 'txHash', 'payer'],
  'payment.unresolved': ['reason'],
  'payment.rejected': ['reason'],
  'refund.started': ['refundAttemptId'],
  'refund.unresolved': ['refundAttemptId', 'reason'],
  'payment.refunded': [
    'refundAttemptId', 'reason', 'refundReference', 'refundAmountAtomic', 'reversalEntries',
  ],
  'execution.started': ['executionAttemptId'],
  'execution.finished': ['executionAttemptId', 'outcome', 'outcomeHash', 'failureClass', 'message', 'httpStatus', 'accounting'],
  'receipt.issued': ['bundle'],
});

function deriveFullGrossRefundReversal(record) {
  if (record.payment.state !== 'settled' || record.execution.state !== 'failed'
      || record.accounting?.allocationState !== 'pending_cogs_reconciliation') {
    throw new Error('refund requires a settled terminal failed full-gross reconciliation hold');
  }
  if ((record.accounting.holderCredits?.length ?? 0) !== 0
      || (record.accounting.ancestorCredits?.length ?? 0) !== 0) {
    throw new Error('refund refuses accounting with finalized Royalty claims');
  }
  const [hold, ...extra] = record.accounting.journalEntries ?? [];
  if (extra.length || !hold
      || hold.category !== 'unresolved-execution-accounting'
      || hold.debitAccountId !== 'wielder:external-gross'
      || hold.creditAccountId !== 'hold:execution-accounting-reconciliation'
      || hold.amountAtomic !== record.quote.amountAtomic
      || record.accounting.grossAtomic !== record.quote.amountAtomic) {
    throw new Error('refund requires one exact full-gross reconciliation hold');
  }
  return [{
    category: 'refund-reverse-reconciliation-hold',
    debitAccountId: hold.creditAccountId,
    creditAccountId: hold.debitAccountId,
    amountAtomic: hold.amountAtomic,
  }, {
    category: 'refund-disbursement',
    debitAccountId: 'wielder:external-gross',
    creditAccountId: `refund:${record.payment.payer}`,
    amountAtomic: record.quote.amountAtomic,
  }];
}

function receiptPayload(record) {
  // Refund execution leases are internal control-plane state. Omitting them
  // keeps the signed receipt schema stable while payment.refunded carries the
  // externally meaningful confirmation and exact reversal accounting.
  const payment = copy(record.payment);
  delete payment.refundExecution;
  return {
    schemaVersion: record.schemaVersion,
    revision: record.receiptHistory.length + 1,
    supersedesReceiptHash: record.receiptHistory.at(-1)?.receiptHash ?? null,
    sequence: record.lastSequence,
    invocationId: record.invocationId,
    idempotencyKey: record.idempotencyKey,
    mode: record.mode,
    skill: copy(record.skill),
    requestHash: record.requestHash,
    creatorId: record.creatorId,
    wielderId: record.wielderId,
    beneficiaryId: record.beneficiaryId,
    quote: copy(record.quote),
    payment,
    execution: copy(record.execution),
    accounting: copy(record.accounting),
    createdAt: record.createdAt,
    completedAt: record.updatedAt,
  };
}

function requireRecord(records, key) {
  const record = records.get(key);
  if (!record) throw new Error(`unknown idempotency key '${key}'`);
  return record;
}

function assertState(record, allowed, action) {
  if (!allowed.includes(record.execution.state)) {
    throw new Error(`${action} cannot run from execution state '${record.execution.state}'`);
  }
}

function assertUnique(index, value, key, label) {
  const existing = index.get(value);
  if (existing && existing !== key) throw new Error(`${label} already binds idempotency key '${existing}'`);
}

export function createInvocationJournal({
  filePath = null,
  signingKeyPath = null,
  now = () => new Date().toISOString(),
  createId = () => `inv-${crypto.randomUUID()}`,
  signer = null,
  lockTestHooks = {},
} = {}) {
  if (Boolean(filePath) !== Boolean(signingKeyPath)) {
    throw new Error('persistent journal and receipt signing key paths must be set together');
  }
  const journalPath = filePath ? safePersistentPath(filePath, 'persistent journal') : null;
  const lockPath = journalPath ? `${journalPath}.lock` : null;
  const canonicalSigningKeyPath = signingKeyPath
    ? safePersistentPath(signingKeyPath, 'persistent receipt key')
    : null;
  if (journalPath && journalPath === canonicalSigningKeyPath) {
    throw new Error('journal and signing key paths must differ');
  }
  const injectedSigner = signer
    ? normalizeReceiptSigner(signer, { requirePersistent: Boolean(journalPath) })
    : null;
  const diskSigner = journalPath ? loadOrCreateReceiptSigner(canonicalSigningKeyPath) : null;
  if (injectedSigner && diskSigner && injectedSigner.keyId !== diskSigner.keyId) {
    throw new Error('injected receipt signer does not match the persistent signing key');
  }
  const receiptSigner = injectedSigner ?? diskSigner ?? createReceiptSigner();
  const receiptPublicKey = crypto.createPublicKey(receiptSigner.publicKeyPem);
  const records = new Map();
  const settlementReferences = new Map();
  const transactionHashes = new Map();
  const verifiedPaymentHashes = new Map();
  const eventLog = [];
  let nextSequence = 1;
  let headHash = null;

  function validateQuote(quote, schemaVersion) {
    const legacyFields = [
      'quoteId', 'amountAtomic', 'currency', 'network', 'asset', 'payTo', 'resource',
      'requestHash', 'requirementsHash', 'expiresAt', 'requirements',
    ];
    if (schemaVersion === 1) {
      exactKeys(quote, legacyFields, 'legacy payment quote');
    } else if (schemaVersion === 2) {
      exactKeys(quote, ['schemaVersion', ...legacyFields, 'executionQuote'], 'payment quote');
      if (quote.schemaVersion !== 2) throw new Error('payment quote must use schema version 2');
      assertExecutionQuote(quote.executionQuote);
      if (quote.executionQuote.quoteId !== quote.quoteId
          || quote.executionQuote.grossAtomic !== quote.amountAtomic) {
        throw new Error('execution quote does not match x402 quote identity and amount');
      }
    } else {
      throw new Error('payment quote schema version is unsupported');
    }
    requireText(quote.quoteId, 'quoteId');
    requireAtomicString(quote.amountAtomic, 'amountAtomic');
    if (quote.currency !== 'USDC') throw new Error("currency must be 'USDC'");
    for (const field of ['network', 'resource', 'requestHash', 'requirementsHash', 'expiresAt']) {
      requireText(quote[field], field);
    }
    if (canonicalAddress(quote.asset, 'asset') !== quote.asset
        || canonicalAddress(quote.payTo, 'payTo') !== quote.payTo) {
      throw new Error('indexed quote addresses must use canonical lowercase hex');
    }
    exactKeys(quote.requirements, [
      'scheme', 'network', 'maxAmountRequired', 'resource', 'description', 'mimeType',
      'payTo', 'maxTimeoutSeconds', 'asset', 'extra',
    ], 'frozen PaymentRequirements');
    exactKeys(quote.requirements.extra, [
      'name', 'version', 'requestHash', 'quoteId', 'issuedAt', 'expiresAt',
    ], 'PaymentRequirements.extra');
    if (quote.requirements.maxAmountRequired !== quote.amountAtomic
        || quote.requirements.network !== quote.network
        || canonicalAddress(quote.requirements.asset, 'requirements.asset') !== quote.asset
        || canonicalAddress(quote.requirements.payTo, 'requirements.payTo') !== quote.payTo
        || quote.requirements.resource !== quote.resource
        || quote.requirements.extra.requestHash !== quote.requestHash
        || quote.requirements.extra.quoteId !== quote.quoteId
        || quote.requirements.extra.expiresAt !== quote.expiresAt) {
      throw new Error('frozen x402 requirements do not match indexed quote fields');
    }
  }

  const V2_ACCOUNTING_FIELDS = [
    'schemaVersion', 'quoteId', 'allocationPolicy', 'grossAtomic', 'executionCostAtomic',
    'settlementCostAtomic', 'protocolFeeAtomic', 'royaltyPoolAtomic', 'refundReserveAtomic',
    'contributionMarginAtomic', 'allocationState', 'holderCredits', 'ancestorCredits',
    'journalEntries', 'executionCogs',
  ];

  function validateV2Usage(usage) {
    exactKeys(usage, ['schemaVersion', 'model', 'inputTokens', 'outputTokens'], 'provider usage');
    if (usage.schemaVersion !== 2 || typeof usage.model !== 'string' || !usage.model
        || !Number.isSafeInteger(usage.inputTokens) || usage.inputTokens < 0
        || !Number.isSafeInteger(usage.outputTokens) || usage.outputTokens < 0) {
      throw new Error('provider usage must use strict schema version 2');
    }
  }

  function validateV2Credits(credits, kind) {
    if (!Array.isArray(credits)) throw new Error(`${kind} Royalty credits must be an array`);
    for (const credit of credits) {
      exactKeys(credit, ['recipientId', 'viaSkillId', 'depth', 'kind', 'amountAtomic'], `${kind} Royalty credit`);
      requireText(credit.recipientId, 'Royalty recipientId');
      requireText(credit.viaSkillId, 'Royalty viaSkillId');
      if (!Number.isSafeInteger(credit.depth) || credit.depth < 0 || credit.kind !== kind) {
        throw new Error(`${kind} Royalty credit identity is invalid`);
      }
      requireAtomicString(credit.amountAtomic, 'Royalty credit amountAtomic');
    }
  }

  function validateV2JournalEntries(entries) {
    if (!Array.isArray(entries)) throw new Error('accounting journalEntries must be an array');
    for (const entry of entries) {
      exactKeys(entry, ['category', 'debitAccountId', 'creditAccountId', 'amountAtomic'], 'accounting journal entry');
      requireText(entry.category, 'accounting category');
      requireText(entry.debitAccountId, 'accounting debitAccountId');
      requireText(entry.creditAccountId, 'accounting creditAccountId');
      requireAtomicString(entry.amountAtomic, 'accounting amountAtomic');
    }
  }

  function validateV2Accounting(record, accounting) {
    exactKeys(accounting, V2_ACCOUNTING_FIELDS, 'v2 execution accounting');
    if (accounting.schemaVersion !== 2
        || accounting.quoteId !== record.quote.quoteId
        || accounting.grossAtomic !== record.quote.amountAtomic) {
      throw new Error('v2 accounting does not match the frozen quote and gross');
    }
    for (const field of [
      'grossAtomic', 'executionCostAtomic', 'settlementCostAtomic', 'protocolFeeAtomic',
      'royaltyPoolAtomic', 'refundReserveAtomic', 'contributionMarginAtomic',
    ]) requireAtomicString(accounting[field], `accounting.${field}`);
    validateV2Credits(accounting.holderCredits, 'holder');
    validateV2Credits(accounting.ancestorCredits, 'ancestor');
    validateV2JournalEntries(accounting.journalEntries);

    const cogs = accounting.executionCogs;
    exactKeys(cogs, [
      'schemaVersion', 'status', 'actualAtomic', 'chargedAtomic', 'quotedWorstCaseAtomic',
      'accruedOverrunAtomic', 'catalogVersion', 'catalogDigest', 'usage', 'failureClass', 'reason',
    ], 'execution COGS');
    const executionQuote = record.quote.executionQuote;
    if (cogs.schemaVersion !== 2
        || cogs.quotedWorstCaseAtomic !== executionQuote.worstCaseExecutionCostAtomic
        || cogs.catalogVersion !== executionQuote.catalogVersion
        || cogs.catalogDigest !== executionQuote.catalogDigest) {
      throw new Error('execution COGS does not match the frozen quote catalog');
    }
    requireAtomicString(cogs.quotedWorstCaseAtomic, 'executionCogs.quotedWorstCaseAtomic');
    requireAtomicString(cogs.accruedOverrunAtomic, 'executionCogs.accruedOverrunAtomic');

    const gross = BigInt(accounting.grossAtomic);
    if (accounting.allocationState === 'finalized') {
      if (accounting.allocationPolicy !== 'lrp-per-hop-v1'
          || cogs.status !== 'known' || cogs.actualAtomic === null
          || cogs.chargedAtomic !== cogs.actualAtomic || cogs.usage === null
          || cogs.failureClass !== null || cogs.reason !== null
          || cogs.accruedOverrunAtomic !== '0') {
        throw new Error('finalized accounting requires known charged COGS and no failure');
      }
      requireAtomicString(cogs.actualAtomic, 'executionCogs.actualAtomic');
      validateV2Usage(cogs.usage);
      if (cogs.usage.model !== executionQuote.model
          || cogs.usage.inputTokens > executionQuote.maxInputTokens
          || cogs.usage.outputTokens > executionQuote.maxOutputTokens) {
        throw new Error('finalized accounting usage exceeds the frozen execution quote');
      }
      if (BigInt(cogs.actualAtomic) > BigInt(cogs.quotedWorstCaseAtomic)) {
        throw new Error('finalized accounting COGS exceeds the frozen quote reserve');
      }
      if (accounting.executionCostAtomic !== cogs.actualAtomic
          || accounting.settlementCostAtomic !== executionQuote.settlementCostAtomic
          || accounting.protocolFeeAtomic !== executionQuote.protocolFeeAtomic
          || accounting.refundReserveAtomic !== executionQuote.refundReserveAtomic
          || accounting.contributionMarginAtomic !== accounting.protocolFeeAtomic) {
        throw new Error('finalized accounting costs or contribution margin do not match the frozen quote');
      }
      const components = [
        'executionCostAtomic', 'settlementCostAtomic', 'protocolFeeAtomic',
        'royaltyPoolAtomic', 'refundReserveAtomic',
      ].reduce((sum, field) => sum + BigInt(accounting[field]), 0n);
      const journalTotal = accounting.journalEntries
        .reduce((sum, entry) => sum + BigInt(entry.amountAtomic), 0n);
      const holderTotal = accounting.holderCredits
        .reduce((sum, credit) => sum + BigInt(credit.amountAtomic), 0n);
      const ancestorTotal = accounting.ancestorCredits
        .reduce((sum, credit) => sum + BigInt(credit.amountAtomic), 0n);
      if (components !== gross || journalTotal !== gross
          || holderTotal + ancestorTotal !== BigInt(accounting.royaltyPoolAtomic)) {
        throw new Error('finalized accounting must conserve gross and the Royalty pool exactly');
      }
      const categoryRows = new Map();
      for (const entry of accounting.journalEntries) {
        if (entry.debitAccountId !== 'wielder:external-gross') {
          throw new Error('finalized accounting journal must debit external gross');
        }
        const rows = categoryRows.get(entry.category) ?? [];
        rows.push(entry);
        categoryRows.set(entry.category, rows);
      }
      const expectedCategories = new Map([
        ['execution-cogs', {
          amountAtomic: accounting.executionCostAtomic,
          creditAccountId: 'provider:execution',
        }],
        ['settlement-cogs', {
          amountAtomic: accounting.settlementCostAtomic,
          creditAccountId: 'provider:settlement',
        }],
        ['protocol-fee', {
          amountAtomic: accounting.protocolFeeAtomic,
          creditAccountId: 'protocol:treasury',
        }],
        ['refund-reserve', {
          amountAtomic: accounting.refundReserveAtomic,
          creditAccountId: 'reserve:refund',
        }],
      ]);
      for (const [category, expected] of expectedCategories) {
        const rows = categoryRows.get(category) ?? [];
        if (rows.length !== 1
            || rows[0].amountAtomic !== expected.amountAtomic
            || rows[0].creditAccountId !== expected.creditAccountId) {
          throw new Error(`finalized accounting category '${category}' does not match its quoted destination`);
        }
      }
      if ([...categoryRows.keys()].some((category) => (
            !expectedCategories.has(category)
            && !['royalty-holder', 'royalty-ancestor'].includes(category)
          ))) {
        throw new Error('finalized accounting journal has invalid Royalty categories');
      }
      const expectedRoyaltyRows = [
        ...accounting.holderCredits.map((credit) => ({
          category: 'royalty-holder',
          creditAccountId: `royalty:${credit.recipientId}`,
          amountAtomic: credit.amountAtomic,
        })),
        ...accounting.ancestorCredits.map((credit) => ({
          category: 'royalty-ancestor',
          creditAccountId: `royalty:${credit.recipientId}`,
          amountAtomic: credit.amountAtomic,
        })),
      ];
      const actualRoyaltyRows = [
        ...(categoryRows.get('royalty-holder') ?? []),
        ...(categoryRows.get('royalty-ancestor') ?? []),
      ];
      const rowKey = (row) => JSON.stringify([
        row.category, row.creditAccountId, row.amountAtomic,
      ]);
      const rowCounts = (rows) => rows.reduce((counts, row) => {
        const key = rowKey(row);
        counts.set(key, (counts.get(key) ?? 0) + 1);
        return counts;
      }, new Map());
      const expectedRows = rowCounts(expectedRoyaltyRows);
      const actualRows = rowCounts(actualRoyaltyRows);
      if (expectedRoyaltyRows.length !== actualRoyaltyRows.length
          || expectedRows.size !== actualRows.size
          || [...expectedRows].some(([key, count]) => actualRows.get(key) !== count)) {
        throw new Error('finalized accounting Royalty journal does not match signed credits');
      }
      return;
    }

    if (accounting.allocationState !== 'pending_cogs_reconciliation'
        || accounting.allocationPolicy !== null
        || ['executionCostAtomic', 'settlementCostAtomic', 'protocolFeeAtomic',
          'royaltyPoolAtomic', 'refundReserveAtomic', 'contributionMarginAtomic']
          .some((field) => accounting[field] !== '0')
        || accounting.holderCredits.length !== 0 || accounting.ancestorCredits.length !== 0
        || accounting.journalEntries.length !== 1) {
      throw new Error('pending accounting must hold full gross with no finalized Royalty claims');
    }
    const [hold] = accounting.journalEntries;
    if (hold.category !== 'unresolved-execution-accounting'
        || hold.debitAccountId !== 'wielder:external-gross'
        || hold.creditAccountId !== 'hold:execution-accounting-reconciliation'
        || hold.amountAtomic !== accounting.grossAtomic) {
      throw new Error('pending accounting requires one exact full-gross hold');
    }
    if (typeof cogs.failureClass !== 'string'
        || !/^[A-Z][A-Z0-9_]{1,63}$/.test(cogs.failureClass)
        || typeof cogs.reason !== 'string' || !cogs.reason) {
      throw new Error('pending execution COGS requires a stable failure class and reason');
    }
    if (cogs.status === 'unknown') {
      if (cogs.actualAtomic !== null || cogs.chargedAtomic !== null
          || cogs.usage !== null || cogs.accruedOverrunAtomic !== '0') {
        throw new Error('unknown COGS must remain null rather than zero');
      }
      return;
    }
    if (cogs.status !== 'known' || cogs.actualAtomic === null
        || cogs.chargedAtomic !== null || cogs.usage === null) {
      throw new Error('pending known COGS has invalid charged or usage fields');
    }
    requireAtomicString(cogs.actualAtomic, 'executionCogs.actualAtomic');
    validateV2Usage(cogs.usage);
    const expectedOverrun = BigInt(cogs.actualAtomic) > BigInt(cogs.quotedWorstCaseAtomic)
      ? BigInt(cogs.actualAtomic) - BigInt(cogs.quotedWorstCaseAtomic)
      : 0n;
    if (cogs.accruedOverrunAtomic !== expectedOverrun.toString()) {
      throw new Error('pending known COGS accrued overrun is inconsistent');
    }
  }

  function validateV2ExecutionFinished(record, data) {
    if (data.outcome === 'succeeded') {
      if (!/^sha256:[0-9a-f]{64}$/.test(String(data.outcomeHash ?? ''))
          || data.failureClass !== null || data.message !== null
          || data.httpStatus < 200 || data.httpStatus >= 400
          || data.accounting?.allocationState !== 'finalized') {
        throw new Error('v2 success requires a hash, success status, finalized accounting, and no failure message');
      }
    } else if (data.outcome === 'failed') {
      if (data.outcomeHash !== null
          || typeof data.failureClass !== 'string' || !/^[A-Z][A-Z0-9_]{1,63}$/.test(data.failureClass)
          || typeof data.message !== 'string' || !data.message
          || data.httpStatus < 400 || data.httpStatus > 599
          || data.accounting?.allocationState !== 'pending_cogs_reconciliation') {
        throw new Error('v2 failure requires a stable failure, failure status, and pending accounting');
      }
    } else {
      throw new Error('v2 execution.finished supports succeeded or failed outcomes only');
    }
    if (data.outcome === 'failed'
        && data.accounting?.executionCogs?.failureClass !== data.failureClass) {
      throw new Error('v2 failure class must match its pending COGS accounting');
    }
    validateV2Accounting(record, data.accounting);
  }

  function validateEventForApply(event) {
    exactKeys(event, [
      'schemaVersion', 'eventId', 'sequence', 'previousHash', 'type', 'idempotencyKey',
      'at', 'data', 'keyId', 'eventHash', 'eventSignature',
    ], 'journal event');
    if (![1, 2].includes(event.schemaVersion)
        || event.eventId !== `event-${String(event.sequence).padStart(8, '0')}`) {
      throw new Error('journal event schema or identifier is invalid');
    }
    if (!Number.isSafeInteger(event.sequence) || event.sequence < 1
        || !Number.isFinite(Date.parse(event.at))) {
      throw new Error('journal event sequence or timestamp is invalid');
    }
    const dataKeys = EVENT_DATA_KEYS[event.type];
    if (!dataKeys) throw new Error(`unknown journal event '${event.type}'`);
    exactKeys(event.data, dataKeys, `${event.type}.data`);
    const record = records.get(event.idempotencyKey);
    if (event.type !== 'invocation.requested' && record
        && event.schemaVersion !== record.schemaVersion) {
      throw new Error('journal event schema version cannot change within one Invocation');
    }
    switch (event.type) {
      case 'invocation.requested':
        if (record) throw new Error(`duplicate request event for '${event.idempotencyKey}'`);
        exactKeys(event.data.skill, ['id', 'versionHash'], 'skill');
        if (event.data.mode !== 'external') throw new Error("journal supports mode 'external' only");
        break;
      case 'payment.offered':
        if (!record || record.execution.state !== 'requested' || record.payment.state !== null) {
          throw new Error('payment.offered requires one unquoted requested Invocation');
        }
        validateQuote(event.data.quote, event.schemaVersion);
        break;
      case 'payment.authorization_verified':
        if (!record || record.schemaVersion !== 2 || record.payment.state !== 'offered') {
          throw new Error('payment.authorization_verified requires an offered v2 payment');
        }
        if (!/^sha256:[0-9a-f]{64}$/.test(String(event.data.verifiedPaymentHash ?? ''))) {
          throw new Error('verified payment authorization hash must be one SHA-256 digest');
        }
        if (verifiedPaymentHashes.has(event.idempotencyKey)
            && verifiedPaymentHashes.get(event.idempotencyKey) !== event.data.verifiedPaymentHash) {
          throw new Error('idempotency key already binds a different verified payment authorization');
        }
        break;
      case 'payment.signed':
        if (!record || record.payment.state !== 'offered') throw new Error('payment.signed requires offered payment');
        assertUnique(settlementReferences, event.data.settlementReference, event.idempotencyKey, 'settlement reference');
        break;
      case 'payment.settled':
        if (!record || !['signed', 'unresolved'].includes(record.payment.state)) {
          throw new Error('payment.settled requires signed or unresolved payment');
        }
        if (record.payment.settlementReference !== event.data.settlementReference
            || record.payment.payer !== event.data.payer) {
          throw new Error('settlement does not match signed payment');
        }
        assertUnique(transactionHashes, event.data.txHash, event.idempotencyKey, 'transaction hash');
        break;
      case 'payment.unresolved':
        if (!record || record.payment.state !== 'signed') throw new Error('payment.unresolved requires signed payment');
        break;
      case 'payment.rejected':
        if (!record || !['offered', 'signed', 'unresolved'].includes(record.payment.state)) {
          throw new Error('payment.rejected has invalid predecessor');
        }
        break;
      case 'refund.started':
        if (!record || record.payment.refundExecution !== null) {
          throw new Error('refund.started requires an unclaimed refund');
        }
        deriveFullGrossRefundReversal(record);
        requireText(event.data.refundAttemptId, 'refundAttemptId');
        break;
      case 'refund.unresolved':
        if (!record || record.payment.refundExecution?.state !== 'executing'
            || record.payment.refundExecution.refundAttemptId !== event.data.refundAttemptId) {
          throw new Error('refund.unresolved requires the claimed refund attempt');
        }
        requireText(event.data.reason, 'reason');
        break;
      case 'payment.refunded':
        if (!record || !['executing', 'unresolved'].includes(record.payment.refundExecution?.state)
            || event.data.refundAttemptId !== record.payment.refundExecution.refundAttemptId
            || event.data.refundAmountAtomic !== record.quote.amountAtomic
            || !same(event.data.reversalEntries, deriveFullGrossRefundReversal(record))) {
          throw new Error('refund must exactly reverse the full settled gross hold');
        }
        break;
      case 'execution.started':
        if (!record || record.payment.state !== 'settled' || record.execution.state !== 'authorized') {
          throw new Error('execution.started requires authorized settled payment');
        }
        break;
      case 'execution.finished':
        if (!record || record.execution.state !== 'executing'
            || event.data.executionAttemptId !== record.execution.executionAttemptId) {
          throw new Error('execution.finished requires the claimed executing attempt');
        }
        if (!TERMINAL_EXECUTION.has(event.data.outcome)) throw new Error('execution outcome is not terminal');
        if (!Number.isSafeInteger(event.data.httpStatus)
            || event.data.httpStatus < 100 || event.data.httpStatus > 599) {
          throw new Error('execution HTTP status is invalid');
        }
        if (event.schemaVersion === 2) validateV2ExecutionFinished(record, event.data);
        break;
      case 'receipt.issued':
        if (!record || !TERMINAL_EXECUTION.has(record.execution.state) || record.receipt) {
          throw new Error('receipt.issued requires one unreceipted terminal Invocation');
        }
        if (!same(event.data.bundle.receipt, receiptPayload(record))) {
          throw new Error('receipt does not byte-bind the derived Invocation record');
        }
        if (!verifySignedReceipt(event.data.bundle, {
          publicKeyPem: receiptSigner.publicKeyPem,
          keyId: receiptSigner.keyId,
        })) throw new Error('receipt signature does not match the pinned Collar key');
        break;
      default:
        throw new Error(`unknown journal event '${event.type}'`);
    }
  }

  function apply(event) {
    validateEventForApply(event);
    let record = records.get(event.idempotencyKey);
    switch (event.type) {
      case 'invocation.requested':
        record = {
          schemaVersion: event.schemaVersion,
          invocationId: event.data.invocationId,
          idempotencyKey: event.idempotencyKey,
          mode: event.data.mode,
          skill: event.data.skill,
          requestHash: event.data.requestHash,
          creatorId: event.data.creatorId,
          requestedBeneficiaryId: event.data.beneficiaryId,
          wielderId: null,
          beneficiaryId: event.data.beneficiaryId,
          quote: null,
          payment: {
            state: null, settlementReference: null, txHash: null, payer: null, reason: null,
            refundReference: null, refundAmountAtomic: null, refundAccounting: null,
            refundExecution: null,
          },
          execution: {
            state: 'requested', executionAttemptId: null, outcomeHash: null,
            failureClass: null, message: null, httpStatus: null,
          },
          accounting: null,
          receipt: null,
          receiptHistory: [],
          createdAt: event.at,
          updatedAt: event.at,
          lastSequence: event.sequence,
        };
        records.set(event.idempotencyKey, record);
        break;
      case 'payment.offered':
        record.quote = event.data.quote;
        record.payment.state = 'offered';
        record.execution.state = 'quoted';
        break;
      case 'payment.authorization_verified':
        verifiedPaymentHashes.set(event.idempotencyKey, event.data.verifiedPaymentHash);
        break;
      case 'payment.signed':
        record.payment = { ...record.payment, state: 'signed', ...event.data, reason: null };
        record.wielderId = event.data.payer;
        record.beneficiaryId ??= event.data.payer;
        settlementReferences.set(event.data.settlementReference, event.idempotencyKey);
        break;
      case 'payment.settled':
        record.payment = { ...record.payment, state: 'settled', ...event.data, reason: null };
        record.wielderId = event.data.payer;
        record.beneficiaryId ??= event.data.payer;
        record.execution.state = 'authorized';
        settlementReferences.set(event.data.settlementReference, event.idempotencyKey);
        transactionHashes.set(event.data.txHash, event.idempotencyKey);
        break;
      case 'payment.unresolved':
        record.payment.state = 'unresolved';
        record.payment.reason = event.data.reason;
        break;
      case 'payment.rejected':
        record.payment.state = 'rejected';
        record.payment.reason = event.data.reason;
        record.execution.state = 'cancelled';
        record.execution.httpStatus = 402;
        break;
      case 'refund.started':
        record.payment.refundExecution = {
          state: 'executing',
          refundAttemptId: event.data.refundAttemptId,
          reason: null,
        };
        break;
      case 'refund.unresolved':
        record.payment.refundExecution = {
          state: 'unresolved',
          refundAttemptId: event.data.refundAttemptId,
          reason: event.data.reason,
        };
        break;
      case 'payment.refunded':
        record.payment.state = 'refunded';
        record.payment.reason = event.data.reason;
        record.payment.refundReference = event.data.refundReference;
        record.payment.refundAmountAtomic = event.data.refundAmountAtomic;
        record.payment.refundAccounting = {
          priorAllocationState: 'pending_cogs_reconciliation',
          reversalEntries: event.data.reversalEntries,
        };
        record.payment.refundExecution = {
          state: 'confirmed',
          refundAttemptId: event.data.refundAttemptId,
          reason: null,
        };
        record.receipt = null;
        break;
      case 'execution.started':
        record.execution.state = 'executing';
        record.execution.executionAttemptId = event.data.executionAttemptId;
        break;
      case 'execution.finished':
        record.execution = {
          state: event.data.outcome,
          executionAttemptId: event.data.executionAttemptId,
          outcomeHash: event.data.outcomeHash,
          failureClass: event.data.failureClass,
          message: event.data.message,
          httpStatus: event.data.httpStatus,
        };
        record.accounting = event.data.accounting;
        break;
      case 'receipt.issued':
        record.receipt = event.data.bundle;
        record.receiptHistory.push(event.data.bundle);
        break;
      default:
        throw new Error(`unknown journal event '${event.type}'`);
    }
    record.updatedAt = event.at;
    record.lastSequence = event.sequence;
  }

  const calculateEventHash = (unsigned) => crypto.createHash('sha256')
    .update(canonicalJson(unsigned)).digest('hex');

  function readVerifiedDiskEvents() {
    if (!journalPath || !fs.existsSync(journalPath)) return [];
    const text = readPrivateFile(journalPath, 'persistent journal');
    if (!text) return [];
    if (!text.endsWith('\n')) throw new Error('journal has a torn or unterminated final event');
    const lines = text.slice(0, -1).split('\n');
    let previousHash = null;
    return lines.map((line, index) => {
      if (!line) throw new Error(`journal contains a blank event at sequence ${index + 1}`);
      let event;
      try { event = JSON.parse(line); } catch (error) {
        throw new Error(`journal event ${index + 1} is malformed JSON`, { cause: error });
      }
      if (event.sequence !== index + 1) throw new Error(`journal sequence gap at ${index + 1}`);
      if (event.previousHash !== previousHash) throw new Error(`journal hash-chain predecessor mismatch at ${index + 1}`);
      const { eventHash, eventSignature, ...unsigned } = event;
      const expectedHash = calculateEventHash(unsigned);
      if (eventHash !== expectedHash) throw new Error(`journal event hash mismatch at ${index + 1}`);
      if (event.keyId !== receiptSigner.keyId
          || !verifyHashSignature(eventHash, eventSignature, receiptPublicKey)) {
        throw new Error(`journal event signature mismatch at ${index + 1}`);
      }
      previousHash = eventHash;
      return event;
    });
  }

  function syncFromDisk() {
    const diskEvents = readVerifiedDiskEvents();
    for (let index = 0; index < eventLog.length; index += 1) {
      if (!same(eventLog[index], diskEvents[index])) {
        throw new Error(`journal history changed at sequence ${index + 1}`);
      }
    }
    for (const event of diskEvents.slice(eventLog.length)) {
      apply(event);
      eventLog.push(event);
    }
    nextSequence = diskEvents.length + 1;
    headHash = diskEvents.at(-1)?.eventHash ?? null;
  }

  const refreshFromAuthority = () => {
    if (journalPath) withLease(lockPath, syncFromDisk, lockTestHooks);
  };

  function append(type, idempotencyKey, data) {
    const expectedRecordSequence = records.get(idempotencyKey)?.lastSequence ?? 0;
    const write = () => {
      if (journalPath) syncFromDisk();
      const currentRecordSequence = records.get(idempotencyKey)?.lastSequence ?? 0;
      if (currentRecordSequence !== expectedRecordSequence) {
        const error = new Error(`journal compare-and-swap conflict for '${idempotencyKey}'`);
        error.name = 'JournalConflictError';
        error.code = 'JOURNAL_CONFLICT';
        throw error;
      }
      const unsigned = {
        schemaVersion: type === 'invocation.requested'
          ? 2
          : (records.get(idempotencyKey)?.schemaVersion ?? 2),
        eventId: `event-${String(nextSequence).padStart(8, '0')}`,
        sequence: nextSequence,
        previousHash: headHash,
        type,
        idempotencyKey,
        at: now(),
        data,
        keyId: receiptSigner.keyId,
      };
      const eventHash = calculateEventHash(unsigned);
      const eventSignature = receiptSigner.signHash(eventHash);
      if (!verifyHashSignature(eventHash, eventSignature, receiptPublicKey)) {
        throw new Error('generated journal event signature does not match the persistent receipt key');
      }
      const event = {
        ...unsigned,
        eventHash,
        eventSignature,
      };
      // Validation must happen before the first durable byte. Replay must
      // never encounter an event that this process already knew was invalid.
      validateEventForApply(event);
      if (journalPath) {
        const existed = fs.existsSync(journalPath);
        const descriptor = fs.openSync(
          journalPath,
          fs.constants.O_WRONLY | fs.constants.O_APPEND | fs.constants.O_CREAT | NOFOLLOW,
          0o600,
        );
        try {
          const stat = fs.fstatSync(descriptor);
          if (!stat.isFile() || (stat.mode & 0o777) !== 0o600) {
            throw new Error('persistent journal must remain a regular file with mode exactly 0600');
          }
          writeAll(descriptor, Buffer.from(`${JSON.stringify(event)}\n`));
          fs.fsyncSync(descriptor);
        } finally {
          fs.closeSync(descriptor);
        }
        if (!existed) fsyncDirectory(path.dirname(journalPath));
      }
      apply(event);
      eventLog.push(event);
      nextSequence += 1;
      headHash = event.eventHash;
      return event;
    };
    return journalPath ? withLease(lockPath, write, lockTestHooks) : write();
  }

  function requestInvocation(input) {
    refreshFromAuthority();
    const key = requireText(input.idempotencyKey, 'idempotencyKey');
    const declaration = {
      mode: input.mode === 'external' ? 'external' : (() => { throw new Error("journal supports mode 'external' only"); })(),
      skill: {
        id: requireText(input.skillId, 'skillId'),
        versionHash: requireText(input.skillVersionHash, 'skillVersionHash'),
      },
      requestHash: requireText(input.requestHash, 'requestHash'),
      creatorId: requireText(input.creatorId, 'creatorId'),
      beneficiaryId: input.beneficiaryId == null ? null : requireText(input.beneficiaryId, 'beneficiaryId'),
    };
    const existing = records.get(key);
    if (existing) {
      const bound = {
        mode: existing.mode,
        skill: existing.skill,
        requestHash: existing.requestHash,
        creatorId: existing.creatorId,
        beneficiaryId: existing.requestedBeneficiaryId,
      };
      if (!same(bound, declaration)) throw new Error('idempotency key already binds a different Invocation declaration');
      return copy(existing);
    }
    append('invocation.requested', key, { invocationId: createId(), ...declaration });
    return copy(records.get(key));
  }

  function offerExternalPayment(key, input) {
    refreshFromAuthority();
    const record = requireRecord(records, key);
    const requirements = copy(input.requirements);
    const frozenQuote = {
      schemaVersion: 2,
      quoteId: requireText(input.quoteId, 'quoteId'),
      amountAtomic: requireAtomicString(input.amountAtomic, 'amountAtomic'),
      currency: input.currency === 'USDC' ? 'USDC' : (() => { throw new Error("currency must be 'USDC'"); })(),
      network: requireText(input.network, 'network'),
      asset: canonicalAddress(input.asset, 'asset'),
      payTo: canonicalAddress(input.payTo, 'payTo'),
      resource: requireText(input.resource, 'resource'),
      requestHash: requireText(input.requestHash, 'requestHash'),
      requirementsHash: requireText(input.requirementsHash, 'requirementsHash'),
      expiresAt: requireText(input.expiresAt, 'expiresAt'),
      requirements,
      executionQuote: copy(input.executionQuote),
    };
    if (record.schemaVersion !== 2) {
      throw new Error('legacy nonterminal Invocation cannot be upgraded to execution quote schema v2');
    }
    validateQuote(frozenQuote, record.schemaVersion);
    if (record.quote) {
      if (!same(record.quote, frozenQuote)) throw new Error('idempotency key already binds a different quote');
      return copy(record);
    }
    assertState(record, ['requested'], 'offerExternalPayment');
    append('payment.offered', key, { quote: frozenQuote });
    return copy(records.get(key));
  }

  function claimExternalPaymentSigned(key, input) {
    refreshFromAuthority();
    const record = requireRecord(records, key);
    const reference = canonicalBytes32(input.settlementReference, 'settlementReference');
    const normalizedPayer = canonicalAddress(input.payer, 'payer');
    if (record.payment.settlementReference) {
      if (record.payment.settlementReference !== reference || record.payment.payer !== normalizedPayer) {
        throw new Error('idempotency key already binds a different signed payment');
      }
      return { claimed: false, record: copy(record) };
    }
    if (record.payment.state !== 'offered') {
      throw new Error(`markExternalPaymentSigned cannot run from payment state '${record.payment.state}'`);
    }
    assertUnique(settlementReferences, reference, key, 'settlement reference');
    try {
      append('payment.signed', key, { settlementReference: reference, payer: normalizedPayer });
      return { claimed: true, record: copy(records.get(key)) };
    } catch (error) {
      if (error.code !== 'JOURNAL_CONFLICT') throw error;
      const winner = requireRecord(records, key);
      if (winner.payment.settlementReference !== reference || winner.payment.payer !== normalizedPayer) {
        throw new Error('idempotency key concurrently bound a different signed payment', { cause: error });
      }
      return { claimed: false, record: copy(winner) };
    }
  }

  const markExternalPaymentSigned = (key, input) => claimExternalPaymentSigned(key, input).record;

  function recordExternalPaymentVerification(key, input) {
    refreshFromAuthority();
    const record = requireRecord(records, key);
    const verifiedPaymentHash = input?.verifiedPaymentHash;
    if (!/^sha256:[0-9a-f]{64}$/.test(String(verifiedPaymentHash ?? ''))) {
      throw new Error('verified payment authorization hash must be one SHA-256 digest');
    }
    const existing = verifiedPaymentHashes.get(key);
    if (existing) {
      if (existing !== verifiedPaymentHash) {
        throw new Error('idempotency key already binds a different verified payment authorization');
      }
      return copy(record);
    }
    if (record.schemaVersion !== 2 || record.payment.state !== 'offered') {
      throw new Error('verified payment authorization can only bind an offered v2 payment');
    }
    try {
      append('payment.authorization_verified', key, { verifiedPaymentHash });
      return copy(records.get(key));
    } catch (error) {
      if (error.code !== 'JOURNAL_CONFLICT') throw error;
      const winner = verifiedPaymentHashes.get(key);
      if (winner !== verifiedPaymentHash) {
        throw new Error('idempotency key concurrently bound a different verified payment authorization', {
          cause: error,
        });
      }
      return copy(requireRecord(records, key));
    }
  }

  function markExternalPaymentSettled(key, input) {
    refreshFromAuthority();
    const record = requireRecord(records, key);
    const reference = canonicalBytes32(input.settlementReference, 'settlementReference');
    const normalizedTxHash = canonicalBytes32(input.txHash, 'txHash');
    const normalizedPayer = canonicalAddress(input.payer, 'payer');
    if (['settled', 'refunded'].includes(record.payment.state)) {
      if (record.payment.settlementReference !== reference || record.payment.txHash !== normalizedTxHash
          || record.payment.payer !== normalizedPayer) {
        throw new Error('idempotency key already binds a different settlement');
      }
      return copy(record);
    }
    if (!['signed', 'unresolved'].includes(record.payment.state)) {
      throw new Error(`markExternalPaymentSettled cannot run from payment state '${record.payment.state}'`);
    }
    if (record.payment.settlementReference !== reference || record.payment.payer !== normalizedPayer) {
      throw new Error('settlement does not match signed payment');
    }
    assertUnique(transactionHashes, normalizedTxHash, key, 'transaction hash');
    append('payment.settled', key, {
      settlementReference: reference,
      txHash: normalizedTxHash,
      payer: normalizedPayer,
    });
    return copy(records.get(key));
  }

  function markExternalPaymentUnresolved(key, { reason }) {
    refreshFromAuthority();
    const record = requireRecord(records, key);
    const normalizedReason = requireText(reason, 'reason');
    if (record.payment.state === 'unresolved' && record.payment.reason === normalizedReason) return copy(record);
    if (record.payment.state !== 'signed') {
      throw new Error(`markExternalPaymentUnresolved cannot run from payment state '${record.payment.state}'`);
    }
    append('payment.unresolved', key, { reason: normalizedReason });
    return copy(records.get(key));
  }

  function reconcileExternalSettlement(input) {
    refreshFromAuthority();
    const reference = canonicalBytes32(input.settlementReference, 'settlementReference');
    const key = settlementReferences.get(reference);
    if (!key) throw new Error(`unknown settlement reference '${reference}'`);
    return markExternalPaymentSettled(key, { ...input, settlementReference: reference });
  }

  function rejectExternalPayment(key, { reason }) {
    refreshFromAuthority();
    const record = requireRecord(records, key);
    const normalizedReason = requireText(reason, 'reason');
    if (record.payment.state === 'rejected' && record.payment.reason === normalizedReason) return copy(record);
    if (!['offered', 'signed', 'unresolved'].includes(record.payment.state)) {
      throw new Error(`rejectExternalPayment cannot run from payment state '${record.payment.state}'`);
    }
    append('payment.rejected', key, { reason: normalizedReason });
    return copy(records.get(key));
  }

  function refundExternalPayment(key, input) {
    refreshFromAuthority();
    const record = requireRecord(records, key);
    const refund = {
      refundAttemptId: requireText(input.refundAttemptId, 'refundAttemptId'),
      reason: requireText(input.reason, 'reason'),
      refundReference: requireText(input.refundReference, 'refundReference'),
      refundAmountAtomic: requireAtomicString(input.refundAmountAtomic, 'refundAmountAtomic'),
    };
    if (record.payment.state === 'refunded') {
      if (record.payment.reason !== refund.reason
          || record.payment.refundReference !== refund.refundReference
          || record.payment.refundAmountAtomic !== refund.refundAmountAtomic
          || record.payment.refundExecution?.refundAttemptId !== refund.refundAttemptId) {
        throw new Error('Invocation already binds a different refund');
      }
      return copy(record);
    }
    if (!['executing', 'unresolved'].includes(record.payment.refundExecution?.state)
        || record.payment.refundExecution.refundAttemptId !== refund.refundAttemptId) {
      throw new Error('refund attempt does not match the durable execution claim');
    }
    if (refund.refundAmountAtomic !== record.quote.amountAtomic) {
      throw new Error('refund must return the full settled gross');
    }
    try {
      append('payment.refunded', key, {
        ...refund,
        reversalEntries: deriveFullGrossRefundReversal(record),
      });
      return copy(records.get(key));
    } catch (error) {
      if (error.code !== 'JOURNAL_CONFLICT') throw error;
      const winner = requireRecord(records, key);
      if (winner.payment.state !== 'refunded'
          || winner.payment.reason !== refund.reason
          || winner.payment.refundReference !== refund.refundReference
          || winner.payment.refundAmountAtomic !== refund.refundAmountAtomic
          || winner.payment.refundExecution?.refundAttemptId !== refund.refundAttemptId) {
        throw error;
      }
      return copy(winner);
    }
  }

  function startRefund(key, { refundAttemptId = null } = {}) {
    refreshFromAuthority();
    const record = requireRecord(records, key);
    if (record.payment.state === 'refunded' || record.payment.refundExecution) {
      return { started: false, record: copy(record) };
    }
    deriveFullGrossRefundReversal(record);
    const attempt = refundAttemptId ?? `refund-attempt:${crypto.createHash('sha256')
      .update(`${record.invocationId}\n${record.payment.txHash}\n${record.quote.amountAtomic}`)
      .digest('hex')}`;
    try {
      append('refund.started', key, { refundAttemptId: requireText(attempt, 'refundAttemptId') });
      return { started: true, record: copy(records.get(key)) };
    } catch (error) {
      if (error.code !== 'JOURNAL_CONFLICT') throw error;
      const winner = requireRecord(records, key);
      if (!winner.payment.refundExecution && winner.payment.state !== 'refunded') throw error;
      return { started: false, record: copy(winner) };
    }
  }

  function markRefundUnresolved(key, input) {
    refreshFromAuthority();
    const record = requireRecord(records, key);
    const refundAttemptId = requireText(input.refundAttemptId, 'refundAttemptId');
    const reason = requireText(input.reason, 'reason');
    if (record.payment.refundExecution?.state === 'unresolved') {
      if (record.payment.refundExecution.refundAttemptId !== refundAttemptId
          || record.payment.refundExecution.reason !== reason) {
        throw new Error('Invocation already binds a different unresolved refund outcome');
      }
      return copy(record);
    }
    if (record.payment.refundExecution?.state !== 'executing'
        || record.payment.refundExecution.refundAttemptId !== refundAttemptId) {
      throw new Error('unresolved refund does not match the durable execution claim');
    }
    try {
      append('refund.unresolved', key, { refundAttemptId, reason });
      return copy(records.get(key));
    } catch (error) {
      if (error.code !== 'JOURNAL_CONFLICT') throw error;
      const winner = requireRecord(records, key);
      if (winner.payment.state === 'refunded') return copy(winner);
      if (winner.payment.refundExecution?.state === 'unresolved'
          && winner.payment.refundExecution.refundAttemptId === refundAttemptId
          && winner.payment.refundExecution.reason === reason) return copy(winner);
      throw error;
    }
  }

  function startExecution(key, { executionAttemptId = null } = {}) {
    refreshFromAuthority();
    const record = requireRecord(records, key);
    if (record.execution.state === 'executing') return { started: false, record: copy(record) };
    if (record.payment.state !== 'settled') throw new Error('external execution requires a settled payment');
    assertState(record, ['authorized'], 'startExecution');
    const attempt = executionAttemptId ?? `attempt:${crypto.createHash('sha256')
      .update(`${record.invocationId}\n${record.requestHash}`).digest('hex')}`;
    try {
      append('execution.started', key, { executionAttemptId: requireText(attempt, 'executionAttemptId') });
      return { started: true, record: copy(records.get(key)) };
    } catch (error) {
      if (error.code !== 'JOURNAL_CONFLICT') throw error;
      const winner = requireRecord(records, key);
      if (winner.execution.state === 'authorized') throw error;
      return { started: false, record: copy(winner) };
    }
  }

  function finishExecution(key, input) {
    refreshFromAuthority();
    const record = requireRecord(records, key);
    const captured = copy(input);
    const outcome = requireText(captured.outcome, 'outcome');
    if (!TERMINAL_EXECUTION.has(outcome)) throw new Error(`unsupported execution outcome '${outcome}'`);
    const data = {
      executionAttemptId: requireText(captured.executionAttemptId ?? record.execution.executionAttemptId, 'executionAttemptId'),
      outcome,
      outcomeHash: captured.outcomeHash ?? null,
      failureClass: captured.failureClass ?? null,
      message: captured.message ?? null,
      httpStatus: captured.httpStatus,
      accounting: captured.accounting ?? null,
    };
    if (TERMINAL_EXECUTION.has(record.execution.state)) {
      const terminal = { ...record.execution, accounting: record.accounting };
      const expected = { state: data.outcome, ...data };
      delete expected.outcome;
      if (!same(terminal, expected)) throw new Error('idempotency key already binds a different execution outcome');
      return copy(record);
    }
    assertState(record, ['executing'], 'finishExecution');
    append('execution.finished', key, data);
    return copy(records.get(key));
  }

  function issueReceipt(key) {
    refreshFromAuthority();
    const record = requireRecord(records, key);
    if (record.receipt) return copy(record.receipt);
    if (!TERMINAL_EXECUTION.has(record.execution.state)) {
      throw new Error('receipt requires a terminal execution outcome');
    }
    const receipt = receiptPayload(record);
    const receiptHash = crypto.createHash('sha256').update(canonicalJson(receipt)).digest('hex');
    const bundle = {
      receipt,
      receiptHash,
      signature: receiptSigner.signHash(receiptHash),
      algorithm: receiptSigner.algorithm,
      keyId: receiptSigner.keyId,
    };
    try {
      append('receipt.issued', key, { bundle });
      return copy(bundle);
    } catch (error) {
      if (error.code !== 'JOURNAL_CONFLICT') throw error;
      const winner = requireRecord(records, key);
      if (winner.receipt && same(winner.receipt, bundle)) return copy(winner.receipt);
      throw error;
    }
  }

  function recoverStaleLock({ expectedLeaseId }) {
    if (!journalPath) throw new Error('ephemeral journal has no persistent lock to recover');
    if (!LEASE_ID.test(expectedLeaseId ?? '')) {
      throw new Error('expected stale-lock lease ID must be exactly 128 lowercase bits');
    }
    const initial = readLeaseOwner(lockPath);
    if (initial.owner.leaseId !== expectedLeaseId) {
      throw new Error(`recorded lease ID ${initial.owner.leaseId} does not match expected lease ID ${expectedLeaseId}`);
    }
    if (initial.owner.hostname !== os.hostname()) {
      throw new Error(`journal lock belongs to different host ${initial.owner.hostname}`);
    }
    const alive = (lockTestHooks.isProcessAlive ?? processIsAlive)(initial.owner.pid);
    if (typeof alive !== 'boolean') throw new Error('journal lock process probe returned no boolean proof');
    if (alive) throw new Error(`journal lock PID ${initial.owner.pid} is still alive`);
    claimAndRemoveLease(lockPath, {
      expectedLeaseId,
      expectedBytes: initial.bytes,
      mismatchMessage: 'journal lock owner changed during recovery',
      hooks: lockTestHooks,
    });
  }

  if (journalPath) withLease(lockPath, syncFromDisk, lockTestHooks);
  return Object.freeze({
    requestInvocation,
    offerExternalPayment,
    recordExternalPaymentVerification,
    claimExternalPaymentSigned,
    markExternalPaymentSigned,
    markExternalPaymentSettled,
    markExternalPaymentUnresolved,
    reconcileExternalSettlement,
    rejectExternalPayment,
    startRefund,
    markRefundUnresolved,
    refundExternalPayment,
    startExecution,
    finishExecution,
    issueReceipt,
    recoverStaleLock,
    getByIdempotencyKey: (key) => {
      refreshFromAuthority();
      return records.has(key) ? copy(records.get(key)) : null;
    },
    getVerifiedPaymentHash: (key) => {
      refreshFromAuthority();
      return verifiedPaymentHashes.get(key) ?? null;
    },
    getBySettlementReference: (reference) => {
      refreshFromAuthority();
      const key = settlementReferences.get(canonicalBytes32(reference, 'settlementReference'));
      return key ? copy(records.get(key)) : null;
    },
    getByTxHash: (hash) => {
      refreshFromAuthority();
      const key = transactionHashes.get(canonicalBytes32(hash, 'txHash'));
      return key ? copy(records.get(key)) : null;
    },
    get events() { refreshFromAuthority(); return copy(eventLog); },
    signingPublicKeyPem: receiptSigner.publicKeyPem,
    signingKeyId: receiptSigner.keyId,
    isPersistent: Boolean(journalPath),
    lockPath,
  });
}
