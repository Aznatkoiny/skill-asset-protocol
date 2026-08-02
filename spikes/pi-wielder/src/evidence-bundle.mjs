import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

import {
  canonicalAtomic,
  canonicalJson,
  canonicalTimestamp,
  exactRecord,
  sha256,
} from './kernel/canonical.mjs';
import {
  receiptKeyId,
  verifySignedReceipt,
} from './kernel/receipt-signing.mjs';

const BASE_SEPOLIA = 'eip155:84532';
const BASE_SEPOLIA_USDC = '0x036cbd53842c5426634e7929541ec2318f3dcf7e';
const BUNDLE_FILES = Object.freeze([
  'README.md',
  'events.jsonl',
  'manifest.json',
  'report.md',
  'summary.json',
]);
const LISTED_FILES = Object.freeze(BUNDLE_FILES.filter((name) => name !== 'manifest.json'));
const PREFIXED_HASH = /^sha256:[0-9a-f]{64}$/;
const RAW_HASH = /^[0-9a-f]{64}$/;
const COMMIT = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;
const ADDRESS = /^0x[0-9a-f]{40}$/;
const TRANSACTION = /^0x[0-9a-f]{64}$/;
const TOKEN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$/;
const EVENT_TYPE = /^[a-z][a-z0-9_.-]{0,127}$/;
const UID_GID = /^(?:0|[1-9][0-9]*)$/;
const SIGNATURE_BYTES = 64;
const MAXIMUM_FILE_BYTES = 16 * 1024 * 1024;
const NORMALIZED_EVENT_DOMAIN = 'wallet-kernel.normalized-evidence-event.v1';
const KERNEL_IDENTITY_DOMAIN = 'wallet-kernel.kernel-identity.v1';
const AGENT_IDENTITY_DOMAIN = 'wallet-kernel.agent-identity.v1';
const PROJECTION_DOMAIN = 'wallet-kernel.projection-export.v1';
const PROJECTION_SET_DOMAIN = 'wallet-kernel.signed-projection-set.v1';
const SESSION_IDENTITY_DOMAIN = 'wallet-kernel.session-identity.v1';
const SUMMARY_DOMAIN = 'wallet-kernel.evidence-summary.v2';
const EVIDENCE_SCHEMA_VERSION = 2;
const DEPLOYMENT_DIGEST_FIELDS = Object.freeze([
  'releaseManifestDigest',
  'releaseTreeHash',
  'serviceArtifactsHash',
  'systemdEffectiveConfigHash',
]);
const DECISIONS = new Set(['allow', 'approval_required', 'deny']);
const EXPECTED_PROBES = Object.freeze({
  authorityDirectory: 'EACCES',
  database: 'EACCES',
  operatorToken: 'EACCES',
  receiptKey: 'EACCES',
  kernelEnvironment: 'EACCES',
  agentCredential: 'READABLE',
  releaseTreeWrite: 'EACCES',
  dependencyTreeWrite: 'EACCES',
  serviceArtifactsWrite: 'EACCES',
  kernelEnvironmentParentWrite: 'EACCES',
});

export class EvidenceError extends Error {
  constructor(code, message, options) {
    super(message, options);
    this.name = 'EvidenceError';
    this.code = code;
  }
}

function fail(code, message, cause) {
  throw new EvidenceError(code, message, cause ? { cause } : undefined);
}

function capture(value, required, optional, code, label) {
  try {
    return exactRecord(value, required, optional, code, label);
  } catch (cause) {
    if (cause?.code === code) throw new EvidenceError(code, cause.message, { cause });
    fail(code, `${label} fields do not match the closed schema`, cause);
  }
}

function prefixedHash(value, label, code = 'EVIDENCE_SCHEMA') {
  if (typeof value !== 'string' || !PREFIXED_HASH.test(value)) {
    fail(code, `${label} must be one canonical SHA-256 hash`);
  }
  return value;
}

function rawHash(value, label, code = 'EVIDENCE_SCHEMA') {
  if (typeof value !== 'string' || !RAW_HASH.test(value)) {
    fail(code, `${label} must be 64 lowercase hexadecimal characters`);
  }
  return value;
}

function timestamp(value, label, code = 'EVIDENCE_SCHEMA') {
  try {
    return canonicalTimestamp(value, label);
  } catch (cause) {
    fail(code, `${label} must be one canonical timestamp`, cause);
  }
}

function atomic(value, label, code = 'EVIDENCE_SCHEMA') {
  try {
    return canonicalAtomic(value, label);
  } catch (cause) {
    fail(code, `${label} must be canonical atomic text`, cause);
  }
}

function identity(value, label) {
  if (typeof value !== 'string' || !UID_GID.test(value)) {
    fail('EVIDENCE_IDENTITY', `${label} must be canonical nonnegative decimal text`);
  }
  const number = Number(value);
  if (!Number.isSafeInteger(number) || String(number) !== value) {
    fail('EVIDENCE_IDENTITY', `${label} must round-trip through one safe integer`);
  }
  return value;
}

function canonicalSignature(value, label, code) {
  if (typeof value !== 'string') fail(code, `${label} must be canonical Ed25519 bytes`);
  let bytes;
  try {
    bytes = Buffer.from(value, 'base64');
  } catch (cause) {
    fail(code, `${label} must be canonical Ed25519 bytes`, cause);
  }
  if (bytes.length !== SIGNATURE_BYTES || bytes.toString('base64') !== value) {
    fail(code, `${label} must be canonical Ed25519 bytes`);
  }
  return bytes;
}

function rawSha256(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function isPlainData(value, ancestors = new Set()) {
  if (value === null || ['string', 'boolean', 'number'].includes(typeof value)) return true;
  if (!value || typeof value !== 'object' || ancestors.has(value)) return false;
  const expectedPrototype = Array.isArray(value) ? Array.prototype : Object.prototype;
  if (Object.getPrototypeOf(value) !== expectedPrototype) return false;
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => typeof key !== 'string')) return false;
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      const length = descriptors.length;
      if (!length || length.enumerable || !Object.hasOwn(length, 'value')
          || keys.length !== value.length + 1) return false;
      for (let index = 0; index < value.length; index += 1) {
        const descriptor = descriptors[String(index)];
        if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')
            || !isPlainData(descriptor.value, ancestors)) return false;
      }
      return true;
    }
    return keys.every((key) => {
      const descriptor = descriptors[key];
      return descriptor?.enumerable && Object.hasOwn(descriptor, 'value')
        && isPlainData(descriptor.value, ancestors);
    });
  } finally {
    ancestors.delete(value);
  }
}

function forbiddenField(name, fieldPath) {
  const compact = name.toLowerCase().replace(/[^a-z0-9]/g, '');
  if (compact.endsWith('hash') || compact.endsWith('digest')) return false;
  if (compact === 'signature') {
    return !/(?:^\$|\.signedProjections\.[0-9]+|\.signedReceipts\.[0-9]+|\.receipts\.[0-9]+)\.signature$/.test(fieldPath);
  }
  return [
    'body', 'requestbody', 'responsebody', 'rawbody', 'prompt', 'prompttext',
    'rawrequest', 'rawresponse', 'paymentpayload', 'paymentheader',
    'paymentsignature', 'authorization', 'payload', 'header', 'content',
    'rawdata', 'datajson', 'metadatajson', 'rawevidence',
    'agentcredential', 'agenttoken',
    'operatortoken', 'operatoridentity', 'providerexception', 'providererror',
    'operatorid', 'operatorname', 'operatoruid', 'operatorgid',
    'uid', 'gid', 'kerneluid', 'kernelgid', 'agentuid', 'agentgid',
    'exception', 'stack', 'filepath', 'localpath', 'privatekey',
  ].includes(compact);
}

function assertSanitized(value, valuePath = '$', ancestors = new Set()) {
  if (typeof value === 'string') {
    if (Buffer.byteLength(value, 'utf8') > 65_536
        || /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/.test(value)
        || /(?:^|[\s"'(=])(?:file:\/\/|\/(?:Users|home|private|tmp|var|etc|opt|root|proc|sys|dev)\/|[A-Za-z]:\\)/i.test(value)
        || /\bBearer\s+[A-Za-z0-9._~+\/-]{8,}={0,2}\b/i.test(value)
        || /\bPAYMENT-SIGNATURE\s*:/i.test(value)
        || (/^[A-Za-z0-9_-]{40,256}$/.test(value) && /[g-zG-Z_-]/.test(value)
          && !/^0x[0-9a-f]{40,64}$/.test(value)
          && !/(?:\.signature|\.receiptSignature|\.publicKeyPem)$/.test(valuePath))) {
      fail('EVIDENCE_SANITIZATION', 'evidence contains forbidden source material');
    }
    return;
  }
  if (value === null || ['boolean', 'number'].includes(typeof value)) return;
  if (!value || typeof value !== 'object' || ancestors.has(value)) {
    fail('EVIDENCE_SANITIZATION', 'evidence must be an acyclic plain data graph');
  }
  ancestors.add(value);
  try {
    for (const [key, child] of Object.entries(value)) {
      const fieldPath = `${valuePath}.${key}`;
      if (forbiddenField(key, fieldPath)) {
        fail('EVIDENCE_SANITIZATION', `evidence field ${valuePath}.${key} is forbidden`);
      }
      assertSanitized(child, fieldPath, ancestors);
    }
  } finally {
    ancestors.delete(value);
  }
}

function parsePublicKey(value, label) {
  const key = capture(
    value,
    ['keyId', 'algorithm', 'publicKeyPem'],
    [],
    'EVIDENCE_KEY_SCHEMA',
    label,
  );
  if (key.algorithm !== 'Ed25519' || typeof key.publicKeyPem !== 'string') {
    fail('EVIDENCE_KEY_SCHEMA', `${label} must contain one Ed25519 public key`);
  }
  let publicKey;
  try {
    publicKey = crypto.createPublicKey(key.publicKeyPem);
  } catch (cause) {
    fail('EVIDENCE_KEY_SCHEMA', `${label} public key is invalid`, cause);
  }
  const canonicalPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
  if (publicKey.asymmetricKeyType !== 'ed25519'
      || canonicalPem !== key.publicKeyPem
      || receiptKeyId(publicKey) !== key.keyId) {
    fail('EVIDENCE_KEY_SCHEMA', `${label} key ID or encoding is invalid`);
  }
  return Object.freeze({ ...key, publicKey });
}

function normalizeKeys(value) {
  if (!Array.isArray(value) || value.length === 0 || value.length > 32) {
    fail('EVIDENCE_KEY_SCHEMA', 'receipt keys must be one bounded nonempty array');
  }
  const parsed = value.map((item, index) => parsePublicKey(item, `receipt key ${index}`));
  parsed.sort((left, right) => left.keyId.localeCompare(right.keyId));
  if (new Set(parsed.map(({ keyId }) => keyId)).size !== parsed.length) {
    fail('EVIDENCE_KEY_SCHEMA', 'receipt key IDs must be unique');
  }
  return parsed;
}

function publicKeysOnly(keys) {
  return keys.map(({ keyId, algorithm, publicKeyPem }) => ({ keyId, algorithm, publicKeyPem }));
}

function validateReceiptRecord(value, keyMap) {
  const record = capture(value, [
    'id', 'intentId', 'revision', 'receipt', 'receiptHash', 'signature', 'algorithm',
    'keyId', 'supersedesReceiptHash', 'createdAt',
  ], [], 'EVIDENCE_RECEIPT_SCHEMA', 'signed receipt');
  if (typeof record.id !== 'string' || !TOKEN.test(record.id)
      || typeof record.intentId !== 'string' || !TOKEN.test(record.intentId)
      || !Number.isSafeInteger(record.revision) || record.revision < 1
      || record.algorithm !== 'Ed25519'
      || (record.supersedesReceiptHash !== null
        && (typeof record.supersedesReceiptHash !== 'string'
          || !RAW_HASH.test(record.supersedesReceiptHash)))) {
    fail('EVIDENCE_RECEIPT_SCHEMA', 'signed receipt fields are invalid');
  }
  rawHash(record.receiptHash, 'signed receipt hash', 'EVIDENCE_RECEIPT_SCHEMA');
  canonicalSignature(record.signature, 'signed receipt signature', 'EVIDENCE_RECEIPT_SIGNATURE');
  timestamp(record.createdAt, 'signed receipt createdAt', 'EVIDENCE_RECEIPT_SCHEMA');
  if (!isPlainData(record.receipt)) {
    fail('EVIDENCE_RECEIPT_SCHEMA', 'signed receipt projection is not plain data');
  }
  const receipt = record.receipt;
  if (receipt.receiptId !== record.id || receipt.revision !== record.revision
      || receipt.supersedesReceiptHash !== record.supersedesReceiptHash
      || receipt.intent?.id !== record.intentId) {
    fail('EVIDENCE_RECEIPT_REVISION', 'signed receipt envelope and projection disagree');
  }
  const key = keyMap.get(record.keyId);
  if (!key || !verifySignedReceipt(record, key)) {
    fail('EVIDENCE_RECEIPT_SIGNATURE', 'signed receipt did not verify against the manifest key');
  }
  assertSanitized(record);
  return record;
}

function validateReceipts(value, keys) {
  if (!Array.isArray(value) || value.length > 10_000) {
    fail('EVIDENCE_RECEIPT_SCHEMA', 'signed receipts must be one bounded array');
  }
  const keyMap = new Map(keys.map((key) => [key.keyId, key]));
  const records = value.map((record) => validateReceiptRecord(record, keyMap));
  records.sort((left, right) => left.intentId.localeCompare(right.intentId)
    || left.revision - right.revision || left.id.localeCompare(right.id));
  const seenIds = new Set();
  const seenHashes = new Set();
  const previousByIntent = new Map();
  for (const record of records) {
    if (seenIds.has(record.id) || seenHashes.has(record.receiptHash)) {
      fail('EVIDENCE_RECEIPT_REVISION', 'signed receipt IDs and hashes must be unique');
    }
    const previous = previousByIntent.get(record.intentId) ?? null;
    if ((previous === null && (record.revision !== 1 || record.supersedesReceiptHash !== null))
        || (previous !== null && (record.revision !== previous.revision + 1
          || record.supersedesReceiptHash !== previous.receiptHash))) {
      fail('EVIDENCE_RECEIPT_REVISION', 'signed receipt revision requires its exact predecessor');
    }
    seenIds.add(record.id);
    seenHashes.add(record.receiptHash);
    previousByIntent.set(record.intentId, record);
  }
  return records;
}

function latestReceiptFinancialMetrics(receipts) {
  const latestByIntent = new Map();
  for (const receipt of receipts) latestByIntent.set(receipt.intentId, receipt);
  let settledGross = 0n;
  let confirmedRefund = 0n;
  let unresolvedExposure = 0n;
  for (const { receipt } of latestByIntent.values()) {
    if (receipt.payment?.state === 'settled') {
      settledGross += atomic(
        receipt.payment.amountAtomic,
        'latest receipt settled amount',
        'EVIDENCE_FINANCIAL_METRICS',
      ).value;
    }
    if (receipt.refund?.state === 'confirmed') {
      confirmedRefund += atomic(
        receipt.refund.amountAtomic,
        'latest receipt confirmed refund amount',
        'EVIDENCE_FINANCIAL_METRICS',
      ).value;
    }
    if (receipt.budget?.disposition === 'unresolved') {
      unresolvedExposure += atomic(
        receipt.budget.amountAtomic,
        'latest receipt unresolved exposure',
        'EVIDENCE_FINANCIAL_METRICS',
      ).value;
    }
  }
  return {
    latestReceiptSettledGrossAtomic: settledGross.toString(10),
    latestReceiptConfirmedRefundAtomic: confirmedRefund.toString(10),
    latestReceiptUnresolvedExposureAtomic: unresolvedExposure.toString(10),
  };
}

function verifyProjection(value, manifest, keys) {
  const bundle = capture(value, [
    'schemaVersion', 'domain', 'projection', 'algorithm', 'keyId', 'publicKeyPem',
    'projectionHash', 'signature',
  ], [], 'EVIDENCE_PROJECTION_SCHEMA', 'signed authority projection');
  if (bundle.schemaVersion !== 1 || bundle.domain !== PROJECTION_DOMAIN
      || bundle.algorithm !== 'Ed25519' || !isPlainData(bundle.projection)) {
    fail('EVIDENCE_PROJECTION_SCHEMA', 'signed authority projection fields are invalid');
  }
  assertSanitized(bundle);
  const key = keys.find(({ keyId }) => keyId === bundle.keyId);
  if (!key || bundle.publicKeyPem !== key.publicKeyPem) {
    fail('EVIDENCE_PROJECTION_SIGNATURE', 'projection signer is not anchored by the manifest');
  }
  const unsigned = {
    schemaVersion: bundle.schemaVersion,
    domain: bundle.domain,
    projection: bundle.projection,
    algorithm: bundle.algorithm,
    keyId: bundle.keyId,
    publicKeyPem: bundle.publicKeyPem,
  };
  const projectionHash = sha256(canonicalJson(unsigned));
  const signature = canonicalSignature(
    bundle.signature,
    'authority projection signature',
    'EVIDENCE_PROJECTION_SIGNATURE',
  );
  if (bundle.projectionHash !== projectionHash
      || !crypto.verify(
        null,
        Buffer.from(projectionHash.slice('sha256:'.length), 'hex'),
        key.publicKey,
        signature,
      )) {
    fail('EVIDENCE_PROJECTION_SIGNATURE', 'signed authority projection is invalid');
  }
  const projection = bundle.projection;
  timestamp(projection.issuedAt, 'projection issuedAt', 'EVIDENCE_PROJECTION_SCHEMA');
  if (Date.parse(projection.issuedAt) > Date.parse(manifest.createdAt)
      || projection.eventHeadHash !== manifest.source.authorityEventHeadHash
      || projection.wallet?.address !== manifest.wallet.address
      || projection.policies?.activePolicyHash !== manifest.inputs.policyHash
      || projection.agentEnrollment?.identityHash !== manifest.isolation.agentIdentityHash
      || projection.isolation?.status !== manifest.isolation.status
      || projection.isolation?.preflightDigest !== manifest.isolation.preflightDigest) {
    fail('EVIDENCE_PROJECTION_BINDING', 'signed projection does not bind the evidence manifest');
  }
  prefixedHash(
    projection.sessionHash,
    'projection session hash',
    'EVIDENCE_PROJECTION_BINDING',
  );
  const projectionReceipts = validateReceipts(projection.signedReceipts, keys);
  if (canonicalJson(projection.signedReceipts) !== canonicalJson(projectionReceipts)) {
    fail('EVIDENCE_PROJECTION_BINDING', 'projection receipts are not canonically ordered');
  }
  assertSanitized(bundle);
  return Object.freeze({ bundle, receipts: projectionReceipts });
}

function projectionSetHash(projections) {
  return sha256(canonicalJson({
    schemaVersion: 1,
    domain: PROJECTION_SET_DOMAIN,
    signedProjections: projections,
  }));
}

function receiptSessionHash(receipt) {
  const sessionId = receipt?.receipt?.intent?.sessionId;
  if (typeof sessionId !== 'string' || !TOKEN.test(sessionId)) {
    fail('EVIDENCE_PROJECTION_PARTITION', 'receipt session ownership is invalid');
  }
  return sha256(canonicalJson({ domain: SESSION_IDENTITY_DOMAIN, sessionId }));
}

function verifyProjectionSet(value, manifest, keys, receipts) {
  if (!Array.isArray(value) || value.length === 0 || value.length > 10_000) {
    fail('EVIDENCE_PROJECTION_SCHEMA', 'signed projections must be one bounded nonempty array');
  }
  const verified = value.map((projection) => verifyProjection(projection, manifest, keys));
  const sorted = [...verified].sort((left, right) => (
    left.bundle.projection.sessionHash.localeCompare(right.bundle.projection.sessionHash)
  ));
  if (canonicalJson(verified.map(({ bundle }) => bundle))
      !== canonicalJson(sorted.map(({ bundle }) => bundle))) {
    fail('EVIDENCE_PROJECTION_BINDING', 'signed projections are not canonically ordered');
  }
  const sessionHashes = sorted.map(({ bundle }) => bundle.projection.sessionHash);
  const projectionHashes = sorted.map(({ bundle }) => bundle.projectionHash);
  if (new Set(sessionHashes).size !== sorted.length
      || new Set(projectionHashes).size !== sorted.length) {
    fail('EVIDENCE_PROJECTION_PARTITION', 'signed projection identities must be unique');
  }
  const bundles = sorted.map(({ bundle }) => bundle);
  if (manifest.source.signedProjectionHash !== projectionSetHash(bundles)) {
    fail('EVIDENCE_PROJECTION_SIGNATURE', 'signed projection aggregate is invalid');
  }
  const partition = [];
  const seenReceiptHashes = new Set();
  for (const { bundle, receipts: projectionReceipts } of sorted) {
    for (const receipt of projectionReceipts) {
      if (receiptSessionHash(receipt) !== bundle.projection.sessionHash
          || seenReceiptHashes.has(receipt.receiptHash)) {
        fail('EVIDENCE_PROJECTION_PARTITION', 'receipt does not belong to exactly one session projection');
      }
      seenReceiptHashes.add(receipt.receiptHash);
      partition.push(receipt);
    }
  }
  const canonicalPartition = validateReceipts(partition, keys);
  if (canonicalJson(canonicalPartition) !== canonicalJson(receipts)) {
    fail('EVIDENCE_PROJECTION_PARTITION', 'session projections do not exactly cover authority receipts');
  }
  const usedKeyIds = new Set([
    ...bundles.map(({ keyId }) => keyId),
    ...receipts.map(({ keyId }) => keyId),
  ]);
  if (usedKeyIds.size !== keys.length || keys.some(({ keyId }) => !usedKeyIds.has(keyId))) {
    fail('EVIDENCE_PROJECTION_BINDING', 'manifest receipt keys must be the exact used key set');
  }
  return bundles;
}

function identityHash(role, pair) {
  const record = capture(pair, ['uid', 'gid'], [], 'EVIDENCE_IDENTITY', `${role} identity`);
  const uid = identity(record.uid, `${role} UID`);
  const gid = identity(record.gid, `${role} GID`);
  const domain = role === 'kernel' ? KERNEL_IDENTITY_DOMAIN : AGENT_IDENTITY_DOMAIN;
  const names = role === 'kernel'
    ? { kernelUid: uid, kernelGid: gid }
    : { agentUid: uid, agentGid: gid };
  return { hash: sha256(canonicalJson({ domain, ...names })), uid, gid };
}

function validateGit(value, mode) {
  const git = capture(value, ['commit', 'dirty'], [], 'EVIDENCE_SCHEMA', 'Git evidence');
  if (typeof git.commit !== 'string' || !COMMIT.test(git.commit) || typeof git.dirty !== 'boolean') {
    fail('EVIDENCE_SCHEMA', 'Git evidence is invalid');
  }
  if (mode === 'base-sepolia-testnet' && git.dirty !== false) {
    fail('EVIDENCE_MODE_GATE', 'testnet evidence requires one clean attested release');
  }
  return git;
}

function validateRuntime(value, mode) {
  const runtime = capture(
    value,
    ['nodeVersion', 'piVersion'],
    [],
    'EVIDENCE_SCHEMA',
    'runtime evidence',
  );
  if (typeof runtime.nodeVersion !== 'string' || !/^v[0-9]+\.[0-9]+\.[0-9]+$/.test(runtime.nodeVersion)
      || runtime.piVersion !== '0.80.6') {
    fail('EVIDENCE_SCHEMA', 'runtime versions are invalid');
  }
  if (mode === 'base-sepolia-testnet' && runtime.nodeVersion !== 'v24.18.1') {
    fail('EVIDENCE_MODE_GATE', 'testnet evidence requires the attested Node v24.18.1 runtime');
  }
  return runtime;
}

function validateProtocol(value) {
  const protocol = capture(value, [
    'x402Version', 'network', 'asset',
  ], [], 'EVIDENCE_SCHEMA', 'protocol evidence');
  if (protocol.x402Version !== 2 || protocol.network !== BASE_SEPOLIA
      || protocol.asset !== BASE_SEPOLIA_USDC) {
    fail('EVIDENCE_SCHEMA', 'only x402 v2 and canonical Base Sepolia USDC are supported');
  }
  return protocol;
}

function validateWallet(value, mode) {
  const wallet = capture(
    value,
    ['provider', 'walletIdHash', 'address'],
    [],
    'EVIDENCE_SCHEMA',
    'wallet evidence',
  );
  if (typeof wallet.provider !== 'string' || !TOKEN.test(wallet.provider)) {
    fail('EVIDENCE_SCHEMA', 'wallet provider is invalid');
  }
  prefixedHash(wallet.walletIdHash, 'wallet ID hash');
  if (typeof wallet.address !== 'string' || !ADDRESS.test(wallet.address)) {
    fail('EVIDENCE_SCHEMA', 'wallet address must be one canonical lowercase EVM address');
  }
  if ((mode === 'offline-deterministic' && wallet.provider !== 'deterministic')
      || (mode === 'base-sepolia-testnet' && wallet.provider !== 'cdp')) {
    fail('EVIDENCE_MODE_GATE', 'wallet provider does not match evidence mode');
  }
  return wallet;
}

function validateIsolation(value, identities) {
  const isolation = capture(value, [
    'status', 'preflightDigest', 'kernelIdentityHash', 'agentIdentityHash',
  ], [], 'EVIDENCE_SCHEMA', 'isolation evidence');
  if (!['simulated', 'enforced'].includes(isolation.status)
      || (isolation.preflightDigest !== null
        && (typeof isolation.preflightDigest !== 'string'
          || !PREFIXED_HASH.test(isolation.preflightDigest)))) {
    fail('EVIDENCE_SCHEMA', 'isolation status or digest is invalid');
  }
  prefixedHash(isolation.kernelIdentityHash, 'Kernel identity hash');
  prefixedHash(isolation.agentIdentityHash, 'Agent identity hash');
  if (isolation.kernelIdentityHash !== identities.kernel.hash
      || isolation.agentIdentityHash !== identities.agent.hash) {
    fail('EVIDENCE_IDENTITY', 'identity hashes do not match the pinned UID and GID pairs');
  }
  if (isolation.kernelIdentityHash === isolation.agentIdentityHash) {
    fail('EVIDENCE_IDENTITY', 'Kernel and Agent evidence identities must be domain-separated');
  }
  return isolation;
}

function validateDeployment(value) {
  const deployment = capture(value, [
    'status', 'releaseManifestDigest', 'releaseTreeHash', 'serviceArtifactsHash',
    'systemdEffectiveConfigHash',
  ], [], 'EVIDENCE_SCHEMA', 'deployment evidence');
  if (!['simulated', 'enforced'].includes(deployment.status)) {
    fail('EVIDENCE_SCHEMA', 'deployment status is invalid');
  }
  for (const name of [
    'releaseManifestDigest', 'releaseTreeHash', 'serviceArtifactsHash',
    'systemdEffectiveConfigHash',
  ]) {
    if (deployment[name] !== null) prefixedHash(deployment[name], `deployment ${name}`);
  }
  return deployment;
}

function validateInputs(value) {
  const inputs = capture(
    value,
    ['policyHash', 'routeMapHash', 'configHash'],
    [],
    'EVIDENCE_SCHEMA',
    'evidence inputs',
  );
  for (const [name, digest] of Object.entries(inputs)) prefixedHash(digest, name);
  return inputs;
}

function validateStatus(value) {
  const status = capture(value, [
    'liveCdp', 'walletFunded', 'testnetTransaction',
  ], [], 'EVIDENCE_SCHEMA', 'evidence status');
  if (!['not-run', 'passed'].includes(status.liveCdp)
      || !['not-run', 'sufficient'].includes(status.walletFunded)
      || !['not-run', 'settled'].includes(status.testnetTransaction)) {
    fail('EVIDENCE_SCHEMA', 'evidence status values are invalid');
  }
  return status;
}

function validatePrivilegedReport(value, context) {
  const report = capture(value, [
    'schemaVersion', 'enrollmentHash', 'kernelUid', 'kernelGid', 'agentUid', 'agentGid',
    'authorityMetadataHash', 'credentialMetadataHash', 'releaseManifestHash',
    'releaseTreeHash', 'nodeExecutableHash', 'serviceArtifactsHash',
    'systemdEffectiveConfigHash', 'environmentMetadataHash', 'probeResults',
    'probedAt', 'expiresAt',
  ], [], 'EVIDENCE_PREFLIGHT', 'privileged isolation report');
  if (report.schemaVersion !== 1) fail('EVIDENCE_PREFLIGHT', 'privileged report schema is invalid');
  for (const name of ['kernelUid', 'kernelGid', 'agentUid', 'agentGid']) {
    identity(report[name], `privileged report ${name}`);
  }
  for (const name of [
    'enrollmentHash', 'authorityMetadataHash', 'credentialMetadataHash',
    'releaseManifestHash', 'releaseTreeHash', 'nodeExecutableHash',
    'serviceArtifactsHash', 'systemdEffectiveConfigHash', 'environmentMetadataHash',
  ]) prefixedHash(report[name], `privileged report ${name}`, 'EVIDENCE_PREFLIGHT');
  const probes = capture(
    report.probeResults,
    Object.keys(EXPECTED_PROBES),
    [],
    'EVIDENCE_PREFLIGHT',
    'privileged isolation probes',
  );
  if (Object.entries(EXPECTED_PROBES).some(([name, result]) => probes[name] !== result)) {
    fail('EVIDENCE_PREFLIGHT', 'privileged isolation probes are not enforced');
  }
  const probedAt = timestamp(report.probedAt, 'privileged report probedAt', 'EVIDENCE_PREFLIGHT');
  const expiresAt = timestamp(report.expiresAt, 'privileged report expiresAt', 'EVIDENCE_PREFLIGHT');
  const lifetime = Date.parse(expiresAt) - Date.parse(probedAt);
  if (lifetime <= 0 || lifetime > 15 * 60 * 1_000
      || Date.parse(context.createdAt) < Date.parse(probedAt)
      || Date.parse(context.createdAt) >= Date.parse(expiresAt)
      || report.kernelUid !== context.identities.kernel.uid
      || report.kernelGid !== context.identities.kernel.gid
      || report.agentUid !== context.identities.agent.uid
      || report.agentGid !== context.identities.agent.gid
      || sha256(canonicalJson(report)) !== context.isolation.preflightDigest
      || report.releaseManifestHash !== context.deployment.releaseManifestDigest
      || report.releaseTreeHash !== context.deployment.releaseTreeHash
      || report.serviceArtifactsHash !== context.deployment.serviceArtifactsHash
      || report.systemdEffectiveConfigHash !== context.deployment.systemdEffectiveConfigHash) {
    fail('EVIDENCE_PREFLIGHT', 'privileged report is expired or disagrees with deployment evidence');
  }
  return {
    preflightDigest: context.isolation.preflightDigest,
    enrollmentHash: report.enrollmentHash,
    probedAt,
    expiresAt,
    releaseManifestDigest: report.releaseManifestHash,
    releaseTreeHash: report.releaseTreeHash,
    serviceArtifactsHash: report.serviceArtifactsHash,
    systemdEffectiveConfigHash: report.systemdEffectiveConfigHash,
  };
}

function validateMode(context, privilegedReport) {
  const nullDeployment = DEPLOYMENT_DIGEST_FIELDS
    .every((name) => context.deployment[name] === null);
  if (context.mode === 'offline-deterministic') {
    if (context.isolation.status !== 'simulated' || context.isolation.preflightDigest !== null
        || context.deployment.status !== 'simulated' || !nullDeployment
        || privilegedReport !== null
        || Object.values(context.status).some((state) => state !== 'not-run')) {
      fail('EVIDENCE_MODE_GATE', 'offline evidence must keep isolation, deployment, and live status simulated');
    }
    return null;
  }
  if (context.isolation.status !== 'enforced' || context.isolation.preflightDigest === null
      || context.deployment.status !== 'enforced' || nullDeployment
      || DEPLOYMENT_DIGEST_FIELDS.some((name) => context.deployment[name] === null)
      || context.status.liveCdp !== 'passed'
      || context.status.walletFunded !== 'sufficient'
      || context.status.testnetTransaction !== 'settled'
      || privilegedReport === null) {
    fail('EVIDENCE_MODE_GATE', 'testnet evidence requires every isolation and deployment gate');
  }
  return validatePrivilegedReport(privilegedReport, context);
}

function validateManifestInput(value) {
  const input = capture(value, [
    'schemaVersion', 'createdAt', 'mode', 'git', 'runtime', 'protocol', 'wallet',
    'isolation', 'deployment', 'inputs', 'source', 'status', 'identityBindings',
    'privilegedReport', 'signedProjections',
  ], [], 'EVIDENCE_BUILD_INPUT', 'evidence manifest input');
  if (input.schemaVersion !== EVIDENCE_SCHEMA_VERSION
      || !['offline-deterministic', 'base-sepolia-testnet'].includes(input.mode)) {
    fail('EVIDENCE_SCHEMA', 'evidence schema version or mode is invalid');
  }
  const createdAt = timestamp(input.createdAt, 'evidence createdAt');
  const identityBindings = capture(input.identityBindings, [
    'kernel', 'agent',
  ], [], 'EVIDENCE_IDENTITY', 'identity bindings');
  const identities = {
    kernel: identityHash('kernel', identityBindings.kernel),
    agent: identityHash('agent', identityBindings.agent),
  };
  const git = validateGit(input.git, input.mode);
  const runtime = validateRuntime(input.runtime, input.mode);
  const protocol = validateProtocol(input.protocol);
  const wallet = validateWallet(input.wallet, input.mode);
  const isolation = validateIsolation(input.isolation, identities);
  const deployment = validateDeployment(input.deployment);
  const inputs = validateInputs(input.inputs);
  const source = capture(input.source, [
    'authorityEventHeadHash', 'signedProjectionHash', 'receiptKeys',
  ], [], 'EVIDENCE_SCHEMA', 'evidence source');
  prefixedHash(source.authorityEventHeadHash, 'authority event head hash');
  prefixedHash(source.signedProjectionHash, 'signed projection hash');
  const keys = normalizeKeys(source.receiptKeys);
  const status = validateStatus(input.status);
  const context = {
    mode: input.mode,
    createdAt,
    identities,
    isolation,
    deployment,
    status,
  };
  const isolationAttestation = validateMode(context, input.privilegedReport);
  const manifest = {
    schemaVersion: EVIDENCE_SCHEMA_VERSION,
    createdAt,
    mode: input.mode,
    git,
    runtime,
    protocol,
    wallet,
    isolation,
    deployment,
    inputs,
    source: {
      authorityEventHeadHash: source.authorityEventHeadHash,
      signedProjectionHash: source.signedProjectionHash,
      receiptKeys: publicKeysOnly(keys),
    },
    status,
  };
  assertSanitized(manifest);
  return { manifest, keys, isolationAttestation, signedProjections: input.signedProjections };
}

function normalizeSourceEvent(value) {
  const event = capture(value, [
    'sequence', 'eventType', 'entityHash', 'decision', 'amountAtomic',
    'transactionId', 'receiptHash', 'receiptSignature',
  ], [], 'EVIDENCE_EVENT_SCHEMA', 'normalized source event');
  if (!Number.isSafeInteger(event.sequence) || event.sequence < 1
      || typeof event.eventType !== 'string' || !EVENT_TYPE.test(event.eventType)) {
    fail('EVIDENCE_EVENT_SCHEMA', 'normalized event sequence or type is invalid');
  }
  prefixedHash(event.entityHash, 'normalized event entity hash', 'EVIDENCE_EVENT_SCHEMA');
  if (event.decision !== null && !DECISIONS.has(event.decision)) {
    fail('EVIDENCE_EVENT_SCHEMA', 'normalized event decision is invalid');
  }
  if (event.amountAtomic !== null) atomic(
    event.amountAtomic,
    'normalized event amount',
    'EVIDENCE_EVENT_SCHEMA',
  );
  if (event.transactionId !== null
      && (typeof event.transactionId !== 'string' || !TRANSACTION.test(event.transactionId))) {
    fail('EVIDENCE_EVENT_SCHEMA', 'normalized event transaction is invalid');
  }
  const hasReceipt = event.receiptHash !== null || event.receiptSignature !== null;
  if (hasReceipt !== (event.receiptHash !== null && event.receiptSignature !== null)
      || hasReceipt !== (event.eventType === 'receipt.issued')) {
    fail('EVIDENCE_EVENT_SCHEMA', 'receipt evidence must appear only on receipt issuance');
  }
  if (hasReceipt) {
    rawHash(event.receiptHash, 'normalized receipt hash', 'EVIDENCE_EVENT_SCHEMA');
    canonicalSignature(
      event.receiptSignature,
      'normalized receipt signature',
      'EVIDENCE_EVENT_SCHEMA',
    );
  }
  assertSanitized(event);
  return event;
}

function buildNormalizedEvents(value, receipts) {
  if (!Array.isArray(value) || value.length === 0 || value.length > 100_000) {
    fail('EVIDENCE_EVENT_SCHEMA', 'normalized source events must be one bounded nonempty array');
  }
  const source = value.map(normalizeSourceEvent).sort((left, right) => left.sequence - right.sequence);
  if (source.some((event, index) => event.sequence !== index + 1)) {
    fail('EVIDENCE_EVENT_SCHEMA', 'normalized source event sequences must be contiguous from one');
  }
  let previousHash = null;
  const events = source.map((event) => {
    const unsigned = {
      schemaVersion: 1,
      domain: NORMALIZED_EVENT_DOMAIN,
      ...event,
      previousHash,
    };
    const eventHash = sha256(canonicalJson(unsigned));
    previousHash = eventHash;
    return { ...event, previousHash: unsigned.previousHash, eventHash };
  });
  verifyReceiptEventParity(events, receipts);
  return events;
}

function verifyReceiptEventParity(events, receipts) {
  const byHash = new Map(receipts.map((receipt) => [receipt.receiptHash, receipt]));
  const seen = new Set();
  for (const event of events) {
    if (event.receiptHash === null) continue;
    const receipt = byHash.get(event.receiptHash);
    if (!receipt || receipt.signature !== event.receiptSignature || seen.has(event.receiptHash)) {
      fail('EVIDENCE_RECEIPT_EVENT', 'normalized receipt event disagrees with signed receipts');
    }
    seen.add(event.receiptHash);
  }
  if (seen.size !== receipts.length) {
    fail('EVIDENCE_RECEIPT_EVENT', 'each signed receipt requires one normalized issuance event');
  }
}

function replayEvents(events) {
  let previousHash = null;
  let previousSequence = 0;
  let decisions = 0;
  const transactions = [];
  const transactionSet = new Set();
  for (const event of events) {
    const normalized = capture(event, [
      'sequence', 'eventType', 'entityHash', 'decision', 'amountAtomic',
      'transactionId', 'receiptHash', 'receiptSignature', 'previousHash', 'eventHash',
    ], [], 'EVIDENCE_EVENT_CHAIN', 'stored normalized event');
    const source = normalizeSourceEvent({
      sequence: normalized.sequence,
      eventType: normalized.eventType,
      entityHash: normalized.entityHash,
      decision: normalized.decision,
      amountAtomic: normalized.amountAtomic,
      transactionId: normalized.transactionId,
      receiptHash: normalized.receiptHash,
      receiptSignature: normalized.receiptSignature,
    });
    const expectedHash = sha256(canonicalJson({
      schemaVersion: 1,
      domain: NORMALIZED_EVENT_DOMAIN,
      ...source,
      previousHash,
    }));
    if (source.sequence !== previousSequence + 1 || normalized.previousHash !== previousHash
        || normalized.eventHash !== expectedHash) {
      fail('EVIDENCE_EVENT_CHAIN', 'normalized evidence chain is invalid');
    }
    previousSequence = source.sequence;
    previousHash = expectedHash;
    if (source.decision !== null) decisions += 1;
    if (source.transactionId !== null) {
      if (transactionSet.has(source.transactionId)) {
        fail('EVIDENCE_TRANSACTION_REUSE', 'normalized transaction IDs must be unique');
      }
      transactionSet.add(source.transactionId);
      transactions.push(source.transactionId);
    }
  }
  return {
    eventCount: events.length,
    decisionCount: decisions,
    transactionCount: transactions.length,
    transactionIds: transactions,
    normalizedEvidenceHeadHash: previousHash,
  };
}

function summaryFor({ manifest, events, receipts, signedProjections, isolationAttestation }) {
  const replay = replayEvents(events);
  return {
    schemaVersion: EVIDENCE_SCHEMA_VERSION,
    domain: SUMMARY_DOMAIN,
    ...replay,
    ...latestReceiptFinancialMetrics(receipts),
    authorityEventHeadHash: manifest.source.authorityEventHeadHash,
    signedProjections,
    receipts,
    isolationAttestation,
  };
}

function reportFor(manifest, summary) {
  return [
    '# Wallet Kernel Evidence Report',
    '',
    `- Mode: ${manifest.mode}`,
    `- Events replayed: ${summary.eventCount}`,
    `- Decisions: ${summary.decisionCount}`,
    `- Settled gross from latest receipts (atomic USDC): ${summary.latestReceiptSettledGrossAtomic}`,
    `- Confirmed refunds from latest receipts (atomic USDC): ${summary.latestReceiptConfirmedRefundAtomic}`,
    `- Unresolved exposure from latest receipts (atomic USDC): ${summary.latestReceiptUnresolvedExposureAtomic}`,
    `- Unique public transactions: ${summary.transactionCount}`,
    `- Signed receipts: ${summary.receipts.length}`,
    `- Live CDP: ${manifest.status.liveCdp}`,
    `- Wallet funded: ${manifest.status.walletFunded}`,
    `- Testnet transaction: ${manifest.status.testnetTransaction}`,
    '',
    'Financial metrics sum the latest signed receipt revision for each intent. Settled gross includes payments later refunded; confirmed refunds are reported separately.',
    '',
    'This report replays the normalized public evidence chain. It does not recompute the private SQLite authority chain from redacted evidence.',
    '',
  ].join('\n');
}

function readmeFor() {
  return [
    '# Wallet Kernel Evidence Bundle',
    '',
    'This directory is a closed, sanitized evidence bundle.',
    'Verification requires the manifest SHA-256 supplied through an out-of-band channel.',
    'The embedded manifest is never accepted as its own trust anchor.',
    '',
  ].join('\n');
}

function canonicalBytes(value) {
  return Buffer.from(`${canonicalJson(value)}\n`, 'utf8');
}

function fsyncDirectory(directory) {
  const descriptor = fs.openSync(directory, fs.constants.O_RDONLY | (fs.constants.O_DIRECTORY ?? 0));
  try { fs.fsyncSync(descriptor); } finally { fs.closeSync(descriptor); }
}

function writeExclusiveFile(destination, bytes) {
  const descriptor = fs.openSync(
    destination,
    fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL
      | (fs.constants.O_NOFOLLOW ?? 0),
    0o600,
  );
  try {
    fs.writeFileSync(descriptor, bytes);
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
}

function canonicalOutputPath(outputDirectory) {
  if (typeof outputDirectory !== 'string' || !path.isAbsolute(outputDirectory)
      || path.resolve(outputDirectory) !== outputDirectory || outputDirectory.includes('\0')) {
    fail('EVIDENCE_OUTPUT_PATH', 'evidence output directory must be one canonical absolute path');
  }
  const parent = path.dirname(outputDirectory);
  let actualParent;
  try { actualParent = fs.realpathSync(parent); } catch (cause) {
    fail('EVIDENCE_OUTPUT_PATH', 'evidence output parent must already exist', cause);
  }
  if (actualParent !== parent) {
    fail('EVIDENCE_OUTPUT_PATH', 'evidence output parent must not traverse symlinks');
  }
  return outputDirectory;
}

function assemble(input) {
  const validated = validateManifestInput(input.manifestInput);
  const receipts = validateReceipts(input.receipts, validated.keys);
  const projections = verifyProjectionSet(
    validated.signedProjections,
    validated.manifest,
    validated.keys,
    receipts,
  );
  if (validated.isolationAttestation !== null
      && !projections.some(({ projection }) => (
        projection.agentEnrollment?.state === 'active'
          && projection.agentEnrollment?.enrollmentHash
            === validated.isolationAttestation.enrollmentHash
      ))) {
    fail('EVIDENCE_PREFLIGHT', 'privileged report does not match the signed enrollment');
  }
  const events = buildNormalizedEvents(input.events, receipts);
  const summary = summaryFor({
    manifest: validated.manifest,
    events,
    receipts,
    signedProjections: projections,
    isolationAttestation: validated.isolationAttestation,
  });
  if (validated.manifest.mode === 'base-sepolia-testnet'
      && summary.transactionCount < 1) {
    fail('EVIDENCE_MODE_GATE', 'settled testnet evidence requires a public transaction ID');
  }
  assertSanitized(summary);
  const fileBytes = new Map([
    ['events.jsonl', Buffer.from(`${events.map(canonicalJson).join('\n')}\n`, 'utf8')],
    ['summary.json', canonicalBytes(summary)],
    ['report.md', Buffer.from(reportFor(validated.manifest, summary), 'utf8')],
    ['README.md', Buffer.from(readmeFor(), 'utf8')],
  ]);
  const files = [...fileBytes].map(([filePath, bytes]) => ({
    path: filePath,
    sha256: rawSha256(bytes),
    bytes: bytes.length,
  })).sort((left, right) => left.path.localeCompare(right.path));
  const manifest = { ...validated.manifest, files };
  assertSanitized(manifest);
  const manifestBytes = canonicalBytes(manifest);
  return { fileBytes, manifestBytes };
}

export function buildEvidenceBundle({ outputDirectory, manifestInput, events, receipts }) {
  const destination = canonicalOutputPath(outputDirectory);
  if (fs.existsSync(destination)) {
    fail('EVIDENCE_OUTPUT_EXISTS', 'evidence output directory already exists');
  }
  const assembled = assemble({ manifestInput, events, receipts });
  let created = false;
  try {
    fs.mkdirSync(destination, { mode: 0o700 });
    created = true;
    fs.chmodSync(destination, 0o700);
    for (const filename of LISTED_FILES) {
      writeExclusiveFile(path.join(destination, filename), assembled.fileBytes.get(filename));
    }
    writeExclusiveFile(path.join(destination, 'manifest.json'), assembled.manifestBytes);
    fsyncDirectory(destination);
    fsyncDirectory(path.dirname(destination));
  } catch (cause) {
    if (created) fs.rmSync(destination, { force: true, recursive: true });
    if (cause instanceof EvidenceError) throw cause;
    fail('EVIDENCE_WRITE', 'evidence bundle could not be written atomically', cause);
  }
  return Object.freeze({ manifestSha256: rawSha256(assembled.manifestBytes) });
}

function canonicalBundleDirectory(directory) {
  if (typeof directory !== 'string' || !path.isAbsolute(directory)
      || path.resolve(directory) !== directory || directory.includes('\0')) {
    fail('EVIDENCE_DIRECTORY', 'evidence directory must be one canonical absolute path');
  }
  let actual;
  try { actual = fs.realpathSync(directory); } catch (cause) {
    fail('EVIDENCE_DIRECTORY', 'evidence directory does not exist', cause);
  }
  const stat = fs.lstatSync(directory);
  if (actual !== directory || !stat.isDirectory() || stat.isSymbolicLink()) {
    fail('EVIDENCE_DIRECTORY', 'evidence directory must not traverse a symlink');
  }
  return directory;
}

function readRegularFile(directory, filename) {
  const destination = path.join(directory, filename);
  let descriptor;
  try {
    descriptor = fs.openSync(destination, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
    const stat = fs.fstatSync(descriptor);
    if (!stat.isFile() || stat.nlink !== 1 || stat.size < 1 || stat.size > MAXIMUM_FILE_BYTES) {
      fail('EVIDENCE_FILE_TYPE', 'evidence files must be bounded single-link regular files');
    }
    const bytes = fs.readFileSync(descriptor);
    const after = fs.fstatSync(descriptor);
    if (after.dev !== stat.dev || after.ino !== stat.ino || after.size !== stat.size) {
      fail('EVIDENCE_FILE_CHANGED', 'evidence file changed while it was read');
    }
    return bytes;
  } catch (cause) {
    if (cause instanceof EvidenceError) throw cause;
    fail('EVIDENCE_FILE_TYPE', 'evidence file could not be read safely', cause);
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function parseCanonicalJsonFile(bytes, label, code) {
  if (bytes.at(-1) !== 0x0a || bytes.subarray(0, -1).includes(0x0a) || bytes.includes(0x00)) {
    fail(code, `${label} must contain canonical JSON plus one newline`);
  }
  let parsed;
  try { parsed = JSON.parse(bytes.subarray(0, -1).toString('utf8')); } catch (cause) {
    fail(code, `${label} is not JSON`, cause);
  }
  if (!isPlainData(parsed) || !bytes.equals(canonicalBytes(parsed))) {
    fail(code, `${label} is not canonical JSON`);
  }
  return parsed;
}

function validateStoredManifest(value) {
  const manifest = capture(value, [
    'schemaVersion', 'createdAt', 'mode', 'git', 'runtime', 'protocol', 'wallet',
    'isolation', 'deployment', 'inputs', 'source', 'files', 'status',
  ], [], 'EVIDENCE_MANIFEST_SCHEMA', 'evidence manifest');
  if (manifest.schemaVersion !== EVIDENCE_SCHEMA_VERSION
      || !['offline-deterministic', 'base-sepolia-testnet'].includes(manifest.mode)) {
    fail('EVIDENCE_MANIFEST_SCHEMA', 'evidence manifest version or mode is invalid');
  }
  manifest.createdAt = timestamp(
    manifest.createdAt,
    'manifest createdAt',
    'EVIDENCE_MANIFEST_SCHEMA',
  );
  manifest.git = validateGit(manifest.git, manifest.mode);
  manifest.runtime = validateRuntime(manifest.runtime, manifest.mode);
  manifest.protocol = validateProtocol(manifest.protocol);
  manifest.wallet = validateWallet(manifest.wallet, manifest.mode);
  const isolation = capture(manifest.isolation, [
    'status', 'preflightDigest', 'kernelIdentityHash', 'agentIdentityHash',
  ], [], 'EVIDENCE_MANIFEST_SCHEMA', 'manifest isolation');
  if (!['simulated', 'enforced'].includes(isolation.status)
      || (isolation.preflightDigest !== null && !PREFIXED_HASH.test(isolation.preflightDigest))) {
    fail('EVIDENCE_MANIFEST_SCHEMA', 'manifest isolation is invalid');
  }
  prefixedHash(isolation.kernelIdentityHash, 'Kernel identity hash', 'EVIDENCE_MANIFEST_SCHEMA');
  prefixedHash(isolation.agentIdentityHash, 'Agent identity hash', 'EVIDENCE_MANIFEST_SCHEMA');
  if (isolation.kernelIdentityHash === isolation.agentIdentityHash) {
    fail('EVIDENCE_MANIFEST_SCHEMA', 'manifest identities are not role-separated');
  }
  manifest.isolation = isolation;
  manifest.deployment = validateDeployment(manifest.deployment);
  manifest.inputs = validateInputs(manifest.inputs);
  const source = capture(manifest.source, [
    'authorityEventHeadHash', 'signedProjectionHash', 'receiptKeys',
  ], [], 'EVIDENCE_MANIFEST_SCHEMA', 'manifest source');
  prefixedHash(source.authorityEventHeadHash, 'authority event head', 'EVIDENCE_MANIFEST_SCHEMA');
  prefixedHash(source.signedProjectionHash, 'signed projection', 'EVIDENCE_MANIFEST_SCHEMA');
  const keys = normalizeKeys(source.receiptKeys);
  if (canonicalJson(source.receiptKeys) !== canonicalJson(publicKeysOnly(keys))) {
    fail('EVIDENCE_MANIFEST_SCHEMA', 'manifest receipt keys are not canonically ordered');
  }
  manifest.source = { ...source, receiptKeys: publicKeysOnly(keys) };
  manifest.status = validateStatus(manifest.status);
  if (!Array.isArray(manifest.files) || manifest.files.length !== LISTED_FILES.length) {
    fail('EVIDENCE_MANIFEST_SCHEMA', 'manifest must list exactly four non-manifest files');
  }
  manifest.files = manifest.files.map((entry) => {
    const file = capture(entry, ['path', 'sha256', 'bytes'], [],
      'EVIDENCE_MANIFEST_SCHEMA', 'manifest file');
    rawHash(file.sha256, 'manifest file digest', 'EVIDENCE_MANIFEST_SCHEMA');
    if (!LISTED_FILES.includes(file.path) || !Number.isSafeInteger(file.bytes)
        || file.bytes < 1 || file.bytes > MAXIMUM_FILE_BYTES) {
      fail('EVIDENCE_MANIFEST_SCHEMA', 'manifest file entry is invalid');
    }
    return file;
  });
  const paths = manifest.files.map(({ path: filePath }) => filePath);
  if (new Set(paths).size !== paths.length
      || paths.some((filePath, index) => index > 0
        && manifest.files[index - 1].path.localeCompare(filePath) >= 0)
      || [...paths].sort().join('\0') !== [...LISTED_FILES].sort().join('\0')) {
    fail('EVIDENCE_MANIFEST_SCHEMA', 'manifest files are not the exact canonical set');
  }
  assertSanitized(manifest);
  return { manifest, keys };
}

function parseEvents(bytes) {
  if (bytes.at(-1) !== 0x0a || bytes.includes(0x00)) {
    fail('EVIDENCE_EVENT_CHAIN', 'events must be canonical JSONL with a final newline');
  }
  const lines = bytes.subarray(0, -1).toString('utf8').split('\n');
  if (lines.length === 0 || lines.some((line) => line.length === 0)) {
    fail('EVIDENCE_EVENT_CHAIN', 'events JSONL must contain nonempty records');
  }
  return lines.map((line) => {
    let event;
    try { event = JSON.parse(line); } catch (cause) {
      fail('EVIDENCE_EVENT_CHAIN', 'events JSONL contains invalid JSON', cause);
    }
    if (!isPlainData(event) || canonicalJson(event) !== line) {
      fail('EVIDENCE_EVENT_CHAIN', 'events JSONL contains noncanonical JSON');
    }
    return event;
  });
}

function validateStoredSummary(value, manifest, replay, keys) {
  const summary = capture(value, [
    'schemaVersion', 'domain', 'eventCount', 'decisionCount',
    'latestReceiptSettledGrossAtomic', 'latestReceiptConfirmedRefundAtomic',
    'latestReceiptUnresolvedExposureAtomic',
    'transactionCount', 'transactionIds', 'normalizedEvidenceHeadHash',
    'authorityEventHeadHash', 'signedProjections', 'receipts', 'isolationAttestation',
  ], [], 'EVIDENCE_SUMMARY_SCHEMA', 'evidence summary');
  if (summary.schemaVersion !== EVIDENCE_SCHEMA_VERSION || summary.domain !== SUMMARY_DOMAIN
      || !Number.isSafeInteger(summary.eventCount) || summary.eventCount < 1
      || !Number.isSafeInteger(summary.decisionCount) || summary.decisionCount < 0
      || !Number.isSafeInteger(summary.transactionCount) || summary.transactionCount < 0
      || !Array.isArray(summary.transactionIds)) {
    fail('EVIDENCE_SUMMARY_SCHEMA', 'evidence summary counters are invalid');
  }
  for (const name of [
    'latestReceiptSettledGrossAtomic',
    'latestReceiptConfirmedRefundAtomic',
    'latestReceiptUnresolvedExposureAtomic',
  ]) atomic(summary[name], `summary ${name}`, 'EVIDENCE_SUMMARY_SCHEMA');
  prefixedHash(
    summary.normalizedEvidenceHeadHash,
    'normalized evidence head',
    'EVIDENCE_SUMMARY_SCHEMA',
  );
  prefixedHash(summary.authorityEventHeadHash, 'authority event head', 'EVIDENCE_SUMMARY_SCHEMA');
  if (canonicalJson({
    eventCount: summary.eventCount,
    decisionCount: summary.decisionCount,
    transactionCount: summary.transactionCount,
    transactionIds: summary.transactionIds,
    normalizedEvidenceHeadHash: summary.normalizedEvidenceHeadHash,
  }) !== canonicalJson(replay)
      || summary.authorityEventHeadHash !== manifest.source.authorityEventHeadHash) {
    fail('EVIDENCE_SUMMARY_MISMATCH', 'summary disagrees with replayed normalized events');
  }
  const receipts = validateReceipts(summary.receipts, keys);
  if (canonicalJson(latestReceiptFinancialMetrics(receipts)) !== canonicalJson({
    latestReceiptSettledGrossAtomic: summary.latestReceiptSettledGrossAtomic,
    latestReceiptConfirmedRefundAtomic: summary.latestReceiptConfirmedRefundAtomic,
    latestReceiptUnresolvedExposureAtomic: summary.latestReceiptUnresolvedExposureAtomic,
  })) {
    fail('EVIDENCE_SUMMARY_MISMATCH', 'summary financial metrics disagree with latest signed receipts');
  }
  const projections = verifyProjectionSet(summary.signedProjections, manifest, keys, receipts);
  validateStoredAttestation(summary.isolationAttestation, manifest, projections);
  assertSanitized(summary);
  return { summary, receipts };
}

function validateStoredAttestation(value, manifest, projections) {
  if (manifest.mode === 'offline-deterministic') {
    if (manifest.isolation.status !== 'simulated' || manifest.isolation.preflightDigest !== null
        || manifest.deployment.status !== 'simulated'
        || DEPLOYMENT_DIGEST_FIELDS.some((name) => manifest.deployment[name] !== null)
        || Object.values(manifest.status).some((item) => item !== 'not-run')
        || value !== null) {
      fail('EVIDENCE_MODE_GATE', 'offline bundle claims a live isolation or deployment result');
    }
    return;
  }
  const attestation = capture(value, [
    'preflightDigest', 'enrollmentHash', 'probedAt', 'expiresAt', 'releaseManifestDigest',
    'releaseTreeHash', 'serviceArtifactsHash', 'systemdEffectiveConfigHash',
  ], [], 'EVIDENCE_PREFLIGHT', 'sanitized privileged attestation');
  for (const name of [
    'preflightDigest', 'enrollmentHash', 'releaseManifestDigest', 'releaseTreeHash',
    'serviceArtifactsHash', 'systemdEffectiveConfigHash',
  ]) prefixedHash(attestation[name], `attestation ${name}`, 'EVIDENCE_PREFLIGHT');
  const probedAt = timestamp(attestation.probedAt, 'attestation probedAt', 'EVIDENCE_PREFLIGHT');
  const expiresAt = timestamp(attestation.expiresAt, 'attestation expiresAt', 'EVIDENCE_PREFLIGHT');
  if (manifest.isolation.status !== 'enforced'
      || manifest.deployment.status !== 'enforced'
      || manifest.status.liveCdp !== 'passed'
      || manifest.status.walletFunded !== 'sufficient'
      || manifest.status.testnetTransaction !== 'settled'
      || attestation.preflightDigest !== manifest.isolation.preflightDigest
      || !projections.some(({ projection }) => (
        projection.agentEnrollment?.state === 'active'
          && attestation.enrollmentHash === projection.agentEnrollment?.enrollmentHash
      ))
      || attestation.releaseManifestDigest !== manifest.deployment.releaseManifestDigest
      || attestation.releaseTreeHash !== manifest.deployment.releaseTreeHash
      || attestation.serviceArtifactsHash !== manifest.deployment.serviceArtifactsHash
      || attestation.systemdEffectiveConfigHash !== manifest.deployment.systemdEffectiveConfigHash
      || Date.parse(expiresAt) <= Date.parse(probedAt)
      || Date.parse(expiresAt) - Date.parse(probedAt) > 15 * 60 * 1_000
      || Date.parse(manifest.createdAt) < Date.parse(probedAt)
      || Date.parse(manifest.createdAt) >= Date.parse(expiresAt)
      || projections.some(({ projection }) => (
        Date.parse(projection.issuedAt) < Date.parse(probedAt)
          || Date.parse(projection.issuedAt) >= Date.parse(expiresAt)
      ))) {
    fail('EVIDENCE_MODE_GATE', 'testnet bundle lacks a matching unexpired privileged attestation');
  }
}

function expectedTextFiles(manifest, summary) {
  return new Map([
    ['README.md', Buffer.from(readmeFor(), 'utf8')],
    ['report.md', Buffer.from(reportFor(manifest, summary), 'utf8')],
  ]);
}

export function verifyEvidenceBundle(outputDirectory, options = {}) {
  const expected = options?.expectedManifestSha256;
  if (typeof expected !== 'string' || !RAW_HASH.test(expected)) {
    fail('EVIDENCE_EXTERNAL_ANCHOR', 'a canonical external manifest SHA-256 is required');
  }
  const directory = canonicalBundleDirectory(outputDirectory);
  const manifestBytes = readRegularFile(directory, 'manifest.json');
  const actualManifestSha256 = rawSha256(manifestBytes);
  if (actualManifestSha256 !== expected) {
    fail('EVIDENCE_EXTERNAL_ANCHOR', 'manifest bytes do not match the external trust anchor');
  }
  const storedNames = fs.readdirSync(directory).sort();
  if (storedNames.join('\0') !== [...BUNDLE_FILES].sort().join('\0')) {
    fail('EVIDENCE_FILE_SET', 'evidence directory must contain exactly five files');
  }
  const parsedManifest = parseCanonicalJsonFile(
    manifestBytes,
    'manifest',
    'EVIDENCE_MANIFEST_SCHEMA',
  );
  const { manifest, keys } = validateStoredManifest(parsedManifest);
  const bytesByName = new Map();
  for (const entry of manifest.files) {
    const bytes = readRegularFile(directory, entry.path);
    if (bytes.length !== entry.bytes || rawSha256(bytes) !== entry.sha256) {
      fail('EVIDENCE_FILE_HASH', 'listed evidence file does not match its manifest hash');
    }
    bytesByName.set(entry.path, bytes);
  }
  const events = parseEvents(bytesByName.get('events.jsonl'));
  const replay = replayEvents(events);
  const parsedSummary = parseCanonicalJsonFile(
    bytesByName.get('summary.json'),
    'summary',
    'EVIDENCE_SUMMARY_SCHEMA',
  );
  const { summary, receipts } = validateStoredSummary(parsedSummary, manifest, replay, keys);
  verifyReceiptEventParity(events, receipts);
  for (const [filename, expectedBytes] of expectedTextFiles(manifest, summary)) {
    if (!bytesByName.get(filename).equals(expectedBytes)) {
      fail('EVIDENCE_REPORT_MISMATCH', 'generated evidence documentation is not recomputable');
    }
  }
  if (manifest.mode === 'base-sepolia-testnet' && replay.transactionCount < 1) {
    fail('EVIDENCE_MODE_GATE', 'settled testnet evidence requires a public transaction ID');
  }
  for (const value of [manifest, events, summary]) assertSanitized(value);
  return Object.freeze({
    valid: true,
    mode: manifest.mode,
    manifestSha256: actualManifestSha256,
    authorityEventHeadHash: manifest.source.authorityEventHeadHash,
    normalizedEvidenceHeadHash: replay.normalizedEvidenceHeadHash,
    eventCount: replay.eventCount,
    decisionCount: replay.decisionCount,
    latestReceiptSettledGrossAtomic: summary.latestReceiptSettledGrossAtomic,
    latestReceiptConfirmedRefundAtomic: summary.latestReceiptConfirmedRefundAtomic,
    latestReceiptUnresolvedExposureAtomic: summary.latestReceiptUnresolvedExposureAtomic,
    transactionCount: replay.transactionCount,
    receiptCount: receipts.length,
    liveCdp: manifest.status.liveCdp,
    walletFunded: manifest.status.walletFunded,
    testnetTransaction: manifest.status.testnetTransaction,
  });
}
