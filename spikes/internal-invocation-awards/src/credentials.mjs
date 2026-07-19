import { createHash, sign as cryptoSign, verify as cryptoVerify } from 'node:crypto';

import {
  cloneFrozen,
  parseUtc,
  policyHash,
  requireExactKeys,
} from './schema.mjs';
import { normalizeEd25519PublicKey } from './public-keys.mjs';

const CREDENTIAL_KEYS = [
  'schemaVersion', 'credentialAuthorizerId', 'invocationId', 'reservationId',
  'idempotencyKey', 'skillId', 'skillVersionHash', 'creatorId', 'wielderId',
  'initiatingPrincipalId', 'principalAttestationId', 'principalAttestationHash',
  'policyId', 'policyVersion', 'policyHash', 'nonce', 'issuedAt', 'expiresAt',
];
const SIGNED_CREDENTIAL_KEYS = [...CREDENTIAL_KEYS, 'signature'];
const MANAGER_APPROVAL_KEYS = [
  'schemaVersion', 'approvalId', 'managerSignerId', 'invocationId', 'creatorId',
  'policyId', 'policyVersion', 'issuedAt', 'expiresAt',
];
const SIGNED_MANAGER_APPROVAL_KEYS = [...MANAGER_APPROVAL_KEYS, 'signature'];
const PRINCIPAL_ATTESTATION_KEYS = [
  'schemaVersion', 'attestationId', 'identitySignerId', 'principalId',
  'invocationId', 'idempotencyKey', 'skillId', 'skillVersionHash', 'creatorId',
  'wielderId', 'beneficiaryId', 'policyId', 'policyVersion', 'policyHash', 'nonce',
  'issuedAt', 'expiresAt',
];
const SIGNED_PRINCIPAL_ATTESTATION_KEYS = [...PRINCIPAL_ATTESTATION_KEYS, 'signature'];
const SHA256_PATTERN = /^sha256:[0-9a-f]{64}$/;

function ordered(source, keys) {
  return Object.fromEntries(keys.map((key) => [key, source[key]]));
}

function bytes(source, keys) {
  return new TextEncoder().encode(JSON.stringify(ordered(source, keys)));
}

function requireString(value, label) {
  if (typeof value !== 'string' || value.length === 0) throw new Error(`${label} must be non-empty`);
}

function trustedSignerKey(map, signerId, label) {
  if (map === null || typeof map !== 'object' || Array.isArray(map)
      || Object.getPrototypeOf(map) !== Object.prototype) {
    throw new Error(`${label} trust map must be a plain object`);
  }
  if (!Object.hasOwn(map, signerId)) {
    throw new Error(`${label} is not provisioned`);
  }
  const configuredKey = map[signerId];
  if (typeof configuredKey !== 'string' || configuredKey.length === 0) {
    throw new Error(`${label} is not provisioned`);
  }
  return normalizeEd25519PublicKey(configuredKey, `${label} ${signerId}`);
}

function decodeSignature(value, label) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) {
    throw new Error(`${label} signature must be canonical base64`);
  }
  const decoded = Buffer.from(value, 'base64');
  if (decoded.length !== 64 || decoded.toString('base64') !== value) {
    throw new Error(`${label} signature must be a 64-byte Ed25519 signature`);
  }
  return decoded;
}

function validateCredentialPayload(input) {
  requireExactKeys(input, CREDENTIAL_KEYS, 'credential');
  if (input.schemaVersion !== 1) throw new Error('credential schemaVersion must equal 1');
  for (const key of [
    'credentialAuthorizerId', 'invocationId', 'reservationId', 'idempotencyKey',
    'skillId', 'creatorId', 'wielderId', 'initiatingPrincipalId',
    'principalAttestationId', 'policyId',
  ]) requireString(input[key], key);
  if (!SHA256_PATTERN.test(input.skillVersionHash)) {
    throw new Error('credential skillVersionHash must be a lowercase SHA-256 hash');
  }
  if (!Number.isSafeInteger(input.policyVersion) || input.policyVersion < 1) {
    throw new Error('credential policyVersion must be a positive integer');
  }
  if (!SHA256_PATTERN.test(input.policyHash)) throw new Error('credential policyHash is invalid');
  if (!SHA256_PATTERN.test(input.principalAttestationHash)) {
    throw new Error('credential principalAttestationHash is invalid');
  }
  if (typeof input.nonce !== 'string' || !/^[0-9a-f]{64}$/.test(input.nonce)) {
    throw new Error('credential nonce must be lowercase 64-character hex without 0x');
  }
  const issuedAt = parseUtc(input.issuedAt, 'credential issuedAt');
  const expiresAt = parseUtc(input.expiresAt, 'credential expiresAt');
  if (expiresAt <= issuedAt) throw new Error('credential expiresAt must follow issuedAt');
  return cloneFrozen(input);
}

export function canonicalCredentialBytes(payload) {
  const validated = validateCredentialPayload(payload);
  return bytes(validated, CREDENTIAL_KEYS);
}

export function signCredential(payload, privateKey) {
  const validated = validateCredentialPayload(payload);
  return cloneFrozen({
    ...validated,
    signature: cryptoSign(null, canonicalCredentialBytes(validated), privateKey).toString('base64'),
  });
}

export function verifyCredential(signed, trustedPublicKey, now) {
  const payload = verifyCredentialSignature(signed, trustedPublicKey);
  const at = parseUtc(now, 'now');
  if (at < parseUtc(payload.issuedAt, 'credential issuedAt')) {
    throw new Error('credential is not yet valid');
  }
  if (at >= parseUtc(payload.expiresAt, 'credential expiresAt')) {
    throw new Error('credential expired');
  }
  return payload;
}

export function verifyCredentialSignature(signed, trustedPublicKey) {
  requireExactKeys(signed, SIGNED_CREDENTIAL_KEYS, 'signed credential');
  const payload = validateCredentialPayload(ordered(signed, CREDENTIAL_KEYS));
  const signature = decodeSignature(signed.signature, 'credential');
  const key = normalizeEd25519PublicKey(trustedPublicKey, 'credential verifier key');
  if (!cryptoVerify(null, canonicalCredentialBytes(payload), key, signature)) {
    throw new Error('credential signature verification failed');
  }
  return payload;
}

function validatePrincipalAttestationPayload(input) {
  requireExactKeys(input, PRINCIPAL_ATTESTATION_KEYS, 'initiating-principal attestation');
  if (input.schemaVersion !== 1) {
    throw new Error('initiating-principal attestation schemaVersion must equal 1');
  }
  for (const key of [
    'attestationId', 'identitySignerId', 'principalId', 'invocationId',
    'idempotencyKey', 'skillId', 'creatorId', 'wielderId', 'beneficiaryId', 'policyId',
  ]) requireString(input[key], key);
  if (!SHA256_PATTERN.test(input.skillVersionHash)) {
    throw new Error('initiating-principal attestation Skill hash is invalid');
  }
  if (!SHA256_PATTERN.test(input.policyHash)) {
    throw new Error('initiating-principal attestation policyHash is invalid');
  }
  if (!Number.isSafeInteger(input.policyVersion) || input.policyVersion < 1) {
    throw new Error('initiating-principal attestation policyVersion must be positive');
  }
  if (typeof input.nonce !== 'string' || !/^[0-9a-f]{64}$/.test(input.nonce)) {
    throw new Error('initiating-principal attestation nonce must be lowercase 64-character hex');
  }
  const issuedAt = parseUtc(input.issuedAt, 'initiating-principal attestation issuedAt');
  const expiresAt = parseUtc(input.expiresAt, 'initiating-principal attestation expiresAt');
  if (expiresAt <= issuedAt) {
    throw new Error('initiating-principal attestation expiresAt must follow issuedAt');
  }
  return cloneFrozen(input);
}

export function canonicalPrincipalAttestationBytes(payload) {
  const validated = validatePrincipalAttestationPayload(payload);
  return bytes(validated, PRINCIPAL_ATTESTATION_KEYS);
}

export function signPrincipalAttestation(payload, privateKey) {
  const validated = validatePrincipalAttestationPayload(payload);
  return cloneFrozen({
    ...validated,
    signature: cryptoSign(
      null,
      canonicalPrincipalAttestationBytes(validated),
      privateKey,
    ).toString('base64'),
  });
}

export function principalAttestationHash(signed) {
  requireExactKeys(
    signed,
    SIGNED_PRINCIPAL_ATTESTATION_KEYS,
    'signed initiating-principal attestation',
  );
  validatePrincipalAttestationPayload(ordered(signed, PRINCIPAL_ATTESTATION_KEYS));
  decodeSignature(signed.signature, 'initiating-principal attestation');
  return `sha256:${createHash('sha256')
    .update(bytes(signed, SIGNED_PRINCIPAL_ATTESTATION_KEYS))
    .digest('hex')}`;
}

export function verifyPrincipalAttestation(signed, {
  policy,
  quote,
  identitySigners,
  now,
}) {
  requireExactKeys(
    signed,
    SIGNED_PRINCIPAL_ATTESTATION_KEYS,
    'signed initiating-principal attestation',
  );
  const payload = validatePrincipalAttestationPayload(
    ordered(signed, PRINCIPAL_ATTESTATION_KEYS),
  );
  if (!policy.permittedIdentitySignerIds.includes(payload.identitySignerId)) {
    throw new Error('identity signer is not permitted by policy');
  }
  const key = trustedSignerKey(identitySigners, payload.identitySignerId, 'identity signer');
  if (!policy.permittedInitiatingPrincipalIds.includes(payload.principalId)) {
    throw new Error('initiating principal is not permitted by policy');
  }
  const bindings = {
    attestationId: quote.principalAttestationId,
    principalId: quote.initiatingPrincipalId,
    invocationId: quote.invocationId,
    idempotencyKey: quote.idempotencyKey,
    skillId: quote.skillId,
    skillVersionHash: quote.skillVersionHash,
    creatorId: quote.creatorId,
    wielderId: quote.wielderId,
    beneficiaryId: quote.beneficiaryId,
    policyId: quote.policyId,
    policyVersion: quote.policyVersion,
    policyHash: quote.policyHash,
  };
  for (const [keyName, expected] of Object.entries(bindings)) {
    if (payload[keyName] !== expected) {
      throw new Error(`initiating-principal attestation ${keyName} binding does not match quote`);
    }
  }
  if (payload.policyHash !== policyHash(policy)) {
    throw new Error('initiating-principal attestation policyHash is stale');
  }
  const at = parseUtc(now, 'now');
  if (at < parseUtc(payload.issuedAt, 'attestation issuedAt')) {
    throw new Error('initiating-principal attestation is not yet valid');
  }
  if (at >= parseUtc(payload.expiresAt, 'attestation expiresAt')) {
    throw new Error('initiating-principal attestation expired');
  }
  if (parseUtc(payload.expiresAt, 'attestation expiresAt') > parseUtc(quote.expiresAt, 'quote expiresAt')) {
    throw new Error('initiating-principal attestation expiry exceeds quote');
  }
  if (!cryptoVerify(
    null,
    canonicalPrincipalAttestationBytes(payload),
    key,
    decodeSignature(signed.signature, 'initiating-principal attestation'),
  )) throw new Error('initiating-principal attestation signature verification failed');
  return payload;
}

function validateManagerApprovalPayload(input) {
  requireExactKeys(input, MANAGER_APPROVAL_KEYS, 'manager approval');
  if (input.schemaVersion !== 1) throw new Error('manager approval schemaVersion must equal 1');
  for (const key of [
    'approvalId', 'managerSignerId', 'invocationId', 'creatorId', 'policyId',
  ]) requireString(input[key], key);
  if (!Number.isSafeInteger(input.policyVersion) || input.policyVersion < 1) {
    throw new Error('manager approval policyVersion must be a positive integer');
  }
  const issuedAt = parseUtc(input.issuedAt, 'manager approval issuedAt');
  const expiresAt = parseUtc(input.expiresAt, 'manager approval expiresAt');
  if (expiresAt <= issuedAt) throw new Error('manager approval expiresAt must follow issuedAt');
  return cloneFrozen(input);
}

export function canonicalManagerApprovalBytes(approval) {
  const validated = validateManagerApprovalPayload(approval);
  return bytes(validated, MANAGER_APPROVAL_KEYS);
}

export function signManagerApproval(approval, privateKey) {
  const validated = validateManagerApprovalPayload(approval);
  return cloneFrozen({
    ...validated,
    signature: cryptoSign(null, canonicalManagerApprovalBytes(validated), privateKey).toString('base64'),
  });
}

export function verifyManagerApproval(approval, {
  policy,
  quote,
  managerSigners,
  now,
}) {
  requireExactKeys(approval, SIGNED_MANAGER_APPROVAL_KEYS, 'signed manager approval');
  const payload = validateManagerApprovalPayload(ordered(approval, MANAGER_APPROVAL_KEYS));
  if (payload.managerSignerId === quote.creatorId) {
    throw new Error('Creator cannot self-approve an internal Invocation');
  }
  if (!policy.permittedManagerSignerIds.includes(payload.managerSignerId)) {
    throw new Error('manager signer is not permitted by policy');
  }
  const trustedKey = trustedSignerKey(managerSigners, payload.managerSignerId, 'manager signer');
  if (payload.invocationId !== quote.invocationId
      || payload.creatorId !== quote.creatorId
      || payload.policyId !== policy.policyId
      || payload.policyVersion !== policy.version) {
    throw new Error('manager approval binding does not match Invocation');
  }
  const at = parseUtc(now, 'now');
  const issuedAt = parseUtc(payload.issuedAt, 'manager approval issuedAt');
  const expiresAt = parseUtc(payload.expiresAt, 'manager approval expiresAt');
  if (at < issuedAt) throw new Error('manager approval is not yet valid');
  if (at >= expiresAt) throw new Error('manager approval expired');
  if (expiresAt > parseUtc(quote.expiresAt, 'quote expiresAt')
      || expiresAt > parseUtc(policy.expiresAt, 'policy expiresAt')) {
    throw new Error('manager approval expiry exceeds Invocation bounds');
  }
  const signature = decodeSignature(approval.signature, 'manager approval');
  if (!cryptoVerify(null, canonicalManagerApprovalBytes(payload), trustedKey, signature)) {
    throw new Error('manager approval signature verification failed');
  }
  return payload;
}

export const CREDENTIAL_SCHEMAS = cloneFrozen({
  InternalExecutionCredentialV1: CREDENTIAL_KEYS,
  InitiatingPrincipalAttestationV1: PRINCIPAL_ATTESTATION_KEYS,
  ManagerApprovalV1: MANAGER_APPROVAL_KEYS,
});
