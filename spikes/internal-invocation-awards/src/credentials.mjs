import { sign as cryptoSign, verify as cryptoVerify } from 'node:crypto';

import {
  cloneFrozen,
  parseUtc,
  requireExactKeys,
} from './schema.mjs';

const CREDENTIAL_KEYS = [
  'schemaVersion', 'credentialAuthorizerId', 'invocationId', 'reservationId',
  'idempotencyKey', 'skillId', 'skillVersionHash', 'policyId', 'policyVersion',
  'nonce', 'issuedAt', 'expiresAt',
];
const SIGNED_CREDENTIAL_KEYS = [...CREDENTIAL_KEYS, 'signature'];
const MANAGER_APPROVAL_KEYS = [
  'schemaVersion', 'approvalId', 'managerSignerId', 'invocationId', 'creatorId',
  'policyId', 'policyVersion', 'issuedAt', 'expiresAt',
];
const SIGNED_MANAGER_APPROVAL_KEYS = [...MANAGER_APPROVAL_KEYS, 'signature'];
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
    'skillId', 'policyId',
  ]) requireString(input[key], key);
  if (!SHA256_PATTERN.test(input.skillVersionHash)) {
    throw new Error('credential skillVersionHash must be a lowercase SHA-256 hash');
  }
  if (!Number.isSafeInteger(input.policyVersion) || input.policyVersion < 1) {
    throw new Error('credential policyVersion must be a positive integer');
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
  requireExactKeys(signed, SIGNED_CREDENTIAL_KEYS, 'signed credential');
  const payload = validateCredentialPayload(ordered(signed, CREDENTIAL_KEYS));
  const signature = decodeSignature(signed.signature, 'credential');
  if (!cryptoVerify(null, canonicalCredentialBytes(payload), trustedPublicKey, signature)) {
    throw new Error('credential signature verification failed');
  }
  const at = parseUtc(now, 'now');
  if (at < parseUtc(payload.issuedAt, 'credential issuedAt')) {
    throw new Error('credential is not yet valid');
  }
  if (at >= parseUtc(payload.expiresAt, 'credential expiresAt')) {
    throw new Error('credential expired');
  }
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
  const trustedKey = managerSigners[payload.managerSignerId];
  if (typeof trustedKey !== 'string' || trustedKey.length === 0) {
    throw new Error('manager signer is not provisioned');
  }
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
  ManagerApprovalV1: MANAGER_APPROVAL_KEYS,
});
