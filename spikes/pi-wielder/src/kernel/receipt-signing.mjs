import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

import { loadOrInitializePrivateFile } from './secure-storage.mjs';

const PKCS8_PRIVATE_KEY_LABEL = ['PRIVATE', 'KEY'].join(' ');
const PKCS8_PRIVATE_KEY_PEM = new RegExp(
  `^-----BEGIN ${PKCS8_PRIVATE_KEY_LABEL}-----\\r?\\n`
    + `(?:[A-Za-z0-9+/]{1,64}={0,2}\\r?\\n)+`
    + `-----END ${PKCS8_PRIVATE_KEY_LABEL}-----(?:[ \\t\\r\\n]*)$`,
);

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalize(value[key])]));
  }
  return value;
}

export const canonicalJson = (value) => JSON.stringify(canonicalize(value));

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

function parseOneEd25519PrivateKey(bytes) {
  const pem = Buffer.from(bytes).toString('utf8');
  if (!PKCS8_PRIVATE_KEY_PEM.test(pem)) {
    throw new Error('receipt private key must contain exactly one PKCS#8 PEM with no trailing data');
  }
  let privateKey;
  try {
    privateKey = crypto.createPrivateKey(pem);
  } catch (error) {
    throw new Error('receipt private key is invalid', { cause: error });
  }
  if (privateKey.type !== 'private' || privateKey.asymmetricKeyType !== 'ed25519') {
    throw new Error('receipt private key must be Ed25519');
  }
  return privateKey;
}

function inferredCompatibilityPathTrust(keyPath) {
  if (typeof keyPath !== 'string' || !path.isAbsolute(keyPath)) {
    throw new Error('persistent receipt key path must be absolute');
  }
  const lexicalParent = path.resolve(path.dirname(keyPath));
  const trustedAncestor = fs.realpathSync(lexicalParent);
  if (trustedAncestor !== lexicalParent) {
    throw new Error('persistent receipt key must not traverse a symlinked directory');
  }
  const uid = process.getuid();
  return Object.freeze({
    mode: 'deterministic',
    trustedAncestor,
    kernelUid: uid,
    agentUid: uid,
  });
}

export function loadOrCreateReceiptSigner(keyPath, options = {}) {
  const pathTrust = options.pathTrust ?? inferredCompatibilityPathTrust(keyPath);
  const privateKey = loadOrInitializePrivateFile({
    filePath: keyPath,
    label: 'Receipt private key',
    createBytes: () => {
      const { privateKey: generated } = crypto.generateKeyPairSync('ed25519');
      return generated.export({ type: 'pkcs8', format: 'pem' });
    },
    validateBytes: parseOneEd25519PrivateKey,
    ...(options.randomBytes ? { randomBytes: options.randomBytes } : {}),
    ...(options.faultInjector ? { faultInjector: options.faultInjector } : {}),
    pathTrust,
  });
  return createReceiptSigner(
    { privateKey, publicKey: crypto.createPublicKey(privateKey) },
    { persistent: true },
  );
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
