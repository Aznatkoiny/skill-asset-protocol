import { KeyObject, createPublicKey } from 'node:crypto';

export function normalizeEd25519PublicKey(input, label = 'trusted key') {
  let key;
  const stringInput = typeof input === 'string' ? input : null;
  if (input instanceof KeyObject) {
    if (input.type !== 'public') {
      throw new Error(`${label} must be a public SPKI PEM or public KeyObject`);
    }
    key = input;
  } else if (typeof input === 'string') {
    if (!input.startsWith('-----BEGIN PUBLIC KEY-----\n')) {
      throw new Error(`${label} must be a public SPKI PEM`);
    }
    try {
      key = createPublicKey(input);
    } catch {
      throw new Error(`${label} must be a valid public SPKI PEM`);
    }
  } else {
    throw new Error(`${label} must be a public SPKI PEM or public KeyObject`);
  }
  if (key.asymmetricKeyType !== 'ed25519') {
    throw new Error(`${label} must be an Ed25519 public key`);
  }
  const canonical = key.export({ type: 'spki', format: 'pem' });
  if (stringInput !== null && stringInput !== canonical) {
    throw new Error(`${label} must be a canonical public SPKI PEM`);
  }
  return canonical;
}
