import crypto from 'node:crypto';

export class KernelError extends Error {
  constructor(code, message, options) {
    super(message, options);
    this.name = 'KernelError';
    this.code = code;
  }
}

export function exactRecord(value, required, optional = [], code = 'SCHEMA', label = 'value') {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new KernelError(code, `${label} must be one plain object`);
  }

  const allowed = new Set([...required, ...optional]);
  const keys = Reflect.ownKeys(value);
  if (required.some((key) => !Object.hasOwn(value, key))
      || keys.some((key) => typeof key !== 'string' || !allowed.has(key))
      || keys.some((key) => {
        const descriptor = Object.getOwnPropertyDescriptor(value, key);
        return !descriptor.enumerable || !Object.hasOwn(descriptor, 'value');
      })) {
    throw new KernelError(code, `${label} fields do not match the closed schema`);
  }

  return structuredClone(value);
}

function throwCanonicalTypeError(message) {
  throw new KernelError('CANONICAL_TYPE', message);
}

function canonicalSerialize(value, ancestors) {
  if (value === null) return 'null';
  if (typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || Object.is(value, -0)) {
      return throwCanonicalTypeError('canonical numbers must be safe integers');
    }
    return String(value);
  }
  if (!value || typeof value !== 'object') {
    return throwCanonicalTypeError('value is not canonical JSON data');
  }
  if (ancestors.has(value)) {
    return throwCanonicalTypeError('canonical JSON data must not contain cycles');
  }

  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      if (Object.getPrototypeOf(value) !== Array.prototype) {
        return throwCanonicalTypeError('canonical arrays must be ordinary arrays');
      }

      const keys = Reflect.ownKeys(value);
      const lengthDescriptor = Object.getOwnPropertyDescriptor(value, 'length');
      if (!lengthDescriptor || lengthDescriptor.enumerable
          || !Object.hasOwn(lengthDescriptor, 'value')
          || keys.length !== lengthDescriptor.value + 1) {
        return throwCanonicalTypeError(
          'canonical arrays must contain only dense enumerable data elements',
        );
      }

      const elements = [];
      for (let index = 0; index < lengthDescriptor.value; index += 1) {
        const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
        if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
          return throwCanonicalTypeError(
            'canonical arrays must contain only dense enumerable data elements',
          );
        }
        elements.push(canonicalSerialize(descriptor.value, ancestors));
      }
      return `[${elements.join(',')}]`;
    }

    if (Object.getPrototypeOf(value) !== Object.prototype) {
      return throwCanonicalTypeError('value is not canonical JSON data');
    }

    const keys = Reflect.ownKeys(value);
    if (keys.some((key) => typeof key !== 'string')) {
      return throwCanonicalTypeError(
        'canonical objects require enumerable string data properties',
      );
    }

    const fields = [];
    for (const key of keys.sort()) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
        return throwCanonicalTypeError(
          'canonical objects require enumerable string data properties',
        );
      }
      fields.push(`${JSON.stringify(key)}:${canonicalSerialize(descriptor.value, ancestors)}`);
    }
    return `{${fields.join(',')}}`;
  } finally {
    ancestors.delete(value);
  }
}

export function canonicalJson(value) {
  return canonicalSerialize(value, new Set());
}

export function sha256(value) {
  if (typeof value !== 'string' && !Buffer.isBuffer(value) && !(value instanceof Uint8Array)) {
    throw new KernelError('HASH_INPUT', 'hash input must be a string or bytes');
  }
  const bytes = typeof value === 'string' ? Buffer.from(value, 'utf8') : Buffer.from(value);
  return `sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`;
}

export function canonicalAtomic(value, label) {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]*)$/.test(value)) {
    throw new KernelError('ATOMIC_FORMAT', `${label} must be canonical atomic USDC text`);
  }
  return Object.freeze({ text: value, value: BigInt(value) });
}

export function canonicalEvmHash(value, label) {
  if (typeof value !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(value)) {
    throw new KernelError('EVM_HASH_FORMAT', `${label} must be one 32-byte EVM hash`);
  }
  return value.toLowerCase();
}

export function canonicalToken(value, label, maximum = 200) {
  if (!Number.isSafeInteger(maximum) || maximum < 1
      || typeof value !== 'string' || value.length > maximum
      || !/^[A-Za-z0-9][A-Za-z0-9._:-]*$/.test(value)) {
    throw new KernelError('TOKEN_FORMAT', `${label} must be a bounded canonical token`);
  }
  return value;
}

export function canonicalTimestamp(value, label) {
  const milliseconds = typeof value === 'string' ? Date.parse(value) : Number.NaN;
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value) {
    throw new KernelError('TIMESTAMP_FORMAT', `${label} must be a canonical ISO timestamp`);
  }
  return value;
}

export function frozenCopy(value) {
  const copy = structuredClone(value);
  const seen = new WeakSet();
  const freeze = (item) => {
    if (item && typeof item === 'object' && !seen.has(item)) {
      seen.add(item);
      for (const key of Reflect.ownKeys(item)) {
        const descriptor = Object.getOwnPropertyDescriptor(item, key);
        if (Object.hasOwn(descriptor, 'value')) freeze(descriptor.value);
      }
      Object.freeze(item);
    }
    return item;
  };
  return freeze(copy);
}
