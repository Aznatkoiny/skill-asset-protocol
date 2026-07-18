export const USDC_DECIMALS = 6;
export const ATOMIC_PER_USDC = 10n ** BigInt(USDC_DECIMALS);
export const BPS_DENOMINATOR = 10_000n;

export class MoneyInputError extends RangeError {
  constructor(code, message) {
    super(message);
    this.name = 'MoneyInputError';
    this.code = code;
  }
}

function fail(code, message) {
  throw new MoneyInputError(code, message);
}

export function assertAtomic(value, label = 'amountAtomic') {
  if (typeof value !== 'bigint') fail('ATOMIC_TYPE', `${label} must be a bigint`);
  if (value < 0n) fail('ATOMIC_NEGATIVE', `${label} must be non-negative`);
  return value;
}

export function assertBps(value, label = 'bps') {
  if (!Number.isSafeInteger(value)) fail('BPS_INTEGER', `${label} must be a safe integer`);
  if (value < 0 || value > 10_000) {
    fail('BPS_RANGE', `${label} must be between 0 and 10000`);
  }
  return BigInt(value);
}

export function parseUsdc(value, label = 'USDC amount') {
  if (typeof value !== 'string') fail('DISPLAY_TYPE', `${label} must be a decimal string`);
  const text = value.trim();
  const match = /^(0|[1-9]\d*)(?:\.(\d{1,6}))?$/.exec(text);
  if (!match) {
    fail(
      'DISPLAY_FORMAT',
      `${label} must be a non-negative decimal with at most six fractional digits`,
    );
  }
  const whole = BigInt(match[1]);
  const fraction = BigInt((match[2] ?? '').padEnd(USDC_DECIMALS, '0') || '0');
  return whole * ATOMIC_PER_USDC + fraction;
}

export function formatUsdc(value) {
  const atomic = assertAtomic(value);
  const whole = atomic / ATOMIC_PER_USDC;
  const fraction = String(atomic % ATOMIC_PER_USDC).padStart(USDC_DECIMALS, '0');
  return `${whole}.${fraction}`;
}

export function floorBps(amountAtomic, bps) {
  return (assertAtomic(amountAtomic) * assertBps(bps)) / BPS_DENOMINATOR;
}

function weightToBigInt(value, label) {
  if (typeof value === 'bigint') {
    if (value < 0n) fail('WEIGHT_NEGATIVE', `${label} must be non-negative`);
    return value;
  }
  if (!Number.isSafeInteger(value) || value < 0) {
    fail('WEIGHT_INTEGER', `${label} must be a non-negative safe integer or bigint`);
  }
  return BigInt(value);
}

function compareKeys(left, right) {
  if (left.key < right.key) return -1;
  if (left.key > right.key) return 1;
  return 0;
}

export function allocateByWeights(amountAtomic, shares) {
  const amount = assertAtomic(amountAtomic);
  if (!Array.isArray(shares) || shares.length === 0) {
    fail('ALLOCATIONS_EMPTY', 'shares must contain at least one allocation');
  }

  const seen = new Set();
  const rows = shares.map((share, index) => {
    const key = String(share?.key ?? '');
    if (!key) fail('ALLOCATION_KEY', `shares[${index}].key must be non-empty`);
    if (seen.has(key)) fail('ALLOCATION_DUPLICATE', `duplicate allocation key '${key}'`);
    seen.add(key);
    return { key, weight: weightToBigInt(share.weight, `shares[${index}].weight`) };
  }).sort(compareKeys);

  const totalWeight = rows.reduce((sum, row) => sum + row.weight, 0n);
  if (totalWeight === 0n) {
    fail('WEIGHTS_ZERO', 'at least one allocation weight must be positive');
  }

  const allocations = rows.map((row) => ({
    key: row.key,
    weight: row.weight,
    amountAtomic: (amount * row.weight) / totalWeight,
  }));
  let remainder = amount - allocations.reduce((sum, row) => sum + row.amountAtomic, 0n);
  for (const row of allocations) {
    if (remainder === 0n) break;
    if (row.weight === 0n) continue;
    row.amountAtomic += 1n;
    remainder -= 1n;
  }
  if (remainder !== 0n) {
    throw new Error('internal invariant: weighted remainder was not exhausted');
  }
  return allocations.map(({ key, amountAtomic: allocated }) => ({
    key,
    amountAtomic: allocated,
  }));
}

export function allocateByBps(amountAtomic, shares) {
  if (!Array.isArray(shares) || shares.length === 0) {
    fail('ALLOCATIONS_EMPTY', 'shares must contain at least one allocation');
  }
  const normalized = shares.map((share, index) => ({
    key: share?.key,
    weight: assertBps(share?.bps, `shares[${index}].bps`),
  }));
  const total = normalized.reduce((sum, row) => sum + row.weight, 0n);
  if (total !== BPS_DENOMINATOR) {
    fail('BPS_TOTAL', `basis-point allocations must sum to 10000 (got ${total})`);
  }
  return allocateByWeights(amountAtomic, normalized);
}
