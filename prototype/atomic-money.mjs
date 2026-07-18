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
