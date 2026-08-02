/**
 * Conservative native-gas envelope for the complete four-write Phase 0 demo.
 * This is an estimate, not a measured or guaranteed final fee.
 */
export const DEMO_GAS_UNITS_ENVELOPE = 6_000_000n;

export function estimateRemainingDemoGasMinimum(input: {
  gasPrice: bigint;
  remainingNewWrites: number;
}): bigint {
  if (!Number.isSafeInteger(input.remainingNewWrites) || input.remainingNewWrites < 0) {
    throw new Error("Remaining new writes must be a non-negative safe integer");
  }
  if (input.remainingNewWrites === 0) return 0n;
  if (input.gasPrice <= 0n) throw new Error("Gas price must be positive");
  return input.gasPrice * DEMO_GAS_UNITS_ENVELOPE;
}
