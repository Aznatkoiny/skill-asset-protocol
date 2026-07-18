import assert from "node:assert/strict";
import test from "node:test";

import {
  DEMO_GAS_UNITS_ENVELOPE,
  estimateRemainingDemoGasMinimum,
} from "../src/funding";

test("no remaining new write needs no native-gas estimate", () => {
  assert.equal(estimateRemainingDemoGasMinimum({ gasPrice: 0n, remainingNewWrites: 0 }), 0n);
});

test("any remaining new write retains the full conservative gas envelope", () => {
  const minimum = estimateRemainingDemoGasMinimum({ gasPrice: 2n, remainingNewWrites: 1 });
  assert.equal(minimum, 2n * DEMO_GAS_UNITS_ENVELOPE);
  assert.equal(
    estimateRemainingDemoGasMinimum({ gasPrice: 2n, remainingNewWrites: 4 }),
    minimum,
  );
});

test("invalid gas prices fail closed", () => {
  assert.throws(
    () => estimateRemainingDemoGasMinimum({ gasPrice: 0n, remainingNewWrites: 1 }),
    /gas price must be positive/i,
  );
  assert.throws(
    () => estimateRemainingDemoGasMinimum({ gasPrice: 1n, remainingNewWrites: -1 }),
    /remaining new writes/i,
  );
});
