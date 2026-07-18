# Phase 0 Proof Safety Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the Aeneid registration demo fail before underfunded native-gas or WIP-fee writes, survive every transaction-confirmation crash without duplicate registration, and publish stage-correct durable metadata whose exact bytes are verified.

**Architecture:** The write path becomes prepare/sign/durably-persist/broadcast/confirm: a mode-0600 signed testnet transaction, its hash, and every immutable proof-building field are journaled before broadcast under an exclusive same-host lease and compare-and-swap revision. On rerun, a matching pending transaction is reconciled before any native-IP or WIP readiness read because the broadcast may already have consumed those balances. Confirmed proof JSON is written completely to a temp file, temp-fsynced, atomically renamed, and directory-fsynced before the journal may clear. Only remaining new prepares receive the conservative native-gas gate, and only a new Derivative prepare receives the WIP balance/allowance gate. Metadata sends the Pinata JWT only to one fixed upload endpoint and permits paired stage overrides only on a strictly validated allow-listed public-IPFS gateway; every returned URI is fetched without credentials and byte-compared before transaction preparation.

**Tech Stack:** TypeScript, Node.js 20+ (`node:test`), viem, Story Protocol SDK 1.4.4, Pinata public IPFS HTTP API

---

## File map

- Create `phase0/src/funding.ts`: conservative native-gas estimate for remaining new writes and diagnostic formatting.
- Create `phase0/tests/funding.test.ts`: zero-remaining, boundary, and estimate tests.
- Create `phase0/src/transactions.ts`: pending-operation schema, exclusive lease, CAS revision, mode-0600 durable journal, intent hashing, and resume state machine.
- Create `phase0/tests/transactions.test.ts`: lease, permissions, durability, CAS, and prepare/broadcast/confirm crash tests.
- Modify `phase0/src/demo.ts`: use the funding preflight and transaction journal for all four writes.
- Modify `phase0/src/story.ts`: encode with the Story SDK, expose WIP fee readiness, sign before broadcast, broadcast raw bytes, wait for receipts, and decode proof events.
- Modify `phase0/src/client.ts`: expose a viem wallet client and the public-client transaction methods.
- Modify `phase0/src/registrations.ts`: persist the confirmed license-template address and durably fsync each confirmed-only manifest before journal clear.
- Modify `phase0/tests/registrations.test.ts`: write-all, fsync/rename ordering, and crash-durability tests.
- Modify `phase0/tests/demo.test.ts` and `phase0/tests/story.test.ts`: new chain seam and no-duplicate recovery coverage.
- Modify `phase0/src/metadata.ts`: Pinata-backed public IPFS publisher and paired stage-specific overrides.
- Modify `phase0/tests/metadata.test.ts`: pin/fetch verification and override-isolation tests.
- Modify `phase0/src/index.ts`: construct the journal/provider and report native-gas and WIP readiness separately.
- Modify `phase0/.env.example`, `.gitignore`, `README.md`, and `package.json`: document safe configuration and wallet-attested scope.

### Safety and human-only boundary

Automated verification uses injected fakes and must not read `phase0/.env`, use a private key, call Pinata, call Story RPC, fund a wallet, wrap IP to WIP, approve WIP, or broadcast a transaction. `pending-transactions.json`, its temporary files, and its process-lock files are always ignored and must never be staged. The journal contains replayable signed bytes even though it contains no private key, so it is local sensitive material. A real Aeneid wallet, Pinata JWT, pinning operation, faucet funding, manual IP-to-WIP wrap, manual WIP approval, and testnet write remain human actions. Mainnet is out of scope and forbidden.

### Task 1: Model native gas for only the remaining new writes

**Files:**
- Create: `phase0/src/funding.ts`
- Create: `phase0/tests/funding.test.ts`
- Modify: `phase0/src/demo.ts:13-16,38-45,162-173`
- Modify: `phase0/src/story.ts:21-24,47-53`
- Modify: `phase0/tests/demo.test.ts:69-138`

- [ ] **Step 1: Write funding tests**

Create `phase0/tests/funding.test.ts`:

```ts
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
```

- [ ] **Step 2: Run the focused test to verify it fails**

Run: `cd phase0 && node --import tsx --test --test-name-pattern='remaining new write|gas prices' tests/funding.test.ts`

Expected: FAIL with `Cannot find module '../src/funding'`.

- [ ] **Step 3: Implement the estimate**

Create `phase0/src/funding.ts`:

```ts
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
```

The gas envelope is deliberately conservative and must be described as an
estimate, not a measured exact fee. Retaining the full envelope for one or more
remaining writes avoids inventing per-stage gas allocations. Do not add
`DEMO_ROOT_MINTING_FEE` to this native-IP amount: that Derivative fee is
denominated in WIP and has its own balance/allowance gate in Task 4.

- [ ] **Step 4: Extend the chain seam with gas price**

Add `getGasPrice(): Promise<bigint>` to `DemoChain`. Add it to `StoryPublicClientBoundary` and implement:

```ts
getGasPrice(): Promise<bigint> {
  return this.publicClient.getGasPrice();
}
```

Update `FakeChain` with `gasPrice = 2n` and a matching method.

Do not call `getBalance` or `getGasPrice` from `runDemo` yet. Task 4 integrates
those reads only after a signed pending operation has been reconciled and only
when at least one genuinely new stage remains.

- [ ] **Step 5: Run Phase 0 tests and typecheck**

Run:

```bash
cd phase0
npm test
npm run typecheck
```

Expected: all tests PASS and TypeScript exits 0.

- [ ] **Step 6: Commit the pure estimator and read seam**

```bash
git add phase0/src/funding.ts phase0/tests/funding.test.ts phase0/src/demo.ts phase0/src/story.ts phase0/tests/demo.test.ts phase0/tests/story.test.ts
git commit -m "feat: estimate gas for remaining Phase 0 writes"
```

### Task 2: Add a private, leased, CAS-safe durable transaction journal

**Files:**
- Create: `phase0/src/transactions.ts`
- Create: `phase0/tests/transactions.test.ts`
- Modify: `phase0/.gitignore`

- [ ] **Step 1: Write permissions, lease, CAS, and durability tests**

Create `phase0/tests/transactions.test.ts` with a temporary file. Add the
production hash function and types to its imports:

```ts
import {
  operationIntentHash,
  type CanonicalOperationIntent,
  type PendingOperation,
} from "../src/transactions";
```

Use a complete valid canonical intent for every lifecycle/CAS/durability test;
the ordinary record must never rely on a fabricated intent hash:

```ts
const INTENT: CanonicalOperationIntent = {
  stage: "root",
  chainId: 1315,
  wallet: "0x00000000000000000000000000000000000000aa",
  registrationName: "demo-research-skill",
  artifactPath: "fixtures/demo-base/SKILL.md",
  spgNftContract: "0x00000000000000000000000000000000000000bb",
  parentIpId: null,
  licenseTermsId: null,
  licenseTemplate: null,
  currencyToken: null,
  defaultMintingFee: null,
  maxMintingFee: null,
  metadata: {
    ipMetadataURI: "ipfs://root-ip-metadata",
    ipMetadataHash: `0x${"4".repeat(64)}`,
    nftMetadataURI: "ipfs://root-nft-metadata",
    nftMetadataHash: `0x${"5".repeat(64)}`,
    artifactMediaHash: `0x${"6".repeat(64)}`,
    artifactMediaType: "text/markdown",
  },
  runConfigHash: `0x${"7".repeat(64)}`,
};

const RECORD: PendingOperation = {
  schemaVersion: 1,
  operationId: "phase0:0x00000000000000000000000000000000000000aa:root",
  stage: "root",
  intent: INTENT,
  intentHash: operationIntentHash(INTENT),
  transactionHash: `0x${"2".repeat(64)}`,
  serializedTransaction: `0x${"3".repeat(128)}`,
  state: "prepared",
};

const INTENT_HASH_MISMATCH: PendingOperation = {
  ...RECORD,
  intentHash: `0x${"0".repeat(64)}`,
};
```

Add the exact lifecycle test:

```ts
await journal.withExclusiveLease(async (leased) => {
  const empty = await leased.load();
  assert.deepEqual(empty, { revision: 0, operation: null });
  const saved = await leased.save(RECORD, empty.revision);
  assert.equal(saved.revision, 1);
  assert.deepEqual(saved.operation, RECORD);
  const cleared = await leased.clear(RECORD.operationId, saved.revision);
  assert.deepEqual(cleared, { revision: 2, operation: null });
});
const stat = await fs.stat(journalPath);
assert.equal(stat.mode & 0o777, 0o600);
assert.equal((await fs.readFile(journalPath, "utf8")).endsWith("\n"), true);
assert.deepEqual((await fs.readdir(directory)).filter((name) => name.includes(".tmp")), []);
```

Add separate tests proving:

1. while one `withExclusiveLease` callback is paused, a second journal instance
   on the same path rejects with `Pending transaction journal is locked`;
2. `save(RECORD, 0)` followed by another `save(RECORD, 0)` rejects as a stale
   CAS revision and leaves revision 1 intact;
3. `clear` rejects the wrong operation ID and stale revision;
4. changing the journal to mode `0644` makes `load` fail before returning signed
   bytes;
5. an injected crash after temporary-file `sync()` but before `rename()` leaves
   the previous final snapshot byte-identical; a normal retry removes its own
   temporary file and advances exactly one revision;
6. saving `INTENT_HASH_MISMATCH`, or loading an on-disk copy whose intent was
   changed without recomputing its hash, fails as intent corruption; use this
   mismatched record only in these corruption tests;
7. malformed hashes, odd-length signed hex, malformed lock owner JSON, and a
   lock owned by a live same-host PID all fail closed.

- [ ] **Step 2: Run the focused test to verify it fails**

Run: `cd phase0 && node --import tsx --test tests/transactions.test.ts`

Expected: FAIL with `Cannot find module '../src/transactions'`.

- [ ] **Step 3: Define the pending-operation schema**

Create `phase0/src/transactions.ts`:

```ts
export type OperationStage = "collection" | "root" | "child" | "grandchild";
export type OperationState = "prepared" | "broadcast";

export interface CanonicalOperationIntent {
  stage: OperationStage;
  chainId: 1315;
  wallet: `0x${string}`;
  registrationName: string | null;
  artifactPath: string | null;
  spgNftContract: `0x${string}` | null;
  parentIpId: `0x${string}` | null;
  licenseTermsId: string | null;
  licenseTemplate: `0x${string}` | null;
  currencyToken: `0x${string}` | null;
  defaultMintingFee: string | null;
  maxMintingFee: string | null;
  metadata: {
    ipMetadataURI: string;
    ipMetadataHash: `0x${string}`;
    nftMetadataURI: string;
    nftMetadataHash: `0x${string}`;
    artifactMediaHash: `0x${string}`;
    artifactMediaType: string;
  } | null;
  runConfigHash: `0x${string}`;
}

export interface PendingOperation {
  schemaVersion: 1;
  operationId: string;
  stage: OperationStage;
  intent: CanonicalOperationIntent;
  intentHash: `0x${string}`;
  transactionHash: `0x${string}`;
  serializedTransaction: `0x${string}`;
  state: OperationState;
}

export interface JournalSnapshot {
  revision: number;
  operation: PendingOperation | null;
}

export interface LeasedOperationJournal {
  load(): Promise<JournalSnapshot>;
  save(operation: PendingOperation, expectedRevision: number): Promise<JournalSnapshot>;
  clear(operationId: string, expectedRevision: number): Promise<JournalSnapshot>;
}

export interface OperationJournal {
  withExclusiveLease<T>(callback: (journal: LeasedOperationJournal) => Promise<T>): Promise<T>;
}
```

Use strict regex validation for 32-byte hashes and nonempty even-length
serialized transaction hex. On every load, recompute `operationIntentHash` from
the persisted intent and require equality with `intentHash`. The intent contains
no prompt, artifact bytes, credential, or private key; it deliberately retains
the registration name, artifact path, metadata URI/hashes, and expected
collection/parent/license fields needed to confirm and save the complete proof
without consulting changed local definitions or republishing metadata after a
crash. Require `registrationName` and `artifactPath` to be nonempty for root,
child, and grandchild intents and exactly null for collection intent.

- [ ] **Step 4: Implement deterministic intent hashing**

Export:

```ts
export function operationIntentHash(value: unknown): `0x${string}` {
  const canonical = JSON.stringify(value, (_key, item) =>
    typeof item === "bigint" ? { $bigint: item.toString() } : item,
  );
  return `0x${createHash("sha256").update(canonical).digest("hex")}`;
}
```

Callers must build `CanonicalOperationIntent` in its declared field order. The
hash binds stage, chain, wallet, registration name, artifact path,
collection/parent, license terms, fee currency and cap, all four metadata
URI/hash fields, and `runConfigHash`. Export a second
helper, `runConfigHash`, over a canonical object containing chain ID, wallet,
and each stage's name, description, artifact path, and artifact SHA-256. This
local fingerprint requires no metadata upload or RPC read.

- [ ] **Step 5: Implement the exclusive lease, CAS, and durable mode-0600 write**

`FileOperationJournal.withExclusiveLease` creates
`pending-transactions.json.lock` using `open(path, "wx", 0o600)`. Write one
trailing-newline JSON owner record containing a random 128-bit `leaseId`,
`hostname()`, `process.pid`, and `startedAtUtc`; sync and close it before reading
the journal. If it exists, report the recorded host/PID/lease ID and fail. Hold
the lease for the entire `runDemo` callback. Release only after rereading the
lock and matching the exact lease ID; a mismatched owner is a CAS failure and
must not be unlinked.

Never auto-delete a lock after a timeout. Document an explicit same-host stale
lock recovery command that requires the recorded lease ID and verifies
`process.kill(pid, 0)` returns `ESRCH` before unlinking. `EPERM`, a different
host, malformed owner data, a live PID, or a changed lease ID fails closed. The
supported boundary is one local filesystem host; network filesystems are out of
scope.

Persist this exact top-level shape:

```ts
interface JournalFile {
  schemaVersion: 1;
  revision: number;
  operation: PendingOperation | null;
}
```

Every `save` or `clear` reloads under the lease and requires
`current.revision === expectedRevision`. Increment exactly once. `clear` also
requires the matching operation ID and writes `operation: null`; retaining the
revision is necessary for CAS.

For every write:

1. create a unique same-directory temporary file with flags `wx` and mode
   `0o600`;
2. write the complete trailing-newline JSON;
3. call the temporary file handle's `sync()` and close it;
4. atomically `rename()` it over the journal;
5. open the containing directory read-only, call `sync()`, and close it;
6. `stat()` the final journal and require `(mode & 0o777) === 0o600`.

On failure, remove only the unique temporary file created by this call. On
load, reject the journal before parsing signed bytes unless its exact mode is
`0600`. Never log `serializedTransaction`.

- [ ] **Step 6: Ignore the journal explicitly**

Append to `phase0/.gitignore`:

```gitignore
# Contains a signed, testnet-only transaction while crash recovery is in flight.
pending-transactions.json
pending-transactions.json.*.tmp
pending-transactions.json.lock
```

Do not put the private key in the journal. The serialized transaction contains
no key material but is replayable authorization and must be treated as local
sensitive data. Add a test that `git check-ignore` covers all three patterns and
`git ls-files` returns none of them.

- [ ] **Step 7: Run journal tests**

Run: `cd phase0 && node --import tsx --test tests/transactions.test.ts && npm run typecheck`

Expected: all journal tests PASS and TypeScript exits 0.

- [ ] **Step 8: Commit the journal**

```bash
git add phase0/src/transactions.ts phase0/tests/transactions.test.ts phase0/.gitignore
git commit -m "feat: journal pending Aeneid transactions"
```

### Task 3: Split Story writes into prepare, broadcast, and confirm

**Files:**
- Modify: `phase0/src/client.ts:1-40`
- Modify: `phase0/src/demo.ts:38-70`
- Modify: `phase0/src/story.ts:1-133`
- Modify: `phase0/tests/story.test.ts`

- [ ] **Step 1: Write Story transaction-boundary tests**

Update `tests/story.test.ts` fakes and add tests proving:

1. `prepareCollection` calls the SDK with `txOptions: { encodedTxDataOnly: true }`, signs the returned `to/data`, and returns the locally computed transaction hash without broadcasting;
2. `broadcastPrepared` sends the exact serialized bytes and requires the RPC hash to equal the prepared hash;
3. `confirmCollection` decodes `CollectionCreated`;
4. `confirmSkill` decodes `IPRegistered` plus `LicenseTermsAttached`;
5. `nonce too low` with the exact expected transaction/receipt reconciles,
   while `nonce too low` with the expected hash absent fails as unresolved or
   replaced;
6. `confirmDerivative` requires matching `IPRegistered` and
   `DerivativeRegistered` child, parent, license terms, and license template;
7. a reverted receipt or any mismatched Derivative event fails without a proof.

Use deterministic fixture values:

```ts
const ENCODED = { to: SPG, data: "0x1234" as const };
const SERIALIZED = `0x${"ab".repeat(64)}` as const;
const TX_HASH = keccak256(SERIALIZED);
```

- [ ] **Step 2: Run Story tests to verify the old seam fails**

Run: `cd phase0 && node --import tsx --test tests/story.test.ts`

Expected: FAIL because `prepareCollection`, `broadcastPrepared`, and confirm methods do not exist.

- [ ] **Step 3: Expose a wallet client without exposing the key**

In `src/client.ts`, add:

```ts
export function getWalletClient() {
  return createWalletClient({
    account: getAccount(),
    chain: aeneidChain,
    transport: http(RPC),
  });
}
```

Never log the account's private key or a serialized pending transaction.

- [ ] **Step 4: Replace the DemoChain write seam**

Use these exact types in `src/demo.ts`:

```ts
export interface PreparedChainTransaction {
  transactionHash: `0x${string}`;
  serializedTransaction: `0x${string}`;
}

export interface DemoChain {
  getChainId(): Promise<number>;
  getBalance(address: `0x${string}`): Promise<bigint>;
  getGasPrice(): Promise<bigint>;
  prepareCollection(input: CollectionInput): Promise<PreparedChainTransaction>;
  prepareSkill(input: SkillInput): Promise<PreparedChainTransaction>;
  prepareDerivative(input: DerivativeInput): Promise<PreparedChainTransaction>;
  broadcastPrepared(input: PreparedChainTransaction): Promise<void>;
  confirmCollection(txHash: `0x${string}`): Promise<CollectionResult>;
  confirmSkill(txHash: `0x${string}`): Promise<SkillResult>;
  confirmDerivative(input: {
    transactionHash: `0x${string}`;
    expectedCollection: `0x${string}`;
    expectedParentIpId: `0x${string}`;
    expectedLicenseTermsId: bigint;
    expectedLicenseTemplate: `0x${string}`;
  }): Promise<DerivativeResult>;
  predictMintingLicenseFee(input: PredictFeeInput): Promise<{ tokenAmount: bigint }>;
}
```

Move the existing input/result inline types into named exported interfaces so journal helpers and fakes use one contract.

- [ ] **Step 5: Encode, sign, and hash before broadcast**

Extend `StoryChain` constructor with a wallet boundary supporting
`prepareTransactionRequest` and `signTransaction`, and a public boundary
supporting `sendRawTransaction`, `getTransaction`, `getTransactionReceipt`, and
`waitForTransactionReceipt`.

For each prepare method:

```ts
const response = await this.sdk.nftClient.createNFTCollection({
  ...input,
  isPublicMinting: true,
  mintOpen: true,
  contractURI: "",
  txOptions: { encodedTxDataOnly: true },
});
const encoded = required(response.encodedTxData, "encoded collection transaction");
const request = await this.wallet.prepareTransactionRequest({
  account: this.wallet.account,
  chain: this.wallet.chain,
  to: encoded.to,
  data: encoded.data,
});
const serializedTransaction = await this.wallet.signTransaction(request);
return {
  serializedTransaction,
  transactionHash: keccak256(serializedTransaction),
};
```

Apply the same `encodedTxDataOnly` pattern to root and Derivative SDK methods. Preserve existing LAP/LRP, fee cap, metadata, and validation behavior.

Treat `encodedTxDataOnly` as an encoding boundary, not a fee-readiness feature.
In SDK 1.4.4 the early encoded-data return bypasses
`handleRegistrationWithFees`, including its automatic IP-to-WIP wrapping and
WIP approval. Task 4 adds the required explicit read-only WIP balance/allowance
gate before any Derivative prepare.

- [ ] **Step 6: Broadcast or reconcile only the exact expected hash**

Implement:

```ts
async broadcastPrepared(input: PreparedChainTransaction): Promise<void> {
  try {
    const observed = await this.publicClient.sendRawTransaction({
      serializedTransaction: input.serializedTransaction,
    });
    if (observed.toLowerCase() !== input.transactionHash.toLowerCase()) {
      throw new Error(`RPC returned ${observed}; expected ${input.transactionHash}`);
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (!/already known|known transaction|nonce too low/i.test(message)) throw error;
    const exactTransaction = await this.findExactTransaction(input.transactionHash);
    if (!exactTransaction) {
      throw new Error(
        `Prepared transaction ${input.transactionHash} is unresolved; its nonce may have been replaced`,
        { cause: error },
      );
    }
  }
}
```

`findExactTransaction` queries both `getTransaction({ hash: expected })` and
`getTransactionReceipt({ hash: expected })`, treating only the clients'
documented not-found errors as absence. It returns true only when a response's
own hash equals the expected hash. Any other RPC error propagates. An
“already known” message or consumed nonce is never sufficient by itself; if the
exact expected hash cannot be found, fail as unresolved/replaced. The next step
still waits for and validates the expected receipt.

- [ ] **Step 7: Decode only successful receipts**

Use viem `parseAbiItem`/`parseEventLogs` with these exact events:

```ts
const COLLECTION_CREATED = parseAbiItem("event CollectionCreated(address indexed spgNftContract)");
const IP_REGISTERED = parseAbiItem("event IPRegistered(address ipId, uint256 indexed chainId, address indexed tokenContract, uint256 indexed tokenId, string name, string uri, uint256 registrationDate)");
const LICENSE_TERMS_ATTACHED = parseAbiItem("event LicenseTermsAttached(address indexed caller, address indexed ipId, address licenseTemplate, uint256 licenseTermsId)");
const DERIVATIVE_REGISTERED = parseAbiItem("event DerivativeRegistered(address indexed caller, address indexed childIpId, uint256[] licenseTokenIds, address[] parentIpIds, uint256[] licenseTermsIds, address licenseTemplate)");
```

Require `receipt.status === "success"` and
`receipt.transactionHash === expectedHash`, then require exactly one relevant
registration event for the expected chain/collection. Root confirmation also
requires the license event for the same `ipId`; return and persist its
`licenseTemplate` with the root proof.

Derivative confirmation parses both event types from the same exact receipt and
requires:

- `DerivativeRegistered.childIpId` equals the `IPRegistered.ipId`;
- `parentIpIds` is exactly `[expectedParentIpId]`, in order;
- `licenseTermsIds` is exactly `[expectedLicenseTermsId]`, in order;
- `licenseTemplate` equals the template persisted from the parent proof;
- the IP registration's chain and token contract equal Aeneid and the expected
  SPG collection.

Return the event-derived child IP, token ID, matched license terms ID, template,
and supplied transaction hash. Normalize root and Derivative confirmation
results so both expose `licenseTermsId: bigint` and
`licenseTemplate: 0x${string}` to the proof builder. Never construct Derivative
ancestry from local inputs alone. Extend
`RegistrationProof` and its strict parser with required `licenseTemplate`; child
and grandchild persist the template emitted by their own
`DerivativeRegistered` event. Add negative tests for mismatched child, parent,
terms ID, template, duplicate events, and missing events.

- [ ] **Step 8: Run Story tests and typecheck**

Run: `cd phase0 && node --import tsx --test tests/story.test.ts && npm run typecheck`

Expected: Story tests PASS; no fake's `sendRawTransaction` runs during a prepare-only assertion.

- [ ] **Step 9: Commit the two-phase chain seam**

```bash
git add phase0/src/client.ts phase0/src/demo.ts phase0/src/story.ts phase0/src/registrations.ts phase0/tests/story.test.ts
git commit -m "refactor: separate Story submission from confirmation"
```

### Task 4: Resume the exact signed transaction after every crash point

**Files:**
- Modify: `phase0/src/demo.ts:72-300`
- Modify: `phase0/src/story.ts:1-180`
- Modify: `phase0/src/registrations.ts:1-255`
- Modify: `phase0/src/index.ts:158-165`
- Modify: `phase0/.gitignore`
- Modify: `phase0/tests/demo.test.ts`
- Modify: `phase0/tests/registrations.test.ts`
- Modify: `phase0/tests/story.test.ts`

- [ ] **Step 1: Add a reusable crash-safe operation helper test**

In `tests/demo.test.ts`, extend fakes with counters for `prepare`, `broadcast`, and `confirm`. Add a table-driven test for crashes:

```ts
for (const crashAfter of ["journal", "broadcast", "confirm", "manifest-save"] as const) {
  test(`resume after ${crashAfter} reuses one root transaction hash`, async () => {
    const journal = new MemoryOperationJournal();
    const chain = new CrashableChain(crashAfter);
    await assert.rejects(runDemo({ wallet: WALLET, chain, metadata, store, journal }), /simulated crash/);
    const preparedHash = journal.operation?.transactionHash;
    const resumed = chain.resumedWithoutCrash();
    await runDemo({ wallet: WALLET, chain: resumed, metadata, store, journal });
    assert.equal(resumed.preparedHashes.filter((x) => x === preparedHash).length, 0);
    assert.equal(resumed.broadcastHashes.every((x) => x === preparedHash), true);
    assert.equal(resumed.confirmHashes.includes(preparedHash), true);
    assert.equal(store.manifest.registrations.root?.txHash, preparedHash);
  });
}
```

Also assert a persisted intent/hash mismatch aborts before broadcast as journal
corruption. A valid pending journal whose persisted wallet/config differs from
the current invocation still reconciles only its exact signed hash, saves that
proof, then blocks every new stage with the explicit configuration-mismatch
error.

For the existing `"manifest-save"` crash row, use a store whose durable-save
hook throws after rename but before directory fsync. Assert
`journal.clearCalls === 0`, the exact pending operation and CAS revision remain,
and no replacement prepare occurs on resume. Whether the post-crash filesystem
exposes the old manifest or the renamed manifest, resume must either re-confirm
the same hash and save it durably or observe the same manifest hash and clear;
both branches forbid a second signed transaction.

In `tests/registrations.test.ts`, add a real-filesystem ordering regression
using the `ManifestWriteHooks` introduced in Step 5:

```ts
test("manifest save resolves only after file and directory fsync", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "phase0-durable-manifest-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const events: string[] = [];
  const store = new FileRegistrationStore(join(directory, "registrations.json"), {
    afterTempSync: () => { events.push("temp-fsync"); },
    afterRename: () => { events.push("rename"); },
    afterDirectorySync: () => { events.push("directory-fsync"); },
  });
  await store.save(createEmptyRegistrationManifest());
  events.push("resolved");
  assert.deepEqual(events, ["temp-fsync", "rename", "directory-fsync", "resolved"]);
  assert.deepEqual(await readdir(directory), ["registrations.json"]);
});

test("crash after temp fsync preserves the previous complete manifest", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "phase0-durable-manifest-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const path = join(directory, "registrations.json");
  const previous = createEmptyRegistrationManifest();
  await new FileRegistrationStore(path).save(previous);
  const previousBytes = await readFile(path);
  const next = createEmptyRegistrationManifest();
  next.wallet = WALLET;
  next.spgNftContract = SPG;
  next.collectionTxHash = TX_HASH;
  next.status = "partial";
  const crashing = new FileRegistrationStore(path, {
    afterTempSync: () => { throw new Error("simulated crash after temp fsync"); },
  });
  await assert.rejects(crashing.save(next), /simulated crash/);
  assert.deepEqual(await readFile(path), previousBytes);
  assert.deepEqual(await readdir(directory), ["registrations.json"]);
});

test("rename interruption exposes only a parseable complete manifest", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "phase0-durable-manifest-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const path = join(directory, "registrations.json");
  const next = createEmptyRegistrationManifest();
  next.wallet = WALLET;
  next.spgNftContract = SPG;
  next.collectionTxHash = TX_HASH;
  next.status = "partial";
  const crashing = new FileRegistrationStore(path, {
    afterRename: () => { throw new Error("simulated crash before directory fsync"); },
  });
  await assert.rejects(crashing.save(next), /simulated crash/);
  assert.deepEqual(await new FileRegistrationStore(path).load(), next);
  assert.deepEqual(await readdir(directory), ["registrations.json"]);
});
```

In the same test file, make `rootOnlyConfirmedStore()` return a manifest whose
collection and root proof are already confirmed and whose stored root metadata
matches the injected metadata provider. Extend `CrashableChain` with
`predictedCurrencyToken`, `predictedFee`, `wipBalance`, `wipAllowance`,
`derivativeFeeSpender`, `feeReadinessCalls`, per-stage prepare counts, and
broadcast counts. Also count `balanceReads`, `gasPriceReads`, and metadata
provider calls. Add these two focused cases:

```ts
test("insufficient WIP balance stops before Derivative prepare", async () => {
  const chain = new CrashableChain(null);
  chain.predictedFee = DEMO_ROOT_MINTING_FEE;
  chain.wipBalance = DEMO_ROOT_MINTING_FEE - 1n;
  chain.wipAllowance = DEMO_ROOT_MINTING_FEE;
  await assert.rejects(
    runDemo({
      wallet: WALLET,
      chain,
      metadata,
      store: rootOnlyConfirmedStore(),
      journal: new MemoryOperationJournal(),
    }),
    /WIP balance.*required/i,
  );
  assert.equal(chain.feeReadinessCalls, 1);
  assert.equal(chain.prepareCounts.child, 0);
  assert.equal(chain.broadcastHashes.length, 0);
});

test("insufficient WIP allowance stops before Derivative prepare", async () => {
  const chain = new CrashableChain(null);
  chain.predictedFee = DEMO_ROOT_MINTING_FEE;
  chain.wipBalance = DEMO_ROOT_MINTING_FEE;
  chain.wipAllowance = DEMO_ROOT_MINTING_FEE - 1n;
  await assert.rejects(
    runDemo({
      wallet: WALLET,
      chain,
      metadata,
      store: rootOnlyConfirmedStore(),
      journal: new MemoryOperationJournal(),
    }),
    /WIP allowance.*required/i,
  );
  assert.equal(chain.feeReadinessCalls, 1);
  assert.equal(chain.prepareCounts.child, 0);
  assert.equal(chain.broadcastHashes.length, 0);
});
```

Add a second table for `crashAfter` values `"broadcast"` and `"confirm"` using a
root-only manifest. The first chain run prepares the child, consumes its WIP in
the simulated broadcast, and crashes while the child journal remains. Resume
with `wipBalance = 0n` and `wipAllowance = 0n`; use a store fake that persists
the recovered child proof and then throws `stop after recovered child` so the
test does not begin the unrelated grandchild. Assert all of the following:

```ts
assert.equal(resumed.feeReadinessCalls, 0);
assert.equal(resumed.prepareCounts.child, 0);
assert.equal(resumed.broadcastHashes[0], pendingChildHash);
assert.equal(resumed.confirmHashes[0], pendingChildHash);
assert.equal(store.manifest.registrations.child?.txHash, pendingChildHash);
```

This regression proves depleted current WIP cannot block confirmation of the
already-signed transaction that consumed it.

Add a final-stage regression for both `"broadcast"` and `"confirm"` crash
points. Start with collection, root, and child confirmed, prepare the
grandchild, and have the simulated broadcast consume the wallet's remaining IP
and WIP. On resume set native balance, WIP balance, and allowance to zero, and
use a metadata provider whose `prepare` throws `Pinata unavailable on resume`.
The pending grandchild is the final stage, so recovery must complete without
any readiness or metadata call:

```ts
assert.equal(resumed.balanceReads, 0);
assert.equal(resumed.gasPriceReads, 0);
assert.equal(resumed.feeReadinessCalls, 0);
assert.equal(resumeMetadata.calls, 0);
assert.equal(resumed.prepareCounts.grandchild, 0);
assert.equal(resumed.broadcastHashes[0], pendingGrandchildHash);
assert.equal(resumed.confirmHashes[0], pendingGrandchildHash);
assert.equal(result.registrations.grandchild?.txHash, pendingGrandchildHash);
assert.equal(result.status, "complete");
```

Add a configuration-drift variant. Let the exact pending hash reconcile and
persist its proof from `pending.intent`, then change the current local
definition's name and artifact path as well as the run-config fingerprint.
Give the journal distinctive values such as `journal-child-name` and
`fixtures/journal-child/SKILL.md`; assert the recovered manifest proof uses
those exact values, not the changed current definition. Then assert the command reports
`Recovered pending transaction, but current run configuration differs` before
publishing metadata or preparing another transaction. It must never construct
or broadcast replacement bytes.

```ts
const changedDefinition: DemoSkillDefinition = {
  stage: "child",
  name: "changed-current-child-name",
  description: "Changed only to prove recovery does not consult current proof fields.",
  artifactPath: "fixtures/changed-current-child/SKILL.md",
};
assert.equal(store.manifest.registrations.child?.name, "journal-child-name");
assert.equal(
  store.manifest.registrations.child?.metadata.artifact.path,
  "fixtures/journal-child/SKILL.md",
);
assert.notEqual(store.manifest.registrations.child?.name, changedDefinition.name);
assert.notEqual(
  store.manifest.registrations.child?.metadata.artifact.path,
  changedDefinition.artifactPath,
);
```

Add a Story-boundary test whose fake SDK exposes WIP `balanceOf` and
`allowance` plus a DerivativeWorkflows address. Assert the method reads the
wallet's WIP balance, reads allowance for that exact spender, and returns both.
An unexpected predicted currency must reject before either read.

- [ ] **Step 2: Run the crash tests to verify they fail**

Run: `cd phase0 && node --import tsx --test --test-name-pattern='resume after|intent-hash|manifest save|directory fsync|WIP balance|WIP allowance|Pinata unavailable|current run configuration' tests/demo.test.ts tests/registrations.test.ts tests/story.test.ts`

Expected: FAIL because `runDemo` does not accept/reconcile an operation journal
and the chain seam has no WIP readiness method.

- [ ] **Step 3: Add the journal to RunDemoInput**

```ts
export interface RunDemoInput {
  wallet: `0x${string}`;
  chain: DemoChain;
  metadata: DemoMetadataProvider;
  store: RegistrationStore;
  journal: LeasedOperationJournal;
  skills?: readonly DemoSkillDefinition[];
}
```

Construct `new FileOperationJournal(fileURLToPath(new URL("../pending-transactions.json", import.meta.url)))` in `index.ts`, then hold its lease around the entire command:

```ts
const journal = new FileOperationJournal(pendingTransactionsPath);
return journal.withExclusiveLease((leasedJournal) => runDemo({
  wallet: account.address,
  chain: storyChain(),
  metadata: new HttpMetadataProvider(),
  store: new FileRegistrationStore(registrationsPath),
  journal: leasedJournal,
}));
```

Tests pass a `MemoryLeasedOperationJournal` directly. No production call to
`runDemo` may bypass `withExclusiveLease`.

- [ ] **Step 4: Implement one generic execute-or-resume helper**

Add to `demo.ts`:

```ts
async function executeOrResume<T>(input: {
  journal: LeasedOperationJournal;
  operationId: string;
  stage: OperationStage;
  intent: CanonicalOperationIntent;
  prepare(): Promise<PreparedChainTransaction>;
  broadcast(tx: PreparedChainTransaction): Promise<void>;
  confirm(operation: PendingOperation): Promise<T>;
}): Promise<{
  result: T;
  operation: PendingOperation;
  journalRevision: number;
}> {
  const intentHash = operationIntentHash(input.intent);
  let snapshot = await input.journal.load();
  let pending = snapshot.operation;
  if (pending) {
    if (pending.operationId !== input.operationId
        || pending.stage !== input.stage
        || pending.intentHash !== intentHash) {
      throw new Error(`Pending ${pending.stage} transaction does not match the current ${input.stage} intent`);
    }
  } else {
    const prepared = await input.prepare();
    pending = {
      schemaVersion: 1,
      operationId: input.operationId,
      stage: input.stage,
      intent: input.intent,
      intentHash,
      transactionHash: prepared.transactionHash,
      serializedTransaction: prepared.serializedTransaction,
      state: "prepared",
    };
    snapshot = await input.journal.save(pending, snapshot.revision);
  }
  await input.broadcast({
    transactionHash: pending.transactionHash,
    serializedTransaction: pending.serializedTransaction,
  });
  if (pending.state !== "broadcast") {
    pending = { ...pending, state: "broadcast" };
    snapshot = await input.journal.save(pending, snapshot.revision);
  }
  const result = await input.confirm(pending);
  return { result, operation: pending, journalRevision: snapshot.revision };
}
```

The caller clears with the returned revision only after the confirmed result has
been inserted into the manifest and `store.save(manifest)` succeeds. Therefore
a crash after confirmation but before manifest save re-confirms the same hash,
and a stale process cannot clear or overwrite a newer journal revision.

- [ ] **Step 5: Make manifest persistence durable before journal clear**

In `src/registrations.ts`, replace `writeFile` with an explicit write-all and
durability sequence. Add these test-only observation hooks; production callers
use the default empty object:

```ts
import {
  mkdir,
  open,
  readFile,
  rename,
  unlink,
  type FileHandle,
} from "node:fs/promises";

export interface ManifestWriteHooks {
  afterTempSync?(): void | Promise<void>;
  afterRename?(): void | Promise<void>;
  afterDirectorySync?(): void | Promise<void>;
}

async function writeAll(handle: FileHandle, bytes: Uint8Array): Promise<void> {
  let offset = 0;
  while (offset < bytes.byteLength) {
    const { bytesWritten } = await handle.write(
      bytes,
      offset,
      bytes.byteLength - offset,
      offset,
    );
    if (bytesWritten === 0) throw new Error("Manifest temporary write made no progress");
    offset += bytesWritten;
  }
}
```

Change the constructor to
`constructor(private readonly path: string, private readonly hooks:
ManifestWriteHooks = {})`. Implement `save` in this exact order:

```ts
async save(manifest: RegistrationManifest): Promise<void> {
  parseRegistrationManifest(manifest);
  const directory = dirname(this.path);
  await mkdir(directory, { recursive: true });
  const temporaryPath = `${this.path}.${process.pid}.${randomUUID()}.tmp`;
  const bytes = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`, "utf8");
  let temporaryHandle: FileHandle | null = null;
  let renamed = false;
  try {
    temporaryHandle = await open(temporaryPath, "wx", 0o600);
    await writeAll(temporaryHandle, bytes);
    await temporaryHandle.sync();
    await this.hooks.afterTempSync?.();
    await temporaryHandle.close();
    temporaryHandle = null;
    await rename(temporaryPath, this.path);
    renamed = true;
    await this.hooks.afterRename?.();
    const directoryHandle = await open(directory, "r");
    try {
      await directoryHandle.sync();
    } finally {
      await directoryHandle.close();
    }
    await this.hooks.afterDirectorySync?.();
  } catch (error) {
    if (temporaryHandle) await temporaryHandle.close().catch(() => undefined);
    if (!renamed) await unlink(temporaryPath).catch(() => undefined);
    throw error;
  }
}
```

Do not unlink `this.path` after rename if directory fsync fails: the final name
contains a complete, temp-fsynced JSON image and recovery can safely accept
either the prior or renamed directory state after a real crash. In `demo.ts`,
the only permitted ordering is:

```ts
await input.store.save(manifest);
await input.journal.clear(executed.operation.operationId, executed.journalRevision);
```

Never place journal clear in `finally`, start it concurrently, or treat rename
alone as a successful save. `RegistrationStore.save` resolves only after
directory fsync, so its resolution is the durability barrier.
Add `registrations.json.*.tmp` to `phase0/.gitignore` so a process-killed
write-all temporary can never be staged as proof.

- [ ] **Step 6: Reconcile a persisted operation before readiness or metadata publication**

After chain-ID validation and manifest load, load the journal before calling
`getBalance`, `getGasPrice`, `predictMintingLicenseFee`, WIP reads, or
`metadata.prepare`. If `snapshot.operation` exists, route solely by its
persisted stage and canonical intent:

1. validate the intent hash, chain ID, stage ordering, and that any already
   persisted prerequisite proof matches the journal-bound collection/parent;
2. call `executeOrResume` with `intent: pending.intent` and a `prepare` callback
   that throws if invoked;
3. broadcast/reconcile only `pending.serializedTransaction` and confirm only
   `pending.transactionHash`;
4. pass the persisted expected collection/parent/license/template fields into
   the confirm method;
5. reconstruct `PreparedMetadata` and the `RegistrationProof` name/artifact
   path from `pending.intent.metadata`, `pending.intent.registrationName`, and
   `pending.intent.artifactPath`, never from a current `skills` definition, new
   upload, or override fetch;
6. durably save the confirmed proof to the manifest using the fsync/rename
   protocol below;
7. clear with the returned CAS revision.

Refactor the proof helper to accept `PendingOperation`, not a current
`DemoSkillDefinition`. Its immutable-field mapping is exact:

```ts
function requiredAddress(
  value: `0x${string}` | null,
  label: string,
): `0x${string}` {
  if (!value) throw new Error(`Pending intent is missing ${label}`);
  return value;
}

function requiredString(value: string | null, label: string): string {
  if (!value) throw new Error(`Pending intent is missing ${label}`);
  return value;
}

const intent = operation.intent;
if (operation.stage === "collection" || !intent.metadata) {
  throw new Error("A registration proof requires journal-bound metadata");
}
const registrationName = requiredString(intent.registrationName, "registration name");
const artifactPath = requiredString(intent.artifactPath, "artifact path");
const proof: RegistrationProof = {
  stage: operation.stage,
  kind: operation.stage === "root" ? "Skill" : "Derivative",
  name: registrationName,
  ipId: confirmed.ipId,
  tokenId: confirmed.tokenId.toString(),
  txHash: operation.transactionHash,
  licenseTermsId: confirmed.licenseTermsId.toString(),
  licenseTemplate: confirmed.licenseTemplate,
  parentIpIds: operation.stage === "root"
    ? []
    : [requiredAddress(intent.parentIpId, "parent IP")],
  defaultMintingFee: intent.defaultMintingFee,
  maxMintingFee: intent.maxMintingFee,
  metadata: {
    ip: { uri: intent.metadata.ipMetadataURI, hash: intent.metadata.ipMetadataHash },
    nft: { uri: intent.metadata.nftMetadataURI, hash: intent.metadata.nftMetadataHash },
    artifact: {
      path: artifactPath,
      mediaHash: intent.metadata.artifactMediaHash,
      mediaType: intent.metadata.artifactMediaType,
    },
  },
};
```

The current definition remains relevant only when computing the post-recovery
`runConfigHash` and deciding whether new stages may start.

For a journal whose transaction hash is already present in the manifest,
require exact hash equality and clear it by CAS without a second broadcast. If
the manifest hash differs, stop as corruption.

Only after pending reconciliation, compute the current local `runConfigHash`.
If it differs from the recovered operation's persisted hash, keep the recovered
proof but throw `Recovered pending transaction, but current run configuration
differs` before any new metadata publication or transaction preparation. This
allows an authorized signed transaction to be recovered when Pinata is down or
local files changed without silently continuing under a different config.

Recompute the exact remaining new stages from the now-current manifest. If none
remain, return immediately with zero native or WIP readiness reads. Otherwise,
and only otherwise, perform the native gate:

```ts
const remainingStages = missingOperationStages(manifest);
if (remainingStages.length > 0) {
  const [balance, gasPrice] = await Promise.all([
    input.chain.getBalance(input.wallet),
    input.chain.getGasPrice(),
  ]);
  const requiredMinimum = estimateRemainingDemoGasMinimum({
    gasPrice,
    remainingNewWrites: remainingStages.length,
  });
  if (balance < requiredMinimum) {
    throw new Error(
      `Wallet ${input.wallet} has ${formatEther(balance)} IP; `
      + `estimated native-gas minimum for ${remainingStages.join(",")} is `
      + `${formatEther(requiredMinimum)} IP. Fund it manually at ${AENEID_FAUCET_URL}`,
    );
  }
}
```

After this gate, verify completed stages using only local artifact bytes against
their stored artifact hashes. Call `metadata.prepare` only for missing stages.
For each new stage, build a complete `CanonicalOperationIntent`, execute it,
save the confirmed proof, and clear by CAS. The root intent sets
`parentIpId`, `licenseTermsId`, `licenseTemplate`, `currencyToken`, and `maxMintingFee` to null;
Derivative intents bind the persisted parent/template, predicted currency and
fee cap, metadata fields, and current `runConfigHash`. Collection intent sets
`registrationName`, `artifactPath`, and `metadata` to null. Every registration
intent copies the exact definition name and artifact path into the journal
before signing; proof construction after confirmation reads those journal
fields exclusively.

- [ ] **Step 7: Fail closed on WIP balance and allowance before every Derivative prepare**

Extend the `DemoChain` seam in `demo.ts`:

```ts
export interface DerivativeFeeReadiness {
  currencyToken: `0x${string}`;
  spender: `0x${string}`;
  requiredAmount: bigint;
  balance: bigint;
  allowance: bigint;
}

predictMintingLicenseFee(input: PredictFeeInput): Promise<{
  currencyToken: `0x${string}`;
  tokenAmount: bigint;
}>;
getDerivativeFeeReadiness(input: {
  wallet: `0x${string}`;
  currencyToken: `0x${string}`;
  requiredAmount: bigint;
}): Promise<DerivativeFeeReadiness>;
```

Update `StorySdkBoundary.ipAsset` so its `Pick` also includes `wipClient` and
`derivativeWorkflowsClient`. Preserve both values returned by fee prediction:

```ts
return {
  currencyToken: required(response.currencyToken, "predicted currencyToken"),
  tokenAmount: required(response.tokenAmount, "predicted tokenAmount"),
};
```

Implement the read-only readiness method in `StoryChain`:

```ts
async getDerivativeFeeReadiness(input: {
  wallet: Address;
  currencyToken: Address;
  requiredAmount: bigint;
}) {
  const wip = this.sdk.ipAsset.wipClient;
  const spender = this.sdk.ipAsset.derivativeWorkflowsClient.address;
  if (input.currencyToken.toLowerCase() !== WIP_TOKEN_ADDRESS.toLowerCase()
      || wip.address.toLowerCase() !== WIP_TOKEN_ADDRESS.toLowerCase()) {
    throw new Error(
      `Derivative fee currency ${input.currencyToken} is not supported WIP ${WIP_TOKEN_ADDRESS}`,
    );
  }
  const [balanceResult, allowanceResult] = await Promise.all([
    wip.balanceOf({ owner: input.wallet }),
    wip.allowance({ owner: input.wallet, spender }),
  ]);
  return {
    currencyToken: wip.address,
    spender,
    requiredAmount: input.requiredAmount,
    balance: balanceResult.result,
    allowance: allowanceResult.result,
  };
}
```

This spender is not guessed: Story SDK 1.4.4 passes
`derivativeWorkflowsClient.address` as `spgSpenderAddress` to
`handleRegistrationWithFees`. The `encodedTxDataOnly` branch returns before
that helper, so the new prepare/sign path does not auto-wrap IP or auto-approve
WIP.

In `demo.ts`, add one helper that validates the chain response matches the
predicted currency and amount, then checks balance and allowance independently:

```ts
async function requireDerivativeFeeReadiness(input: {
  chain: DemoChain;
  wallet: `0x${string}`;
  predicted: { currencyToken: `0x${string}`; tokenAmount: bigint };
}) {
  const readiness = await input.chain.getDerivativeFeeReadiness({
    wallet: input.wallet,
    currencyToken: input.predicted.currencyToken,
    requiredAmount: input.predicted.tokenAmount,
  });
  if (readiness.currencyToken.toLowerCase() !== input.predicted.currencyToken.toLowerCase()
      || readiness.requiredAmount !== input.predicted.tokenAmount) {
    throw new Error("Derivative WIP readiness response does not match the predicted fee");
  }
  if (readiness.balance < input.predicted.tokenAmount) {
    throw new Error(
      `WIP balance ${readiness.balance} is below required ${input.predicted.tokenAmount} `
      + `for Derivative fee token ${readiness.currencyToken}`,
    );
  }
  if (readiness.allowance < input.predicted.tokenAmount) {
    throw new Error(
      `WIP allowance ${readiness.allowance} is below required ${input.predicted.tokenAmount} `
      + `for DerivativeWorkflows spender ${readiness.spender}`,
    );
  }
  return readiness;
}
```

For child and grandchild separately, predict the fee and include its currency
and amount in the stable intent. Put the readiness check strictly inside the
`prepare` callback:

```ts
const executed = await executeOrResume({
  journal: input.journal,
  operationId,
  stage,
  intent,
  prepare: async () => {
    await requireDerivativeFeeReadiness({
      chain: input.chain,
      wallet: input.wallet,
      predicted,
    });
    return input.chain.prepareDerivative(derivativeInput);
  },
  broadcast: (transaction) => input.chain.broadcastPrepared(transaction),
  confirm: (operation) => input.chain.confirmDerivative({
    transactionHash: operation.transactionHash,
    expectedCollection: requiredAddress(operation.intent.spgNftContract, "SPG collection"),
    expectedParentIpId: requiredAddress(operation.intent.parentIpId, "parent IP"),
    expectedLicenseTermsId: BigInt(requiredString(operation.intent.licenseTermsId, "license terms ID")),
    expectedLicenseTemplate: requiredAddress(operation.intent.licenseTemplate, "license template"),
  }),
});
```

`executeOrResume` loads and validates a matching pending journal before it ever
calls `prepare`. Therefore a persisted signed Derivative must be
rebroadcast/reconciled and confirmed from its exact bytes without consulting
current WIP balance or allowance. The transaction may already have consumed
that WIP; rechecking would deadlock crash recovery. Only a genuinely new child
or grandchild prepare reads readiness. Re-read for the grandchild after the
child proof is durably saved; do not assume the child's readiness also covers
the next transaction. For a new operation, zero or insufficient WIP/allowance
must cause zero Derivative prepare, sign, journal, and broadcast calls.

Do not add automatic deposit or approval transactions. A human testnet operator
must wrap enough Aeneid IP into WIP and approve the reported
DerivativeWorkflows spender before the demo. Those prerequisite actions remain
outside the four-operation journal and outside automated verification.

- [ ] **Step 8: Separate pending-proof recovery from new-stage drift checks**

At the beginning of the pending route, handle a journal left behind after a
successful manifest save:

```ts
const snapshot = await input.journal.load();
const pending = snapshot.operation;
if (pending) {
  const confirmedHash = pending.stage === "collection"
    ? manifest.collectionTxHash
    : manifest.registrations[pending.stage]?.txHash ?? null;
  if (confirmedHash) {
    if (confirmedHash.toLowerCase() !== pending.transactionHash.toLowerCase()) {
      throw new Error(`Confirmed ${pending.stage} proof does not match the pending transaction hash`);
    }
    await input.journal.clear(pending.operationId, snapshot.revision);
  }
}
```

This cleanup requires no metadata provider and no balance read. If the pending
proof is absent from the manifest, recover it from the exact receipt plus the
journal-bound intent as described in Step 6.

Only after pending recovery, compare each already-confirmed stage's current
local artifact bytes with its stored artifact media hash. Do not upload or fetch
metadata for a confirmed stage. A mismatch blocks new prepares but never blocks
saving proof for the exact pending transaction that was already signed. The
`manifest-save`, `Pinata unavailable`, and run-config-drift tests must prove
these orderings.

- [ ] **Step 9: Run all crash, resume, durability, and WIP-readiness tests**

Run:

```bash
cd phase0
npm test
npm run typecheck
```

Expected: all tests PASS. Each crash scenario records one transaction hash;
rerun performs no second prepare/sign and finalizes the original proof.
Insufficient WIP balance and insufficient allowance each report zero Derivative
prepare and broadcast calls. No test reads RPC state or performs a WIP action.
The depleted-after-broadcast/confirm regressions recover the same child hash
with zero readiness reads and zero child re-prepare.
The final-grandchild regressions also make zero native-balance, gas-price, WIP,
and metadata-provider calls while confirming the exact persisted hash.

- [ ] **Step 10: Commit crash recovery, durable proof storage, and derivative fee readiness**

```bash
git add phase0/src/demo.ts phase0/src/story.ts phase0/src/registrations.ts phase0/src/index.ts phase0/tests/demo.test.ts phase0/tests/registrations.test.ts phase0/tests/story.test.ts phase0/.gitignore
git commit -m "fix: reconcile Phase 0 transactions and WIP fees"
```

### Task 5: Publish exact metadata bytes to durable public IPFS

**Files:**
- Modify: `phase0/src/metadata.ts:1-124`
- Modify: `phase0/tests/metadata.test.ts`
- Modify: `phase0/.env.example`

- [ ] **Step 1: Write pinning and stage-isolation tests**

Replace the httpbin-default test with these tests:

1. With no override, two multipart uploads go to the exact
   `https://uploads.pinata.cloud/v3/files`, use `Authorization: Bearer
   fixture-token`, `redirect: "error"`, and `network=public`, and return
   distinct IP/NFT CIDs. Both gateway URIs are fetched and byte-matched; GET
   requests carry no `Authorization` header.
2. `root` uses only `ROOT_IP_METADATA_URI`/`ROOT_NFT_METADATA_URI`; a root URI cannot leak into child or grandchild.
3. Supplying only one URI in a stage pair fails before upload/fetch.
4. Table-test `http:`, embedded username/password, query, fragment,
   `gateway.pinata.cloud.evil`, and poisoned paths (`/not-ipfs/`, an extra path
   segment, and percent-encoded traversal) for paired stage overrides. Every
   case rejects with `fetchCalls === 0`.
5. Apply the same table to `publicGatewayBaseUrl`. Permit only
   `https://gateway.pinata.cloud/ipfs/` or an HTTPS subdomain of
   `mypinata.cloud` with exact `/ipfs/` path, no port, credentials, query, or
   fragment; every invalid gateway rejects before upload with `fetchCalls ===
   0`. Add one positive dedicated-gateway case using
   `https://team.mypinata.cloud/ipfs/` and same-origin stage CIDs.
6. Set a fake `PINATA_UPLOAD_URL` environment value and assert it is ignored:
   the only POST still targets the exact constant endpoint. No production
   option or environment variable may redirect the JWT-bearing request.

Use these exact adversarial tables in `metadata.test.ts`:

```ts
const INVALID_STAGE_URIS = [
  "http://gateway.pinata.cloud/ipfs/bafyvalidcid123",
  "https://user:pass@gateway.pinata.cloud/ipfs/bafyvalidcid123",
  "https://gateway.pinata.cloud/ipfs/bafyvalidcid123?download=1",
  "https://gateway.pinata.cloud/ipfs/bafyvalidcid123#fragment",
  "https://gateway.pinata.cloud.evil/ipfs/bafyvalidcid123",
  "https://gateway.pinata.cloud/not-ipfs/bafyvalidcid123",
  "https://gateway.pinata.cloud/ipfs/bafyvalidcid123/extra",
  "https://gateway.pinata.cloud/ipfs/%2e%2e/bafyvalidcid123",
];

const INVALID_GATEWAY_BASES = [
  "http://gateway.pinata.cloud/ipfs/",
  "https://user:pass@gateway.pinata.cloud/ipfs/",
  "https://gateway.pinata.cloud:444/ipfs/",
  "https://gateway.pinata.cloud/ipfs/?query=1",
  "https://gateway.pinata.cloud/ipfs/#fragment",
  "https://gateway.pinata.cloud.evil/ipfs/",
  "https://evil-mypinata.cloud/ipfs/",
  "https://gateway.pinata.cloud/not-ipfs/",
  "https://gateway.pinata.cloud/ipfs/extra/",
];
```

For each stage URI, supply it as both members of the root pair; for each gateway
base, leave stage overrides absent and supply a fixture JWT. Construct/prepare
with an injected fetcher that increments `fetchCalls` and throws if invoked.
Assert rejection and `fetchCalls === 0` after every row.

Use injected fetch responses; no test contacts Pinata or a gateway.

- [ ] **Step 2: Run metadata tests to verify current behavior fails**

Run: `cd phase0 && node --import tsx --test tests/metadata.test.ts`

Expected: FAIL because the current provider defaults to httpbin and uses global, non-stage-specific overrides.

- [ ] **Step 3: Define stage-specific configuration**

Replace `ipMetadataURI`/`nftMetadataURI` options with the following single
TypeScript block:

```ts
export type StageMetadataUris = Partial<Record<DemoStage, {
  ip: string;
  nft: string;
}>>;

export interface HttpMetadataProviderOptions {
  fetcher?: typeof fetch;
  stageUris?: StageMetadataUris;
  pinataJwt?: string;
  publicGatewayBaseUrl?: string;
}
```

There is deliberately no upload-URL option. Define and use this module-private
constant for every JWT-bearing request:

```ts
const PINATA_PUBLIC_UPLOAD_URL = "https://uploads.pinata.cloud/v3/files";
const DEFAULT_PUBLIC_GATEWAY_BASE_URL = "https://gateway.pinata.cloud/ipfs/";
```

Load env pairs with exact names:

```text
ROOT_IP_METADATA_URI / ROOT_NFT_METADATA_URI
CHILD_IP_METADATA_URI / CHILD_NFT_METADATA_URI
GRANDCHILD_IP_METADATA_URI / GRANDCHILD_NFT_METADATA_URI
```

If one member of a pair exists without the other, throw
`` `${stage.toUpperCase()} metadata overrides must provide both IP and NFT URIs` ``.
Parse and validate the complete gateway and all supplied stage pairs before
calling `fetcher` even once. Do not read `PINATA_UPLOAD_URL`.

- [ ] **Step 4: Implement public Pinata upload as the default**

Use the documented public upload endpoint and built-in `FormData`/`Blob`:

```ts
async function pinPublicJson(input: {
  fetcher: typeof fetch;
  jwt: string;
  gatewayBaseUrl: string;
  name: string;
  bytes: Uint8Array;
}): Promise<string> {
  const form = new FormData();
  form.set("network", "public");
  form.set("name", input.name);
  form.set("file", new Blob([input.bytes], { type: "application/json" }), input.name);
  const response = await input.fetcher(PINATA_PUBLIC_UPLOAD_URL, {
    method: "POST",
    headers: { Authorization: `Bearer ${input.jwt}` },
    body: form,
    redirect: "error",
  });
  if (!response.ok) throw new Error(`Metadata pin failed (${response.status})`);
  const body = await response.json() as { data?: { cid?: string } };
  const cid = body.data?.cid;
  if (!cid || !/^b[a-z0-9]+$/.test(cid)) throw new Error("Pinata response is missing a public CID");
  return new URL(cid, input.gatewayBaseUrl.endsWith("/") ? input.gatewayBaseUrl : `${input.gatewayBaseUrl}/`).toString();
}
```

Defaults:

```ts
const gatewayBaseUrl = validatePublicGatewayBaseUrl(
  options.publicGatewayBaseUrl ?? DEFAULT_PUBLIC_GATEWAY_BASE_URL,
);
```

The `Authorization` header exists only inside this exact POST expression. Do
not put it in shared headers or a fetch wrapper, and do not manually follow
redirects. The injected-fetch test must fail if any JWT-bearing request URL is
not byte-for-byte `PINATA_PUBLIC_UPLOAD_URL`.

If a stage has no override and `PINATA_JWT` is absent, fail with
`` `PINATA_JWT is required to publish durable metadata for ${stage}` `` before
any chain preparation. Never log the JWT.

- [ ] **Step 5: Verify uploaded or overridden bytes identically**

Add these validators. They return normalized URLs only after all origin/path
rules pass:

```ts
function strictHttpsUrl(value: string, label: string): URL {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`${label} must be a valid HTTPS URL`);
  }
  if (url.protocol !== "https:") throw new Error(`${label} must use HTTPS`);
  if (url.username || url.password) throw new Error(`${label} must not contain credentials`);
  if (url.search) throw new Error(`${label} must not contain a query`);
  if (url.hash) throw new Error(`${label} must not contain a fragment`);
  if (!/^https:\/\/[^/:?#]+(?:\/|$)/.test(value)) {
    throw new Error(`${label} must not contain an explicit port or malformed authority`);
  }
  return url;
}

function isAllowedPinataGatewayHost(hostname: string): boolean {
  return hostname === "gateway.pinata.cloud"
    || /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.mypinata\.cloud$/.test(hostname);
}

export function validatePublicGatewayBaseUrl(value: string): string {
  const url = strictHttpsUrl(value, "IPFS public gateway base URL");
  if (!isAllowedPinataGatewayHost(url.hostname)) {
    throw new Error("IPFS public gateway must use gateway.pinata.cloud or a mypinata.cloud subdomain");
  }
  if (url.pathname !== "/ipfs/") {
    throw new Error("IPFS public gateway path must be exactly /ipfs/");
  }
  return url.toString();
}

export function validateStageMetadataUri(
  value: string,
  gatewayBaseUrl: string,
  label: string,
): string {
  const base = new URL(validatePublicGatewayBaseUrl(gatewayBaseUrl));
  const url = strictHttpsUrl(value, label);
  if (url.origin !== base.origin) {
    throw new Error(`${label} origin must exactly match the configured public gateway`);
  }
  if (!url.pathname.startsWith(base.pathname)) {
    throw new Error(`${label} path must start with ${base.pathname}`);
  }
  const cid = url.pathname.slice(base.pathname.length);
  if (!/^b[a-z0-9]+$/.test(cid)) {
    throw new Error(`${label} must end in exactly one lowercase CID and no extra path`);
  }
  return url.toString();
}
```

Validate both members of every supplied stage pair with
`validateStageMetadataUri` during provider construction or at the start of
`prepare`, before upload or verification fetch. This deliberately forbids
arbitrary web origins: overrides are alternate already-pinned objects on the
configured, allow-listed Pinata public gateway.

Keep `verifyExactBytes`. Whether a URI came from a validated stage override or
a fresh pin, fetch it without `Authorization` and compare exact serialized
bytes and SHA-256 before returning `PreparedMetadata`. Delete `inlineHttpsUri`
and every httpbin reference.

- [ ] **Step 6: Update `.env.example` without secrets**

Replace global override fields with:

```dotenv
# Default durable metadata path. Never commit the JWT.
PINATA_JWT=
IPFS_PUBLIC_GATEWAY_BASE_URL=https://gateway.pinata.cloud/ipfs/

# Optional paired, stage-specific public-IPFS overrides. Both values in a pair
# must use the exact configured Pinata gateway origin, /ipfs/<cid>, and return
# the exact serialized bytes the CLI generates.
ROOT_IP_METADATA_URI=
ROOT_NFT_METADATA_URI=
CHILD_IP_METADATA_URI=
CHILD_NFT_METADATA_URI=
GRANDCHILD_IP_METADATA_URI=
GRANDCHILD_NFT_METADATA_URI=
```

Document that the upload endpoint is intentionally not configurable and that
`IPFS_PUBLIC_GATEWAY_BASE_URL` accepts only the default host or an HTTPS
`*.mypinata.cloud` host with exact `/ipfs/` path.

- [ ] **Step 7: Run metadata tests and typecheck**

Run: `cd phase0 && node --import tsx --test tests/metadata.test.ts && npm run typecheck`

Expected: all metadata tests PASS; injected fetch sees exactly two public
uploads for an unoverridden stage, every JWT-bearing request uses only the
exact Pinata constant with redirects disabled, gateway GETs contain no JWT,
and every invalid URL table row reports zero injected-fetch calls. No real
network call occurs.

- [ ] **Step 8: Commit metadata safety**

```bash
git add phase0/src/metadata.ts phase0/tests/metadata.test.ts phase0/.env.example
git commit -m "fix: pin stage-specific Phase 0 metadata"
```

### Task 6: Align CLI wording and operator documentation with the proof boundary

**Files:**
- Modify: `phase0/src/index.ts:62-174,185-203`
- Modify: `phase0/README.md`
- Modify: `phase0/package.json`

- [ ] **Step 1: Correct provenance wording in CLI output**

Replace “provenance demo”/“authored” implications with:

```ts
console.log("✓ Phase 0 wallet-attested registration status:", manifest.status);
console.log("evidence level : wallet_asserted");
console.log("scope          : wallet registration + declared Derivative ancestry; not authorship, originality, or safety");
```

Advanced `register-skill` output becomes `Skill registered by the connected wallet as a Story IP Asset`.

- [ ] **Step 2: Update the check command**

Have `npm run check` report native IP and WIP as two independent readiness
domains:

```text
pending recovery           : none|required (<stage>, <transaction hash>)
remaining new writes       : <0..4>
native IP balance         : <amount> IP
gas price                 : <amount>
estimated gas minimum     : <amount> IP
native gas ready          : yes|no
Derivative fee token      : <WIP address>
configured fee estimate   : 0.001 WIP per Derivative
WIP balance               : <amount> WIP
WIP allowance             : <amount> WIP
DerivativeWorkflows spender: <address>
next Derivative WIP ready : yes|no
```

Acquire the journal lease, load and validate the manifest and journal, and
derive `remainingNewWrites` from confirmed manifest stages. With no pending
operation, calculate native readiness with
`estimateRemainingDemoGasMinimum({ gasPrice, remainingNewWrites })`; zero
remaining writes requires zero gas and performs no gas-price or balance read.
Obtain WIP balance, allowance, token, and spender through
`getDerivativeFeeReadiness` with `WIP_TOKEN_ADDRESS` and
`DEMO_ROOT_MINTING_FEE` only when the next new stage is a Derivative. Label the
latter a configured fee estimate: the demo still predicts and rechecks the
actual fee immediately before each new Derivative prepare.

If a pending operation exists, print only its stage/hash plus `pending recovery
: required`; print all readiness values as `deferred until exact-hash recovery`
and perform zero native-balance, gas-price, WIP, allowance, or metadata calls.
Those balances may already have been consumed by the pending transaction.
`check` never reconciles or clears a transaction because it is read-only; the
operator runs the demo to recover the exact persisted hash under the same
lease. Do not collapse the domains into one `funding ready` value, and do not
claim an IP balance covers a WIP fee. `check` must not upload metadata, wrap IP,
approve WIP, sign, broadcast, or mutate the journal.

- [ ] **Step 3: Rewrite README setup and recovery sections**

Document:

```markdown
This testnet demo proves `wallet_asserted` registration and declared Derivative
ancestry. It does not prove authorship, originality, repository control, or
safety.

Before broadcast, the demo signs the transaction locally and atomically saves
its hash, serialized testnet transaction, and canonical operation intent to the
mode-0600 ignored `pending-transactions.json`. The whole demo holds an exclusive
same-host journal lease and updates it with compare-and-swap revisions. A rerun
validates the journal-bound intent and prerequisite proofs, reconciles or
rebroadcasts the exact persisted bytes/hash without a Pinata or funding read,
waits for that same hash, saves confirmed proof from persisted metadata, then
clears the matching journal revision. Only after recovery does it compare the
current local run configuration and permit another prepare. Never delete the
journal or `.lock` merely to force progress; an intent/config mismatch or an
unresolved/replaced nonce requires operator investigation. Stale-lock recovery
is explicit and allowed only for a same-host PID proven absent while the lease
record remains unchanged.

Metadata defaults to public IPFS pinning. Pinata credentials and any wallet key
remain local. The JWT-bearing upload URL is fixed to
`https://uploads.pinata.cloud/v3/files`, redirects are disabled, and gateway
verification requests never carry the JWT. Stage-specific URI overrides must
be supplied in complete IP/NFT pairs, use the exact configured allow-listed
Pinata gateway origin and `/ipfs/<cid>` path, and return byte-identical content.

The native-IP estimate covers gas only. Derivative minting fees use WIP. Because
the crash-safe path requests `encodedTxDataOnly`, the Story SDK does not perform
its normal automatic IP-to-WIP wrapping or WIP approval. Before a real testnet
demo, a human must use supported Story testnet tooling to wrap sufficient IP to
WIP and approve the exact DerivativeWorkflows spender printed by `npm run
check`. The demo checks the predicted fee, current WIP balance, and current
allowance again before each Derivative prepare and fails closed if either is
insufficient. If a matching signed Derivative is already in the journal, the
demo reconciles that exact transaction without rechecking current WIP; the
pending transaction may already have consumed it. These prerequisite
wrap/approval transactions are not journaled by this demo.
```

State that the native gas figure is a conservative preflight estimate, not a
guarantee of final gas use. Because the four-write envelope has no validated
per-stage allocation, any positive number of remaining new writes retains the
full conservative envelope; zero remaining writes requires zero. State that
the configured WIP figure is not a substitute for the per-parent on-chain
prediction. Preserve the existing Aeneid/mainnet boundary and human faucet
step.

- [ ] **Step 4: Update package description**

Set `phase0/package.json` description to:

```json
"description": "Phase 0 testnet spike: wallet-attested Skill registration and declared Derivative ancestry on Story Aeneid."
```

- [ ] **Step 5: Run the full Phase 0 suite**

Run:

```bash
cd phase0
npm test
npm run typecheck
```

Expected: all tests PASS with no network, wallet key, Pinata credential,
journal residue, WIP wrap/approval, or transaction.

- [ ] **Step 6: Verify ignored and tracked boundaries**

Run:

```bash
git check-ignore -v phase0/.env phase0/pending-transactions.json phase0/pending-transactions.json.audit.tmp phase0/pending-transactions.json.lock phase0/registrations.json.audit.tmp
git ls-files phase0/.env phase0/pending-transactions.json phase0/pending-transactions.json.audit.tmp phase0/pending-transactions.json.lock phase0/registrations.json.audit.tmp
```

Expected: all five sensitive/local paths are reported ignored by the first
command; the second command prints nothing.

- [ ] **Step 7: Verify protected corpus and mainnet boundaries**

Run:

```bash
git diff bad032b -- CONTEXT.md docs/PRD.md docs/adr
rg -n '1514|mainnet' phase0/src
```

Expected: protected-corpus diff is empty. Any `1514`/mainnet source match is a rejection or explanatory guard, never a transaction target.

- [ ] **Step 8: Commit operator documentation**

```bash
git add phase0/src/index.ts phase0/README.md phase0/package.json phase0/package-lock.json
git commit -m "docs: define Phase 0 wallet-attested proof boundary"
```

- [ ] **Step 9: Hand off the human-only run status**

```text
Phase 0 now rejects native-IP gas dust, rejects insufficient WIP balance or
allowance before Derivative prepare, persists a signed testnet transaction before
broadcast, reconciles the same hash after crashes, and verifies durable
stage-specific metadata bytes. Automated tests used fakes only. No Pinata
upload, wallet funding, IP-to-WIP wrap, WIP approval, Aeneid write, private-key
operation, or mainnet transaction was performed; a real testnet proof remains
an explicit human-run gate.
```
