# Agent Spend Control Plane Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the hardened Pi-Wielder spike into a customer-hosted Wallet Kernel that gives Pi policy-bounded, approval-aware, restart-safe x402 v2 spending through a customer-owned CDP wallet on Base Sepolia.

**Architecture:** Build the new buyer control plane alongside the verified x402 v1 spike, using a local SQLite authority for policies, Spend Sessions, Spend Intents, budgets, approvals, payment attempts, outcomes, reconciliation, and signed receipts. A pure Policy Engine and one-time `AuthorizedPermit` capability sit in front of provider-neutral wallet adapters; a custom x402 v2 transport preserves the required persist-before-retry boundary that an automatic fetch wrapper cannot expose. After offline parity, cut the standalone Pi path over to the new loopback proxy while retaining the old Collar and payment suites as regression oracles.

**Tech Stack:** Node.js 24.18.1+ for deterministic development and exact Node.js
24.18.1 for the attested `cdp-testnet` release, ECMAScript modules, built-in
`node:sqlite`, Hono, built-in `node:test`, Ed25519/SHA-256 from `node:crypto`,
`@coinbase/cdp-sdk` 1.54.0, `@x402/core` 2.19.0, `@x402/evm` 2.19.0, viem, Pi
0.80.6; Base Sepolia and test USDC only.

---

## Scope, ordering, and baseline

Implement against `codex/agent-spend-control-design` at or after design commit
`07c3549`. At execution time, create an isolated worktree with
`superpowers:using-git-worktrees`; do not implement directly in a dirty checkout.

This is one vertical product slice. The modules are separately testable, but the
commercial acceptance milestone is reached only after the durable store, policy,
approval, wallet, transport, operator, Pi, and restart paths work together.

Current verified baseline on 2026-07-31:

- `npm run test --prefix spikes/pi-wielder`: 237/237 passing with loopback permission;
- `npm run e2e --prefix spikes/pi-wielder`: 41/41 passing offline;
- `npm test --prefix prototype`: 23/23 passing;
- `CONTEXT.md`, `docs/PRD.md`, and `docs/adr/` are protected and must remain unchanged;
- `docs/superpowers/plans/marketing-assets/` is user-owned and must remain untouched.

The existing `src/payment-policy.mjs`, `src/proxy.mjs`, `src/x402-seller.mjs`, and
seller-side `src/invocation-journal.mjs` remain x402 v1 regression boundaries until
Task 14 proves parity. Do not migrate their data into the Wallet Kernel and do not
reinterpret `LEDGER_FILE` or `COLLAR_JOURNAL_FILE` as SQLite.

The public `README.md` and `site/` exist only on the older public branch. They are
outside this plan. A website reframe is a separate post-evidence plan; no public claim
may revive the quarantined historical `n=48` aggregate.

### Live trust boundary: Pi and the Wallet Kernel are different principals

The commercial `cdp-testnet` mode is supported only when the Wallet Kernel runs as a
dedicated OS service account (or equivalently isolated container identity) and Pi runs
as a different unprivileged UID/container. The Kernel identity alone can read the
SQLite authority, receipt key, operator token, policy bootstrap inputs, CDP
credentials, and RPC secret. The Pi identity can read only its agent credential and
ordinary working files. A tool-capable Pi process must receive filesystem permission
denied—not merely an instruction—when it attempts to open, stat through, or modify the
Kernel authority directory or service environment.

Pi creates its own agent credential under the Pi identity and emits a separate
non-secret enrollment descriptor containing only `agentInstanceId`, credential digest,
and Pi UID/GID. An authenticated/offline operator enrollment imports that descriptor into
SQLite. The Kernel never opens the Pi credential file or persists/logs the raw token;
the agent listener necessarily receives the bearer per request, hashes it immediately,
zeroes its temporary bytes, and retains only the digest. At startup, live mode
rejects UID/GID `0`, requires a distinct Kernel/Pi UID, pins the enrolled Pi UID/GID
to the closed configured expected identity, and clears supplementary groups in
the isolation probe. Same-identity execution is allowed only in injected
`deterministic` tests, is labeled `isolation: simulated`, and is never evidence of
commercial isolation. There is no environment flag that weakens this check in
`cdp-testnet`.

The implementation includes a deployment preflight and negative process fixture under
the configured Pi identity that receives OS-level denial for the operator token,
database, receipt key, Kernel environment, and CDP secret while retaining access to
the Pi credential. Therefore a tool-capable Pi is constrained by host permissions,
not prompt instructions. If the host cannot
provide distinct identities/containers, live admission remains blocked and the pilot
is not security-ready on that host.

The same boundary covers executable and operator-channel integrity. Commercial mode
runs from a root-owned manifest-verified release tree that neither Pi nor the Kernel
service account can modify; a privileged prelaunch gate verifies Node, source,
dependencies, launcher, service/socket definitions, and loader environment before
dropping privileges. The owner bearer travels only over a Kernel-owned Unix socket.
The live browser console uses a root service-manager-held loopback socket plus a
one-time UDS-minted launch capability, so Pi cannot impersonate the console during a
Kernel crash and the browser never sees the owner bearer.

The first live pilot target is Linux with systemd service and socket activation;
macOS remains a deterministic development host in this slice. A different service
manager/container must implement and pass the same inherited-listener and privileged
prelaunch contract before it can claim `cdp-testnet` support.

## File structure

### New Kernel modules

- `spikes/pi-wielder/src/kernel/canonical.mjs` — closed-object validation,
  canonical JSON, hashes, identifiers, timestamps, and atomic-USDC strings.
- `spikes/pi-wielder/src/kernel/secure-storage.mjs` — absolute path, owner, mode,
  symlink, database, WAL, SHM, key, and token checks.
- `spikes/pi-wielder/src/kernel/trusted-path.mjs` — Linux live-mode descriptor walk
  from the configured trusted ancestor, closed ownership policies, and stable
  ancestor-chain metadata hashing.
- `spikes/pi-wielder/src/kernel/authority-lock.mjs` — crash-released, process-lifetime
  single-writer exclusion shared by the daemon and offline bootstrap commands.
- `spikes/pi-wielder/src/kernel/release-integrity.mjs` — closed privileged deployment
  manifest validation and runtime re-verification for the live executable tree.
- `spikes/pi-wielder/src/kernel/sqlite-schema.mjs` — explicit schema-v1 tables and
  indexes; atomic money remains canonical decimal `TEXT`.
- `spikes/pi-wielder/src/kernel/sqlite-store.mjs` — SQLite open/migrate,
  `BEGIN IMMEDIATE` transactions, domain mutation plus event-hash commit, and chain
  verification.
- `spikes/pi-wielder/src/kernel/policy-engine.mjs` — immutable policy validation and
  pure `allow | approval_required | deny` evaluation.
- `spikes/pi-wielder/src/kernel/policy-repository.mjs` — predecessor-linked policy
  versions and active-version lookup.
- `spikes/pi-wielder/src/kernel/agent-enrollment.mjs` — non-secret Pi capability
  digest enrollment, revocation, and distinct-identity binding.
- `spikes/pi-wielder/src/kernel/intent-builder.mjs` — kernel-issued Spend Sessions,
  exact request capture, intent hashing, and retry matching without caller-owned
  payment headers.
- `spikes/pi-wielder/src/kernel/budget-ledger.mjs` — atomic reserve, commit, release,
  unresolved hold, per-seller/session, full-session, and rolling-24-hour accounting.
- `spikes/pi-wielder/src/kernel/approval-queue.mjs` — exact one-time approvals,
  denials, expiry, and pending-cap enforcement.
- `spikes/pi-wielder/src/kernel/authorized-permit.mjs` — in-process, one-time,
  unforgeable signing capabilities.
- `spikes/pi-wielder/src/kernel/authority-mutation-coordinator.mjs` — one shared
  in-process FIFO lease for every live authority mutation and terminal receipt gap.
- `spikes/pi-wielder/src/kernel/receipt-signing.mjs` — generic Ed25519 receipt
  primitives extracted without changing seller-journal behavior.
- `spikes/pi-wielder/src/kernel/signed-receipts.mjs` — terminal buyer receipt
  projection, signature, verification, and superseding revisions.
- `spikes/pi-wielder/src/kernel/recovery.mjs` — startup audit, wallet blocking,
  trusted reconciliation, and seller-side refund observation.
- `spikes/pi-wielder/src/kernel/projection-exporter.mjs` — sanitized signed read-only
  export with no import path.
- `spikes/pi-wielder/src/kernel/wallet-kernel.mjs` — authoritative lifecycle
  orchestrator.

### New adapters and local surfaces

- `spikes/pi-wielder/src/adapters/deterministic-wallet-adapter.mjs` — offline
  contract adapter with injected deterministic signing.
- `spikes/pi-wielder/src/adapters/wallet-adapter-contract.mjs` — provider-neutral
  identity/result validation and permit-bound signing contract.
- `spikes/pi-wielder/src/adapters/eip3009-exact.mjs` — closed x402 v2 EIP-3009
  typed-data and payload builder using Kernel-bound nonce and validity.
- `spikes/pi-wielder/src/adapters/cdp-wallet-adapter.mjs` — CDP Server Wallet adapter
  using `account.signTypedData()` over the permit-bound authorization and no raw key.
- `spikes/pi-wielder/src/adapters/base-sepolia-observer.mjs` — read-only RPC balance,
  settlement, nonce-use, and full-refund observation; it has no signer or send method.
- `spikes/pi-wielder/src/adapters/seller-evidence-resolver.mjs` — bounded same-origin
  fetch and domain-separated signature verification for execution/refund attestations.
- `spikes/pi-wielder/src/adapters/x402-v2-transport.mjs` — bounded v2 challenge
  decoding, signature-header encoding, one paid retry, and settlement decoding.
- `spikes/pi-wielder/src/spend-control-proxy.mjs` — Pi-facing route map and stable
  approval, denial, unresolved, and receipt responses.
- `spikes/pi-wielder/src/operator/auth.mjs` — owner-only token and authenticated local
  session handling.
- `spikes/pi-wielder/src/operator/api.mjs` — narrow channel-aware operator API for
  the Unix admin transport and authenticated socket-activated browser session.
- `spikes/pi-wielder/src/operator/cli.mjs` — preflight, policy, approval, receipt,
  isolation/enrollment, session, reconciliation, and export commands.
- `spikes/pi-wielder/src/operator/console.mjs` — local static console server.
- `spikes/pi-wielder/src/agent/credential.mjs` — Pi-identity-only raw capability
  creation plus non-secret enrollment descriptor.
- `spikes/pi-wielder/src/agent/isolation-preflight.mjs` — distinct UID/GID,
  OS-denial preflight, and durable isolation-attestation repository contracts for live
  mode.
- `spikes/pi-wielder/scripts/build-release-manifest.mjs` — privileged, exclusive
  manifest creation for a root-owned installed release.
- `spikes/pi-wielder/scripts/render-systemd-units.mjs` — closed privileged rendering
  of exact-path service/socket templates for the installed Linux release.
- `spikes/pi-wielder/scripts/inspect-systemd-effective.mjs` — bounded PID1
  introspection and canonical effective service/socket projection after daemon reload.
- `spikes/pi-wielder/scripts/preflight-live-deployment.mjs` — root/service-manager
  prelaunch verification before dropping to the Kernel UID.
- `spikes/pi-wielder/scripts/prelaunch-kernel-reader.mjs` — minimal privileged
  trampoline that drops all groups/UID before dynamically loading the bounded
  read-only authority/report checker.
- `spikes/pi-wielder/deploy/systemd/wallet-kernel.service` and
  `wallet-kernel-console.socket` — hardened live-pilot service/socket activation units.
- `spikes/pi-wielder/src/agent/auth.mjs` — digest-only active-enrollment auth and
  durable agent-instance/session lookup; it never reads the Pi credential file or is
  accepted by the operator API.
- `spikes/pi-wielder/operator-console/index.html` — Overview, Policies, Approvals,
  and Receipts shell.
- `spikes/pi-wielder/operator-console/app.mjs` — authenticated local API client.
- `spikes/pi-wielder/operator-console/styles.css` — self-contained local styles.
- `spikes/pi-wielder/src/control-plane.mjs` — environment construction and
  channel-aware process entrypoint for Unix admin, inherited console, and agent
  loopback transports.
- `spikes/pi-wielder/src/config.mjs` — closed environment, route-map, policy-file,
  testnet-mode, and secret-presence validation without secret serialization.

### New tests and evidence tooling

Keep tests flat under `spikes/pi-wielder/tests/` so the existing
`tests/*.test.mjs` script continues to discover them. Create focused
`kernel-*.test.mjs`, `wallet-adapter-*.test.mjs`, `x402-v2-transport.test.mjs`,
`spend-control-proxy.test.mjs`, `operator-*.test.mjs`, and
`spend-control-process-e2e.test.mjs` files as named in the tasks below.

Create reusable fixtures in `spikes/pi-wielder/tests/fixtures/`, a new
`spikes/pi-wielder/spend-control-e2e.mjs`, and evidence builder/verifier scripts under
`spikes/pi-wielder/scripts/`. Existing evidence directories are immutable.
Create `.github/workflows/pi-wielder-systemd.yml` for the mandatory secret-free Linux
service/socket integration gate.

### Modified files

- `.gitignore`
- `spikes/pi-wielder/package.json`
- `spikes/pi-wielder/package-lock.json`
- `spikes/pi-wielder/.env.example`
- `spikes/pi-wielder/src/invocation-journal.mjs`
- `spikes/pi-wielder/pi-extension/x402.ts`
- `spikes/pi-wielder/tests/pi-extension-contract.test.mjs`
- `spikes/pi-wielder/README.md`
- `spikes/pi-wielder/RUNBOOK.md`
- `docs/handoffs/2026-07-31-agent-spend-control-release-handoff.md` (create)

## Stable domain contracts

Use these names and values consistently in every task:

```js
export const KERNEL_SCHEMA_VERSION = 1;
export const X402_VERSION = 2;
export const BASE_SEPOLIA_CAIP2 = 'eip155:84532';
export const BASE_SEPOLIA_USDC = '0x036cbd53842c5426634e7929541ec2318f3dcf7e';
export const BASE_SEPOLIA_USDC_EIP712_NAME = 'USDC';
export const BASE_SEPOLIA_USDC_EIP712_VERSION = '2';

export const DECISIONS = Object.freeze(['allow', 'approval_required', 'deny']);
export const SPEND_SESSION_STATES = Object.freeze(['open', 'policy_blocked', 'closed']);
export const PAYMENT_STATES = Object.freeze([
  'none', 'reserved', 'signing', 'signed', 'retrying', 'unresolved', 'settled', 'rejected',
]);
export const INTENT_STATES = Object.freeze([
  'captured', 'challenged', 'approval_pending', 'authorized', 'reserved', 'signing',
  'signed', 'retrying', 'unresolved', 'terminal',
]);
export const EXECUTION_STATES = Object.freeze(['none', 'succeeded', 'failed', 'unknown']);
export const EXECUTION_RESOLUTION_STATES = Object.freeze([
  'refund_pending', 'reconciliation_required', 'resolved',
]);
export const BUYER_OUTCOMES = Object.freeze([
  'completed', 'upstream_failed', 'payment_denied', 'payment_failed',
  'payment_unresolved', 'payment_rejected', 'execution_failed',
  'execution_unknown', 'refunded',
]);
export const RECONCILIATION_OUTCOMES = Object.freeze([
  'settled', 'rejected', 'execution_succeeded', 'execution_failed',
  'execution_unknown', 'refund_confirmed', 'refund_rejected', 'unresolved',
]);
```

All monetary values cross a persistence or API boundary as canonical non-negative
base-10 strings. Convert to `bigint` only for arithmetic. Never use SQLite `INTEGER`,
JavaScript `number`, floating point, `parseFloat`, or `toFixed` for USDC.

Every EVM transaction/block hash crossing a boundary is canonical lowercase
`0x` plus 64 hex characters. A shared `canonicalEvmHash()` validates 32 bytes and
lowercases before any comparison, hash, confirmation display, event, or persistence;
closed signed attestations must already contain that canonical form. SQLite uniqueness
therefore operates on canonical bytes. Tests replay the same hash with uppercase and
mixed-case spelling across intents, payment candidates, settlements, refunds, and
reconciliations and prove it cannot bypass uniqueness.

The Wallet Adapter interface is exactly:

```js
/**
 * @typedef {object} WalletAdapter
 * @property {() => Promise<{
 *   provider: string,
 *   walletId: string,
 *   address: string,
 *   network: 'eip155:84532',
 * }>} walletIdentity
 * @property {(authorizedPermit: object, paymentRequired: object) =>
 *   Promise<{paymentPayload: object}>} signX402Exact
 */
```

The agent can never supply `PAYMENT-REQUIRED`, `PAYMENT-SIGNATURE`,
`PAYMENT-RESPONSE`, legacy `X-PAYMENT*`, `Idempotency-Key`, an approval identifier,
or a Spend Session identifier. The proxy owns those values.

### Task 1: Lock the runtime, dependencies, and canonical boundaries

**Files:**

- Modify: `spikes/pi-wielder/package.json:1-25`
- Modify: `spikes/pi-wielder/package-lock.json`
- Create: `spikes/pi-wielder/src/kernel/canonical.mjs`
- Create: `spikes/pi-wielder/tests/kernel-canonical.test.mjs`

- [ ] **Step 1: Write the failing canonical-boundary tests**

Create `spikes/pi-wielder/tests/kernel-canonical.test.mjs`:

```js
import assert from 'node:assert/strict';
import test from 'node:test';

import {
  KernelError,
  canonicalAtomic,
  canonicalEvmHash,
  canonicalJson,
  exactRecord,
  sha256,
} from '../src/kernel/canonical.mjs';

test('canonical JSON sorts object keys recursively without mutating input', () => {
  const input = Object.freeze({ z: 1, a: Object.freeze({ y: 2, b: 3 }) });
  assert.equal(canonicalJson(input), '{"a":{"b":3,"y":2},"z":1}');
  assert.deepEqual(input, { z: 1, a: { y: 2, b: 3 } });
});

test('atomic USDC accepts canonical strings only', () => {
  assert.deepEqual(canonicalAtomic('0', 'amount'), { text: '0', value: 0n });
  assert.deepEqual(canonicalAtomic('250000', 'amount'), { text: '250000', value: 250000n });
  for (const value of [1, 1n, '', '01', '-1', '1.0', '1e6']) {
    assert.throws(() => canonicalAtomic(value, 'amount'),
      (error) => error instanceof KernelError && error.code === 'ATOMIC_FORMAT');
  }
});

test('closed records reject inherited, missing, and unknown fields', () => {
  assert.deepEqual(exactRecord({ a: 1 }, ['a'], [], 'SHAPE', 'record'), { a: 1 });
  assert.throws(() => exactRecord({ a: 1, b: 2 }, ['a'], [], 'SHAPE', 'record'),
    (error) => error.code === 'SHAPE');
  assert.throws(() => exactRecord(Object.create({ a: 1 }), ['a'], [], 'SHAPE', 'record'),
    (error) => error.code === 'SHAPE');
  assert.throws(() => exactRecord({ a: 1, [Symbol('hidden')]: 2 }, ['a'], [], 'SHAPE', 'record'),
    (error) => error.code === 'SHAPE');
});

test('sha256 hashes canonical bytes with an explicit prefix', () => {
  assert.match(sha256(Buffer.from('wallet-kernel')), /^sha256:[0-9a-f]{64}$/);
});

test('EVM hashes canonicalize once before comparison or persistence', () => {
  const upper = `0x${'AB'.repeat(32)}`;
  assert.equal(canonicalEvmHash(upper, 'transaction'), `0x${'ab'.repeat(32)}`);
  for (const value of ['', 'ab', `0x${'ab'.repeat(31)}`, `0x${'gg'.repeat(32)}`]) {
    assert.throws(() => canonicalEvmHash(value, 'transaction'),
      (error) => error.code === 'EVM_HASH_FORMAT');
  }
});

test('canonical JSON rejects values JSON would drop, coerce, or ambiguously encode', () => {
  for (const value of [
    { dropped: undefined },
    { fn() {} },
    { symbol: Symbol('x') },
    { bigint: 1n },
    { infinity: Number.POSITIVE_INFINITY },
    { negativeZero: -0 },
    { date: new Date('2026-07-31T00:00:00.000Z') },
    Object.defineProperty({ a: 1 }, 'hidden', { value: 2, enumerable: false }),
    Object.defineProperty({}, 'getter', { enumerable: true, get() { throw new Error('must not run'); } }),
    Object.defineProperty([1], 'hidden', { value: 2, enumerable: false }),
    Object.defineProperty([1], '0', { enumerable: true, get() { throw new Error('must not run'); } }),
    Object.assign([1], { [Symbol('hidden')]: 2 }),
  ]) {
    assert.throws(() => canonicalJson(value),
      (error) => error instanceof KernelError && error.code === 'CANONICAL_TYPE');
  }
});
```

- [ ] **Step 2: Run the test and verify the module is absent**

Run:

```bash
node --test spikes/pi-wielder/tests/kernel-canonical.test.mjs
```

Expected: FAIL with `ERR_MODULE_NOT_FOUND` for `src/kernel/canonical.mjs`.

- [ ] **Step 3: Pin the runtime and protocol dependencies**

From `spikes/pi-wielder`, run:

```bash
npm install --save-exact @coinbase/cdp-sdk@1.54.0 @x402/core@2.19.0 @x402/evm@2.19.0
npm install --save-dev --save-exact @earendil-works/pi-coding-agent@0.80.6
npm pkg set engines.node=">=24.18.1"
```

Expected: `package.json` and `package-lock.json` contain exact dependency versions,
the existing Hono/viem dependencies remain present, and the live release procedure
later pins the attested Node executable to exactly `v24.18.1`.

- [ ] **Step 4: Implement canonical values and stable errors**

Create `spikes/pi-wielder/src/kernel/canonical.mjs`:

```js
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

function canonicalize(value) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || Object.is(value, -0)) {
      throw new KernelError('CANONICAL_TYPE', 'canonical numbers must be safe integers');
    }
    return value;
  }
  if (Array.isArray(value)) {
    const keys = Reflect.ownKeys(value);
    const indexes = Array.from({ length: value.length }, (_, index) => String(index));
    const allowedKeys = new Set([...indexes, 'length']);
    if (keys.length !== indexes.length + 1
        || !Object.hasOwn(value, 'length')
        || indexes.some((key) => {
          const descriptor = Object.getOwnPropertyDescriptor(value, key);
          return !descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value');
        })
        || keys.some((key) => !allowedKeys.has(key))) {
      throw new KernelError('CANONICAL_TYPE',
        'canonical arrays must contain only dense enumerable data elements');
    }
    return value.map(canonicalize);
  }
  if (value && typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype) {
    const keys = Reflect.ownKeys(value);
    if (keys.some((key) => typeof key !== 'string')
        || keys.some((key) => {
          const descriptor = Object.getOwnPropertyDescriptor(value, key);
          return !descriptor.enumerable || !Object.hasOwn(descriptor, 'value');
        })) {
      throw new KernelError('CANONICAL_TYPE', 'canonical objects require enumerable data properties');
    }
    return Object.fromEntries(keys.sort().map((key) => [key, canonicalize(value[key])]));
  }
  throw new KernelError('CANONICAL_TYPE', 'value is not canonical JSON data');
}

export const canonicalJson = (value) => JSON.stringify(canonicalize(value));

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
  if (typeof value !== 'string'
      || !new RegExp(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,${maximum - 1}}$`).test(value)) {
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
  const freeze = (item) => {
    if (item && typeof item === 'object' && !Object.isFrozen(item)) {
      for (const child of Object.values(item)) freeze(child);
      Object.freeze(item);
    }
    return item;
  };
  return freeze(copy);
}
```

- [ ] **Step 5: Run focused and regression tests**

Run:

```bash
node --test spikes/pi-wielder/tests/kernel-canonical.test.mjs
npm run test --prefix spikes/pi-wielder
```

Expected: 6 canonical tests pass and the existing 237-test suite remains green.
Loopback listener tests require an environment that permits `127.0.0.1` binding.

- [ ] **Step 6: Commit the runtime boundary**

```bash
git add spikes/pi-wielder/package.json spikes/pi-wielder/package-lock.json \
  spikes/pi-wielder/src/kernel/canonical.mjs \
  spikes/pi-wielder/tests/kernel-canonical.test.mjs
git commit -m "build: pin wallet kernel runtime"
```

### Task 2: Create the secure SQLite authority and explicit schema

**Files:**

- Modify: `.gitignore`
- Modify: `spikes/pi-wielder/.env.example:1-62`
- Create: `spikes/pi-wielder/src/kernel/secure-storage.mjs`
- Create: `spikes/pi-wielder/src/kernel/trusted-path.mjs`
- Create: `spikes/pi-wielder/src/kernel/authority-lock.mjs`
- Create: `spikes/pi-wielder/src/kernel/sqlite-schema.mjs`
- Create: `spikes/pi-wielder/src/kernel/sqlite-store.mjs`
- Create: `spikes/pi-wielder/tests/kernel-store.test.mjs`
- Create: `spikes/pi-wielder/tests/kernel-trusted-path.test.mjs`
- Create: `spikes/pi-wielder/tests/kernel-authority-lock.test.mjs`
- Create: `spikes/pi-wielder/tests/fixtures/kernel-db-writer.mjs`
- Create: `spikes/pi-wielder/tests/fixtures/kernel-lock-worker.mjs`

- [ ] **Step 1: Add ignored local authority paths**

Append to `.gitignore`:

```gitignore
# Agent Spend Control Plane local authority
spikes/pi-wielder/**/*.sqlite
spikes/pi-wielder/**/*.sqlite-wal
spikes/pi-wielder/**/*.sqlite-shm
spikes/pi-wielder/**/*.operator-token
spikes/pi-wielder/**/*.receipt-key
spikes/pi-wielder/**/*.agent-credential
spikes/pi-wielder/**/*.agent-enrollment
spikes/pi-wielder/**/*.authority-lock.sqlite*
```

Append to `spikes/pi-wielder/.env.example`:

```dotenv
# --- Agent Spend Control Plane local authority (absolute, outside checkout) --
WALLET_KERNEL_DB_FILE=
WALLET_KERNEL_RECEIPT_KEY_FILE=
WALLET_KERNEL_OPERATOR_TOKEN_FILE=
WALLET_KERNEL_TRUSTED_ANCESTOR=
WALLET_KERNEL_EXPECTED_AGENT_UID=
WALLET_KERNEL_EXPECTED_AGENT_GID=
WALLET_KERNEL_POLICY_FILE=
WALLET_KERNEL_ROUTE_FILE=
WALLET_KERNEL_PORT=8402
WALLET_KERNEL_OPERATOR_PORT=8405
```

- [ ] **Step 2: Write failing store, file-safety, and transaction tests**

Create `spikes/pi-wielder/tests/kernel-store.test.mjs` with these concrete cases:

```js
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import test from 'node:test';

import { openKernelStore } from '../src/kernel/sqlite-store.mjs';
import { acquireAuthorityLock } from '../src/kernel/authority-lock.mjs';
import { readPrivateInputFile } from '../src/kernel/secure-storage.mjs';

function authority() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'wallet-kernel-'));
  fs.chmodSync(directory, 0o700);
  const pathTrust = Object.freeze({
    mode: 'deterministic',
    trustedAncestor: directory,
    kernelUid: process.getuid(),
    agentUid: process.getuid(),
  });
  return { directory, databasePath: path.join(directory, 'kernel.sqlite'), pathTrust };
}

test('persistent store enables WAL, FULL sync, foreign keys, and schema v1', () => {
  const { databasePath, pathTrust } = authority();
  const store = openKernelStore({ filePath: databasePath, pathTrust });
  assert.equal(store.pragma('journal_mode'), 'wal');
  assert.equal(store.pragma('synchronous'), 2);
  assert.equal(store.pragma('foreign_keys'), 1);
  assert.equal(store.pragma('user_version'), 1);
  assert.equal(store.integrityCheck(), 'ok');
  store.close();
  for (const suffix of ['', '-wal', '-shm']) {
    const target = `${databasePath}${suffix}`;
    if (fs.existsSync(target)) assert.equal(fs.statSync(target).mode & 0o777, 0o600);
  }
});

test('persistent store rejects checkout, symlink, permissive, and wrong-owner-like paths', () => {
  const { directory, databasePath, pathTrust } = authority();
  assert.throws(() => openKernelStore({
    filePath: path.resolve('spikes/pi-wielder/kernel.sqlite'), pathTrust,
  }),
    /outside the checkout/);
  const target = path.join(directory, 'target.sqlite');
  fs.writeFileSync(target, '', { mode: 0o600 });
  fs.symlinkSync(target, databasePath);
  assert.throws(() => openKernelStore({ filePath: databasePath, pathTrust }), /symlink/);
  fs.unlinkSync(databasePath);
  fs.chmodSync(directory, 0o755);
  assert.throws(() => openKernelStore({ filePath: databasePath, pathTrust }), /owner-only/);
});

test('pre-existing SQLite sidecars fail closed instead of being chmod-repaired', () => {
  for (const suffix of ['-wal', '-shm']) {
    const { directory, databasePath, pathTrust } = authority();
    fs.writeFileSync(`${databasePath}${suffix}`, '', { mode: 0o644 });
    assert.throws(() => openKernelStore({ filePath: databasePath, pathTrust }), /owner-only/);
    fs.chmodSync(`${databasePath}${suffix}`, 0o600);
    fs.unlinkSync(`${databasePath}${suffix}`);
    fs.symlinkSync(path.join(directory, 'missing'), `${databasePath}${suffix}`);
    assert.throws(() => openKernelStore({ filePath: databasePath, pathTrust }), /symlink/);
  }
});

test('production policy and route inputs must be owner-only files outside the checkout', () => {
  const { directory, pathTrust } = authority();
  const configPath = path.join(directory, 'policy.json');
  fs.writeFileSync(configPath, '{}\n', { mode: 0o600 });
  assert.equal(readPrivateInputFile(configPath, 'Policy file', { pathTrust }).toString('utf8'), '{}\n');
  fs.chmodSync(configPath, 0o644);
  assert.throws(() => readPrivateInputFile(configPath, 'Policy file', { pathTrust }), /owner-only/);
});

test('domain mutation and event hash append commit or roll back together', () => {
  const store = openKernelStore({ filePath: ':memory:', allowMemory: true });
  store.mutate({ entityType: 'test', entityId: 'one', eventType: 'test.created', data: { value: 1 } },
    ({ db }) => db.prepare('INSERT INTO metadata(key, value) VALUES (?, ?)').run('sample', 'one'));
  assert.equal(store.events().length, 1);
  assert.equal(store.verifyEventChain(), true);
  assert.throws(() => store.mutate(
    { entityType: 'test', entityId: 'two', eventType: 'test.failed', data: { value: 2 } },
    () => { throw new Error('fault'); },
  ), /fault/);
  assert.equal(store.events().length, 1);
  assert.equal(store.getMetadata('sample'), 'one');
  store.close();
});

test('a newer unknown schema fails closed', () => {
  const { databasePath, pathTrust } = authority();
  const first = openKernelStore({ filePath: databasePath, pathTrust });
  first.close();
  const raw = new DatabaseSync(databasePath);
  raw.exec('PRAGMA user_version = 99');
  raw.close();
  assert.throws(() => openKernelStore({ filePath: databasePath, pathTrust }), /newer schema/);
});

test('one process owns the authority until its lifetime lock closes', async () => {
  const { databasePath, pathTrust } = authority();
  const owner = acquireAuthorityLock({ databasePath, role: 'kernel', pathTrust });
  assert.throws(() => acquireAuthorityLock({ databasePath, role: 'bootstrap', pathTrust }),
    (error) => error.code === 'AUTHORITY_BUSY');
  owner.close();
  acquireAuthorityLock({ databasePath, role: 'bootstrap', pathTrust }).close();
});
```

In `kernel-authority-lock.test.mjs`, also spawn `kernel-lock-worker.mjs` twice against
one path and prove only one reports ready. Abort the owner with `process.abort()` and
prove a new process acquires the same lock without deleting or trusting a PID file;
SQLite's operating-system lock is the lease and is released by process death. Reject
an in-checkout, symlinked, permissive, or wrong-owner-like derived lock database.

In `kernel-trusted-path.test.mjs`, exercise the live path primitive independently.
The only live implementation is Linux: it opens the configured trusted ancestor and
each descendant directory by descriptor with `O_DIRECTORY | O_NOFOLLOW` (using the
Linux `/proc/self/fd/<parent-fd>/<component>` open-at boundary), validates the opened
descriptor with `fstat()`, and re-`fstat()`s the held chain before returning. The
trusted ancestor must be root-owned with no group/other write bit. For Kernel-private
targets, every intermediate owner is exactly root or the configured Kernel UID, no
intermediate has group/other write, and the terminal parent is Kernel-owned `0700`.
World/group-writable ancestors are rejected even when the sticky bit is set. Symlinks,
dot components, path escape, device/inode changes, a non-Linux live host, and an
unavailable `/proc/self/fd` boundary all fail closed. Deterministic tests may inject a
same-UID synthetic trusted ancestor, but the result is explicitly `simulated` and is
not accepted by `cdp-testnet`.

The descriptor walk returns a canonical ordered projection of
`(role, depth, device, inode, uid, gid, mode)` for the entire chain. Tests pause after
each opened component and attempt symlink, rename, and directory-entry swaps from a
dropped Pi UID both before and after validation; every attempt must receive
`EACCES`/`EPERM`, and any injected privileged swap must be detected by the final
descriptor recheck. Apply the same primitive to every live Kernel authority, policy,
route, environment, report, evidence, operator-socket, and directional-handoff root,
not merely to the SQLite parent. Release-tree validation applies the stricter
root-only variant. No live filesystem consumer may fall back to `realpath()` plus an
immediate-parent `lstat()`.

- [ ] **Step 3: Run the store test and verify imports fail**

Run:

```bash
node --test spikes/pi-wielder/tests/kernel-store.test.mjs \
  spikes/pi-wielder/tests/kernel-trusted-path.test.mjs
```

Expected: FAIL with `ERR_MODULE_NOT_FOUND` for the store/trusted-path/authority-lock modules.

- [ ] **Step 4: Implement secure persistent paths**

Create `spikes/pi-wielder/src/kernel/trusted-path.mjs` with this exact live boundary:

```text
openTrustedParent({ mode, trustedAncestor, targetFile, kernelUid, agentUid,
  terminalOwnerUid, terminalMode, role }) -> {
    canonicalParentPath, ancestorMetadataHash,
    openLeaf(flags, mode?), openSibling(suffix, flags),
    openNamedLeaf(name, flags, mode?), linkNamedToLeaf(name), unlinkNamed(name),
    fsyncParent(), revalidate(), close()
  }
```

Every method rejects use after close and `close()` is idempotent. `openSibling()` is
private to the exact `['', '-wal', '-shm']` SQLite suffix set; named methods accept
only the private-temp grammar specified below. The guard holds every directory
descriptor until `close()`, and `revalidate()` compares the full original fstat
projection. It exposes no raw `/proc/self/fd` path to callers.

Create `spikes/pi-wielder/src/kernel/secure-storage.mjs`:

```js
import fs from 'node:fs';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { openTrustedParent } from './trusted-path.mjs';

const CHECKOUT_ROOT = fs.realpathSync(fileURLToPath(new URL('../../../../', import.meta.url)));
const NOFOLLOW = fs.constants.O_NOFOLLOW;

function assertSecurePlatform() {
  if (typeof process.getuid !== 'function' || !Number.isInteger(NOFOLLOW)) {
    throw new Error('Wallet Kernel pilot requires POSIX owner and O_NOFOLLOW semantics');
  }
}

function inside(parent, child) {
  const relative = path.relative(parent, child);
  return relative === '' || (!relative.startsWith(`..${path.sep}`) && relative !== '..');
}

function assertOwner(stat, label) {
  assertSecurePlatform();
  if (stat.uid !== process.getuid()) {
    throw new Error(`${label} must be owned by the current user`);
  }
}

function privateParent(filePath, label, checkoutRoot, pathTrust) {
  if (!path.isAbsolute(filePath)) throw new Error(`${label} path must be absolute`);
  const lexicalParent = path.resolve(path.dirname(filePath));
  if (inside(checkoutRoot, lexicalParent)) throw new Error(`${label} must be outside the checkout`);
  const guard = openTrustedParent({
    ...pathTrust,
    targetFile: filePath,
    terminalOwnerUid: process.getuid(),
    terminalMode: 0o700,
  });
  return guard;
}

export function preparePrivateFile(filePath, label,
  { checkoutRoot = CHECKOUT_ROOT, pathTrust } = {}) {
  const guard = privateParent(filePath, label, checkoutRoot, pathTrust);
  try {
    try {
      const created = guard.openLeaf(
        fs.constants.O_RDWR | fs.constants.O_CREAT | fs.constants.O_EXCL | NOFOLLOW, 0o600);
      fs.closeSync(created);
    } catch (error) {
      if (error.code !== 'EEXIST') throw error;
    }
    const descriptor = guard.openLeaf(fs.constants.O_RDONLY | NOFOLLOW);
    try {
      const stat = fs.fstatSync(descriptor);
      assertOwner(stat, label);
      if (!stat.isFile() || (stat.mode & 0o777) !== 0o600) {
        throw new Error(`${label} must be an owner-only regular file`);
      }
      guard.revalidate();
    } finally { fs.closeSync(descriptor); }
    return filePath;
  } finally {
    guard.close();
  }
}

export function readPrivateInputFile(filePath, label, {
  checkoutRoot = CHECKOUT_ROOT,
  maximumBytes = 1_048_576,
  pathTrust,
} = {}) {
  const guard = privateParent(filePath, label, checkoutRoot, pathTrust);
  let descriptor;
  try {
    descriptor = guard.openLeaf(fs.constants.O_RDONLY | NOFOLLOW);
    const stat = fs.fstatSync(descriptor);
    assertOwner(stat, label);
    if (!stat.isFile() || (stat.mode & 0o777) !== 0o600) {
      throw new Error(`${label} must be an owner-only regular file`);
    }
    if (stat.size <= 0 || stat.size > maximumBytes) {
      throw new Error(`${label} size is outside the allowed boundary`);
    }
    const bytes = fs.readFileSync(descriptor);
    guard.revalidate();
    return bytes;
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
    guard.close();
  }
}

export function preflightSqliteFiles(databasePath, { pathTrust } = {}) {
  const guard = privateParent(databasePath, 'Wallet Kernel database', CHECKOUT_ROOT, pathTrust);
  const existing = new Set();
  try {
    for (const suffix of ['', '-wal', '-shm']) {
      const target = `${databasePath}${suffix}`;
      let descriptor;
      try { descriptor = guard.openSibling(suffix, fs.constants.O_RDONLY | NOFOLLOW); }
      catch (error) { if (error.code === 'ENOENT') continue; throw error; }
      try {
        const stat = fs.fstatSync(descriptor);
        if (!stat.isFile()) throw new Error(`SQLite ${suffix || 'database'} must be regular`);
        assertOwner(stat, `SQLite ${suffix || 'database'}`);
        if ((stat.mode & 0o777) !== 0o600) throw new Error(`SQLite ${suffix || 'database'} must be owner-only`);
        existing.add(target);
      } finally { fs.closeSync(descriptor); }
    }
    guard.revalidate();
    return existing;
  } finally {
    guard.close();
  }
}

export function secureNewSqliteSideFiles(databasePath, existing, { pathTrust } = {}) {
  const guard = privateParent(databasePath, 'Wallet Kernel database', CHECKOUT_ROOT, pathTrust);
  try {
    for (const suffix of ['', '-wal', '-shm']) {
      const target = `${databasePath}${suffix}`;
      let descriptor;
      try { descriptor = guard.openSibling(suffix, fs.constants.O_RDONLY | NOFOLLOW); }
      catch (error) { if (error.code === 'ENOENT') continue; throw error; }
      try {
        const stat = fs.fstatSync(descriptor);
        if (!stat.isFile()) throw new Error(`SQLite ${suffix || 'database'} must be regular`);
        assertOwner(stat, `SQLite ${suffix || 'database'}`);
        if (!existing.has(target)) fs.fchmodSync(descriptor, 0o600);
      } finally { fs.closeSync(descriptor); }
    }
    guard.revalidate();
  } finally {
    guard.close();
  }
  preflightSqliteFiles(databasePath, { pathTrust });
}

export function loadOrInitializePrivateFile({
  filePath,
  label,
  createBytes,
  validateBytes,
  randomBytes = crypto.randomBytes,
  faultInjector = () => {},
  pathTrust,
}) {
  const guard = privateParent(filePath, label, CHECKOUT_ROOT, pathTrust);
  const readExisting = () => {
    const descriptor = guard.openLeaf(fs.constants.O_RDONLY | NOFOLLOW);
    try {
      const stat = fs.fstatSync(descriptor);
      assertOwner(stat, label);
      if (!stat.isFile() || (stat.mode & 0o777) !== 0o600) {
        throw new Error(`${label} must be an owner-only regular file`);
      }
      const bytes = fs.readFileSync(descriptor);
      if (bytes.length === 0) throw new Error(`${label} must not be empty`);
      guard.revalidate();
      return validateBytes(bytes);
    } finally {
      fs.closeSync(descriptor);
    }
  };
  let bytes;
  let temporaryName;
  try {
    try { return readExisting(); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
    bytes = Buffer.from(createBytes());
    if (bytes.length === 0) throw new Error(`${label} initializer returned empty content`);
    validateBytes(bytes);
    const suffix = randomBytes(16).toString('hex');
    temporaryName = `.${path.basename(filePath)}.tmp-${process.pid}-${suffix}`;
    const descriptor = guard.openNamedLeaf(temporaryName,
      fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | NOFOLLOW, 0o600);
    try {
      fs.writeFileSync(descriptor, bytes);
      faultInjector('after_private_temp_write');
      fs.fsyncSync(descriptor);
      faultInjector('after_private_temp_fsync');
    } finally {
      fs.closeSync(descriptor);
    }

    try {
      // link() is Node's no-replace publish primitive: EEXIST means a racer won.
      guard.linkNamedToLeaf(temporaryName);
      faultInjector('after_private_publish');
    } catch (error) {
      if (error.code !== 'EEXIST') throw error;
    }
    guard.fsyncParent();
    faultInjector('after_private_directory_fsync');
    return readExisting();
  } finally {
    try {
      if (bytes) bytes.fill(0);
      if (temporaryName) {
        try { guard.unlinkNamed(temporaryName); }
        catch (error) { if (error.code !== 'ENOENT') throw error; }
        guard.fsyncParent();
      }
      guard.revalidate();
    } finally {
      guard.close();
    }
  }
}
```

Use `readPrivateInputFile()` for every policy and route read in bootstrap and daemon
composition. Parse only the returned bounded bytes; never validate a path and reopen it
later, and never retain raw configuration bytes after canonical validation.

Import `openTrustedParent()` from `trusted-path.mjs`. Every file-backed public
function above and `openKernelStore()` requires an explicit frozen `pathTrust` object;
there is no permissive default. In live mode it contains the configured
`trustedAncestor`, Kernel/Pi UID policy, and `mode: 'cdp-testnet'`. In deterministic
tests it names the synthetic fixture ancestor and `mode: 'deterministic'`. The
returned guard owns the full descriptor chain through each leaf
`open(... | O_NOFOLLOW)` and final `fstat()`/parent fsync operation; its leaf/link/
unlink methods resolve only through `/proc/self/fd`, validate bounded basenames, and
never reopen an absolute path. Propagate the same
object through SQLite sidecar creation and the authority-lock database.

Use `loadOrInitializePrivateFile()` for the receipt key, operator token, and agent
credential in Tasks 7, 13, and 14. The first two run only as the Kernel UID; the last
runs only in Task 14's Pi-side credential helper and is never called by Kernel
composition. Add a private-temp recovery helper used before
`readExisting()`: it may inspect
only the exact `.<basename>.tmp-<pid>-<32 hex>` namespace in the already validated
owner-only parent; it rejects symlinked, wrong-owner, permissive, or invalid candidates.
If the final file is absent it no-replace-publishes the lexicographically first valid
candidate, and if the final is valid it removes only validated candidates, fsyncing the
directory after each resolution. This makes every injected abort point restart-safe.

Add fresh-process tests proving an existing empty, truncated, symlinked, or invalid
key/token fails closed; two processes racing initialization produce one valid final
file rather than an overwrite; and `process.abort()` after temp write, temp fsync,
no-replace publish, or parent-directory fsync recovers to one valid reusable value with
no truncated final file.

- [ ] **Step 4a: Implement the shared process-lifetime authority lock**

Create `authority-lock.mjs` with this exact public boundary:

```js
export function acquireAuthorityLock({ databasePath, role, pathTrust }) {
  // Return an idempotent close() handle, or throw KernelError('AUTHORITY_BUSY').
}
```

Derive the path internally as `${databasePath}.authority-lock.sqlite`; callers cannot
choose it. Validate/create it as an owner-only regular file outside the checkout using
`secure-storage.mjs`, open a separate `DatabaseSync` with `timeout: 0`, force rollback
journal mode, and hold `BEGIN EXCLUSIVE` for the handle's entire lifetime. `role` is
exactly `kernel`, `bootstrap`, or `prelaunch` and is diagnostic only; do not persist PIDs, hostnames,
tokens, or owner-controlled lock content. Map only SQLite busy/locked results to
`AUTHORITY_BUSY`; malformed paths and filesystem state fail with their own stable
preflight error. `close()` rolls back the exclusive transaction and closes the lock
connection. An OS process death releases the SQLite lock automatically, so a leftover
lock database is reusable and is never treated as proof of a live or stale owner.

The running control plane must acquire role `kernel` before opening the authority
database, recovery, wallet initialization, or either listener, and hold it until
admission stops, listeners close, the authority database closes, and finally the lock
handle closes. All offline bootstrap commands acquire role `bootstrap` through this
same module. Task 13's prelaunch child first drops to the exact Kernel UID/GID, then
acquires `prelaunch`, opens the main authority strictly read-only for its bounded
enrollment/attestation lookup, performs no pragma/schema/event/write operation, closes
it, and releases before the root preflight exits and the daemon starts. The root parent
never calls this module.
Unit and fresh-process tests prove every pairwise Kernel/bootstrap/prelaunch contention,
clean close; crash release; and that a contender
can never mutate the main database before acquiring the lock.

- [ ] **Step 5: Create schema v1 with explicit domain tables**

Create `spikes/pi-wielder/src/kernel/sqlite-schema.mjs` with the following wrapper,
placing the SQL below between the backticks:

```js
export const KERNEL_SCHEMA_VERSION = 1;

export const SCHEMA_V1_SQL = String.raw`
-- exact schema shown below
`;
```

Replace the single comment line with these exact `STRICT` tables:

```sql
CREATE TABLE IF NOT EXISTS metadata (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS policy_versions (
  id TEXT PRIMARY KEY,
  schema_version INTEGER NOT NULL,
  canonical_json TEXT NOT NULL,
  policy_hash TEXT NOT NULL UNIQUE,
  predecessor_hash TEXT,
  applied_at TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS spend_sessions (
  id TEXT PRIMARY KEY,
  adapter_id TEXT NOT NULL,
  wallet_address TEXT NOT NULL,
  policy_version_id TEXT NOT NULL REFERENCES policy_versions(id),
  state TEXT NOT NULL CHECK (state IN ('open','policy_blocked','closed')),
  created_at TEXT NOT NULL,
  closed_at TEXT
) STRICT;

CREATE TABLE IF NOT EXISTS agent_enrollments (
  agent_instance_id TEXT PRIMARY KEY,
  credential_digest TEXT NOT NULL UNIQUE,
  enrollment_hash TEXT NOT NULL UNIQUE,
  agent_uid TEXT NOT NULL CHECK (
    agent_uid GLOB '[1-9]*' AND agent_uid NOT GLOB '*[^0-9]*'
  ),
  agent_gid TEXT NOT NULL CHECK (
    agent_gid GLOB '[1-9]*' AND agent_gid NOT GLOB '*[^0-9]*'
  ),
  state TEXT NOT NULL CHECK (state IN ('active','revoked')),
  enrolled_by_operator_hash TEXT NOT NULL,
  enrolled_at TEXT NOT NULL,
  revoked_by_operator_hash TEXT,
  revoked_at TEXT,
  UNIQUE(agent_instance_id, credential_digest),
  UNIQUE(agent_instance_id, credential_digest, enrollment_hash),
  CHECK (
    (state = 'active' AND revoked_by_operator_hash IS NULL AND revoked_at IS NULL) OR
    (state = 'revoked' AND revoked_by_operator_hash IS NOT NULL AND revoked_at IS NOT NULL)
  )
) STRICT;

CREATE TABLE IF NOT EXISTS isolation_attestations (
  id TEXT PRIMARY KEY,
  report_hash TEXT NOT NULL UNIQUE,
  enrollment_hash TEXT NOT NULL REFERENCES agent_enrollments(enrollment_hash),
  report_json TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('current','superseded')),
  imported_by_operator_hash TEXT NOT NULL,
  probed_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  imported_at TEXT NOT NULL,
  superseded_at TEXT,
  CHECK (
    (state = 'current' AND superseded_at IS NULL) OR
    (state = 'superseded' AND superseded_at IS NOT NULL)
  )
) STRICT;

CREATE TABLE IF NOT EXISTS agent_session_bindings (
  id TEXT PRIMARY KEY,
  agent_instance_id TEXT NOT NULL,
  credential_digest TEXT NOT NULL,
  enrollment_hash TEXT NOT NULL,
  session_id TEXT NOT NULL UNIQUE REFERENCES spend_sessions(id),
  state TEXT NOT NULL CHECK (state IN ('open','closed')),
  created_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  closed_at TEXT,
  FOREIGN KEY(agent_instance_id, credential_digest, enrollment_hash)
    REFERENCES agent_enrollments(agent_instance_id, credential_digest, enrollment_hash)
) STRICT;

CREATE TABLE IF NOT EXISTS spend_intents (
  id TEXT PRIMARY KEY,
  request_id TEXT NOT NULL UNIQUE,
  session_id TEXT NOT NULL REFERENCES spend_sessions(id),
  enrollment_hash TEXT NOT NULL REFERENCES agent_enrollments(enrollment_hash),
  route_id TEXT NOT NULL,
  method TEXT NOT NULL,
  request_url_hash TEXT NOT NULL,
  seller_origin TEXT NOT NULL,
  resource_path TEXT NOT NULL,
  body_hash TEXT NOT NULL,
  header_allowlist_hash TEXT NOT NULL,
  ordinary_fingerprint TEXT NOT NULL,
  retry_matchable INTEGER NOT NULL DEFAULT 1 CHECK (retry_matchable IN (0,1)),
  purpose_label TEXT NOT NULL,
  correlation_id TEXT NOT NULL,
  idempotency_key TEXT NOT NULL UNIQUE,
  wallet_address TEXT NOT NULL,
  intent_hash TEXT NOT NULL UNIQUE,
  challenge_projection_json TEXT,
  challenge_hash TEXT,
  challenge_received_at TEXT,
  state TEXT NOT NULL CHECK (state IN (
    'captured','challenged','approval_pending','authorized','reserved','signing',
    'signed','retrying','unresolved','terminal'
  )),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS policy_decisions (
  intent_id TEXT PRIMARY KEY REFERENCES spend_intents(id),
  policy_version_id TEXT NOT NULL REFERENCES policy_versions(id),
  decision TEXT NOT NULL CHECK (decision IN ('allow','approval_required','deny')),
  reason_code TEXT NOT NULL,
  challenge_hash TEXT NOT NULL,
  accepted_index INTEGER,
  quote_id TEXT,
  amount_ceiling_atomic TEXT NOT NULL CHECK (
    amount_ceiling_atomic = '0' OR
    (amount_ceiling_atomic GLOB '[1-9]*' AND amount_ceiling_atomic NOT GLOB '*[^0-9]*')
  ),
  decided_at TEXT NOT NULL,
  CHECK (
    (accepted_index IS NULL AND quote_id IS NULL) OR
    (accepted_index >= 0 AND quote_id IS NOT NULL)
  )
) STRICT;

CREATE TABLE IF NOT EXISTS budget_reservations (
  intent_id TEXT PRIMARY KEY REFERENCES spend_intents(id),
  session_id TEXT NOT NULL REFERENCES spend_sessions(id),
  seller_origin TEXT NOT NULL,
  reserved_atomic TEXT NOT NULL CHECK (reserved_atomic = '0' OR
    (reserved_atomic GLOB '[1-9]*' AND reserved_atomic NOT GLOB '*[^0-9]*')),
  committed_atomic TEXT NOT NULL CHECK (committed_atomic = '0' OR
    (committed_atomic GLOB '[1-9]*' AND committed_atomic NOT GLOB '*[^0-9]*')),
  released_atomic TEXT NOT NULL CHECK (released_atomic = '0' OR
    (released_atomic GLOB '[1-9]*' AND released_atomic NOT GLOB '*[^0-9]*')),
  unresolved_atomic TEXT NOT NULL CHECK (unresolved_atomic = '0' OR
    (unresolved_atomic GLOB '[1-9]*' AND unresolved_atomic NOT GLOB '*[^0-9]*')),
  state TEXT NOT NULL CHECK (state IN ('reserved','committed','released','unresolved')),
  committed_at TEXT,
  updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS approvals (
  id TEXT PRIMARY KEY,
  intent_id TEXT NOT NULL UNIQUE REFERENCES spend_intents(id),
  decision TEXT NOT NULL CHECK (
    decision IN ('pending','approved','denied','expired','cancelled','consumed')
  ),
  operator_id_hash TEXT,
  intent_hash TEXT NOT NULL,
  challenge_hash TEXT NOT NULL,
  quote_id TEXT NOT NULL,
  accepted_index INTEGER NOT NULL CHECK (accepted_index >= 0),
  amount_ceiling_atomic TEXT NOT NULL CHECK (
    amount_ceiling_atomic = '0' OR
    (amount_ceiling_atomic GLOB '[1-9]*' AND amount_ceiling_atomic NOT GLOB '*[^0-9]*')
  ),
  wallet_address TEXT NOT NULL,
  policy_version_id TEXT NOT NULL REFERENCES policy_versions(id),
  expires_at TEXT NOT NULL,
  reason_code TEXT,
  decided_at TEXT,
  consumed_at TEXT
) STRICT;

CREATE TABLE IF NOT EXISTS payment_attempts (
  id TEXT PRIMARY KEY,
  intent_id TEXT NOT NULL UNIQUE REFERENCES spend_intents(id),
  state TEXT NOT NULL CHECK (state IN (
    'reserved','signing','signed','retrying','unresolved','settled','rejected'
  )),
  payment_required_projection_json TEXT NOT NULL,
  accepted_index INTEGER NOT NULL CHECK (accepted_index >= 0),
  payment_payload_json TEXT,
  payment_header TEXT,
  payment_hash TEXT,
  quote_id TEXT NOT NULL,
  nonce TEXT UNIQUE,
  valid_after TEXT CHECK (valid_after IS NULL OR valid_after = '0' OR
    (valid_after GLOB '[1-9]*' AND valid_after NOT GLOB '*[^0-9]*')),
  valid_before TEXT CHECK (valid_before IS NULL OR valid_before = '0' OR
    (valid_before GLOB '[1-9]*' AND valid_before NOT GLOB '*[^0-9]*')),
  settlement_json TEXT,
  transaction_id TEXT UNIQUE,
  reason_code TEXT,
  signing_claimed_at TEXT,
  signed_at TEXT,
  retry_started_at TEXT,
  settled_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS payment_reconciliation_candidates (
  id TEXT PRIMARY KEY,
  intent_id TEXT NOT NULL REFERENCES payment_attempts(intent_id),
  transaction_id TEXT NOT NULL UNIQUE,
  state TEXT NOT NULL CHECK (state IN ('pending','abandoned','rejected','confirmed')),
  evidence_json TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS execution_outcomes (
  intent_id TEXT PRIMARY KEY REFERENCES spend_intents(id),
  state TEXT NOT NULL CHECK (state IN ('succeeded','failed','unknown')),
  http_status INTEGER CHECK (http_status IS NULL OR (http_status BETWEEN 100 AND 599)),
  response_hash TEXT,
  metadata_json TEXT NOT NULL,
  recorded_at TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS execution_resolutions (
  intent_id TEXT PRIMARY KEY REFERENCES execution_outcomes(intent_id),
  state TEXT NOT NULL CHECK (state IN (
    'refund_pending','reconciliation_required','resolved'
  )),
  reason_code TEXT NOT NULL,
  blocks_wallet INTEGER NOT NULL CHECK (blocks_wallet IN (0,1)),
  opened_at TEXT NOT NULL,
  resolved_at TEXT,
  CHECK (
    (state = 'resolved' AND blocks_wallet = 0 AND resolved_at IS NOT NULL) OR
    (state != 'resolved' AND blocks_wallet = 1 AND resolved_at IS NULL)
  )
) STRICT;

CREATE TABLE IF NOT EXISTS refunds (
  id TEXT PRIMARY KEY,
  intent_id TEXT NOT NULL REFERENCES spend_intents(id),
  original_transaction_id TEXT NOT NULL,
  amount_atomic TEXT NOT NULL CHECK (amount_atomic = '0' OR
    (amount_atomic GLOB '[1-9]*' AND amount_atomic NOT GLOB '*[^0-9]*')),
  state TEXT NOT NULL CHECK (
    state IN ('pending','unresolved','abandoned','confirmed','rejected')
  ),
  evidence_json TEXT,
  refund_transaction_id TEXT UNIQUE,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS reconciliations (
  id TEXT PRIMARY KEY,
  intent_id TEXT NOT NULL REFERENCES spend_intents(id),
  kind TEXT NOT NULL CHECK (kind IN ('payment','execution','refund')),
  outcome TEXT NOT NULL CHECK (outcome IN (
    'settled','rejected','execution_succeeded','execution_failed',
    'execution_unknown','refund_confirmed','refund_rejected','unresolved'
  )),
  evidence_json TEXT NOT NULL,
  operator_id_hash TEXT NOT NULL,
  recorded_at TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS buyer_outcomes (
  intent_id TEXT PRIMARY KEY REFERENCES spend_intents(id),
  status TEXT NOT NULL CHECK (status IN (
    'completed','upstream_failed','payment_denied','payment_failed',
    'payment_unresolved','payment_rejected','execution_failed',
    'execution_unknown','refunded'
  )),
  reason_code TEXT NOT NULL,
  revision INTEGER NOT NULL CHECK (revision >= 1),
  recorded_at TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS signed_receipts (
  id TEXT PRIMARY KEY,
  intent_id TEXT NOT NULL REFERENCES spend_intents(id),
  revision INTEGER NOT NULL CHECK (revision >= 1),
  receipt_json TEXT NOT NULL,
  receipt_hash TEXT NOT NULL UNIQUE,
  signature TEXT NOT NULL,
  algorithm TEXT NOT NULL CHECK (algorithm = 'Ed25519'),
  key_id TEXT NOT NULL,
  supersedes_receipt_hash TEXT,
  created_at TEXT NOT NULL,
  UNIQUE(intent_id, revision)
) STRICT;

CREATE TABLE IF NOT EXISTS events (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  entity_type TEXT NOT NULL,
  entity_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  data_json TEXT NOT NULL,
  previous_hash TEXT,
  event_hash TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS idx_intents_session_hash
  ON spend_intents(session_id, intent_hash, state);
CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_open_instance
  ON agent_session_bindings(agent_instance_id) WHERE state = 'open';
CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_open_credential
  ON agent_session_bindings(credential_digest) WHERE state = 'open';
CREATE UNIQUE INDEX IF NOT EXISTS idx_one_active_agent_enrollment
  ON agent_enrollments(state) WHERE state = 'active';
CREATE UNIQUE INDEX IF NOT EXISTS idx_one_current_isolation_attestation
  ON isolation_attestations(state) WHERE state = 'current';
CREATE UNIQUE INDEX IF NOT EXISTS idx_intents_retry_fingerprint
  ON spend_intents(session_id, ordinary_fingerprint) WHERE retry_matchable = 1;
CREATE UNIQUE INDEX IF NOT EXISTS idx_intents_session_correlation
  ON spend_intents(session_id, correlation_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_one_open_session_binding
  ON spend_sessions(adapter_id, wallet_address, policy_version_id)
  WHERE state = 'open';
CREATE INDEX IF NOT EXISTS idx_budget_session_seller
  ON budget_reservations(session_id, seller_origin, state);
CREATE INDEX IF NOT EXISTS idx_budget_committed_at
  ON budget_reservations(committed_at);
CREATE INDEX IF NOT EXISTS idx_approvals_state_expiry
  ON approvals(decision, expires_at);
CREATE INDEX IF NOT EXISTS idx_payment_state
  ON payment_attempts(state);
CREATE UNIQUE INDEX IF NOT EXISTS idx_refunds_one_open_intent
  ON refunds(intent_id) WHERE state IN ('pending','unresolved');
CREATE UNIQUE INDEX IF NOT EXISTS idx_payment_candidate_one_open_intent
  ON payment_reconciliation_candidates(intent_id) WHERE state = 'pending';
```

In `kernel-store.test.mjs`, attempt direct inserts for every declared state enum,
negative/leading-zero/non-digit/empty atomic text, negative accepted index, invalid HTTP
status, and nonpositive receipt revision. Assert SQLite rejects each invalid value and
accepts the boundary-valid forms. Bounds that depend on another JSON row remain the
startup semantic audit's responsibility in Task 11.

- [ ] **Step 6: Implement the SQLite transaction and hash-chain store**

Create `spikes/pi-wielder/src/kernel/sqlite-store.mjs` with this public contract:

```js
import { DatabaseSync } from 'node:sqlite';
import { canonicalJson, sha256 } from './canonical.mjs';
import {
  preflightSqliteFiles,
  preparePrivateFile,
  secureNewSqliteSideFiles,
} from './secure-storage.mjs';
import { KERNEL_SCHEMA_VERSION, SCHEMA_V1_SQL } from './sqlite-schema.mjs';

export function openKernelStore({ filePath, allowMemory = false, pathTrust,
  now = () => new Date().toISOString() }) {
  if (filePath === ':memory:' && !allowMemory) throw new Error('in-memory authority requires explicit test injection');
  const existing = filePath === ':memory:' ? new Set()
    : preflightSqliteFiles(filePath, { pathTrust });
  if (filePath !== ':memory:') {
    preparePrivateFile(filePath, 'Wallet Kernel database', { pathTrust });
  }
  const db = new DatabaseSync(filePath, { timeout: 5_000, readBigInts: true });
  db.exec('PRAGMA foreign_keys = ON; PRAGMA trusted_schema = OFF; PRAGMA synchronous = FULL;');
  if (filePath !== ':memory:') db.exec('PRAGMA journal_mode = WAL;');
  const version = Number(db.prepare('PRAGMA user_version').get().user_version);
  if (version > KERNEL_SCHEMA_VERSION) throw new Error('Wallet Kernel database uses a newer schema');
  if (version === 0) {
    db.exec('BEGIN IMMEDIATE');
    try {
      db.exec(SCHEMA_V1_SQL);
      db.exec(`PRAGMA user_version = ${KERNEL_SCHEMA_VERSION}`);
      db.exec('COMMIT');
    } catch (error) {
      db.exec('ROLLBACK');
      throw error;
    }
  }
  if (filePath !== ':memory:') secureNewSqliteSideFiles(filePath, existing, { pathTrust });

  const liveTransactions = new WeakSet();
  let transactionOpen = false;
  const within = (token, operation) => {
    if (!liveTransactions.has(token)) throw new Error('invalid authority transaction');
    return operation({ db, appendEvent: (event) => appendEvent(event, db) });
  };
  const transaction = (operation) => {
    if (transactionOpen) throw new Error('nested authority transaction is forbidden');
    transactionOpen = true;
    const token = Object.freeze(Object.create(null));
    try {
      db.exec('BEGIN IMMEDIATE');
      liveTransactions.add(token);
      const value = operation(token);
      if (value && typeof value.then === 'function') {
        throw new Error('authority transactions must be synchronous');
      }
      if (filePath !== ':memory:') preflightSqliteFiles(filePath, { pathTrust });
      db.exec('COMMIT');
      return value;
    } catch (error) {
      if (db.isTransaction) db.exec('ROLLBACK');
      throw error;
    } finally {
      liveTransactions.delete(token);
      transactionOpen = false;
    }
  };

  const appendEvent = ({ entityType, entityId, eventType, data }, txDb = db) => {
    const previous = txDb.prepare('SELECT event_hash FROM events ORDER BY sequence DESC LIMIT 1').get();
    const createdAt = now();
    const dataJson = canonicalJson(data);
    const previousHash = previous?.event_hash ?? null;
    const eventHash = sha256(canonicalJson({
      entityType, entityId, eventType, data, previousHash, createdAt,
    }));
    txDb.prepare(`INSERT INTO events
      (entity_type, entity_id, event_type, data_json, previous_hash, event_hash, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)`)
      .run(entityType, entityId, eventType, dataJson, previousHash, eventHash, createdAt);
    return eventHash;
  };

  const mutate = (event, operation) => transaction((token) => within(token,
    ({ db: txDb, appendEvent: appendInTransaction }) => {
      const value = operation({ db: txDb });
      appendInTransaction(event);
      return value;
    }));

  const events = () => db.prepare('SELECT * FROM events ORDER BY sequence').all();
  const readStatement = (sql) => {
    if (typeof sql !== 'string' || !/^\s*SELECT\b/i.test(sql) || sql.includes(';')) {
      throw new Error('only one parameterized SELECT is exposed outside a transaction');
    }
    return db.prepare(sql);
  };
  const readOne = (sql, parameters = []) => readStatement(sql).get(...parameters);
  const readAll = (sql, parameters = []) => readStatement(sql).all(...parameters);
  const pragma = (name) => {
    if (!['journal_mode', 'synchronous', 'foreign_keys', 'user_version'].includes(name)) {
      throw new Error('PRAGMA is not exposed');
    }
    const value = Object.values(db.prepare(`PRAGMA ${name}`).get())[0];
    return typeof value === 'bigint' ? Number(value) : value;
  };
  const verifyEventChain = () => {
    let previousHash = null;
    for (const row of events()) {
      const expected = sha256(canonicalJson({
        entityType: row.entity_type,
        entityId: row.entity_id,
        eventType: row.event_type,
        data: JSON.parse(row.data_json),
        previousHash,
        createdAt: row.created_at,
      }));
      if (row.previous_hash !== previousHash || row.event_hash !== expected) return false;
      previousHash = row.event_hash;
    }
    return true;
  };

  return Object.freeze({
    transaction,
    within,
    mutate,
    readOne,
    readAll,
    events,
    verifyEventChain,
    pragma,
    integrityCheck: () => db.prepare('PRAGMA integrity_check').get().integrity_check,
    getMetadata: (key) => db.prepare('SELECT value FROM metadata WHERE key = ?').get(key)?.value ?? null,
    close: () => db.close(),
    ...(allowMemory ? { execForTest: (sql) => db.exec(sql) } : {}),
  });
}
```

Kernel modules use `readOne()`/`readAll()` for parameterized reads and receive the raw
database handle plus event appender only inside `mutate()` or `within(liveToken, ...)`.
The public store has no raw-handle or direct-event escape hatch; HTTP and operator
surfaces must never receive the store object. Store tests assert
`store.rawForModules === undefined` and `store.appendEvent === undefined`, reject
non-SELECT/multi-statement reads, and prove all writes require a store-owned
transaction.

The opaque transaction token is the only cross-repository composition mechanism.
Standalone repository methods open one transaction. Every repository mutation that
participates in a multi-table aggregate exposes the explicit
`*InTransaction(token, ...)` method named in its task; those methods validate the live
token and never begin/commit/rollback. Wallet Kernel and reconciliation coordinators own the one outer
`store.transaction()` and call only those scoped methods for multi-table transitions.
The token never crosses an `await`, listener, worker, log, or return value. Store tests
prove nested transactions, an async callback, a stale/forged token, and calling a
standalone wrapper from inside a transaction all fail and fully roll back.

Every event `data` object uses a closed per-event schema containing identifiers,
hashes, states, reason codes, and canonical atomic amounts only. In particular, never
append raw bodies, response bodies, payment payload/header bytes, credentials, tokens,
provider exceptions, or local paths to `events.data_json`; those private payment bytes
live only in the dedicated `payment_attempts` columns needed for exact retry/recovery.

- [ ] **Step 7: Add the cross-process single-writer claim test**

This fixture deliberately tests SQLite transaction serialization below the composition
root; it is not a production entrypoint. The daemon/bootstrap exclusion proof remains
`kernel-authority-lock.test.mjs`, and every production store open requires its caller
to already hold that capability.

Create `spikes/pi-wielder/tests/fixtures/kernel-db-writer.mjs`:

```js
import { openKernelStore } from '../../src/kernel/sqlite-store.mjs';

const [databasePath, trustedAncestor, claimId] = process.argv.slice(2);
const pathTrust = Object.freeze({
  mode: 'deterministic', trustedAncestor,
  kernelUid: process.getuid(), agentUid: process.getuid(),
});
const store = openKernelStore({ filePath: databasePath, pathTrust });
try {
  const outcome = store.transaction((token) => store.within(token,
    ({ db, appendEvent }) => {
      const current = db.prepare('SELECT value FROM metadata WHERE key = ?').get('claim');
      if (current) return 'already_claimed';
      db.prepare('INSERT INTO metadata(key, value) VALUES (?, ?)').run('claim', claimId);
      appendEvent({
        entityType: 'test',
        entityId: claimId,
        eventType: 'test.claimed',
        data: { claimId },
      });
      return 'claimed';
    }));
  process.stdout.write(`${outcome}\n`);
} finally {
  store.close();
}
```

Add these imports and this test to `kernel-store.test.mjs`:

```js
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

function childResult(child) {
  return new Promise((resolve, reject) => {
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('error', reject);
    child.on('exit', (code) => code === 0
      ? resolve(stdout.trim())
      : reject(new Error(`writer exited ${code}: ${stderr}`)));
  });
}

test('two processes serialize one conditional claim and one hash-chain event', async () => {
  const { directory, databasePath, pathTrust } = authority();
  const initial = openKernelStore({ filePath: databasePath, pathTrust });
  initial.close();
  const fixture = fileURLToPath(new URL('./fixtures/kernel-db-writer.mjs', import.meta.url));
  const children = ['a', 'b'].map((claimId) => spawn(
    process.execPath,
    [fixture, databasePath, directory, claimId],
    { stdio: ['ignore', 'pipe', 'pipe'] },
  ));
  assert.deepEqual((await Promise.all(children.map(childResult))).sort(),
    ['already_claimed', 'claimed']);
  const reopened = openKernelStore({ filePath: databasePath, pathTrust });
  assert.equal(reopened.verifyEventChain(), true);
  assert.equal(reopened.events().filter((event) => event.event_type === 'test.claimed').length, 1);
  reopened.close();
});
```

Run:

```bash
node --test spikes/pi-wielder/tests/kernel-store.test.mjs \
  spikes/pi-wielder/tests/kernel-trusted-path.test.mjs \
  spikes/pi-wielder/tests/kernel-authority-lock.test.mjs
```

Expected: all store/lock tests pass, including cross-process serialization, lifetime
contention, and crash release.

- [ ] **Step 8: Commit the durable authority**

```bash
git add .gitignore spikes/pi-wielder/.env.example \
  spikes/pi-wielder/src/kernel/secure-storage.mjs \
  spikes/pi-wielder/src/kernel/trusted-path.mjs \
  spikes/pi-wielder/src/kernel/authority-lock.mjs \
  spikes/pi-wielder/src/kernel/sqlite-schema.mjs \
  spikes/pi-wielder/src/kernel/sqlite-store.mjs \
  spikes/pi-wielder/tests/kernel-store.test.mjs \
  spikes/pi-wielder/tests/kernel-trusted-path.test.mjs \
  spikes/pi-wielder/tests/kernel-authority-lock.test.mjs \
  spikes/pi-wielder/tests/fixtures/kernel-db-writer.mjs \
  spikes/pi-wielder/tests/fixtures/kernel-lock-worker.mjs
git commit -m "feat: add durable wallet kernel store"
```

### Task 3: Implement immutable policy versions and the pure Policy Engine

**Files:**

- Create: `spikes/pi-wielder/policies/base-sepolia.example.json`
- Create: `spikes/pi-wielder/src/kernel/policy-engine.mjs`
- Create: `spikes/pi-wielder/src/kernel/policy-repository.mjs`
- Create: `spikes/pi-wielder/tests/kernel-policy.test.mjs`

- [ ] **Step 1: Write the failing policy matrix**

Create tests that use this exact base policy:

```js
const policy = {
  schemaVersion: 1,
  network: 'eip155:84532',
  asset: '0x036cbd53842c5426634e7929541ec2318f3dcf7e',
  wallet: '0x1000000000000000000000000000000000000000',
  methods: ['GET', 'POST'],
  sellers: [{
    origin: 'https://seller.example',
    pathPrefixes: ['/paid/'],
    payTo: '0x2000000000000000000000000000000000000000',
    evidencePath: '/.well-known/wallet-kernel/evidence',
    executionSigner: '0x2000000000000000000000000000000000000000',
    refundSigner: '0x2000000000000000000000000000000000000000',
    refundSource: '0x3000000000000000000000000000000000000000',
    perRequestMaxAtomic: '500000',
    autoApproveAtomic: '100000',
    humanApproveAtomic: '500000',
    sellerSessionMaxAtomic: '1000000',
  }],
  sessionMaxAtomic: '2000000',
  rolling24hMaxAtomic: '5000000',
  challengeMaxAgeMs: 60000,
  approvalTtlMs: 300000,
  maxPendingApprovals: 20,
  defaultAction: 'deny',
};
```

Assert all of the following:

```text
50,000 atomic exact request -> allow / WITHIN_AUTO_LIMIT
250,000 atomic exact request -> approval_required / HUMAN_APPROVAL_REQUIRED
500,001 atomic request -> deny / PER_REQUEST_LIMIT
unsupported scheme, version, network, asset, method, seller, path, payee -> deny, never approval
non-canonical evidence path or invalid evidence signer/refund source -> policy validation error
duplicate canonical seller origin or duplicate canonical path prefix -> policy validation error
non-HTTPS seller origin other than literal loopback HTTP -> policy validation error
zero compatible payment options -> stable mismatch denial; duplicate/multiple compatible options -> deny / PAYMENT_OPTIONS_AMBIGUOUS
one compatible option plus unsupported alternatives -> select its original array index, never index zero by default
seller/session, full-session, or rolling-24-hour exposure overflow -> deny
pending approval capacity reached -> deny / APPROVAL_CAPACITY
unknown policy or challenge fields -> validation error before a decision
same frozen input snapshot -> byte-identical decision and no mutation
```

Also persist two policy versions and assert the second row points to the first policy
hash while the first row remains byte-identical.

- [ ] **Step 2: Run the test and verify the policy module is absent**

```bash
node --test spikes/pi-wielder/tests/kernel-policy.test.mjs
```

Expected: FAIL with `ERR_MODULE_NOT_FOUND`.

- [ ] **Step 3: Add the canonical example policy**

Create `spikes/pi-wielder/policies/base-sepolia.example.json` using the exact policy
object above, formatted as JSON. It is public configuration, contains no credential,
and uses only documented test addresses.
`evidencePath` is a queryless absolute path on the exact seller origin and is pinned
inside the immutable PolicyVersion; it cannot be a full URL, redirect target, or route
file override. Require one leading slash (never `//`), no dot segment, encoded slash,
credentials, query, or fragment, and prove `new URL(evidencePath, origin)` preserves
the exact origin and canonical pathname. `executionSigner` and `refundSigner` are
public EVM addresses whose distinct domain-separated signatures attest execution and
future full-refund observations. `refundSource` is the separately pinned public EVM
address from which the on-chain USDC refund transfer must originate; it grants no
off-chain attestation authority. Validation requires the canonical path and all three
addresses. Neither evidence signer nor the refund source grants spending or signing
authority to the buyer, and an attestation can never substitute for the on-chain
payment/refund proof required by its reconciliation path.

- [ ] **Step 4: Implement closed-schema validation and pure evaluation**

Create `policy-engine.mjs` with these exports and decision shape:

```js
export function validatePolicyDocument(document) {
  // Return a deeply frozen, normalized closed-schema policy; throw KernelError on invalid input.
}

export function selectExactCandidate({ policy, intent, paymentRequired }) {
  // Return { acceptedIndex, accepted } for exactly one compatible candidate,
  // or a stable deny result with null acceptedIndex/quoteId.
}

export function evaluateSpendPolicy(input) {
  // Return exactly:
  return Object.freeze({
    decision: 'allow',
    reasonCode: 'WITHIN_AUTO_LIMIT',
    policyHash: computedPolicyHash,
    challengeHash: computedChallengeHash,
    quoteId: computedQuoteId,
    amountCeilingAtomic: '50000',
    acceptedIndex: 0,
  });
}
```

The return above specifies the closed output schema and one allowed example;
the implementation computes every value from `input` and returns the applicable
decision and reason code. The identifiers are locally computed values, not fixture
literals or caller inputs.

The input is also closed and exact:

```js
const validatedPolicy = validatePolicyDocument(policy);
const policyHash = sha256(canonicalJson(validatedPolicy));
const input = Object.freeze({
  policy: validatedPolicy,
  policyVersion: { id: 'policy-1', hash: policyHash },
  intent: {
    id: 'intent-1',
    method: 'POST',
    requestUrl: 'https://seller.example/paid/infer',
    sellerOrigin: 'https://seller.example',
    resourcePath: '/paid/infer',
    walletAddress: '0x1000000000000000000000000000000000000000',
  },
  wallet: {
    provider: 'deterministic',
    walletId: 'buyer-a',
    address: '0x1000000000000000000000000000000000000000',
    network: 'eip155:84532',
  },
  paymentRequired,
  challengeReceivedAtMs: 1785502800000,
  nowMs: 1785502801000,
  budgetSnapshot: {
    sellerSessionExposureAtomic: '0',
    sessionExposureAtomic: '0',
    rolling24hExposureAtomic: '0',
    pendingApprovalCount: 0,
  },
});
```

Reject unknown or missing keys at every level. `selectExactCandidate()` owns selection;
the transport and Kernel may never supply or default an index. It keeps the original
array indexes, filters for exact/Base-Sepolia/Base-Sepolia-USDC/EIP-3009 and the
selected seller policy's payee, and validates canonical amounts without using amount
to eliminate alternatives. Base-Sepolia-USDC compatibility requires exact
`extra.name === 'USDC'` and `extra.version === '2'`; these seller fields cannot select
another EIP-712 domain. EIP-3009 means `extra.assetTransferMethod` is absent or exactly
`eip3009`; `permit2` and unknown methods are unsupported. Zero compatible
candidates returns the stable ordered mismatch denial, while more than one—including
duplicates—returns `PAYMENT_OPTIONS_AMBIGUOUS`. Exactly one candidate is evaluated and
its original index is persisted in `policy_decisions`, approvals, and payment attempts.

Validate `policyVersion.hash` against the canonical policy, and require the intent
wallet, live adapter identity, PolicyVersion wallet, selected network, and selected
asset to agree before applying amount or approval rules. Tests independently mutate
every input field and prove a stable denial/validation error with no mutation. Add
explicit 0/1/2-candidate, duplicate, reorder, and unsupported-alternative cases;
reordering changes `challengeHash`/`quoteId`, and no code path defaults to index `0`.
Policy validation accepts a seller origin only as canonical HTTPS or, solely so the
same pure validator can support offline evidence, HTTP at literal `127.0.0.1` or
`[::1]`; it never accepts an HTTP hostname. Task 12's mode-aware configuration and
route checks reject that loopback exception in `cdp-testnet`.

The implementation must perform checks in this order so reason codes are stable:

```js
const CHECK_ORDER = Object.freeze([
  'X402_VERSION',
  'SCHEME_UNSUPPORTED',
  'NETWORK_MISMATCH',
  'ASSET_MISMATCH',
  'WALLET_MISMATCH',
  'METHOD_UNSUPPORTED',
  'SELLER_UNTRUSTED',
  'RESOURCE_PATH',
  'PAYEE_MISMATCH',
  'PAYMENT_OPTIONS_AMBIGUOUS',
  'CHALLENGE_EXPIRED',
  'PER_REQUEST_LIMIT',
  'SELLER_SESSION_LIMIT',
  'SESSION_LIMIT',
  'ROLLING_24H_LIMIT',
  'APPROVAL_CAPACITY',
]);
```

Use `paymentRequired.x402Version === 2`, `accepted.scheme === 'exact'`, the exact
CAIP-2 network, canonical lower-case asset/payee addresses, and
`new URL(paymentRequired.resource.url)` matched to the exact Spend Intent URL. Derive
`maxTimeoutSeconds` only from a structurally validated positive safe integer in the
pilot range `1..3600`; it is a protocol maximum, never an extension of the tighter
local challenge or approval deadline.
Reject duplicate canonical seller origins before evaluation. Seller selection is an
exact map lookup by canonical origin, never a first-match or array-order operation;
within that one seller entry, the canonical resource path must start with at least one
unique canonical `pathPrefixes` value. Reordering distinct seller entries cannot
change which authority applies to an intent. Add duplicate-origin, duplicate-prefix,
overlapping-prefix, and seller-array-reordering tests; overlapping unique prefixes in
one entry are harmless because they share one payee and one set of limits.

Derive `challengeHash` from canonical closed challenge-projection bytes (version, hashed
resource URL, fixed public route metadata, and the ordered full financial requirements,
but no seller error/extensions/free text) and derive `quoteId` as
`sha256(canonicalJson({ challengeHash, acceptedIndex }))`; do not require a nonstandard
seller-supplied request hash.

`challengeReceivedAt` is the Kernel clock value captured with the decoded unpaid
response; x402 v2 does not require a seller-issued challenge timestamp. Reject when
`nowMs - challengeReceivedAtMs > challengeMaxAgeMs`. Approval expiry is the earlier of
that local challenge deadline and `decisionTime + approvalTtlMs`; an operator decision
can never extend challenge validity.

For a deny before unique selection, return `acceptedIndex: null`, `quoteId: null`, and
`amountCeilingAtomic: '0'`; these nullable pairs are persisted exactly as constrained
by schema v1. Return `allow` when the selected amount is at or below `autoApproveAtomic`,
`approval_required` when it is above that value and at or below
`humanApproveAtomic`, and `deny` above it. Unsupported protocol shape is always deny
and cannot be overridden.

The module must not import `node:sqlite`, `node:fs`, `fetch`, a wallet module, or a
clock. It receives `nowMs` and `budgetSnapshot` as values.

- [ ] **Step 5: Implement predecessor-linked PolicyVersion persistence**

Create `policy-repository.mjs` exporting:

```text
export function createPolicyRepository(store) {
  return {
    apply(document, appliedAt),
    active(),
    history(),
    get(id),
    recordDecisionInTransaction(token, {
      intentId, policyVersionId, evaluation, decidedAt,
    }),
  };
}
```

`apply()` validates and canonicalizes before entering a transaction and rejects a
policy whose wallet differs from an existing open or policy-blocked Spend Session. In
one transaction it inserts the immutable row, updates `metadata.active_policy_id`,
changes every prior-version open session to `policy_blocked`, and appends the policy
and per-session block events. Admission, approval retry, reservation, and new signing
must reject `policy_blocked` before transport; an already signed/retrying attempt may
only finish or become unresolved under its persisted old binding. Return the exact
blocked session IDs so the operator can transition them deliberately. Reapplying the
identical active hash is an idempotent lookup, not a duplicate version or re-block.

`recordDecisionInTransaction()` is the sole PolicyDecision writer. It accepts only
Task 2's live opaque transaction token and starts no transaction. Through that token it
reloads the exact immutable PolicyVersion and SpendIntent, requires the intent's
persisted challenge hash to equal `evaluation.challengeHash`, requires the canonical
PolicyVersion hash to equal `evaluation.policyHash`, validates the closed pure-engine
result, inserts the immutable `policy_decisions` row, and appends its event. An exact
replay returns the existing row; any different result for that intent is semantic
corruption. Task 10 uses this scoped method in the same outer transaction that attaches
the challenge. Its changed-challenge replacement aggregate may additionally create the
next Approval through its own scoped repository method; no orchestrator writes
`policy_decisions` directly.

At this task boundary, test only policy persistence and session-state effects that now
exist: applying a tighter same-wallet policy succeeds, becomes active, atomically marks
every prior-version open session `policy_blocked`, returns those IDs, and is idempotent
on exact replay. Do not make `kernel-policy.test.mjs` import future approval, budget,
transport, wallet, or Kernel modules. Tasks 6 and 10 add pending-approval, reservation,
in-flight signing, admission rejection, and guarded-transition enforcement once those
modules exist; Task 14 proves the same boundary through the agent surface.

- [ ] **Step 6: Run the focused tests and the old policy regression suite**

```bash
node --test spikes/pi-wielder/tests/kernel-policy.test.mjs
npm run test:policy --prefix spikes/pi-wielder
```

Expected: the new policy matrix passes and all 51 legacy v1 policy tests remain green.

- [ ] **Step 7: Commit the policy boundary**

```bash
git add spikes/pi-wielder/policies/base-sepolia.example.json \
  spikes/pi-wielder/src/kernel/policy-engine.mjs \
  spikes/pi-wielder/src/kernel/policy-repository.mjs \
  spikes/pi-wielder/tests/kernel-policy.test.mjs
git commit -m "feat: add versioned agent spend policy"
```

### Task 4: Add kernel-issued Spend Sessions and exact Spend Intents

**Files:**

- Create: `spikes/pi-wielder/src/kernel/agent-enrollment.mjs`
- Create: `spikes/pi-wielder/src/kernel/intent-builder.mjs`
- Create: `spikes/pi-wielder/tests/kernel-agent-enrollment.test.mjs`
- Create: `spikes/pi-wielder/tests/kernel-intent.test.mjs`

- [ ] **Step 1: Write the failing session and intent boundary tests**

Create `kernel-intent.test.mjs` around an in-memory Kernel store, an applied example
policy, one active non-secret enrollment, a deterministic `idFactory`, and a fixed
clock. First, `kernel-agent-enrollment.test.mjs` exercises this exact boundary:

```js
const descriptor = Object.freeze({
  schemaVersion: 1,
  agentInstanceId: 'AAAAAAAAAAAAAAAAAAAAAA',
  credentialDigest: `sha256:${'ab'.repeat(32)}`,
  agentUid: '501',
  agentGid: '20',
});
const descriptorHash = sha256(canonicalJson(descriptor));
const enrollments = createAgentEnrollmentRepository({ store, now });
const enrolled = enrollments.enroll({
  descriptor,
  expectedDescriptorHash: descriptorHash,
  operatorIdHash: `sha256:${'cd'.repeat(32)}`,
  mode: 'cdp-testnet',
  kernelUid: 502,
  kernelGid: 502,
  expectedAgentUid: 501,
  expectedAgentGid: 20,
});
assert.equal(enrolled.enrollmentHash, descriptorHash);
assert.equal(enrollments.active().credentialDigest, descriptor.credentialDigest);
```

`descriptorHash` is always SHA-256 over the UTF-8 canonical JSON object with no
trailing newline; the handoff file bytes are exactly that canonical JSON plus one
newline. The Pi helper and Kernel importer use this same rule.

Require the exact five-field descriptor, canonical 16-byte instance ID, fixed SHA-256
credential digest, canonical nonzero decimal UID/GID strings, exact descriptor hash,
bounded operator hash, and no token/token-like or unknown field. Parse each identity
string with an exact safe-integer round trip before OS use; configuration exposes
`expectedAgentUid`/`expectedAgentGid` as numbers. Live mode requires the parsed values
to equal those configured numbers, parsed `agentUid !== kernelUid`, and all UID/GID
values nonzero. Persist only the canonical strings. A shared primary group is permitted for macOS compatibility
only because every authority path has zero group permissions and the real denial
probe passes. The isolation probe must
clear supplementary groups before dropping to the
pinned primary GID/UID. Deterministic mode
permits only an explicit injected same-UID fixture and labels it simulated. Exact
reenrollment is idempotent; a second active identity/digest/UID/GID conflicts. Revocation
requires the exact persisted enrollment hash and operator hash, atomically marks the
row revoked and any `current` isolation attestation for that enrollment `superseded`
at the same timestamp, then returns any still-bound session IDs without closing,
releasing, or altering monetary state. Authentication and `currentFor()` must reject
that epoch immediately. A replacement may
be enrolled only after every binding for the revoked enrollment is safely closed.
Every session binding and Spend Intent carries the immutable `enrollmentHash`; Task
10 revalidates that epoch inside each authoritative capture/reservation/signing
transaction so a pre-revocation HTTP auth result cannot authorize post-revocation
spend.

Then exercise the intent/session API:

```js
const intents = createIntentRepository({
  store,
  idFactory: sequenceIds('session', 'intent', 'request'),
  now: () => '2026-07-31T12:00:00.000Z',
  allowLoopbackHttp: false,
});

const session = intents.openOrResumeSession({
  agentInstanceId: descriptor.agentInstanceId,
  walletAddress: '0x1000000000000000000000000000000000000000',
  policyVersionId: activePolicy.id,
});

const intent = intents.captureIntent({
  sessionId: session.id,
  routeId: 'example-skill',
  method: 'POST',
  requestUrl: 'https://seller.example/paid/infer',
  headers: { 'content-type': 'application/json', accept: 'application/json' },
  bodyBytes: Buffer.from('{"prompt":"redacted after hashing"}'),
  purposeLabel: 'skill.invoke',
  correlationId: 'pi-call-001',
});
```

Assert:

```js
assert.equal(session.id, 'session-1');
assert.equal(intent.id, 'intent-1');
assert.equal(intent.requestId, 'request-1');
assert.equal(intent.enrollmentHash, enrolled.enrollmentHash);
assert.equal(intent.routeId, 'example-skill');
assert.equal(intent.sellerOrigin, 'https://seller.example');
assert.equal(intent.resourcePath, '/paid/infer');
assert.match(intent.requestUrlHash, /^sha256:[0-9a-f]{64}$/);
assert.match(intent.bodyHash, /^sha256:[0-9a-f]{64}$/);
assert.match(intent.headerAllowlistHash, /^sha256:[0-9a-f]{64}$/);
assert.match(intent.intentHash, /^sha256:[0-9a-f]{64}$/);
assert.match(intent.idempotencyKey, /^wk_[0-9a-f]{64}$/);
assert.equal(JSON.stringify(store.readOne(
  'SELECT * FROM spend_intents WHERE id = ?', [intent.id],
)).includes('redacted after hashing'), false);
```

Add table-driven rejection coverage for these lower-cased header names:

```js
const FORBIDDEN_AGENT_HEADERS = Object.freeze([
  'payment-required',
  'payment-signature',
  'payment-response',
  'x-payment',
  'x-payment-required',
  'x-payment-response',
  'idempotency-key',
  'x-approval-id',
  'x-spend-session',
]);
```

For each header, assert `captureIntent()` throws `AGENT_HEADER_FORBIDDEN` and inserts
no row. Also assert caller-supplied `sessionId` at `openOrResumeSession()`, a missing or
non-token `routeId`, credentials in a URL, a non-HTTPS upstream, fragments, search
parameters (including `?prompt=RAW_PROMPT_SENTINEL`), an unknown session, a closed
session, a policy wallet mismatch, and duplicate `correlationId` fail closed without
persisting the sentinel. With a repository explicitly constructed as
`allowLoopbackHttp: true`, accept HTTP only when the URL host is the literal canonical
loopback address `127.0.0.1` or `[::1]`; still reject hostnames and every non-loopback
HTTP URL. CDP mode never enables this option.

Finally, capture the same ordinary retry twice and assert:

```js
assert.equal(intents.matchRetry({ sessionId: session.id, request }), intent.id);
assert.equal(intents.matchRetry({ sessionId: 'another-session', request }), null);
assert.equal(intents.matchRetry({ sessionId: session.id, request: changedBody }), null);
```

Race two initial captures with the same session, normalized ordinary request, and
purpose. Assert both resolve to the same persisted intent/request ID, exactly one
`intent.captured` event exists, and no second approval can later be created. A
different session or fingerprint still creates its own intent.

- [ ] **Step 2: Run the focused test and observe the missing module**

```bash
node --test spikes/pi-wielder/tests/kernel-agent-enrollment.test.mjs \
  spikes/pi-wielder/tests/kernel-intent.test.mjs
```

Expected: FAIL with `ERR_MODULE_NOT_FOUND` for the enrollment/intent modules.

- [ ] **Step 3: Implement exact capture and retry matching**

Create `agent-enrollment.mjs` with this exact surface:

```text
export function createAgentEnrollmentRepository({ store, now }) -> {
  enroll({ descriptor, expectedDescriptorHash, operatorIdHash,
    mode, kernelUid, kernelGid, expectedAgentUid, expectedAgentGid }),
  active(),
  get(agentInstanceId),
  revoke({ agentInstanceId, expectedEnrollmentHash, operatorIdHash }),
}
```

Every mutation owns one `BEGIN IMMEDIATE`, reloads state, and appends its event in the
same transaction. It persists only the descriptor projection/hash, operator hashes,
and timestamps—never the descriptor bytes or raw token. `revoke()` is allowed even
when a bound session has unresolved money because its only immediate effect is to deny
future agent authentication and supersede that enrollment's admission-only isolation
attestation; it does not pretend the session or money is resolved. The enrollment and
attestation events commit together. Revoke/reopen tests require zero `current`
attestations, a retained historical superseded row, recovery-only startup, and
semantic-corruption failure if a forged current row is reattached to the revoked epoch.

Create `intent-builder.mjs` with this export surface:

```js
export const FORBIDDEN_AGENT_HEADERS = Object.freeze([
  'payment-required', 'payment-signature', 'payment-response',
  'x-payment', 'x-payment-required', 'x-payment-response',
  'idempotency-key', 'x-approval-id', 'x-spend-session',
]);

export function canonicalIntentFingerprint({ routeId, method, requestUrl, headers, bodyBytes }) {
  // Return the closed canonical object used by both captureIntent and matchRetry.
}

export function createIntentRepository({ store, idFactory, now, allowLoopbackHttp = false }) {
  return Object.freeze({
    openOrResumeSession,
    transitionBlockedSessionInTransaction,
    closeBoundSessionInTransaction,
    getSession,
    captureIntent,
    captureIntentInTransaction,
    attachChallenge,
    attachChallengeInTransaction,
    transition,
    transitionInTransaction,
    getIntent,
    matchRetry,
  });
}
```

`openOrResumeSession({ agentInstanceId, walletAddress, policyVersionId })` runs under
one `BEGIN IMMEDIATE`. It loads the exact active enrollment, derives
`adapterId = pi:<agentInstanceId>`, credential digest, and immutable enrollment hash
internally, and validates
or creates the
`agent_session_bindings` row and SpendSession atomically, appending both events in that
same transaction; there is no committed unbound-session gap. It returns the one
existing open row for that exact binding without appending another event, or creates
both rows when none exists. It never resumes across a
changed enrollment, wallet, or policy; corruption that yields ambiguous open authority
fails startup with `SESSION_AUTHORITY_AMBIGUOUS`. Neither adapter ID nor credential
digest is accepted as a caller value; neither can be a PID, port, HTTP field, or
unauthenticated Pi header.
`captureIntent()` reloads that exact triple as `active` inside its write transaction,
copies `enrollment_hash` into the Spend Intent, and fails with `AGENT_REVOKED` before
persisting if revocation won the serialization race.
`captureIntentInTransaction(token, input)` and
`attachChallengeInTransaction(token, input)` are the scoped forms used by Wallet
Kernel aggregates. Each validates Task 2's live opaque token, starts no transaction,
reloads the same authority rows through that token, and invokes the same internal
implementation as its standalone wrapper. `captureIntent()` and `attachChallenge()`
each own one transaction only by wrapping that shared scoped implementation. This
allows a replacement intent, its challenge, its PolicyDecision, and its Approval to be
created without nested transactions or duplicate SQL after an old changed-challenge
aggregate has released its retry fingerprint in the same outer transaction.
`transitionInTransaction(token, { intentId, expectedState, nextState, reasonCode })`
is the scoped form used by Wallet Kernel aggregates; it conditionally changes exactly
one legal state edge and appends the intent event through the live token without
starting a transaction. The standalone `transition()` wraps that same implementation
in its own transaction for non-composed paths.
Graceful process shutdown does not close the Spend Session. Only an explicit operator
session-end/policy-transition procedure in Task 10 may close it. That procedure may
terminalize pending/unsigned work but refuses signing, signed, retrying, unresolved, or
refund-unresolved work. Thus session and
seller/session budgets survive a Kernel restart.

This repository is the sole creator/replacer/closer of the paired SpendSession and
`agent_session_bindings` rows. Define two guarded authority operations here so later
orchestration never writes either row directly or nests a second transaction:

```text
transitionBlockedSessionInTransaction(token,
  { sessionId, targetPolicyVersionId, expectedSessionHash })
  -> { previousSession, replacementSession }
closeBoundSessionInTransaction(token, { sessionId, expectedSessionHash })
  -> { closedSession }
```

Each operation validates Task 2's live opaque transaction token, starts no transaction,
reloads the exact session/binding pair inside the caller-owned transaction, checks the
displayed confirmation hash, and conditionally updates the pair.
Transition requires `policy_blocked` plus the current active same-wallet policy and
atomically closes the old pair and creates one replacement pair for the same enrolled
agent. Close accepts `open` or `policy_blocked` and creates no replacement. Both
refuse any signing/signed/retrying/unresolved payment, open execution/refund case, or
other nonterminal monetary ambiguity. They additionally require Task 10 to have
terminalized every pending/approved approval and unsigned intent, released every
definitely unsigned reservation, and written the corresponding BuyerOutcome inside the
same still-live token before the paired rows may close. They append only their owned
session/binding events. Exact replay returns the persisted result; a stale hash or
concurrent winner fails without mutation. Task 10 owns the outer transaction and then
issues any required receipt revisions before returning operator success. Task 4 tests
these methods through `store.transaction()`, including paired-row atomicity, stale
tokens/hashes, rollback, and sole-writer ownership; Tasks 6 and 10
add the cross-module state matrix once those modules exist.

Normalize and validate the bounded token `routeId`, and normalize methods to upper
case. Parse the full URL once in memory, require HTTPS by default, and reject
credentials, fragments, and every search parameter. When and only when
`allowLoopbackHttp` is explicitly true, also accept HTTP only for the literal canonical
loopback address `127.0.0.1` or `[::1]`; do not resolve a hostname for this exception.
Agent routes come from fixed queryless route-map paths, so Pi cannot encode
prompts in a URL. Persist the route ID plus only `request_url_hash = sha256(canonical
normalized URL)`, origin, fixed path, body hash, and an allowlisted-header hash—never
the full URL or search text. The allowlist is
exactly `accept`, `content-type`, and `user-agent`; values are trimmed, but order is
canonicalized. Retry matching recomputes the URL hash. Generate the session ID, intent
ID, public request ID, correlation identifier fallback, and `wk_` idempotency key
inside the repository. The request ID is opaque and safe to return to Pi; it is not an
approval capability and cannot authorize a retry by itself.
Derive and persist `ordinaryFingerprint` from route ID, canonical method, normalized
URL, allowlisted-header hash, body hash, and purpose label; it deliberately excludes the
Kernel-issued request ID and correlation ID. The partial unique index permits at most
one `retry_matchable=1` row for a session/fingerprint. `captureIntent()` handles a
concurrent unique-index loser by loading and exact-comparing the winner, never by
creating a second intent. `matchRetry()` queries only that unique active row and fails
closed if startup semantic validation ever observes ambiguity. Atomically clear
`retry_matchable` only when the intent reaches a proven terminal state. Keep it set
through approval, reservation, signing, signed, retrying, and unresolved states so a
late identical follower always resolves to the existing request ID and receives its
terminal result or `REQUEST_IN_FLIGHT`; it can never create a second signing path.
Only terminalization after settlement/rejection, a safe unsigned failure/denial, or
trusted reconciliation may release the fingerprint for a later identical request.
Derive `intentHash` from:

```js
canonicalJson({
  requestId,
  sessionId,
  enrollmentHash,
  routeId,
  method,
  requestUrlHash: sha256(requestUrl),
  bodyHash,
  headerAllowlistHash,
  purposeLabel,
  correlationId,
  walletAddress,
  policyVersionId,
})
```

Persist `session.started`, `intent.captured`, challenge attachment, and every state
transition through `store.mutate()`. `attachChallenge()` is one-way: an exact replay
is idempotent and a different challenge for the same intent throws
`CHALLENGE_CHANGED`. The bounded raw `PaymentRequired` exists only in active process
memory. Persist `challengeHash` over a closed `challenge_projection_json` containing
only `x402Version`, hashed resource URL, fixed public route description/MIME metadata,
and every ordered accepted financial/protocol field; omit seller error text, full URL,
extensions, and all other free-form values. Approval retry performs a fresh probe,
rebuilds the projection, and must reproduce its exact hash before it can reuse the
intent.

Add a file-backed reopen test: call `openOrResumeSession()`, close the store, reopen,
and call it with the same binding. Assert the same ID, one row, one `session.started`
event, and unchanged budget exposure. Each changed binding field must not resume the
old session. Scan the reopened SQLite rows and event JSON for
`RAW_PROMPT_SENTINEL`; it must be absent while the request/body hashes remain.

- [ ] **Step 4: Prove capture precedes any transport call**

Add a test with a transport spy whose `probe()` reads the SQLite row before returning.
The test invokes a minimal coordinator callback and asserts the row already exists and
has state `captured`. This regression guard remains when the callback moves into
`wallet-kernel.mjs` in Task 10.

- [ ] **Step 5: Run focused and canonical tests**

```bash
node --test spikes/pi-wielder/tests/kernel-canonical.test.mjs \
  spikes/pi-wielder/tests/kernel-agent-enrollment.test.mjs \
  spikes/pi-wielder/tests/kernel-intent.test.mjs
```

Expected: all tests pass; the persisted-row assertion contains hashes but no raw body.

- [ ] **Step 6: Commit the Spend Intent boundary**

```bash
git add spikes/pi-wielder/src/kernel/agent-enrollment.mjs \
  spikes/pi-wielder/src/kernel/intent-builder.mjs \
  spikes/pi-wielder/tests/kernel-agent-enrollment.test.mjs \
  spikes/pi-wielder/tests/kernel-intent.test.mjs
git commit -m "feat: persist exact agent spend intents"
```

### Task 5: Implement durable conserved budgets and unresolved holds

**Files:**

- Create: `spikes/pi-wielder/src/kernel/budget-ledger.mjs`
- Create: `spikes/pi-wielder/tests/kernel-budget.test.mjs`
- Create: `spikes/pi-wielder/tests/fixtures/budget-writer.mjs`

- [ ] **Step 1: Write the failing budget conservation matrix**

Create `kernel-budget.test.mjs` using canonical atomic strings. For one seller/session
limit of `1000000`, full-session limit of `2000000`, and rolling-24-hour limit of
`5000000`, assert this sequence exactly:

```js
const ledger = createBudgetLedger({ store, now: fixedNow });

assert.deepEqual(ledger.snapshot({ sessionId, sellerOrigin }), {
  sellerSessionExposureAtomic: '0',
  sessionExposureAtomic: '0',
  rolling24hExposureAtomic: '0',
  walletBlocked: false,
});

ledger.reserve({ intentId: firstIntent, amountAtomic: '250000' });
assert.equal(ledger.snapshot({ sessionId, sellerOrigin }).sessionExposureAtomic, '250000');
seedRetryingPaymentAttempt({
  intentId: firstIntent,
  amountAtomic: '250000',
  paymentHash: `sha256:${'cd'.repeat(32)}`,
});
ledger.commit({
  intentId: firstIntent,
  settlementEvidence: Object.freeze({
    source: 'x402-payment-response',
    headerHash: `sha256:${'bc'.repeat(32)}`,
    success: true,
    transaction: `0x${'aa'.repeat(32)}`,
    network: 'eip155:84532',
    payer: walletAddress,
    amountAtomic: '250000',
    paymentHash: `sha256:${'cd'.repeat(32)}`,
  }),
});
assert.equal(ledger.snapshot({ sessionId, sellerOrigin }).rolling24hExposureAtomic, '250000');

ledger.reserve({ intentId: secondIntent, amountAtomic: '300000' });
ledger.release({ intentId: secondIntent, reasonCode: 'SIGNER_REJECTED' });
assert.equal(ledger.snapshot({ sessionId, sellerOrigin }).sessionExposureAtomic, '250000');

ledger.reserve({ intentId: thirdIntent, amountAtomic: '400000' });
ledger.holdUnresolved({ intentId: thirdIntent, reasonCode: 'PAID_RESPONSE_AMBIGUOUS' });
assert.equal(ledger.snapshot({ sessionId, sellerOrigin }).walletBlocked, true);
assert.throws(() => ledger.reserve({ intentId: fourthIntent, amountAtomic: '1' }),
  (error) => error.code === 'WALLET_UNRESOLVED');
```

Seed a committed payment with `execution_outcomes.state = 'failed'` plus an open
`refund_pending` execution resolution, and another with execution `unknown` plus
`reconciliation_required`. In each case `snapshot().walletBlocked` is true and a new
reservation fails `WALLET_RESOLUTION_REQUIRED`. Marking only the execution row or only
the refund row resolved is insufficient; the authoritative resolution transition must
close every linked blocker atomically before `walletBlocked` becomes false.

The invariant after every mutation is:

```text
reserved_atomic + committed_atomic + released_atomic + unresolved_atomic
  = PolicyDecision.amount_ceiling_atomic
```

x402 v2 `exact` uses one full disposition at a time. `reserve()` writes the amount to
`reserved_atomic`; `commit()`, `release()`, or `holdUnresolved()` atomically moves the
full amount into the corresponding column and zeros the prior column. Trusted payment
reconciliation moves the full amount from `unresolved_atomic` to either
`committed_atomic` or `released_atomic`; a confirmed full refund moves it from
`committed_atomic` to `released_atomic`.

Also assert:

- the same intent cannot reserve twice;
- a release is legal before a signing claim or through the exact typed pre-sign
  rejection exception defined below, and can never release an unresolved hold;
- committing the same exact transaction is idempotent, while reusing it for another
  intent is rejected;
- `commit()` rejects a missing/non-`retrying` PaymentAttempt, an amount or binding
  mismatch, or a transaction ID not atomically written to that exact attempt;
- `recordConfirmedRefund()` moves one full committed amount to released exactly once
  only when given a persisted matching reconciliation evidence ID and unique refund
  transaction ID;
- seller/session, whole-session, and rolling-24-hour limits reject at one atomic unit
  over their ceiling;
- the rolling window includes committed timestamps `> now - 24h` and excludes an
  entry exactly at the lower boundary;
- reopening the file-backed database reconstructs identical snapshots;
- no database monetary column is returned as a JavaScript `number`.

- [ ] **Step 2: Run the test and observe the missing module**

```bash
node --test spikes/pi-wielder/tests/kernel-budget.test.mjs
```

Expected: FAIL with `ERR_MODULE_NOT_FOUND` for `src/kernel/budget-ledger.mjs`.

- [ ] **Step 3: Implement transaction-local snapshots and mutations**

Create `budget-ledger.mjs` with this API:

```text
export function createBudgetLedger({ store, now }) {
  return Object.freeze({
    snapshot({ sessionId, sellerOrigin, at }),
    snapshotInTransaction(token, { sessionId, sellerOrigin, at }),
    reserve({ intentId, amountAtomic }),
    reserveInTransaction(token, { intentId, amountAtomic }),
    commit({ intentId, settlementEvidence }),
    commitInTransaction(token, { intentId, settlementEvidence }),
    release({ intentId, reasonCode }),
    releaseInTransaction(token, { intentId, reasonCode, preSignRejection }),
    holdUnresolved({ intentId, reasonCode }),
    holdUnresolvedInTransaction(token, { intentId, reasonCode }),
    resolvePayment({ intentId, outcome, evidenceId }),
    resolvePaymentInTransaction(token, { intentId, outcome, evidenceId }),
    recordConfirmedRefund({ intentId, evidenceId, refundTransactionId }),
    recordConfirmedRefundInTransaction(token,
      { intentId, evidenceId, refundTransactionId }),
  });
}
```

Each standalone mutation starts `BEGIN IMMEDIATE`; its matching `*InTransaction`
method requires Task 2's live opaque token and starts no transaction. Both paths call
the same internal implementation, reload every relevant row, recompute all
exposure with `BigInt`, check invariants, update the reservation, and append its
event before commit. Never accept a caller-provided budget snapshot for a mutation;
the pure Policy Engine receives a snapshot, but `reserve()` joins the Spend Intent to
its persisted PolicyDecision and immutable PolicyVersion, parses the canonical policy,
requires `amountAtomic === PolicyDecision.amount_ceiling_atomic`, and reloads those
seller/session/rolling limits inside the authoritative transaction. No caller can
supply or widen a ceiling. This closes both substitution and time-of-check/time-of-use
gaps.

`commit()` requires the exact persisted PaymentAttempt in `retrying` state and a closed
sanitized `settlementEvidence` returned by Task 9's pure classifier. In one transaction
it validates success, network, payer, canonical optional amount, payment/header hash,
and every available binding against the attempt; derives `transaction_id` only from
that validated evidence; writes the unique transaction plus canonical settlement;
moves the reservation from reserved to committed, and appends the event. Trusted
reconciliation alone moves an unresolved hold through `resolvePayment()`. It never accepts a detached
transaction ID or caller-authored settlement as budget evidence; idempotency is an
exact lookup of the already
committed attempt, and the database uniqueness constraint rejects reuse by any other
intent.

Use these exposure formulas:

```js
const exposure = (row) => BigInt(row.reserved_atomic)
  + BigInt(row.committed_atomic)
  + BigInt(row.unresolved_atomic);
const sellerSessionExposure = sum(rowsForSessionAndSeller.map(exposure));
const sessionExposure = sum(rowsForSession.map(exposure));
const rolling24hExposure = sum(rowsCommittedAfterWindowStart.map(
  (row) => BigInt(row.committed_atomic),
)) + sum(allActiveOrUnresolvedRowsForWallet.map(
  (row) => BigInt(row.reserved_atomic) + BigInt(row.unresolved_atomic),
));
```

Every active or unresolved hold counts against rolling capacity regardless of age,
while finalized committed spend ages out at the exact 24-hour boundary.

`snapshot().walletBlocked` is a transaction-local wallet query over unresolved
reservations, non-resolved `execution_resolutions`, and pending/unresolved refunds—not
merely the current session. Any such row blocks every new reservation until trusted
reconciliation closes it. `resolvePayment()` accepts only `settled` or `rejected` and
requires a pre-existing reconciliation evidence ID; it cannot be called by an agent
surface. For `settled`, its same `BEGIN IMMEDIATE` moves the monetary row to committed,
persists the canonical transaction, creates execution `unknown` plus
`reconciliation_required`, and writes the blocking `buyer_outcomes` revision. For
`rejected`, only exact post-expiry unused-authorization proof releases the hold and
writes `payment_rejected`. A candidate-level rejected transaction never calls
`resolvePayment()`. `recordConfirmedRefund()` requires the same evidence gate, an already
committed exact payment, and a seller-side full-refund record; it never invokes a
wallet transfer.

Ordinary `release()` is legal from `reserved` before a signing claim. The one additional
legal release is an exact `signing -> rejected/released` transition inside the Kernel's
outer transaction after catching a real Task 8 `WalletSigningError` with code
`WALLET_PRE_SIGN_REJECTED` and `signatureMayExist === false`. Pass that typed object as
`preSignRejection`; independently require the PaymentAttempt is still `signing` with
null payload/header/hash/signed timestamp. Every other signing-state error, missing or
caller-shaped proof, and any may-exist state goes to `holdUnresolvedInTransaction()`.

- [ ] **Step 4: Add a two-process oversubscription fixture**

Create `tests/fixtures/budget-writer.mjs` that opens the database and calls
`ledger.reserve()` for the intent ID and amount from `process.argv`, then writes either
`reserved` or `LIMIT_EXCEEDED` to stdout. In `kernel-budget.test.mjs`, seed two intents
of `600000` against a `1000000` seller/session ceiling, launch two fixture processes,
and assert the sorted results are:

```js
['LIMIT_EXCEEDED', 'reserved']
```

Reopen the database and assert exactly one reservation exists, its amount is
`600000`, and `store.verifyEventChain()` is true.

- [ ] **Step 5: Run budget, store, and legacy policy tests**

```bash
node --test spikes/pi-wielder/tests/kernel-store.test.mjs \
  spikes/pi-wielder/tests/kernel-budget.test.mjs
npm run test:policy --prefix spikes/pi-wielder
```

Expected: the process race conserves the ceiling and all legacy policy tests pass.

- [ ] **Step 6: Commit durable budgets**

```bash
git add spikes/pi-wielder/src/kernel/budget-ledger.mjs \
  spikes/pi-wielder/tests/kernel-budget.test.mjs \
  spikes/pi-wielder/tests/fixtures/budget-writer.mjs
git commit -m "feat: enforce durable agent spend budgets"
```

### Task 6: Add exact approvals and one-time AuthorizedPermits

**Files:**

- Create: `spikes/pi-wielder/src/kernel/approval-queue.mjs`
- Create: `spikes/pi-wielder/src/kernel/authorized-permit.mjs`
- Create: `spikes/pi-wielder/tests/kernel-approvals.test.mjs`
- Create: `spikes/pi-wielder/tests/kernel-permit.test.mjs`

- [ ] **Step 1: Write the failing durable approval tests**

Create an approval for an existing `approval_required` decision and assert its public
record is bound to all of these exact fields:

```js
const binding = Object.freeze({
  intentId,
  intentHash,
  challengeHash,
  quoteId,
  amountCeilingAtomic: '250000',
  walletAddress: '0x1000000000000000000000000000000000000000',
  policyVersionId,
  acceptedIndex: 0,
  expiresAt: '2026-07-31T12:05:00.000Z',
});
```

Assert `approve({ approvalId, expectedIntentHash: intentHash,
operatorIdHash: 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' })` persists only
the stable operator hash and time,
survives database reopen. In a caller-owned transaction that also inserts the exact
matching reservation fixture, `consumeForInTransaction(token, binding)` changes
`approved` to `consumed` exactly once; rolling back either write preserves both prior
states. For every individual changed binding field, assert
`APPROVAL_BINDING_MISMATCH` and no row/event mutation. Assert denial, expiry, an
already-consumed approval, and an unknown approval never return authorization.
An unconsumed approved row remains usable only before its immutable `expiresAt`;
inside Task 10's caller-owned aggregate, `consumeForInTransaction()` at or after
expiry delegates to the scoped expiry transition and returns no authorization while
the caller terminalizes the intent and writes its BuyerOutcome in that same token.

At `maxPendingApprovals`, assert a new request is rejected atomically with
`APPROVAL_CAPACITY`; after one Task 10 aggregate denial or expiry, exactly one slot becomes
available. A pending approval must be discoverable only via
`findRetryable({ sessionId, intentHash })`, never from an agent-provided approval ID.

- [ ] **Step 2: Write the failing capability-forgery tests**

In `kernel-permit.test.mjs`:

```js
const authority = createPermitAuthority();
const intentHash = sha256(canonicalJson({ fixture: 'intent-1' }));
const challengeHash = sha256(canonicalJson({ fixture: 'challenge-1' }));
const quoteId = sha256(canonicalJson({ challengeHash, acceptedIndex: 0 }));
const binding = Object.freeze({
  intentId: 'intent-1',
  intentHash,
  challengeHash,
  quoteId,
  acceptedIndex: 0,
  network: 'eip155:84532',
  asset: '0x036cbd53842c5426634e7929541ec2318f3dcf7e',
  walletAddress: '0x1000000000000000000000000000000000000000',
  payTo: '0x2000000000000000000000000000000000000000',
  amountAtomic: '50000',
  validAfter: '0',
  validBefore: '1785502860',
  nonce: `0x${'01'.repeat(32)}`,
});
const permit = authority.issue(binding);

assert.equal(Object.isFrozen(permit), true);
assert.deepEqual(Object.keys(permit), ['kind', 'intentId']);
assert.deepEqual(authority.verifyAndConsume(permit), binding);
assert.throws(() => authority.verifyAndConsume(permit), /already consumed/);
assert.throws(() => authority.verifyAndConsume(Object.freeze({ ...permit })), /forged/);
assert.throws(() => authority.verifyAndConsume({ kind: 'AuthorizedPermit', intentId: 'intent-1' }),
  /forged/);
```

Also assert JSON serialization, structured cloning, and a fresh process cannot create a
valid permit. No permit is written to SQLite, logs, receipts, or HTTP.

- [ ] **Step 3: Run both focused tests and observe missing modules**

```bash
node --test spikes/pi-wielder/tests/kernel-approvals.test.mjs \
  spikes/pi-wielder/tests/kernel-permit.test.mjs
```

Expected: FAIL with `ERR_MODULE_NOT_FOUND` for the two new modules.

- [ ] **Step 4: Implement the durable approval queue**

Create `approval-queue.mjs`:

```text
export function createApprovalQueue({ store, idFactory, now }) {
  return Object.freeze({
    request(binding),
    requestInTransaction(token, binding),
    get(approvalId),
    list({ state, limit }),
    approve({ approvalId, expectedIntentHash, operatorIdHash }),
    listDue({ at, limit }),
    findRetryable({ sessionId, intentHash }),
    consumeForInTransaction(token, binding),
    denyForIntentInTransaction(token, {
      approvalId, intentId, expectedIntentHash, operatorIdHash, reasonCode,
    }),
    expireForIntentInTransaction(token, {
      approvalId, intentId, expectedIntentHash, at,
    }),
    cancelForIntentInTransaction(token, { intentId, reasonCode }),
  });
}
```

Every transition uses a conditional `UPDATE ... WHERE decision = ?` inside
`BEGIN IMMEDIATE`, checks exactly one changed row, and appends the matching event. An
exact duplicate request returns the existing record; a different binding for the same
intent fails. `listDue()` is read-only, compares canonical timestamps against its
explicit `at`, and returns bounded `(approvalId, intentId, intentHash)` candidates in
stable order; it never mutates a row. `request(binding)` derives `expiresAt` as the minimum of the
remaining local challenge lifetime and policy approval TTL; it never trusts an expiry
supplied by an operator or Pi.
`requestInTransaction(token, binding)` is the scoped creation form: it validates the
live opaque token, starts no transaction, reloads the exact PolicyDecision and intent
binding, derives the same bounded expiry, and invokes the same internal implementation
as `request()`. The standalone method owns one transaction only by wrapping this
scoped implementation. Task 10 never calls the standalone method from an aggregate.
Approve and the scoped denial additionally match `expectedIntentHash` in the same
conditional transaction, so the operator's displayed confirmation is not a
pre-transaction check.
`consumeForInTransaction()` is the only approval-consumption path used by the Wallet
Kernel's reserve/signing aggregate. `denyForIntentInTransaction()` moves only `pending`
to `denied`; `expireForIntentInTransaction()` moves only a due `pending` or unconsumed
`approved` row to `expired`. `cancelForIntentInTransaction()` moves only `pending` or
`approved` to `cancelled`, with exact reason `POLICY_SUPERSEDED`, `SESSION_CLOSED`, or
`APPROVAL_CHALLENGE_CHANGED`; the changed-challenge path therefore has the explicit
legal approval state `cancelled`. Each scoped method checks the exact intent binding,
appends its event through the live token, starts no transaction, and never changes a
consumed approval. No public repository method can deny or expire an approval in a
standalone transaction: Task 10 owns those aggregate mutations so approval state,
terminal SpendIntent, and BuyerOutcome cannot split across a crash.

- [ ] **Step 5: Implement the unforgeable in-process authority**

Create `authorized-permit.mjs`:

```js
export function deriveAuthorizationWindow({
  nowMs, challengeReceivedAtMs, challengeMaxAgeMs,
  approvalExpiresAt, maxTimeoutSeconds, randomBytes,
}) {
  // Return one deeply frozen { nonce, validAfter, validBefore } binding.
}

export function createPermitAuthority() {
  const live = new WeakMap();
  const consumed = new WeakSet();
  return Object.freeze({
    issue(binding) {
      const permit = Object.freeze({ kind: 'AuthorizedPermit', intentId: binding.intentId });
      live.set(permit, Object.freeze(structuredClone(binding)));
      return permit;
    },
    verifyAndConsume(permit) {
      if (consumed.has(permit)) throw new Error('AuthorizedPermit already consumed');
      const binding = live.get(permit);
      if (!binding) throw new Error('AuthorizedPermit is forged');
      live.delete(permit);
      consumed.add(permit);
      return binding;
    },
  });
}
```

Only `wallet-kernel.mjs` receives `issue`; wallet adapters receive only the bound
`verifyAndConsume` function. A permit is issued after a fresh policy/approval/budget
check and consumed immediately before the one signer invocation. The signing binding
extends the approval/policy binding with exact `requestUrl`, `scheme`, `network`,
`asset`, `walletAddress` (payer), `payTo`, `amountAtomic`, `nonce`, `validAfter`, and
`validBefore`. `deriveAuthorizationWindow()` is pure apart from its injected
`randomBytes`: capture `nowMs` once, set `validAfter` exactly to `'0'`, require exactly
32 bytes from one injected cryptographic-randomness call, and calculate:

```js
const nowSeconds = Math.floor(nowMs / 1000);
const challengeDeadlineSeconds = Math.floor(
  (challengeReceivedAtMs + challengeMaxAgeMs) / 1000,
);
const approvalDeadlineSeconds = approvalExpiresAt === null
  ? challengeDeadlineSeconds
  : Math.floor(Date.parse(approvalExpiresAt) / 1000);
const validBefore = String(Math.min(
  nowSeconds + maxTimeoutSeconds,
  challengeDeadlineSeconds,
  approvalDeadlineSeconds,
));
```

Require `validBefore > nowSeconds`, canonical decimal seconds, and an integer
`maxTimeoutSeconds` in the already validated bounded protocol range. The no-approval
golden fixture has a 60-second challenge/protocol window, so its value remains fixed
now plus 60 seconds. The adapter may sign only the EIP-3009 typed data constructed from
that binding. In Task 6, inject the clock/randomness and test each of the three
deadlines as the minimum, sub-second truncation, an exhausted window, wrong-length
randomness, and exactly one randomness call. Task 10 owns persistence and the database
nonce-collision test.

- [ ] **Step 6: Run focused tests and restart coverage**

```bash
node --test spikes/pi-wielder/tests/kernel-approvals.test.mjs \
  spikes/pi-wielder/tests/kernel-permit.test.mjs
```

Expected: approval persistence and every permit-forgery case pass.

- [ ] **Step 7: Commit approval authorization**

```bash
git add spikes/pi-wielder/src/kernel/approval-queue.mjs \
  spikes/pi-wielder/src/kernel/authorized-permit.mjs \
  spikes/pi-wielder/tests/kernel-approvals.test.mjs \
  spikes/pi-wielder/tests/kernel-permit.test.mjs
git commit -m "feat: add exact one-time spend approvals"
```

### Task 7: Extract receipt crypto and sign every terminal buyer outcome

**Files:**

- Create: `spikes/pi-wielder/src/kernel/authority-mutation-coordinator.mjs`
- Create: `spikes/pi-wielder/src/kernel/receipt-signing.mjs`
- Create: `spikes/pi-wielder/src/kernel/signed-receipts.mjs`
- Create: `spikes/pi-wielder/tests/kernel-authority-coordinator.test.mjs`
- Create: `spikes/pi-wielder/tests/kernel-receipts.test.mjs`
- Modify: `spikes/pi-wielder/src/invocation-journal.mjs:256-365`

- [ ] **Step 1: Freeze the existing seller-journal receipt behavior**

Run before editing:

```bash
npm run test:journal --prefix spikes/pi-wielder
```

Expected: all 29 invocation-journal tests pass. Save this count in the commit message
notes; the extraction may not alter serialized seller events, receipt hashes, key
format, or schema-v1 terminal replay behavior.

- [ ] **Step 2: Write failing Kernel receipt tests**

Create `kernel-receipts.test.mjs` with a temporary owner-only Ed25519 key and this
closed receipt projection:

```js
const receiptIntentHash = sha256(canonicalJson({ fixture: 'intent-1' }));
const responseHash = sha256(Buffer.from('{"ok":true}', 'utf8'));
const receipt = {
  schemaVersion: 1,
  receiptId: 'receipt-1',
  revision: 1,
  issuedAt: '2026-07-31T12:00:01.000Z',
  intent: {
    id: 'intent-1',
    requestId: 'request-1',
    intentHash: receiptIntentHash,
    sessionId: 'session-1',
    sellerOrigin: 'https://seller.example',
    resourcePath: '/paid/infer',
    purposeLabel: 'skill.invoke',
  },
  outcome: { status: 'completed', reasonCode: 'PAYMENT_SETTLED' },
  policy: { versionId: 'policy-1', decision: 'allow', reasonCode: 'WITHIN_AUTO_LIMIT' },
  approval: { state: 'not_required', operatorIdHash: null },
  payment: {
    state: 'settled',
    amountAtomic: '50000',
    network: 'eip155:84532',
    asset: '0x036cbd53842c5426634e7929541ec2318f3dcf7e',
    payTo: '0x2000000000000000000000000000000000000000',
    transactionId: `0x${'ab'.repeat(32)}`,
  },
  execution: { state: 'succeeded', httpStatus: 200, responseHash },
  budget: { disposition: 'committed', amountAtomic: '50000' },
  reconciliation: null,
  refund: null,
  supersedesReceiptHash: null,
};
```

Assert successful verification in a fresh signer/verifier instance using only the
public key. Assert field mutation, signature mutation, wrong key, unknown field, and
non-canonical atomic amount fail verification.

Build terminal fixtures for all of these exact outcomes and assert each receives one
receipt:

```text
ordinary non-402 success
ordinary non-402 HTTP failure
unpaid transport timeout/connection failure
malformed or oversized payment challenge denial
expired payment challenge denial
policy denied
approval denied
approval expired
approval challenge changed before signing
policy transition cancels unsigned work -> payment_denied / POLICY_SUPERSEDED
guarded session close cancels unsigned work -> payment_denied / SESSION_CLOSED
unsigned signing failure with released reservation
signed payment unresolved with held reservation
trusted post-expiry unused-authorization rejection with released reservation
payment settled and execution succeeded
payment settled and execution failed
payment settled and execution unknown
refund unresolved
refund confirmed
trusted reconciliation of payment, execution, or refund
```

Every fixture first writes exactly one closed `buyer_outcomes` row. Initial terminal
facts use revision `1`; each trusted reconciliation or refund fact increments that
row and the receipt revision together without deleting history from events/receipts.
The row is the sole source for receipt `outcome.status` and `outcome.reasonCode`.
Reason codes are bounded stable uppercase tokens, not seller/provider text.
The approval projection state is closed to `not_required`, `pending`, `approved`,
`denied`, `expired`, `cancelled`, or `consumed`; the two guarded-cancellation fixtures
project `cancelled` and their exact reason code.

For all three ordinary/no-payment outcomes, use one closed projection: `policy: null`,
`approval: { state: 'not_required', operatorIdHash: null }`,
`payment: { state: 'none' }`, and `budget: null`. Execution is `succeeded` for a 2xx
ordinary response, `failed` for a received 4xx/5xx response, and `unknown` for a
pre-response transport failure; unavailable fields are explicit `null`, never omitted.
Approved/denied receipts contain only `operatorIdHash`, computed by the authenticated
operator service, and never a raw operator identifier.

For malformed, oversized, or expired pre-policy challenges, use the exact closed
projection `policy: null`, `approval: { state: 'not_required', operatorIdHash: null }`,
`payment: { state: 'none' }`, `budget: null`, and
`execution: { state: 'none', httpStatus: null, responseHash: null }`, plus only the
matching authoritative `outcome: { status: 'payment_denied', reasonCode }` row. Never
infer the reason from generic event JSON, and never place rejected header/body bytes or seller error
text in the receipt.

Assert the projection contains no raw body, prompt, response body, operator token,
CDP credential, payment signature header, payment payload, stack, or provider exception.
Refund and reconciliation receipts use revision `n + 1` and point
`supersedesReceiptHash` to revision `n`.

In `kernel-authority-coordinator.test.mjs`, queue labeled synchronous callbacks in
call order and assert their entry/exit trace is exact FIFO even when an earlier callback
throws. Close the injected admission gate while two callbacks are queued and prove
each rechecks only when it reaches the head and performs zero callback writes. A
callback that returns a Promise/thenable is an invariant violation: synchronously call
the injected fail-stop callback with `AUTHORITY_COORDINATOR_ASYNC_CALLBACK`, release
the slot, and ensure all followers fail the now-closed gate. Enqueue another mutation
from a terminal callback's injected post-domain/pre-receipt fault hook without awaiting
it; prove the follower does not enter until the terminal callback either commits its
receipt or synchronously closes admission. Also assert the public object is frozen and
exposes only `runExclusive(operation)`—no raw acquire, release, queue, or gate setter.

- [ ] **Step 3: Extract generic signing without changing exports**

Move the existing generic implementations of these functions to
`src/kernel/receipt-signing.mjs`:

```js
export { canonicalJson, receiptKeyId, createReceiptSigner,
  loadOrCreateReceiptSigner, verifySignedReceipt };
```

In `invocation-journal.mjs`, import them and re-export the same five names so every
current caller remains source-compatible. Route key-file creation through
`loadOrInitializePrivateFile()` and retain the existing Ed25519 key encoding. Existing
empty or malformed keys fail closed; they are never silently replaced.

`loadOrCreateReceiptSigner()` supplies one PKCS#8 Ed25519 private-key PEM to the atomic
initializer. Its validator parses exactly one key with `crypto.createPrivateKey()`,
requires `asymmetricKeyType === 'ed25519'`, rejects trailing non-whitespace or malformed
PEM, and derives the public key/key ID. It never trims, repairs, or replaces an invalid
existing key. Reopen and two-process-race tests prove both callers derive the same key
ID and no initialization temp file remains.

- [ ] **Step 4: Implement post-commit terminal receipt issuance**

Create `authority-mutation-coordinator.mjs` with this exact surface:

```text
export function createAuthorityMutationCoordinator({
  assertAdmissionOpen, markAuthorityUnhealthy,
}) -> Object.freeze({
  runExclusive(operation) -> Promise<result>,
})
```

`runExclusive()` accepts exactly one function and queues calls in invocation order.
When a call reaches the head, it synchronously invokes `assertAdmissionOpen()` before
the operation; a closed gate rejects without invoking it. The operation itself must
finish synchronously and may contain one or more synchronous SQLite transactions plus
receipt projection/signing, but no `await`, fetch, timer, callback escape, listener
work, or returned thenable. The coordinator automatically releases the slot on return
or throw and advances exactly one follower. If the callback returns any thenable, call
`markAuthorityUnhealthy('AUTHORITY_COORDINATOR_ASYNC_CALLBACK')` synchronously before
release and reject the call. A callback may enqueue a follower but may not await it;
that follower remains FIFO-blocked until the current callback releases. The module
owns no database, resolver, listener, or public acquire/release primitive.

Construct one instance per live authority process only in Task 14's composition root.
The same object identity and same synchronous fail-stop callback are injected into the
Wallet Kernel and Reconciler; live operator mutation routes call only those facades.
Startup recovery and audited offline bootstrap instead run under Task 2's exclusive
process-lifetime authority lock before live admission and never create a competing
coordinator. No repository, adapter, or route may construct a private instance.

Create `signed-receipts.mjs`:

```text
export function createSignedReceiptRepository({ store, signer, idFactory, now }) {
  return Object.freeze({
    issueForTerminal({ intentId }),
    issueRevisionForTerminal({ intentId, supersedesReceiptHash }),
    issueMissingTerminalReceipts(),
    assertParity(),
    assertParityInTransaction(token),
    latest(intentId),
    list({ sessionId, limit }),
    verify(record),
  });
}
```

The authoritative terminal domain transition commits its required `buyer_outcomes`
row and event first. Then read that durable state, derive the closed projection, sign it, and insert the receipt plus
`receipt.issued` event in a second transaction. Public output remains withheld until
the receipt commit succeeds. If the process crashes or signing fails between those
transactions, the terminal domain fact remains authoritative and startup recovery
calls `issueMissingTerminalReceipts()` before serving traffic. That repair is
idempotent and can only project an existing buyer-outcome revision; it cannot infer a
reason from events or alter payment, execution, refund, reconciliation, approval, or
budget records. Enforce `signed_receipts.revision === buyer_outcomes.revision`, one
revision sequence per intent, and an exact predecessor receipt hash.

Receipt parity is a global authority invariant, not merely a startup cleanup. Before
any transaction may insert or increment any `buyer_outcomes` row, it calls
`assertParityInTransaction(token)` and requires every existing outcome's current
revision to equal its latest signed receipt revision. In addition, every mutating
agent/operator entrypoint—including capture, challenge, approval, reservation,
signing claim, reconciliation-candidate persistence, policy/session mutation, and
revocation—runs through one in-process FIFO authority-mutation coordinator and
rechecks the admission gate only after acquiring it. A terminal operation holds that
exclusive lease continuously across its domain transaction and receipt-signing/insert
transaction; it performs no network call while holding it. If receipt creation fails
after a domain commit, the Kernel synchronously closes its admission gate with
`RECEIPT_PARITY_REQUIRED` before returning the error, rejects every subsequent agent
or operator mutation, and asks composition to stop both listeners. A mutation already
queued behind the terminal lease rechecks the now-closed gate and performs zero writes.
It may expose no
success and may not advance that or any other BuyerOutcome. An exclusive authority
recovery phase—daemon startup or Task 13's audited offline bootstrap preflight—is the
only repair path: it issues exactly the missing current revision, verifies global
parity, and only then opens listeners or permits the requested bootstrap write. Because revision `n + 1` cannot commit while
revision `n` is missing, recovery never has to infer an overwritten prior outcome from
events.

Add a fault test immediately after the terminal commit and before signing. Reopen the
database, run recovery, assert exactly one valid receipt appears, and assert no
monetary row or pre-existing event is replayed. Also pause an in-process signing and
receipt-insert failure after its domain commit, concurrently submit capture, challenge,
reservation, approval, reconciliation, session, and revocation mutations, then release
the failure: assert none passes the held lease, the admission gate closes before the
terminal request returns, every queued mutation fails without a write, both listeners begin
shutdown, and reopen repairs the exact missing revision before serving.

- [ ] **Step 5: Run Kernel and seller receipt suites**

```bash
node --test spikes/pi-wielder/tests/kernel-authority-coordinator.test.mjs \
  spikes/pi-wielder/tests/kernel-receipts.test.mjs
npm run test:journal --prefix spikes/pi-wielder
```

Expected: all Kernel receipt cases pass and the legacy 29-test journal suite remains
byte-compatible.

- [ ] **Step 6: Commit generic and buyer receipts**

```bash
git add spikes/pi-wielder/src/kernel/receipt-signing.mjs \
  spikes/pi-wielder/src/kernel/authority-mutation-coordinator.mjs \
  spikes/pi-wielder/src/kernel/signed-receipts.mjs \
  spikes/pi-wielder/src/invocation-journal.mjs \
  spikes/pi-wielder/tests/kernel-authority-coordinator.test.mjs \
  spikes/pi-wielder/tests/kernel-receipts.test.mjs
git commit -m "feat: sign terminal wallet kernel receipts"
```

### Task 8: Define the Wallet Adapter seam and deterministic offline adapter

**Files:**

- Create: `spikes/pi-wielder/src/adapters/wallet-adapter-contract.mjs`
- Create: `spikes/pi-wielder/src/adapters/eip3009-exact.mjs`
- Create: `spikes/pi-wielder/src/adapters/deterministic-wallet-adapter.mjs`
- Create: `spikes/pi-wielder/tests/wallet-adapter-contract.test.mjs`
- Create: `spikes/pi-wielder/tests/eip3009-exact.test.mjs`
- Create: `spikes/pi-wielder/tests/wallet-adapter-deterministic.test.mjs`

- [ ] **Step 1: Write the failing adapter contract tests**

In `wallet-adapter-contract.test.mjs`, define one reusable suite:

```js
export function walletAdapterContract(name, factory) {
  test(`${name}: exposes identity and exact signing only`, async () => {
    const fixture = factory();
    assert.deepEqual(Object.keys(fixture.adapter).sort(), ['signX402Exact', 'walletIdentity']);
    assert.deepEqual(await fixture.adapter.walletIdentity(), {
      provider: fixture.provider,
      walletId: fixture.walletId,
      address: fixture.address,
      network: 'eip155:84532',
    });
  });

  test(`${name}: rejects forged, consumed, and mismatched permits before signing`, async () => {
    const fixture = factory();
    await assert.rejects(() => fixture.adapter.signX402Exact(
      { kind: 'AuthorizedPermit', intentId: 'intent-1' },
      fixture.paymentRequired,
    ), /forged/);
    assert.equal(fixture.signCalls(), 0);
  });

  test(`${name}: never returns or serializes key material`, async () => {
    const fixture = factory();
    const result = await fixture.signAuthorized();
    assert.deepEqual(Object.keys(result), ['paymentPayload']);
    assert.doesNotMatch(JSON.stringify({ identity: await fixture.adapter.walletIdentity(), result }),
      /private|secret|seed|mnemonic|api.key/i);
  });
}
```

The shared suite must additionally pass a genuine permit with one changed challenge,
accepted index, amount, payee, network, asset, wallet, expiry, or nonce field and assert
the signer is never called. Separately mutate each returned resource, accepted, and
authorization field and assert post-sign validation rejects it before persistence or
retry. A successful exact signing consumes the permit once; a second call with the
same object fails before signing.

Define one typed error boundary in `wallet-adapter-contract.mjs`:

```js
export class WalletSigningError extends KernelError {
  constructor(code, message, { signatureMayExist }) {
    super(code, message);
    this.signatureMayExist = signatureMayExist;
  }
}

export function createDeadlineRunner({
  setTimeoutImpl = setTimeout,
  clearTimeoutImpl = clearTimeout,
} = {}) {}

export async function executeAuthorizedSigning({
  prepare,
  invokeSigner,
  finalize,
  runWithDeadline,
  preSignTimeoutMs,
  signerTimeoutMs,
}) {}
```

Permit/payment validation, account resolution, identity validation, and typed-data
construction all occur before the signer call; their typed failure is
`WALLET_PRE_SIGN_REJECTED` with `signatureMayExist: false`. Immediately before
invoking `signTypedData`, enter the may-exist zone. A synchronous throw, rejected or
timed-out promise, malformed returned signature, `assemble()` failure, or post-sign
payload mismatch becomes `WALLET_SIGNATURE_AMBIGUOUS` with
`signatureMayExist: true`. Do not attach or serialize the provider exception. The
shared suite asserts this taxonomy and that arbitrary untyped adapter errors are never
treated as proof that no signature exists.

`executeAuthorizedSigning()` is the sole two-zone implementation used by every
adapter. `createDeadlineRunner()` implements a one-shot `Promise.race`, clears its
timer on settlement, uses only stable timeout codes, and never retains the rejected
provider value. It calls `runWithDeadline({ phase, timeoutMs, operation })`, whose deadline is
armed before invoking the operation thunk. It wraps all `prepare()` errors/timeouts as
typed pre-sign rejection. It enters the may-exist zone before calling the
`invokeSigner()` thunk and wraps signer timeout plus every `finalize()` error as typed
ambiguity. Tests inject a fake clock/deadline and a never-settling promise, proving the
call cannot remain in `signing` indefinitely. The default composition uses bounded
5-second pre-sign and 15-second signer deadlines; a timeout never attempts cancellation
as proof that signing did not occur.

- [ ] **Step 2: Write the exact EIP-3009 builder and deterministic adapter tests**

Create `eip3009-exact.test.mjs` and `wallet-adapter-deterministic.test.mjs`. Use this
exact Kernel-issued signing binding. Test setup must first exercise the implemented
Task 3/4/6 path in an in-memory authority—apply the policy, capture the exact intent,
attach the `paymentRequired` fixture, evaluate it, and derive the authorization
window—then bind the returned hashes. Do not hand-author hashes that merely match the
SHA-256 regex:

```js
const fixtureAccount = privateKeyToAccount(
  keccak256(toBytes('wallet-kernel-eip3009-golden-test-only')),
);
const signingBinding = Object.freeze({
  intentId: 'intent-1',
  intentHash: persistedIntent.intentHash,
  requestUrl: 'https://seller.example/paid/infer',
  resourceDescription: 'offline fixture',
  resourceMimeType: 'application/json',
  challengeHash: policyDecision.challengeHash,
  quoteId: policyDecision.quoteId,
  acceptedIndex: 0,
  scheme: 'exact',
  network: 'eip155:84532',
  asset: '0x036cbd53842c5426634e7929541ec2318f3dcf7e',
  walletAddress: fixtureAccount.address,
  payTo: '0x2000000000000000000000000000000000000000',
  amountAtomic: '50000',
  nonce: authorizationWindow.nonce,
  validAfter: authorizationWindow.validAfter,
  validBefore: authorizationWindow.validBefore,
  policyVersionId: 'policy-1',
});
```

Assert the builder returns typed data with the pinned Base Sepolia USDC EIP-712 domain
`{ name: 'USDC', version: '2', chainId: 84532, verifyingContract:
BASE_SEPOLIA_USDC }`, public `authorizationTypes`, and every permit-bound
authorization field. These name/version constants come from the token contract's
testnet domain and are local authority, not seller-selected metadata. Its
`assemble(signature)` returns this protocol-shaped payload:

Pin this contract/domain tuple against Circle's Base Sepolia EIP-3009 quickstart
(`https://developers.circle.com/gateway/quickstarts/eco-gasless-deposits`) as well as
the version-pinned official x402 golden below; a later upstream change requires an
explicit dependency/policy migration, never runtime trust in challenge metadata.

```js
const exact = buildEip3009Exact({ binding: signingBinding, paymentRequired });
const fixtureSignature = await fixtureAccount.signTypedData(exact.typedData);
const paymentPayload = Object.freeze({
  x402Version: 2,
  resource: {
    url: 'https://seller.example/paid/infer',
    description: 'offline fixture',
    mimeType: 'application/json',
  },
  accepted: {
    scheme: 'exact',
    network: 'eip155:84532',
    asset: '0x036cbd53842c5426634e7929541ec2318f3dcf7e',
    amount: '50000',
    payTo: '0x2000000000000000000000000000000000000000',
    maxTimeoutSeconds: 60,
    extra: { name: 'USDC', version: '2' },
  },
  payload: {
    signature: fixtureSignature,
    authorization: {
      from: fixtureAccount.address,
      to: '0x2000000000000000000000000000000000000000',
      value: '50000',
      validAfter: '0',
      validBefore: '1785502860',
      nonce: `0x${'01'.repeat(32)}`,
    },
  },
});
assert.deepEqual(await exact.assemble(fixtureSignature), paymentPayload);
```

The test-only account is derived in memory from the public domain-separated label; no
literal private key or generated key file exists. The `resource` and full `accepted`
objects above are the exact official v2 shapes;
`maxTimeoutSeconds` and closed `extra` are never dropped. Reject any token
`name`/`version` other than exact `USDC`/`2`, a non-EIP-3009 transfer method, wrong chain,
malformed bytes32 nonce, invalid canonical validity, expiry beyond the approved
challenge, and any output mismatch before any signer call. `validatePaymentPayload()` must recover the
typed-data signer from the canonical signature and require it to equal
`binding.walletAddress`; length-only validation is forbidden. Inject a `signTypedData`
function that delegates to `fixtureAccount.signTypedData()` and counts calls. Assert the adapter passes the
shared contract suite,
performs zero network calls, deep-freezes its result, and constructs rather than
accepts every payment-payload field.

Add a golden compatibility test using `ExactEvmScheme` from
`@x402/evm/exact/client`. With `Date.now()` fixed to `1785502800000` and
`globalThis.crypto.getRandomValues()` fixed to 32 bytes of `0x01`, ask the official
scheme to build the exact same full accepted requirement through a recording
`signTypedData` stub that records the typed data and delegates signing to the same
fixture account. Its generated `validAfter` is `'0'`, `validBefore` is fixed-now
seconds plus `maxTimeoutSeconds`, and its nonce is the fixed 32 bytes. Assert its
recorded typed data equals `buildEip3009Exact(...).typedData` and its returned inner
payload equals `(await assemble(fixtureSignature)).payload`; also pass our full assembled payload
through the official v2 `PaymentPayload` schema/HTTP codec. Restore both globals in
`t.after()`. This prevents a self-authored buyer and seller fixture from agreeing on a
non-interoperable payload. Run the golden once with absent
`extra.assetTransferMethod` (the pinned official client defaults to EIP-3009) and once
with explicit `eip3009`; prove `permit2` is rejected before the signer stub is called.
Also mutate `extra.name` and `extra.version` independently and prove each challenge is
denied before permit creation or signer invocation.

- [ ] **Step 3: Run the tests and observe missing modules**

```bash
node --test spikes/pi-wielder/tests/wallet-adapter-contract.test.mjs \
  spikes/pi-wielder/tests/eip3009-exact.test.mjs \
  spikes/pi-wielder/tests/wallet-adapter-deterministic.test.mjs
```

Expected: FAIL with `ERR_MODULE_NOT_FOUND`.

- [ ] **Step 4: Implement contract validation and the offline adapter**

Create `wallet-adapter-contract.mjs`:

```js
export function validateWalletIdentity(identity) {
  // Enforce the exact provider, walletId, address, and eip155:84532 output shape.
}

export function assertPermitMatchesPayment(binding, paymentRequired, acceptedIndex) {
  // Recompute the canonical challenge hash and compare every signed field.
}

export async function validatePaymentPayload({ paymentPayload, binding, paymentRequired, typedData }) {
  // Enforce closed v2 equality and recover the exact permit-bound typed-data signer.
}
```

Create `eip3009-exact.mjs` using the public `authorizationTypes` export from
`@x402/evm` and `getAddress` from `viem`:

```js
export function buildEip3009Exact({ binding, paymentRequired }) {
  const accepted = paymentRequired.accepts[binding.acceptedIndex];
  const authorization = Object.freeze({
    from: binding.walletAddress,
    to: accepted.payTo,
    value: accepted.amount,
    validAfter: binding.validAfter,
    validBefore: binding.validBefore,
    nonce: binding.nonce,
  });
  const typedData = Object.freeze({
    domain: Object.freeze({
      name: BASE_SEPOLIA_USDC_EIP712_NAME,
      version: BASE_SEPOLIA_USDC_EIP712_VERSION,
      chainId: 84532,
      verifyingContract: getAddress(accepted.asset),
    }),
    types: authorizationTypes,
    primaryType: 'TransferWithAuthorization',
    message: Object.freeze({
      from: getAddress(authorization.from),
      to: getAddress(authorization.to),
      value: BigInt(authorization.value),
      validAfter: BigInt(authorization.validAfter),
      validBefore: BigInt(authorization.validBefore),
      nonce: authorization.nonce,
    }),
  });
  return Object.freeze({
    typedData,
    async assemble(signature) {
      return await validatePaymentPayload({
        paymentPayload: {
          x402Version: 2,
          resource: Object.freeze({
            url: binding.requestUrl,
            description: binding.resourceDescription,
            mimeType: binding.resourceMimeType,
          }),
          accepted: structuredClone(accepted),
          payload: { signature, authorization },
        },
        binding,
        paymentRequired,
        typedData,
      });
    },
  });
}
```

Validate the entire binding and challenge before construction. For this pilot the
accepted requirement is closed to exactly `scheme`, `network`, `asset`, `amount`,
`payTo`, `maxTimeoutSeconds`, and
`extra: { name, version, assetTransferMethod? }`; `name` and `version` must equal the
pinned `BASE_SEPOLIA_USDC_EIP712_NAME` and
`BASE_SEPOLIA_USDC_EIP712_VERSION`, and the optional transfer method must be
`eip3009`. Extension-bearing or unknown shapes are unsupported. The builder imports
the pinned domain constants and never copies seller-provided name/version into typed
data, even after equality validation. Require the
challenge resource URL, description, and
MIME type to exactly equal static operator-owned route metadata before copying those
three public constants into the payload. Never copy seller `error`, extensions, agent
input, or other seller free text into signed/persisted bytes. Deep-freeze cloned
outputs so neither the caller nor signer can mutate them. The adapter never accepts
arbitrary typed data from Pi or an operator.

Create `deterministic-wallet-adapter.mjs`:

```js
export function createDeterministicWalletAdapter({
  identity, verifyAndConsume, signTypedData,
  runWithDeadline = createDeadlineRunner(),
  preSignTimeoutMs = 5_000, signerTimeoutMs = 15_000,
}) {
  const normalizedIdentity = validateWalletIdentity(identity);
  return Object.freeze({
    async walletIdentity() {
      return structuredClone(normalizedIdentity);
    },
    async signX402Exact(authorizedPermit, paymentRequired) {
      return await executeAuthorizedSigning({
        runWithDeadline, preSignTimeoutMs, signerTimeoutMs,
        prepare: async () => {
          const binding = verifyAndConsume(authorizedPermit);
          assertPermitMatchesPayment(binding, paymentRequired, binding.acceptedIndex);
          if (getAddress(normalizedIdentity.address) !== getAddress(binding.walletAddress)) {
            throw new Error('wallet identity mismatch');
          }
          return { binding, exact: buildEip3009Exact({ binding, paymentRequired }) };
        },
        invokeSigner: ({ exact }) => signTypedData(exact.typedData),
        finalize: async ({ exact }, signature) => Object.freeze({
          paymentPayload: await exact.assemble(signature),
        }),
      });
    },
  });
}
```

Perform permit verification before awaiting any injected signer. The deterministic
adapter is test/evidence infrastructure only and may not be selectable when
`WALLET_KERNEL_MODE=cdp-testnet`.

Wrap the deterministic implementation with the typed boundary above: everything
through `buildEip3009Exact()` is the pre-sign zone, while the call expression and all
subsequent signature/payload validation are the may-exist zone. Tests cover a
synchronous signer throw, async rejection, deadline timeout, malformed signature, and
post-sign mismatch; every one reports ambiguity and never invokes the signer twice.

- [ ] **Step 5: Run the contract suite**

```bash
node --test spikes/pi-wielder/tests/wallet-adapter-contract.test.mjs \
  spikes/pi-wielder/tests/eip3009-exact.test.mjs \
  spikes/pi-wielder/tests/wallet-adapter-deterministic.test.mjs
```

Expected: every adapter boundary and forged-capability assertion passes.

- [ ] **Step 6: Commit the provider-neutral seam**

```bash
git add spikes/pi-wielder/src/adapters/wallet-adapter-contract.mjs \
  spikes/pi-wielder/src/adapters/eip3009-exact.mjs \
  spikes/pi-wielder/src/adapters/deterministic-wallet-adapter.mjs \
  spikes/pi-wielder/tests/wallet-adapter-contract.test.mjs \
  spikes/pi-wielder/tests/eip3009-exact.test.mjs \
  spikes/pi-wielder/tests/wallet-adapter-deterministic.test.mjs
git commit -m "feat: define wallet signing adapter contract"
```

### Task 9: Implement the bounded x402 v2 HTTP transport

**Files:**

- Create: `spikes/pi-wielder/src/adapters/x402-v2-transport.mjs`
- Create: `spikes/pi-wielder/tests/fixtures/x402-v2-resource.mjs`
- Create: `spikes/pi-wielder/tests/x402-v2-transport.test.mjs`

- [ ] **Step 1: Write failing protocol and adversarial transport tests**

Use an injected in-process `fetchImpl` for unit tests; it records requests and returns
real `Response` objects. The unpaid request returns HTTP 402 with a
`PAYMENT-REQUIRED` header encoded from this fixture:

```js
export const PAYMENT_REQUIRED = Object.freeze({
  x402Version: 2,
  error: 'Payment required',
  resource: {
    url: 'https://seller.example/paid/infer',
    description: 'offline fixture',
    mimeType: 'application/json',
  },
  accepts: [{
    scheme: 'exact',
    network: 'eip155:84532',
    asset: '0x036cbd53842c5426634e7929541ec2318f3dcf7e',
    amount: '50000',
    payTo: '0x2000000000000000000000000000000000000000',
    maxTimeoutSeconds: 60,
    extra: { name: 'USDC', version: '2' },
  }],
});
```

Exercise this exact API:

```js
const transport = createX402V2Transport({ fetchImpl, mode: 'cdp-testnet', limits: {
  requestTimeoutMs: 5_000,
  maximumResponseBytes: 1_048_576,
  maximumPaymentHeaderBytes: 16_384,
} });

const challenge = await transport.probe(requestSnapshot);
assert.equal(challenge.kind, 'payment_required');
assert.deepEqual(challenge.paymentRequired, PAYMENT_REQUIRED);

const paymentHeader = transport.encodePayment(paymentPayload);
const paymentHash = sha256(Buffer.from(paymentHeader, 'ascii'));
const settlementBinding = Object.freeze({
  network: 'eip155:84532',
  walletAddress: '0x1000000000000000000000000000000000000000',
  amountAtomic: '50000',
  paymentHash,
});
const paid = await transport.retryPaid({
  request: requestSnapshot,
  paymentHeader,
  binding: settlementBinding,
});
assert.equal(paid.kind, 'settled_response');
assert.deepEqual(paid.settlement, settlementFixture);
```

This ASCII-header digest is the one canonical `paymentHash` persisted with the exact
payload/header and reused by transport, settlement, recovery, and receipt bindings;
no layer invents a second payload-hash definition.

Assert exactly one unpaid request and one paid request. The first has no payment
header; the second differs only by `PAYMENT-SIGNATURE`. Assert no automatic retry,
redirect, credential forwarding to another origin, legacy header fallback, third
request, or body mutation.

Reject each of these before signing:

```text
missing or duplicate PAYMENT-REQUIRED header
malformed base64 or JSON
x402Version other than 2
missing/empty accepts or a structurally malformed requirement
header over 16 KiB
402 body over the byte ceiling
redirect response
resource URL mismatch
```

The transport deliberately accepts and returns two or more structurally valid options
without choosing one. It never filters by scheme, network, asset, payee, or amount;
Task 3's Policy Engine is the sole selection owner and persists the original index.
Official header codecs only decode base64/JSON, so apply bounded closed structural
validation after decoding rather than treating the codec's TypeScript cast as runtime
validation.

For the paid response, separate settlement proof from resource-body delivery. Decode
and validate the single `PAYMENT-RESPONSE` header before reading or releasing any body.
A second 402, changed challenge, missing/malformed settlement, or connection/timeout
before trustworthy response headers is `paid_response_ambiguous` and retains the hold.
Once a valid settlement says the exact payment settled, return
`kind: 'settled_response'` even if the body later times out, disconnects, or exceeds
the byte ceiling; include the settlement and HTTP status, omit the body, and classify
execution as `unknown` with a stable delivery reason only when the received status is
2xx. Any validly settled 3xx, 4xx, or 5xx response is `execution_failed` immediately,
never followed, and opens refund resolution regardless of body delivery. Only a
bounded delivered 2xx body is `execution_succeeded`. The Kernel must commit that
payment and record execution separately. `success: false` is not safe rejection proof:
the EIP-3009 authorization can remain usable until expiry, so it always returns
`paid_response_ambiguous` and holds. HTTP status alone is never rejection proof.

Define and directly test this pure classifier:

```js
export function classifyX402PaymentResponse({ rawHeader, decoded, binding }) {
  // Recognize only success, transaction, network, payer?, amount?, errorReason?,
  // errorMessage?, extensions?, and extra? with exact runtime types.
}
```

Its sanitized evidence contains only source, header hash, `success`, transaction,
network, normalized payer, canonical amount when present, a bounded stable reason code,
and the already-persisted `paymentHash`; never raw header, error message, extensions,
or extra. It returns `settled` only when `success === true`, network equals the signed
binding, payer is present and equals the wallet, transaction canonicalizes through
`canonicalEvmHash()` to `/^0x[0-9a-f]{64}$/`, optional amount is canonical and equals the signed exact
amount, and success carries no error fields. The standard response has no
asset/payee/nonce/quote fields, so do not claim it cryptographically binds those; its
causal binding is arrival on the sole paid retry carrying the persisted payment hash.

Missing, duplicate, malformed, unknown-key/type, `success: false`, network/payer/
amount/transaction mismatch, second 402, timeout, or connection loss all return a
stable unresolved classification and retain the full hold. Mutate every recognized
field independently. Prove success with absent amount is valid for `exact`, but
missing payer is unresolved; prove false with an empty or reverted transaction remains
unresolved. Only Task 11's trusted post-expiry nonce observation may release.

Add separate tests for: loss before headers -> unresolved hold; valid settlement plus
2xx body timeout -> committed payment/execution unknown; valid settlement plus
oversized 2xx body -> committed payment/execution unknown; table-driven valid
settlement plus HTTP 302/404/500 -> committed payment/execution failed with no redirect
follow; and malformed settlement with any status ->
unresolved hold. None may issue a third request.

- [ ] **Step 2: Run the test and observe the missing module**

```bash
node --test spikes/pi-wielder/tests/x402-v2-transport.test.mjs
```

Expected: FAIL with `ERR_MODULE_NOT_FOUND`.

- [ ] **Step 3: Implement the v2 codecs and bounded two-call transport**

Create `x402-v2-transport.mjs` using only official protocol codecs:

```js
import {
  decodePaymentRequiredHeader,
  decodePaymentResponseHeader,
  encodePaymentSignatureHeader,
} from '@x402/core/http';

export function createX402V2Transport({ fetchImpl, mode, limits }) {
  return Object.freeze({
    async probe(request) {
      // One redirect-disabled unpaid fetch; return response or decoded v2 challenge.
    },
    encodePayment(paymentPayload) {
      const value = encodePaymentSignatureHeader(paymentPayload);
      if (Buffer.byteLength(value) > limits.maximumPaymentHeaderBytes) {
        throw new Error('PAYMENT-SIGNATURE exceeds byte ceiling');
      }
      return value;
    },
    async retryPaid({ request, paymentHeader, binding }) {
      // One redirect-disabled retry. Decode settlement before bounded body delivery;
      // never sign, commit budgets, or retry itself.
    },
  });
}
```

Reuse `composeDeadline()`, `readBodyWithLimit()`, and cancellation behavior from
`src/runtime-boundaries.mjs`. Pass `redirect: 'manual'`. Add a closed `mode` constructor
option: `cdp-testnet` rejects every non-HTTPS upstream, while `deterministic` additionally
accepts HTTP only for literal `127.0.0.1` or `[::1]` URLs. Tests use injected
protocol-shaped fetches without network. Clone request
body bytes once at capture and reuse those exact bytes for both calls.

`retryPaid()` returns a closed discriminated union for `paid_response_ambiguous` or
`settled_response`; a response header alone never returns `payment_rejected`. Only
`settled_response` carries matched settlement evidence. Its body field is either the bounded bytes or `null` with
`executionState: 'unknown'` and a delivery reason; callers may never convert that
post-settlement delivery failure back into payment uncertainty.

Do not use `wrapFetchWithPayment`, `CdpX402Client`, or any wrapper that signs and
retries internally. The Wallet Kernel must persist `paymentPayloadJson`, the exact
encoded `PAYMENT-SIGNATURE` value, and `paymentHash` before `retryPaid()` can run.

- [ ] **Step 4: Add a reusable deterministic v2 resource fixture**

Create `tests/fixtures/x402-v2-resource.mjs` exporting `PAYMENT_REQUIRED`, a valid
payment payload, a settlement object, codec-produced header values, and a
`createResourceFetch()` state machine. It must validate the second request’s exact
signature header and expose call counts; it must never contact a facilitator or chain.

- [ ] **Step 5: Run transport and legacy paying-fetch suites**

```bash
node --test spikes/pi-wielder/tests/x402-v2-transport.test.mjs
npm run test:policy --prefix spikes/pi-wielder
node --test spikes/pi-wielder/tests/paying-fetch.test.mjs
```

Expected: all v2 transport cases pass, and the v1 regression tests remain green.

- [ ] **Step 6: Commit x402 v2 transport**

```bash
git add spikes/pi-wielder/src/adapters/x402-v2-transport.mjs \
  spikes/pi-wielder/tests/fixtures/x402-v2-resource.mjs \
  spikes/pi-wielder/tests/x402-v2-transport.test.mjs
git commit -m "feat: add bounded x402 v2 transport"
```

### Task 10: Orchestrate the restart-safe Wallet Kernel lifecycle

**Files:**

- Create: `spikes/pi-wielder/src/kernel/wallet-kernel.mjs`
- Create: `spikes/pi-wielder/tests/wallet-kernel.test.mjs`

- [ ] **Step 1: Write the failing lifecycle acceptance matrix**

Construct the Kernel only from injected repositories, adapter, transport, signer,
clock, IDs, and fault injector:

```js
const kernel = createWalletKernel({
  store,
  policies,
  enrollments,
  intents,
  budgets,
  approvals,
  receipts,
  permitAuthority,
  walletAdapter,
  transport,
  authorityMutationCoordinator,
  markAuthorityUnhealthy,
  now,
  faultInjector,
});
```

Exercise `openOrResumeSession()` and `execute({ sessionId, routeId, request, purposeLabel,
correlationId })`. The route ID
comes from the trusted proxy's immutable route registry, never an agent body/header.
Every result includes
the Kernel-issued public `requestId`; never substitute an approval ID. Assert these terminal
results and durable side effects:

| Scenario | Public result | Budget | Signing/retry | Receipt |
|---|---|---|---|---|
| ordinary non-402 2xx | `completed` | none | 0 / 0 | signed |
| ordinary non-402 4xx/5xx | `upstream_failed` | none | 0 / 0 | signed |
| unpaid timeout/connection failure | `upstream_failed` | none | 0 / 0 | signed |
| malformed/oversized/expired challenge | `payment_denied` | none | 0 / 0 | signed |
| policy deny | `payment_denied` | none | 0 / 0 | signed |
| approval needed | `payment_approval_required` | none | 0 / 0 | pending, nonterminal |
| approval denied/expired | `payment_denied` | none | 0 / 0 | signed |
| allowed settled success | `completed` | committed | 1 / 1 | signed |
| settled execution HTTP 3xx/4xx/5xx | `execution_failed` | committed | 1 / 1 | signed |
| valid settlement then 2xx body timeout/overflow | `execution_unknown` | committed | 1 / 1 | signed |
| typed pre-signer validation/account failure | `payment_failed` | released | 0 / 0 | signed |
| signer throw/rejection/timeout or post-sign validation failure | `payment_unresolved` | unresolved | 1 / 0 | signed |
| signer may have returned but persistence fails | process abort | held on recovery | 1 / 0 | signed during startup recovery; later reconciliation may supersede |
| paid response ambiguous | `payment_unresolved` | unresolved | 1 / 1 | signed |
| settlement reports `success: false` | `payment_unresolved` | unresolved | 1 / 1 | signed |
| second 402 or changed/missing settlement | `payment_unresolved` | held | 1 / 1 | signed |

For every terminal row in this matrix, the same authoritative transaction writes or
increments the exact `buyer_outcomes { status, reason_code, revision }` projection
before receipt issuance. No terminal path relies on event text to remember its public
status/reason, and recovery can deterministically fill a missing receipt.

For every settled execution HTTP 3xx/4xx/5xx, the same authoritative transaction inserts
`execution_resolutions.state = 'refund_pending'`, opens one linked `refunds.state =
'pending'` row for the full committed amount/original transaction, and immediately
blocks new spending by that wallet. For `execution_unknown`, it inserts
`execution_resolutions.state = 'reconciliation_required'` with no invented refund and
also blocks immediately. Success creates no resolution row. Assert the settlement,
execution, resolution/refund, budget commit, and wallet-block result are atomic at the
fault boundary; neither failed nor unknown execution can appear without its required
open resolution case.

For the approval path, call `execute()` again with the exact same ordinary request
after operator approval. Assert the Kernel finds the approved intent, performs a fresh
policy/challenge/budget check, consumes the approval, and never exposes or accepts an
approval identifier through the request.
The fresh check, `consumeForInTransaction()`, and budget reservation share one
`BEGIN IMMEDIATE` aggregate transaction. A crash may therefore leave an approved row
with no reservation before the retry begins, or a consumed row with its exact
reservation after commit, but never a consumed approval without its reservation.
That transaction also reloads the intent's exact enrollment hash and requires the
matching enrollment is still `active`. New-intent capture, fresh-probe admission,
auto-approved reservation, approved-retry reservation, and the later signing-claim
transaction repeat the same exact active-enrollment check; an auth result cached before
revocation is never sufficient.

While approval remains pending, identical requests return the same public request ID
and do not create another Spend Intent or Approval. After approval, concurrent exact
retries serialize one approval consumption and at most one signature; followers return
the same terminal result or stable `REQUEST_IN_FLIGHT`. If the fresh unpaid probe
returns an expired or changed challenge, terminalize the old approval with a signed
`APPROVAL_CHALLENGE_CHANGED` receipt and do not sign during that call. When the changed
challenge is valid and its fresh pure evaluation remains `approval_required`, create a
new Spend Intent/Approval with a new public request ID in the same domain transaction.
If the fresh result is `allow` or `deny`, or the challenge is expired/invalid, create
no replacement row in that transaction: return the old `payment_denied` result and
receipt, and let a later exact tool call enter the ordinary new-intent lifecycle from
scratch. A changed ordinary request never matches the old approval.
Concretely, the changed-challenge domain transaction calls
`cancelForIntentInTransaction(..., 'APPROVAL_CHALLENGE_CHANGED')`, so the old Approval
is legally `cancelled`, transitions the old intent to `terminal`, writes
`payment_denied / APPROVAL_CHALLENGE_CHANGED` revision 1, clears the old intent's
`retry_matchable` flag, and then, only for a fresh `approval_required` result, calls
`captureIntentInTransaction()`, `attachChallengeInTransaction()`,
`policies.recordDecisionInTransaction()`, and `requestInTransaction()` to create the
complete replacement binding from the already validated fresh challenge. Every call
uses the same live token; none opens a nested transaction or duplicates repository
SQL. The replacement receives newly Kernel-generated request, intent, correlation,
and idempotency identifiers, while preserving the same ordinary request fingerprint
only after the old row becomes non-matchable. The coordinator is retained until the
old terminal outcome has its receipt; a receipt failure closes global admission
before the new approval can be acted on. Faults at every write boundary prove the old
aggregate and new request either commit together or not at all.

Add a barriered concurrency test that pauses immediately after the durable signing
claim, submits two identical agent retries, and proves both resolve to the original
intent, no new intent/approval/reservation appears, and signer/retry counts remain at
most one. Repeat while `signed`, `retrying`, and `unresolved`; the fingerprint is
released only after a committed terminal transition.

At the signing claim, call Task 6's `deriveAuthorizationWindow()` exactly once and
persist its nonce/validity in the same transaction that moves the PaymentAttempt to
`signing`. Seed an existing attempt with the generated nonce and prove the unique-index
collision rolls back the claim, invokes the signer zero times, safely releases the
unsigned reservation as `payment_failed / NONCE_COLLISION`, and draws no implicit
second nonce inside that operation.

Revocation and the signing claim have an explicit SQLite linearization point. If
revocation commits first, capture/reservation/signing revalidation fails; an existing
unsigned reservation is released and terminalized as `payment_denied / AGENT_REVOKED`
with a receipt, and the signer call count remains zero. If the signing-claim
transaction commits first, the attempt is already money-sensitive and may finish or
become unresolved under its persisted binding; later revocation blocks all new work
but never pretends to cancel a possibly signed authorization. Barrier tests pause at
authentication, capture, unpaid-probe return, reservation, and immediately before the
signing claim, race `revoke()`, and prove exactly those two serialized outcomes.

The signing claim is also the final wallet-wide admission linearization point. Inside
that same `BEGIN IMMEDIATE`, call
`budgetLedger.snapshotInTransaction(token, { sessionId, sellerOrigin, at })` and
recheck `walletBlocked` plus every open payment-resolution, execution-resolution, and
refund blocker across the wallet. The current intent's own expected unsigned
reservation is excluded only from the blocker predicate, never from exposure totals.
If another intent became payment-unresolved, execution unknown/failed, or refund
pending after this intent reserved, the later claim releases this still-unsigned
reservation and terminalizes it as `payment_denied / WALLET_RECOVERY_REQUIRED` in the
domain transaction, including the durable `BuyerOutcome`; while the mutation
coordinator lease remains held, Task 7's mandatory second transaction signs and
inserts the receipt before the call returns. If that receipt transaction fails, global
admission enters the same fail-stop used by every other money-sensitive mutation. The
claim issues no permit and invokes the signer zero times.
Barrier tests create each of those three blocker classes between reservation and
claim and prove the later claim loses safely. A blocker that commits after the signing
claim follows the ordinary money-sensitive recovery rules and cannot retroactively
release the authorization.

- [ ] **Step 2: Specify and test the monetary transition order**

The successful lifecycle order is exact:

```text
1. persist SpendSession and SpendIntent
2. make one unpaid probe
3. persist decoded challenge and pure PolicyDecision
4. persist approval request, or reserve budget
5. generate and persist the bytes32 nonce and validity with the unique signing claim
6. issue one AuthorizedPermit and invoke signer once
7. validate the signer output against that nonce/validity, then persist the exact payment payload
   JSON, encoded header, hash, and state=signed
8. persist state=retrying
9. make one paid retry with those exact bytes
10. persist settlement, execution outcome, budget disposition, and required execution
    resolution/refund case plus the matching `buyer_outcomes` revision as authoritative facts; a valid settlement always commits
    spend even when later body delivery is unknown, and failed/unknown execution blocks
    the wallet in that same transaction
11. derive, sign, and persist the receipt from the committed terminal facts
12. return only sanitized result plus receipt
```

Add a trace array to injected fakes and assert byte-for-byte equality with this order.
Output is never released before steps 10–11 commit. Inject a crash between steps 10
and 11 and prove startup issues the missing receipt without repeating a monetary
transition.

Step 10 has exactly one transaction owner: `wallet-kernel.mjs` calls
`store.transaction((token) => ...)`, uses only BudgetLedger's `*InTransaction`
operations plus store/repository operations scoped through that same token, appends all
domain events, and returns synchronously. No participant starts a nested transaction,
and fault injection after each individual write proves the whole settlement/execution/
resolution/refund/buyer-outcome unit rolls back together.

Reservation and signing claim are deliberately two transactions so
`after_reservation_commit` is a real recoverable boundary. The first aggregate
re-evaluates the immutable policy/budget snapshot and calls `reserveInTransaction()`;
for an approved retry it also calls `consumeForInTransaction()` in that same token,
while the auto-approved path has no Approval row. The later signing-claim transaction
reloads the exact reservation/policy/enrollment epoch, calls the transaction-local
wallet snapshot, and rechecks the deadline, active enrollment, and absence of any
other wallet-wide recovery/refund blocker before it derives/persists the one
nonce/window, moves the attempt to `signing`, and appends its events before issuing
the in-memory permit. Expiry, revocation, or a newly committed wallet blocker at that
second boundary safely releases the still-unsigned reservation and
terminalizes it in the same transaction; nonce collision or another failed claim
recheck likewise invokes the signer zero times. A crash between the two transactions
leaves exactly the `reserved, no signing claim` state classified by Task 11.

- [ ] **Step 3: Run the focused test and observe the missing orchestrator**

```bash
node --test spikes/pi-wielder/tests/wallet-kernel.test.mjs
```

Expected: FAIL with `ERR_MODULE_NOT_FOUND` for `wallet-kernel.mjs`.

- [ ] **Step 4: Implement the closed Kernel API and state machine**

Create `wallet-kernel.mjs` with no environment reads and no direct network, filesystem,
CDP, or HTTP-server imports:

```text
export function createWalletKernel(dependencies) {
  return Object.freeze({
    openOrResumeSession({ agentInstanceId, walletAddress, policyVersionId }),
    applyPolicy({ document, expectedPolicyHash }),
    revokeAgent({ agentInstanceId, expectedEnrollmentHash, operatorIdHash }),
    transitionSessionPolicy({ sessionId, targetPolicyVersionId, expectedSessionHash }),
    closeSession({ sessionId, expectedSessionHash }),
    approvePending({ approvalId, expectedIntentHash, operatorIdHash }),
    denyPending({ approvalId, expectedIntentHash, operatorIdHash, reasonCode }),
    expireDueApprovals({ limit }),
    execute({ sessionId, routeId, request, purposeLabel, correlationId }),
    status({ sessionId, intentId }),
  });
}
```

Dependencies include Task 7's receipt-parity checks, the shared FIFO
`authorityMutationCoordinator`, and one injected `markAuthorityUnhealthy(code)`
callback owned by `control-plane.mjs`. Every mutation acquires the coordinator and
rechecks its gate before its first write; every BuyerOutcome-writing transaction also
performs the token-scoped global parity check. A terminal mutation retains the lease
across its domain commit and receipt commit. After a domain commit, any receipt
signing/insertion failure invokes the callback synchronously while still holding that
lease; the callback closes the shared admission gate before queued work can recheck it
and before the Kernel rejects the call. Tests pause at this gap, queue a second intent
plus every operator mutation class, and prove each observes
`RECEIPT_PARITY_REQUIRED` with zero writes after the lease releases.

`applyPolicy()` and `revokeAgent()` are the only live wrappers around Task 3's policy
mutation and Task 4's enrollment revocation. Each first validates its closed input and
displayed hash, then performs the repository's synchronous standalone transaction
inside `authorityMutationCoordinator.runExclusive()`. `applyPolicy()` recomputes the
canonical document hash, requires `expectedPolicyHash`, rechecks the loaded wallet and
same-wallet live-rotation rule, applies the immutable version, and returns its exact
blocked-session summaries. `revokeAgent()` requires the authenticated operator hash,
conditionally revokes only the exact active enrollment, supersedes its admission
attestation through the repository transaction, and returns the still-bound session
IDs without closing or resolving them. Neither writes a BuyerOutcome or receipt. Race
tests queue both methods against reservation and signing claim: FIFO order determines
the winner, a policy/revocation winner blocks the later admission check, and a prior
signing claim may only finish or become unresolved under its persisted epoch.

The operator route never calls ApprovalQueue mutations directly. `approvePending()`
serializes the exact conditional approval under the coordinator. `denyPending()` owns
one domain transaction that calls `denyForIntentInTransaction()`, terminalizes the
same SpendIntent, and inserts BuyerOutcome revision 1 as `payment_denied` with the
validated bounded denial reason. `expireDueApprovals()` obtains a read-only
`listDue()` batch and, in stable order, gives each still-due approval its own
coordinator-held domain transaction calling `expireForIntentInTransaction()`,
terminalizing the intent, and inserting `payment_denied / APPROVAL_EXPIRED` revision
1. Each denial/expiry retains the lease through the mandatory second receipt
transaction; a crash can leave only a terminal outcome missing its receipt, which
startup parity repair fills before listeners. There is no durable `denied` or
`expired` approval paired with a nonterminal intent or missing BuyerOutcome.
Startup recovery runs the same expiry aggregate before readiness; normal operation
runs a bounded due batch before admitting a new approval at the capacity limit and
before applying an operator decision. An exact approved retry that discovers its own
expiry executes that one aggregate directly. Read-only list/status routes never sweep
or mutate as a side effect.

`execute()` is the sole agent execution entrypoint. It first performs Task 4's exact
session/fingerprint lookup: a matching retryable intent with an approved decision is
dispatched internally to the private approved-retry path, while a new fingerprint is
captured once. The proxy never chooses between “new” and “retry,” never accepts an
approval ID, and never calls a second public retry method.

At every state change, use a conditional transition and stable `KernelError.code`.
Signing claim is durable and unique. After a signer returns, immediately canonicalize
and encode its payload, then commit the exact payload JSON and header before any await
or paid-network operation. Never sign again for a row in `signing`, `signed`,
`retrying`, or `unresolved`.

If the process cannot prove whether a signer returned or a paid request reached the
seller, fail closed to a recoverable hold. Do not infer rejection from timeout,
connection reset, process death, malformed response, or missing settlement header.
Release after a signing claim only for an error that is an actual `WalletSigningError`
with code `WALLET_PRE_SIGN_REJECTED` and `signatureMayExist === false`; every
untyped/unknown error and every `signatureMayExist !== false` case becomes unresolved.
In particular, a synchronous signer throw, async rejection/timeout, malformed
signature, and post-sign assembly/validation failure all hold and block without a
second signer call. A `PAYMENT-RESPONSE` reporting failure also holds until Task 11 can
prove the authorization unused after expiry.
Every terminal pre-payment outcome—including free failure, transport failure, invalid
challenge, policy denial, and approval denial/expiry—must transition with a signed
receipt even though no BudgetReservation exists. Its domain transaction first writes
the exact initial `buyer_outcomes` row; the receipt repository only projects that row.

`transitionSessionPolicy()` is operator-only orchestration. It requires a
`policy_blocked` session, the current active PolicyVersion as target, exact wallet and
agent binding backed by the currently active enrollment, normal (not recovery-only)
mode, and a confirmation hash over the displayed session/binding state. If
any intent is signing, signed, retrying, unresolved, or has unresolved refund work, it
returns `SESSION_TRANSITION_BLOCKED` without mutation; that old session still cannot
admit spend. Otherwise it owns one `store.transaction((token) => ...)`: cancel each
`pending` or `approved` approval through
`cancelForIntentInTransaction(..., 'POLICY_SUPERSEDED')`, release only definitely
unsigned reservations through BudgetLedger, transition each affected intent to
`terminal`, and write buyer outcome `payment_denied / POLICY_SUPERSEDED` revision `1`
through `store.within()`. It then calls Task 4's repository-owned
`transitionBlockedSessionInTransaction()` with that same token. No Kernel or operator
code writes a session/binding row directly or opens a nested transaction. The
transaction appends every owned event and rolls back as one unit at each injected
write boundary. Issue all required terminal receipts from the committed BuyerOutcomes
before returning operator success. Recovery fills a crash-time receipt gap before listeners open. Test stale
confirmation, non-active target, concurrent transition, pending approval, unsigned
reservation, and every in-flight/ambiguous blocker.

The lifecycle matrix here owns the deferred policy-block enforcement tests: after a
tighter same-wallet apply, the old session rejects admission before probe, approval
consumption, reservation, permit issue, or signer invocation; an already
signed/retrying attempt may record only its persisted outcome. Assert exact zero call
counts at every forbidden boundary.

`closeSession()` is the authenticated operator session-end wrapper around the same
aggregate transaction, ending with Task 4's
`closeBoundSessionInTransaction()`. It requires `expectedSessionHash`, applies the
identical in-flight/ambiguity blockers, maps every safely cancelled/unsigned intent to
buyer outcome `payment_denied / SESSION_CLOSED`, changes its `pending` or `approved`
approval to `cancelled`, releases only definitely unsigned reservations, and commits
all intent/outcome/session/binding events together. It issues all resulting terminal
receipts after that domain commit and leaves the agent enrollment active but unbound.
It is the only supported way to end an exhausted
session or prepare a wallet rotation. Hot wallet rotation is forbidden: after close,
the daemon must stop; the operator provisions the new customer wallet, applies the
new-wallet policy under the offline bootstrap lock, updates closed configuration, and
restarts. Agent requests while unbound return `AGENT_SESSION_UNAVAILABLE`, never
silently create a new session under the old process configuration. Test guarded close,
same-policy restart creating one fresh session, and the no-hot-wallet-rotation gate.

- [ ] **Step 5: Add fault injection at every monetary boundary**

Call `faultInjector(point, context)` at these exact points:

```js
export const KERNEL_FAULT_POINTS = Object.freeze([
  'after_intent_commit',
  'after_challenge_commit',
  'after_reservation_commit',
  'after_signing_claim_commit',
  'after_signer_return',
  'after_signed_payment_commit',
  'after_retry_claim_commit',
  'after_paid_response',
  'after_settlement_commit',
  'before_terminal_receipt_commit',
]);
```

`after_challenge_commit` fires only after one transaction has persisted both the
challenge projection and PolicyDecision, and before any approval, reservation, or
deny outcome exists. Approval consumption and reservation commit together, so no
fault point can produce a consumed approval without its exact reservation. Task 11's
matrix gives each resulting row one explicit recovery classification.

In `wallet-kernel.test.mjs`, throw a sentinel error at each point and inspect the
still-open store. Assert each row is either safely unsigned or in the exact durable
state that Task 11 recovery must classify. The separate-process abort/reopen matrix is
deliberately deferred until `recovery.mjs` exists in Task 11.

```text
no missing or duplicated reservation
signed bytes never change
one transaction ID commits at most once
event chain and receipt signatures verify
```

Add explicit lifecycle assertions for the typed release predicate, each may-exist
signer failure, an arbitrary untyped adapter error, and a restart from `signing`.
Exactly the typed pre-signer case releases; all others preserve full unresolved
exposure and no terminal path asks the adapter to sign twice.

- [ ] **Step 6: Run lifecycle and old x402 lifecycle suites**

```bash
node --test spikes/pi-wielder/tests/wallet-kernel.test.mjs
node --test spikes/pi-wielder/tests/x402-lifecycle.test.mjs
```

Expected: every fault point lands in its specified durable state, and the existing v1
lifecycle suite remains green.

- [ ] **Step 7: Commit the Wallet Kernel lifecycle**

```bash
git add spikes/pi-wielder/src/kernel/wallet-kernel.mjs \
  spikes/pi-wielder/tests/wallet-kernel.test.mjs
git commit -m "feat: orchestrate restart-safe agent spending"
```

### Task 11: Add startup recovery, trusted reconciliation, and sanitized export

**Files:**

- Create: `spikes/pi-wielder/src/kernel/recovery.mjs`
- Create: `spikes/pi-wielder/src/kernel/projection-exporter.mjs`
- Create: `spikes/pi-wielder/tests/kernel-recovery.test.mjs`
- Create: `spikes/pi-wielder/tests/kernel-reconciliation.test.mjs`
- Create: `spikes/pi-wielder/tests/projection-exporter.test.mjs`
- Create: `spikes/pi-wielder/tests/kernel-restart.test.mjs`
- Create: `spikes/pi-wielder/tests/fixtures/kernel-crash-worker.mjs`

- [ ] **Step 1: Write the failing startup recovery matrix**

Seed one database row at each nonterminal payment/execution/refund state, close the
store, reopen it, and call:

```js
const report = recoverKernelAuthority({
  store, intents, budgets, approvals, receipts, now: fixedNow,
});
```

Assert:

| Durable state on reopen | Recovery action | Wallet can spend? |
|---|---|---|
| valid open agent binding/session | retain for the same credential digest | yes |
| valid `policy_blocked` binding/session | retain for transition/status only | no |
| revoked enrollment with retained binding/session | operator-only status/reconciliation; agent denied | no |
| active enrollment with zero bindings and zero orphan open/policy-blocked sessions | retain as valid unbound; composition may open only after policy/isolation gates | not until composition |
| dangling/mismatched binding, orphan open/policy-blocked session, or more than one candidate pair | fail startup semantic audit | no listener |
| captured, no challenge | intent `terminal`; buyer outcome `upstream_failed` / `RECOVERY_ABANDONED_UNSIGNED`; no reservation; receipt | yes |
| challenged + persisted deny decision, no outcome | intent `terminal`; buyer outcome `payment_denied` with the persisted PolicyDecision reason; receipt | yes |
| challenged + persisted allow/approval-required decision, no approval/reservation | intent `terminal`; buyer outcome `payment_failed` / `RECOVERY_ABANDONED_UNSIGNED`; receipt | yes |
| pending approval, unexpired | leave pending | yes |
| pending approval, expired | atomically expire approval + terminalize intent + write `payment_denied / APPROVAL_EXPIRED` revision 1; receipt | yes |
| approved but unconsumed, unexpired | retain for exact ordinary retry only; no reservation | yes |
| approved but unconsumed, expired | atomically expire approval + terminalize intent + write `payment_denied / APPROVAL_EXPIRED` revision 1; receipt | yes |
| consumed approval without its exact reservation | fail startup semantic audit | no listener |
| reserved, no signing claim | release, terminal receipt | yes |
| signing | atomically change PaymentAttempt and SpendIntent to `unresolved`, retain full hold and `retry_matchable = 1`, write `payment_unresolved / RECOVERY_PAYMENT_AMBIGUOUS` revision 1; receipt | no |
| signed | retain exact bytes, atomically change PaymentAttempt and SpendIntent to `unresolved`, retain full hold and `retry_matchable = 1`, write `payment_unresolved / RECOVERY_PAYMENT_AMBIGUOUS` revision 1; receipt | no |
| retrying | atomically change PaymentAttempt and SpendIntent to `unresolved`, retain full hold and `retry_matchable = 1`, write `payment_unresolved / RECOVERY_PAYMENT_AMBIGUOUS` revision 1; receipt | no |
| unresolved with pending/abandoned/rejected payment candidate history | retain exact immutable history, current fresh case hash, existing outcome/receipt, and hold | no |
| settled, execution missing | atomically insert execution `unknown`, open `reconciliation_required`, transition intent to `terminal` with `retry_matchable = 0`, write `execution_unknown / RECOVERY_EXECUTION_MISSING` revision 1, retain committed spend; receipt | no |
| failed execution without `refund_pending` case/refund row | fail semantic audit | no listener |
| unknown execution without `reconciliation_required` case | fail semantic audit | no listener |
| failed/unknown execution with open resolution case | retain exact case and full block | no |
| refund pending/unresolved, or only abandoned history awaiting a replacement | retain immutable history, current fresh case hash, open `refund_pending` resolution, and full block | no |

Recovery never invents an extra state: `RECOVERY_ABANDONED_UNSIGNED` is a stable
reason code on the applicable existing `upstream_failed` or `payment_failed`
BuyerOutcome value while the Spend Intent uses the existing `terminal` state. That
transition and its first outcome revision commit atomically before the receipt is
projected.
The same rule applies to every recovery-created terminal fact. Expiring an approval
uses Task 6's scoped transition in the transaction that terminalizes its intent and
inserts the outcome. Each `signing`/`signed`/`retrying` ambiguity transaction
conditionally changes both the PaymentAttempt and its exact SpendIntent from their
matching predecessor states to `unresolved`, retains the exact hold/bytes and
`retry_matchable = 1`, and inserts the initial
`payment_unresolved / RECOVERY_PAYMENT_AMBIGUOUS` outcome. The settled-without-
execution transaction inserts the `unknown` execution, its wallet-blocking
`reconciliation_required` case, conditionally transitions the exact SpendIntent from
its legal predecessor to `terminal` while clearing `retry_matchable`, and inserts the
initial `execution_unknown / RECOVERY_EXECUTION_MISSING` outcome together. That stable
reason is the only recovery classification for a persisted settlement lacking an
execution row. Fault injection after each individual write proves the execution,
resolution case, terminal intent, outcome, and retained committed budget all roll back
or commit as one unit.
Only after each domain commit does recovery sign/insert its receipt; startup stays
closed until global receipt parity is restored. An existing matching outcome with a
missing receipt is repaired idempotently, while a conflicting existing outcome or
receipt is semantic corruption rather than a second revision.
`after_challenge_commit` means the challenge projection and PolicyDecision committed
atomically but Task 10 had not yet created an approval or reservation. Recovery uses
the persisted deny reason only for a deny; it never silently reconstructs a missing
approval/reservation or resumes network work. Approval consumption and reservation
are one aggregate transaction, so the consumed-without-reservation row is corruption,
not a recoverable crash state.

`abandoned` is immutable candidate history, not proof that payment/refund ambiguity
ended. Recovery accepts zero or more abandoned/rejected predecessors plus at most one
current pending payment candidate or pending/unresolved refund candidate, recomputes
the displayed case hash from the complete ordered history, and requires it to differ
from the pre-abandon hash. With no replacement yet, the rotated fresh hash and full
hold remain active. Restart tests cover abandon-before-crash, replacement-before-
crash, and abandon racing confirmation for both payment and refund observations; no
case releases value, removes the wallet block, or revises the BuyerOutcome/receipt.

Recovery is idempotent: a second call changes no rows, events, or receipt revisions.
Test both legal unbound cases: first clean bootstrap before its initial session, and
restart after guarded close with the still-active enrollment. Recovery creates no
session; only Task 14 composition may do so after all admission gates. Individually
seed each dangling/orphan/ambiguous variant and require corruption.
It verifies `PRAGMA integrity_check`, foreign keys, schema version, every SQL/domain
CHECK, the full cross-table semantic audit defined in Step 4, event hash chain, and all
receipt signatures before returning ready; any failure keeps the process out of the
serving state.

- [ ] **Step 2: Write exact reconciliation and refund-observation tests**

Inject a trusted resolver whose result is fetched by the Kernel, not supplied by the
agent. Keep RPC-observed facts separate from locally persisted x402 bindings:

```js
const rpcTransferProof = Object.freeze({
  source: 'base-sepolia-rpc',
  network: 'eip155:84532',
  transactionId: `0x${'ab'.repeat(32)}`,
  blockHash: `0x${'cd'.repeat(32)}`,
  blockNumber: '1234567',
  transactionStatus: 'success',
  confirmations: 3,
  transferLogIndex: 4,
  authorizationLogIndex: 5,
  tokenContract: BASE_SEPOLIA_USDC,
  from: walletAddress,
  to: sellerPayTo,
  valueAtomic: '50000',
  authorizationNonce: `0x${'01'.repeat(32)}`,
  observedAt: '2026-07-31T12:10:00.000Z',
});
```

The resolver may claim only those chain facts. The Kernel independently loads the
persisted signed PaymentAttempt and its local `intentHash`, `challengeHash`, `quoteId`,
payload hash, payer, payee, asset, amount, nonce, and validity window; it verifies the
receipt/status plus the USDC `Transfer` and authorization-use logs, then stores a
canonical proof that contains `rpcProofHash` and `localAttemptHash` as separately named
provenance. Never label intent/challenge/quote values as RPC-observed. Require exact
network, transaction, payer, payee, asset, amount, and nonce agreement. One changed
field produces `RECONCILIATION_MISMATCH` and changes neither domain rows nor event
head. Replaying the exact proof is idempotent.

Because a paid-response loss may leave no transaction ID in the Kernel, the
authenticated operator may optionally name one public `paymentTransactionId` while
confirming the displayed intent and payment-case hashes. The API accepts no receipt,
log, amount, nonce, wallet, payee, status, block, or generic evidence. Canonicalize and
persist the candidate in `payment_reconciliation_candidates` before invoking the
observer. Without a candidate, payment reconciliation may only attempt the
post-expiry unused-authorization observation below; it performs no unbounded log
search. A sufficiently confirmed reverted or exact-binding-mismatched candidate is
terminally `rejected` without releasing the hold, allowing a later candidate only with
the newly displayed case hash. Missing/insufficient evidence remains `pending`.
An exact settled transfer atomically marks its candidate `confirmed` with the payment
commit. A later exact post-expiry unused-authorization proof atomically marks any
still-pending candidate `rejected` before releasing the hold, because that transaction
cannot have consumed the persisted authorization. Exact replay is idempotent, while
concurrent/different candidates, cross-intent reuse, and case-variant transaction
spelling cannot overwrite or bypass the unique history.
If an operator recognizes a nonexistent or mistyped candidate before either proof is
available, a separate authenticated abandon operation may conditionally change only
that exact `pending` row to `abandoned`. It requires the newly displayed
domain-separated case hash, appends an immutable audit event, rotates the case hash,
and preserves the full monetary hold and BuyerOutcome without a receipt revision. A
replacement candidate is legal only against that fresh hash. It can never mark a
candidate rejected/confirmed, release/commit value, resolve execution, or overwrite
history. Test payment and refund candidates that never appear on-chain, stale/concurrent
abandon, abandonment racing confirmation, and replacement after abandonment.

A reported settlement failure, reverted transaction, or missing transaction is not
release evidence while the signed authorization can still be submitted. The only
rejection proof that releases a signed hold is a trusted read-only observation with
this closed shape:

```js
const unusedAfterExpiry = Object.freeze({
  kind: 'authorization_unused_after_expiry',
  network: 'eip155:84532',
  asset: BASE_SEPOLIA_USDC,
  payer: walletAddress,
  nonce: `0x${'01'.repeat(32)}`,
  validBefore: '1785502860',
  authorizationState: false,
  observedBlockNumber: '1234570',
  observedBlockHash: `0x${'ef'.repeat(32)}`,
  observedBlockTimestamp: '1785502860',
  confirmations: 3,
});
```

Require every binding to match persistence, `observedBlockTimestamp >= validBefore`,
the configured minimum confirmation count, and a false USDC authorization-state read
at that recorded block. Before expiry, an already-used nonce, missing block identity,
or any uncertainty stays unresolved. Test that only this exact post-expiry unused-nonce
proof releases; a false `PAYMENT-RESPONSE` never does.

Execution reconciliation uses a distinct signed seller proof, never RPC inference. The
trusted resolver fetches and verifies this closed attestation for the persisted intent:

```js
const executionAttestation = Object.freeze({
  schemaVersion: 1,
  domain: 'wallet-kernel.execution.v1',
  network: 'eip155:84532',
  sellerOrigin: 'https://seller.example',
  intentHash,
  transactionId: `0x${'ab'.repeat(32)}`,
  outcome: 'succeeded', // or 'failed'; never 'unknown'
  httpStatus: 200,
  responseHash: `sha256:${'12'.repeat(32)}`, // nullable only when no body was observed
  issuedAt: '2026-07-31T12:10:00.000Z',
  expiresAt: '2026-07-31T12:15:00.000Z',
  signer: configuredExecutionSigner,
  signature,
});
```

The signed bytes are exactly the UTF-8 bytes of `canonicalJson()` over the closed
object above after removing only `signature`; the seller signs those bytes with
`signMessage({ message: { raw: bytes } })`, and the resolver uses
`recoverMessageAddress()` over the same raw bytes. The literal `domain` field is
mandatory and prevents execution/refund cross-use. Verify the recovered address
equals the PolicyVersion's exact `executionSigner`; require network, seller, intent,
settled transaction, bounded time window, outcome, and status to match persistence.
When the unknown execution row already has an HTTP status or response hash, the
attestation must repeat it exactly. When delivery failed before either was available,
the attestation may supply the missing bounded status/hash as signed seller evidence;
persist them in reconciliation metadata, but never construct or claim to deliver an
output body. `responseHash` may be `null` only when neither persistence nor the seller
has a body hash; a succeeded attestation still requires a success HTTP status. A verified
`succeeded` attestation changes unknown execution to succeeded, resolves its case, and
issues a receipt revision without inventing or delivering an output. A verified
`failed` attestation changes it to failed and atomically changes the case to
`refund_pending` while creating the one full-amount pending refund row. Missing,
expired, mismatched, or badly signed evidence leaves `reconciliation_required` and the
wallet blocked.

For refunds, use this exact independently signed seller attestation:

```js
const refundAttestation = Object.freeze({
  schemaVersion: 1,
  domain: 'wallet-kernel.refund.v1',
  network: 'eip155:84532',
  sellerOrigin: 'https://seller.example',
  intentHash,
  originalTransactionId: `0x${'ab'.repeat(32)}`,
  refundTransactionId: `0x${'34'.repeat(32)}`,
  asset: BASE_SEPOLIA_USDC,
  originalPayer: walletAddress,
  originalPayee: sellerPayTo,
  refundSource: configuredRefundSource,
  amountAtomic: '50000',
  issuedAt: '2026-07-31T12:10:00.000Z',
  expiresAt: '2026-07-31T12:15:00.000Z',
  signer: configuredRefundSigner,
  signature,
});
```

Sign and recover the refund message with the same exact raw canonical-byte rule as
the execution attestation, but with its distinct literal domain. For refunds, the authenticated operator supplies exactly one public
`refundTransactionId` while confirming the persisted intent hash; no amount, asset,
wallet, payee, status, or evidence object is accepted. Persist that candidate ID on a
pending refund row bound to the original committed attempt before lookup. The trusted
seller evidence provider must first return a valid closed
`wallet-kernel.refund.v1` attestation signed by the PolicyVersion's exact
`refundSigner`, binding seller origin, original/refund transaction IDs, network, asset,
original payer/payee, the PolicyVersion's exact `refundSource`, and full amount with
bounded issue/expiry timestamps. The attestation signer is evidence authority only;
it need not control the refund source. Separately,
the read-only chain observer requires a sufficiently confirmed successful Base
Sepolia receipt with one exact USDC transfer from that configured refund source to the
buyer wallet for the full original amount. It stores separate `attestationHash`,
`rpcProofHash`, and `localRefundBindingHash` provenance and consumes each
transaction/log once. The buyer
never constructs, signs, broadcasts, or retries a refund transaction. A confirmed
refund releases the full amount exactly once and issues a superseding receipt.
Missing or insufficiently confirmed evidence remains pending and wallet-blocking. A
sufficiently confirmed reverted transaction or successful transaction that lacks the
exact full-refund transfer terminalizes only that candidate as `rejected`; it never
releases value or resolves the execution case. The same observation endpoint may then
persist one new candidate only with the newly displayed refund-case hash. A missing or
bad seller signature/provider result remains `unknown`, not rejected. Re-observing the
same candidate is idempotent, and no candidate/evidence row is overwritten. Test cross-intent transaction reuse, changed
original/refund transaction, wrong sender/recipient/chain/asset, partial amount, and
wrong attestation signer/refund source, operator-supplied fake evidence fields,
rejected-candidate replacement, concurrent
supersede, and the one-open-refund index.

- [ ] **Step 3: Run the tests and observe missing modules**

```bash
node --test spikes/pi-wielder/tests/kernel-recovery.test.mjs \
  spikes/pi-wielder/tests/kernel-reconciliation.test.mjs \
  spikes/pi-wielder/tests/projection-exporter.test.mjs
```

Expected: FAIL with `ERR_MODULE_NOT_FOUND`.

- [ ] **Step 4: Implement fail-closed recovery and operator-only reconciliation**

Create `recovery.mjs`:

```text
export function recoverKernelAuthority({ store, intents, budgets, approvals, receipts, now }) {
  // Verify physical and semantic authority invariants, classify every incomplete row,
  // and return a frozen report.
}

export function createReconciler({
  store, budgets, receipts, resolver, now, idFactory,
  authorityMutationCoordinator, markAuthorityUnhealthy,
}) {
  return Object.freeze({
    reconcilePayment({ intentId, operatorIdHash, paymentTransactionId = null,
      expectedPaymentCaseHash }),
    reconcileExecution({ intentId, operatorIdHash, expectedExecutionCaseHash }),
    observeRefund({ intentId, operatorIdHash, refundTransactionId,
      expectedRefundCaseHash }),
    abandonCandidate({ intentId, kind, operatorIdHash, expectedCaseHash }),
  });
}
```

`resolver` is exactly `{ observePayment(persistedAttemptBinding),
observeExecution(persistedExecutionBinding),
observeRefund(persistedRefundBinding) }`. The payment method returns only
`settled_transfer`, `payment_candidate_rejected`,
`authorization_unused_after_expiry`, or `unknown`; the refund method returns only
`refund_attested_and_confirmed` with separate sanitized seller/RPC proofs,
`refund_candidate_rejected` with conclusive chain evidence, or `unknown`; the execution method returns only `execution_attested` with a
verified closed seller attestation projection and hash—but no signature—or `unknown`.
`reconcilePayment()` and `observeRefund()` first commit any operator-named transaction
into their one open candidate binding after checking the respective displayed case
hash, then pass that persisted row—not request data—to the resolver. A null payment
candidate selects only the post-expiry unused-authorization path. The
API never accepts an arbitrary caller evidence object. Reconciliation persistence commits
the domain change and incremented `buyer_outcomes` revision first; a superseding signed
receipt is then derived from that durable fact and committed
before public success is returned. Recovery fills an interrupted receipt gap
idempotently. Resolver timeout or malformed evidence cannot release a budget hold.
There is no caller-authored generic `rejected`, `settled`, or `refund_confirmed`
result. Each method validates its own closed result schema and source before any budget
transition.

The reconciler receives the same shared FIFO `authorityMutationCoordinator` and
fail-stop `markAuthorityUnhealthy(code)` callback as Task 10. It never holds a
coordinator lease across resolver/network work. `reconcilePayment()` and
`observeRefund()` use one short lease to recheck the admission gate and atomically
persist the candidate, release it before calling the resolver, then acquire a new
lease for the authoritative resolution. `reconcileExecution()` first takes a bounded
read-only binding snapshot, resolves outside any lease/transaction, then acquires its
resolution lease. On every resolution lease, recheck the shared gate and global
receipt parity before the first write, reload the exact persisted binding and case
hash inside the domain transaction, and discard a stale resolver result with zero
writes.

Any resolution that writes a BuyerOutcome retains that second lease continuously
across the domain commit and required receipt-signing/insert transaction. If receipt
creation fails after the domain commit, synchronously call
`markAuthorityUnhealthy('RECEIPT_PARITY_REQUIRED')` while still holding the lease;
queued agent and operator mutations then recheck the closed gate and perform zero
writes. Candidate persistence and `abandonCandidate()` also use the shared coordinator
and gate but have no receipt phase because they do not write a BuyerOutcome. Barrier
tests pause before and after each lease, during the network gap, and after the terminal
domain commit to prove no network-under-lease, stale-result overwrite, post-commit
unsafe retry, or receipt-parity race is possible.

`reconcileExecution()` is legal only for an open
`execution_resolutions.state = 'reconciliation_required'` row. A successful resolution
updates the execution outcome plus case (and, for failure, pending refund) in one
authority transaction. A `settled_transfer` payment resolution atomically commits the
payment, marks its persisted candidate `confirmed`, inserts
`execution_outcomes.state = 'unknown'`, opens
`execution_resolutions.state = 'reconciliation_required'`, and writes buyer outcome
`execution_unknown`; it remains wallet-blocking until separate signed execution
evidence resolves it. It can never jump directly from payment ambiguity to completed.
An `authorization_unused_after_expiry` resolution atomically marks any open payment
candidate `rejected`, releases the authorization hold, and writes the terminal
`payment_rejected` outcome before its receipt is exposed.
`observeRefund()` is legal only for `refund_pending` with the matching open refund row;
confirmation resolves both the refund and execution case in the same budget
transaction. Candidate rejection closes only that candidate and increments the
blocking outcome/receipt revision; every untrusted mismatch or partial provider result
changes no row. Each reconciliation method recomputes its domain-separated displayed
case hash inside the same transaction; stale hashes and concurrent winners return a
stable conflict with no resolver call or mutation.

Each candidate-persistence write and each later authoritative resolution write has one
transaction owner. Resolve external evidence between those transactions; for the
resolution call `store.transaction((token) => ...)`, re-read/revalidate
the persisted case/candidate/hash, and use only BudgetLedger's
`resolvePaymentInTransaction()` or `recordConfirmedRefundInTransaction()` plus
token-scoped domain mutations. No resolver/network call or nested transaction occurs
while the SQLite write transaction is open.
`abandonCandidate()` accepts `kind` only as `payment` or `refund-observation`, reloads
the one exact open candidate and case inside `BEGIN IMMEDIATE`, and conditionally marks
it `abandoned` with an event. It performs no resolver/network call, no budget or
BuyerOutcome mutation, and returns the fresh replacement case hash. Its stale hash or
a concurrent confirmation/rejection loses with zero writes.

Recovery uses two explicit audit phases; it never applies the final-state invariants to
a crash gap before classifying that gap. The pre-classification audit verifies physical
integrity, schema/foreign keys/CHECKs, event-chain validity, signatures of every
existing receipt, canonical state/atomic strings, challenge indices and hashes,
route/policy/approval immutable bindings, reservation arithmetic, internally complete
PaymentAttempt fields for its current state, transaction/candidate uniqueness,
candidate history/case hashes, legal predecessors, enrollment/session uniqueness and
bindings, and isolation-attestation hashes. It admits only the exact incomplete shapes
listed in Step 1: missing dependent outcome/receipt rows at named fault boundaries,
`signing`/`signed`/`retrying`, settled-without-execution, due approval, reserved-before-
claim, and the other enumerated unsigned abandonment cases. A near miss—extra row,
wrong predecessor, conflicting outcome/receipt, partial execution case, or missing
data not named by the matrix—is `AUTHORITY_SEMANTIC_CORRUPTION` with zero repair.

After deterministic classification and domain repair, run the full semantic audit:
every reservation sums to its decision ceiling and uses that PolicyVersion's limits;
every PaymentAttempt payload/header/hash/nonce/amount/state agrees with its
SpendIntent state and BudgetReservation disposition; settlements own
their unique transaction IDs; payment/refund candidate histories are canonical and
have at most one open row; every failed/unknown settled execution has exactly its
required resolution/refund state; executions/refunds/reconciliations have legal
predecessors; retryable fingerprints and open bindings are unique; every binding and
intent carries its exact immutable enrollment hash; at most one attestation is current;
every terminal/ambiguous intent has exactly one current BuyerOutcome whose revision
matches domain/reconciliation history; and every BuyerOutcome revision has exactly one
valid projecting receipt. A missing receipt for an otherwise exact committed outcome
is the sole receipt repair case and is filled before this second audit; a conflicting
receipt is never repaired. Any final mismatch returns
`AUTHORITY_SEMANTIC_CORRUPTION`, keeps both listeners closed, and performs no further
mutation. Add corruption and allowed-gap tests for each cross-table class using
individually well-formed rows so SQL constraints alone cannot make them vacuous.

- [ ] **Step 5: Prove recovery in fresh processes at every fault point**

Create `kernel-crash-worker.mjs` to acquire the shared Kernel authority lock, open a
supplied temporary database, run one intent, and call `process.abort()` at the supplied
`KERNEL_FAULT_POINTS` value from Task 10. The abort releases the OS-backed SQLite lock
without a cleanup callback; the parent must prove a new owner acquires it before
reopening the main authority. In
`kernel-restart.test.mjs`, spawn one worker per point, reopen the database, call the now
implemented `recoverKernelAuthority()`, and assert:

```text
no missing or duplicated reservation
no second signer invocation
persisted signed bytes never change
no blind paid retry after restart
one transaction ID commits at most once
ambiguous states block the wallet
terminal receipt gaps are filled without replaying money
event chain and every receipt signature verify
```

Persist deterministic signer and transport call counts in separate owner-only fixture
files so the fresh test process can prove no repeat call occurred. Run:

```bash
node --test spikes/pi-wielder/tests/kernel-restart.test.mjs
```

Expected: every process-abort boundary recovers or blocks exactly as specified.

- [ ] **Step 6: Implement a one-way sanitized projection**

Create `projection-exporter.mjs`:

```text
export function createProjectionExporter({ store, receipts, signer, now }) {
  return Object.freeze({
    snapshot({ sessionId }),
    exportSigned({ sessionId }),
  });
}
```

The export contains schema/version, wallet public identity, hashed agent enrollment
state, isolation status/preflight digest (never raw UID/GID/path), policy hashes, aggregate
budgets, approval state counts, open execution/refund resolution counts and blocker
reason codes, sanitized intent metadata, signed receipts, event-head
hash, and export signature. It excludes raw request/response bodies, header values,
payment payloads, payment signatures, credentials, operator identities beyond a stable
hash, provider errors, and filesystem paths. There is deliberately no `import`,
`restore`, `apply`, or mutation method.

In `projection-exporter.test.mjs`, recursively scan keys and serialized values against:

```js
const FORBIDDEN_EXPORT_TERMS = /prompt|body|authorization|payment.signature|private|secret|token|stack|file.path/i;
```

Verify the export signature in a fresh process and prove mutating any projected field
breaks verification.

- [ ] **Step 7: Run recovery, reconciliation, projection, and refund regressions**

```bash
node --test spikes/pi-wielder/tests/kernel-recovery.test.mjs \
  spikes/pi-wielder/tests/kernel-reconciliation.test.mjs \
  spikes/pi-wielder/tests/projection-exporter.test.mjs \
  spikes/pi-wielder/tests/kernel-restart.test.mjs
node --test spikes/pi-wielder/tests/collar-failure.test.mjs
```

Expected: all Kernel recovery cases and the existing seller refund/reconciliation
suite pass.

- [ ] **Step 8: Commit recovery and read-only projection**

```bash
git add spikes/pi-wielder/src/kernel/recovery.mjs \
  spikes/pi-wielder/src/kernel/projection-exporter.mjs \
  spikes/pi-wielder/tests/kernel-recovery.test.mjs \
  spikes/pi-wielder/tests/kernel-reconciliation.test.mjs \
  spikes/pi-wielder/tests/projection-exporter.test.mjs \
  spikes/pi-wielder/tests/kernel-restart.test.mjs \
  spikes/pi-wielder/tests/fixtures/kernel-crash-worker.mjs
git commit -m "feat: recover and reconcile wallet authority"
```

### Task 12: Add the live-shaped CDP wallet adapter and closed configuration

**Files:**

- Create: `spikes/pi-wielder/src/config.mjs`
- Create: `spikes/pi-wielder/src/adapters/cdp-wallet-adapter.mjs`
- Create: `spikes/pi-wielder/src/adapters/base-sepolia-observer.mjs`
- Create: `spikes/pi-wielder/src/adapters/seller-evidence-resolver.mjs`
- Create: `spikes/pi-wielder/tests/config.test.mjs`
- Create: `spikes/pi-wielder/tests/wallet-adapter-cdp.test.mjs`
- Create: `spikes/pi-wielder/tests/base-sepolia-observer.test.mjs`
- Create: `spikes/pi-wielder/tests/seller-evidence-resolver.test.mjs`
- Modify: `spikes/pi-wielder/.env.example`

- [ ] **Step 1: Extend the non-secret environment template**

Append these blank values to `.env.example`; do not add an example value that could be
mistaken for a credential:

```dotenv
WALLET_KERNEL_MODE=deterministic
WALLET_KERNEL_OPERATOR_SOCKET_FILE=
WALLET_KERNEL_ENROLLMENT_INBOX=
WALLET_KERNEL_AGENT_RUN_OUTBOX=
WALLET_KERNEL_RELEASE_ROOT=
WALLET_KERNEL_RELEASE_MANIFEST=
WALLET_KERNEL_SERVICE_DEFINITION_FILE=
WALLET_KERNEL_SOCKET_DEFINITION_FILE=
WALLET_KERNEL_ENV_FILE=
WALLET_KERNEL_EVIDENCE_ROOT=
WALLET_KERNEL_ISOLATION_REPORT_FILE=
CDP_API_KEY_ID=
CDP_API_KEY_SECRET=
CDP_WALLET_SECRET=
CDP_WALLET_NAME=
WALLET_KERNEL_BASE_SEPOLIA_RPC_URL=
```

Document beside `WALLET_KERNEL_MODE` that only `deterministic` and `cdp-testnet` are
accepted, and that `cdp-testnet` is pinned to Base Sepolia. There is no mainnet mode.
The RPC URL is a customer-supplied read-only observation endpoint, never a funding,
signing, or transaction-send capability.

- [ ] **Step 2: Write failing closed-configuration tests**

Create `config.test.mjs` with an explicit environment object; never mutate or inspect
the developer's real `process.env`. Assert:

```js
const config = loadControlPlaneConfig({
  env: fixtureEnv, checkoutRoot, uid, platform: 'linux',
});
assert.deepEqual(config.publicConfig, {
  mode: 'cdp-testnet',
  agentHost: '127.0.0.1',
  agentPort: 8402,
  operatorAdminTransport: 'unix',
  operatorSocketPath: fixtureEnv.WALLET_KERNEL_OPERATOR_SOCKET_FILE,
  operatorConsoleTransport: 'socket-activated-loopback',
  operatorConsoleActivationName: 'wallet-kernel-console',
  operatorHost: '127.0.0.1',
  operatorPort: 8405,
  databasePath: fixtureEnv.WALLET_KERNEL_DB_FILE,
  policyPath: fixtureEnv.WALLET_KERNEL_POLICY_FILE,
  routePath: fixtureEnv.WALLET_KERNEL_ROUTE_FILE,
  receiptKeyPath: fixtureEnv.WALLET_KERNEL_RECEIPT_KEY_FILE,
  operatorTokenPath: fixtureEnv.WALLET_KERNEL_OPERATOR_TOKEN_FILE,
  enrollmentInboxPath: fixtureEnv.WALLET_KERNEL_ENROLLMENT_INBOX,
  agentRunOutboxPath: fixtureEnv.WALLET_KERNEL_AGENT_RUN_OUTBOX,
  trustedAncestor: fixtureEnv.WALLET_KERNEL_TRUSTED_ANCESTOR,
  releaseRoot: fixtureEnv.WALLET_KERNEL_RELEASE_ROOT,
  releaseManifestPath: fixtureEnv.WALLET_KERNEL_RELEASE_MANIFEST,
  serviceDefinitionPath: fixtureEnv.WALLET_KERNEL_SERVICE_DEFINITION_FILE,
  socketDefinitionPath: fixtureEnv.WALLET_KERNEL_SOCKET_DEFINITION_FILE,
  environmentFilePath: fixtureEnv.WALLET_KERNEL_ENV_FILE,
  evidenceRoot: fixtureEnv.WALLET_KERNEL_EVIDENCE_ROOT,
  isolationReportPath: fixtureEnv.WALLET_KERNEL_ISOLATION_REPORT_FILE,
  expectedAgentUid: Number(fixtureEnv.WALLET_KERNEL_EXPECTED_AGENT_UID),
  expectedAgentGid: Number(fixtureEnv.WALLET_KERNEL_EXPECTED_AGENT_GID),
  cdpWalletName: 'pilot-wallet',
  network: 'eip155:84532',
  observer: 'base-sepolia-read-only',
});
assert.equal(JSON.stringify(config).includes(fixtureEnv.CDP_API_KEY_SECRET), false);
assert.equal(JSON.stringify(config).includes(fixtureEnv.CDP_WALLET_SECRET), false);
```

Reject missing/noncanonical/zero expected agent UID/GID, a zero live Kernel UID/GID,
an expected live agent UID equal to the injected Kernel UID,
missing CDP credential presence in CDP mode, empty wallet
name, unknown environment fields with
the `WALLET_KERNEL_` prefix, relative/in-checkout/symlink/permissive config paths,
missing live operator socket/release/handoff/evidence/isolation-report paths, a live self-bound TCP operator endpoint
or missing root-owned console socket activation,
non-loopback agent hosts, colliding deterministic ports, invalid ports, `production`, `mainnet`, `eip155:8453`,
or any asset other than Base Sepolia USDC. In `cdp-testnet`, require every policy seller
origin to be HTTPS and require an HTTPS RPC URL
without username/password and recognize it in the closed environment schema, but treat
the whole URL as secret because a path/query can contain a provider key. It must not
appear in `publicConfig`, logs, errors, receipts, projections, or evidence. The
deterministic mode does not require CDP credentials or an RPC endpoint and must ignore
rather than serialize any present values.
Also reject `NODE_OPTIONS`, `NODE_PATH`, every key with prefix `LD_` or `DYLD_`,
`GCONV_PATH`, and `GLIBC_TUNABLES` in live mode before dynamic SDK/adapter imports;
tests cover each class. The rendered systemd unit removes the loader controls before
Node starts; this application check is defense in depth, not the first line of
protection.
`cdp-testnet` additionally requires the validated runtime platform to equal `linux`, the systemd
activation contract, a root-owned configured `trustedAncestor`, and distinct
root-owned service and socket unit files. `trustedAncestor` must lexically contain
every configured live filesystem path; Task 2's descriptor walker then applies the
role-specific owner/mode policy to the complete chain. A sticky writable ancestor,
even `/tmp`, is never a valid live root.

In the same test file, exercise `validateRouteMap({ document, mode })` before Task 14
adds the concrete route file. Require a closed schema, unique bounded route IDs, fixed
methods/kinds/content types and byte ceilings, and queryless credential-free upstream
URLs. `cdp-testnet` accepts HTTPS only. `deterministic` also accepts HTTP only for the
literal canonical loopback address `127.0.0.1` or `[::1]`, never a hostname. Return a
deeply frozen registry with exact lookup by route ID, and
never allow a request to supply or replace an upstream URL.

- [ ] **Step 3: Write the failing injected-CDP adapter contract**

In `wallet-adapter-cdp.test.mjs`, create a fake client with:

```js
const fixtureAccount = privateKeyToAccount(
  keccak256(toBytes('wallet-kernel-cdp-adapter-test-only')),
);
const account = {
  address: fixtureAccount.address,
  async signTypedData(typedData) {
    calls.push(typedData);
    return await fixtureAccount.signTypedData(typedData);
  },
};
const cdpClient = {
  evm: {
    async getAccount({ name }) {
      assert.equal(name, 'pilot-wallet');
      return account;
    },
  },
};
```

Run the reusable `walletAdapterContract('cdp', factory)` suite from Task 8. Assert an
authorized call invokes `account.signTypedData()` once with the exact permit-bound
`from`, `to`, `value`, `validAfter`, `validBefore`, and 32-byte nonce.
Assert every invalid permit/payload case invokes it zero times, concurrent initialization
resolves one account promise, and neither the client nor account is returned or logged.
Assert `createAccount()` and `getOrCreateAccount()` do not exist on the injected fake
and are never required: the customer must provision the named wallet before preflight.

- [ ] **Step 4: Run the tests and observe missing modules**

```bash
node --test spikes/pi-wielder/tests/config.test.mjs \
  spikes/pi-wielder/tests/wallet-adapter-cdp.test.mjs \
  spikes/pi-wielder/tests/base-sepolia-observer.test.mjs \
  spikes/pi-wielder/tests/seller-evidence-resolver.test.mjs
```

Expected: FAIL with `ERR_MODULE_NOT_FOUND`.

- [ ] **Step 5: Implement secret-free public configuration**

Create `config.mjs`:

```js
export const CONTROL_PLANE_MODES = Object.freeze(['deterministic', 'cdp-testnet']);

export function validateRouteMap({ document, mode }) {
  // Return a deeply frozen exact-ID registry or throw KernelError on any unknown field.
}

export function loadControlPlaneConfig({ env, checkoutRoot,
  uid = process.getuid(), gid = process.getgid(), platform = process.platform }) {
  return Object.freeze({
    publicConfig: Object.freeze({
      mode,
      agentHost: '127.0.0.1',
      agentPort,
      operatorAdminTransport: mode === 'cdp-testnet' ? 'unix' : 'loopback-demo',
      operatorSocketPath: mode === 'cdp-testnet' ? operatorSocketPath : null,
      operatorConsoleTransport: mode === 'cdp-testnet'
        ? 'socket-activated-loopback' : 'loopback-demo',
      operatorConsoleActivationName: mode === 'cdp-testnet'
        ? 'wallet-kernel-console' : null,
      operatorHost: '127.0.0.1',
      operatorPort,
      databasePath,
      policyPath,
      routePath,
      receiptKeyPath,
      operatorTokenPath,
      enrollmentInboxPath,
      agentRunOutboxPath,
      trustedAncestor: mode === 'cdp-testnet' ? trustedAncestor : null,
      releaseRoot: mode === 'cdp-testnet' ? releaseRoot : null,
      releaseManifestPath: mode === 'cdp-testnet' ? releaseManifestPath : null,
      serviceDefinitionPath: mode === 'cdp-testnet' ? serviceDefinitionPath : null,
      socketDefinitionPath: mode === 'cdp-testnet' ? socketDefinitionPath : null,
      environmentFilePath: mode === 'cdp-testnet' ? environmentFilePath : null,
      evidenceRoot: mode === 'cdp-testnet' ? evidenceRoot : null,
      isolationReportPath: mode === 'cdp-testnet' ? isolationReportPath : null,
      expectedAgentUid,
      expectedAgentGid,
      cdpWalletName,
      network: 'eip155:84532',
      observer: mode === 'cdp-testnet' ? 'base-sepolia-read-only' : 'deterministic',
    }),
    assertCredentialPresence() {},
  });
}
```

Compute each identifier from validated input; the literal names above define the only
allowed public keys. `assertCredentialPresence()` checks that the three CDP variables
exist for `cdp-testnet` but returns no values. Pass the original environment only to
the SDK constructor in the process composition root; do not copy credentials into the
config, database, logs, errors, or receipts.
`platform` is a closed unit-test seam, not an environment/configuration field. Accept
only Node's known platform tokens and require exact `linux` in `cdp-testnet`; tests
inject `linux` for the live-shape fixture and independently inject `darwin`/`win32` to
prove rejection. The real `control-plane.mjs` always omits this argument and, before
constructing any live dependency or listener, independently requires actual
`process.platform === 'linux'`. No composition dependency or environment value can
override that second gate, so the injection seam cannot make a macOS process live.
In `cdp-testnet`, the owner bearer may travel only over the Kernel-owned Unix-domain
socket named by `operatorSocketPath`. The live CLI must execute under the
Kernel/operator OS identity that can traverse the socket's owner-only parent. The live
browser console is served only from the inherited root service-manager socket named
`wallet-kernel-console`, bound to exact `127.0.0.1:8405` and held across Kernel
crashes/restarts; application code may never self-bind that port in live mode. Browser
auth uses a short-lived one-time launch capability minted through the Unix admin
channel, never the owner bearer. Missing/inconsistent socket activation blocks live
console and agent admission.
The Kernel configuration has no agent-credential path and rejects
`WALLET_KERNEL_AGENT_CREDENTIAL_FILE` if it appears in the Kernel environment. Live
composition loads only the active non-secret enrollment from SQLite and requires its
canonical `agent_uid` to equal `expectedAgentUid` and differ from the Kernel UID.
Deterministic tests may inject an explicit same-UID enrollment dependency, but no
environment field enables that exception.

- [ ] **Step 6: Implement CDP signing over the permit-bound EIP-3009 builder**

Reuse `buildEip3009Exact()` from Task 8. The Kernel has already generated and
persisted the cryptographically random bytes32 nonce plus canonical `validAfter` and
`validBefore` seconds with the signing claim before issuing the AuthorizedPermit.
Create `cdp-wallet-adapter.mjs`:

```js
export function createCdpWalletAdapter({
  cdpClient, walletName, verifyAndConsume,
  runWithDeadline = createDeadlineRunner(),
  preSignTimeoutMs = 5_000, signerTimeoutMs = 15_000,
}) {
  let accountPromise;
  const account = () => {
    accountPromise ??= cdpClient.evm.getAccount({ name: walletName });
    return accountPromise;
  };
  return Object.freeze({
    async walletIdentity() {
      const value = await runWithDeadline({
        phase: 'wallet_identity', timeoutMs: preSignTimeoutMs, operation: account,
      });
      return validateWalletIdentity({
        provider: 'coinbase-cdp',
        walletId: walletName,
        address: value.address,
        network: 'eip155:84532',
      });
    },
    async signX402Exact(authorizedPermit, paymentRequired) {
      return await executeAuthorizedSigning({
        runWithDeadline, preSignTimeoutMs, signerTimeoutMs,
        prepare: async () => {
          const binding = verifyAndConsume(authorizedPermit);
          assertPermitMatchesPayment(binding, paymentRequired, binding.acceptedIndex);
          const value = await account();
          const liveIdentity = validateWalletIdentity({
            provider: 'coinbase-cdp', walletId: walletName,
            address: value.address, network: 'eip155:84532',
          });
          if (getAddress(liveIdentity.address) !== getAddress(binding.walletAddress)) {
            throw new Error('wallet identity mismatch');
          }
          return {
            value,
            exact: buildEip3009Exact({ binding, paymentRequired }),
          };
        },
        invokeSigner: ({ value, exact }) => value.signTypedData(exact.typedData),
        finalize: async ({ exact }, signature) => Object.freeze({
          paymentPayload: await exact.assemble(signature),
        }),
      });
    },
  });
}
```

Do not use `account.signX402Payment()`, `CdpX402Client`, or a wrapped fetch. The
higher-level x402 signer generates its nonce internally, so it cannot satisfy the
approved pre-sign AuthorizedPermit nonce binding; wrapped fetch also hides the exact
payload-persistence boundary. CDP's typed-data signing keeps key custody inside the
customer’s CDP project while signing the Kernel-constructed authorization. Automated
tests inject `cdpClient`; they never construct a real SDK client.

The shared helper keeps permit validation, account resolution, live-address equality,
and builder creation definitively before `signTypedData`; its second zone begins before
the signer invocation and includes signature recovery/payload validation. Add CDP-specific
tests for account lookup rejection (zero signer calls and typed pre-sign failure),
synchronous signer throw, async rejection/timeout, malformed returned signature, and
post-sign payload mismatch (all typed ambiguous failures). No thrown object retains a
provider `cause`, stack fragment, credential, or raw response.

In `control-plane.mjs`, and nowhere else, construct the real client with:

```js
const cdpClient = new CdpClient({
  apiKeyId: env.CDP_API_KEY_ID,
  apiKeySecret: env.CDP_API_KEY_SECRET,
  walletSecret: env.CDP_WALLET_SECRET,
});
```

Pass it directly to the adapter and discard the environment reference after
composition. Before opening agent admission, require `walletIdentity().address` to
equal the active PolicyVersion wallet. Never call account export, faucet, transfer,
transaction-send, or arbitrary sign methods from the control plane.

- [ ] **Step 6a: Implement the Base Sepolia read-only observer**

Create `base-sepolia-observer.mjs` with this exact provider-neutral surface:

```text
createBaseSepoliaObserver({ publicClient, now, minimumConfirmations = 2 }) -> {
  preflight(),
  fundingStatus({ walletAddress, requiredAtomic }),
  observePayment(persistedBinding),
  observeRefund(persistedBinding),
}
```

`preflight()` requires chain ID `84532` and the exact Base Sepolia USDC contract.
`fundingStatus()` reads `balanceOf` at one captured block and returns only wallet,
asset, canonical `balanceAtomic`/`requiredAtomic`, `sufficient | insufficient`, block
number/hash, and observation time. It is informational and never authorizes policy or
mutates a budget.

`observePayment()` and `observeRefund()` accept only persisted Kernel bindings, never
an HTTP request or caller-authored evidence object. For ambiguous payment, the binding
may contain the one open operator-named transaction from
`payment_reconciliation_candidates`; the observer performs no unbounded log or chain
search. A settled payment requires a sufficiently confirmed successful receipt for
that persisted candidate transaction plus exact USDC
`AuthorizationUsed(payer, nonce)` and `Transfer(payer, payee, amount)` logs. A reverted
or exact-binding-mismatched confirmed candidate returns
`payment_candidate_rejected` without releasing the authorization hold; a missing or
insufficiently confirmed candidate is `unknown`. With or without a candidate, it becomes
`authorization_unused_after_expiry` only when a recorded block timestamp is at or
after `validBefore` and an exact USDC `authorizationState(payer, nonce)` read at that
block is false. A refund observation takes the operator-named transaction only from
the persisted pending-refund row and requires a confirmed successful exact full-amount
`Transfer(refundSource, payer, amount)` in that transaction, where `refundSource`
comes from the attempt's immutable PolicyVersion seller projection—not the operator,
attestation signer, route file, or RPC response. Missing receipts,
insufficient confirmations, and provider uncertainty remain `unknown`. A sufficiently
confirmed reverted or exact-binding-mismatched refund transaction returns
`refund_candidate_rejected`; that closes only the candidate, never releases spend or
resolves the execution case. Even a matching transfer is only the chain half of refund proof;
Task 11/Step 6b's independently verified signed refund attestation is also mandatory.

The adapter exposes no client, generic RPC, wallet, signer, faucet, transfer,
`sendTransaction`, or `writeContract` method. Fake-client tests allow only
`getChainId`, `getBlockNumber`, `getBlock`, `getTransactionReceipt`, and exact USDC
`readContract`; log decoding is local. Provider failures become stable redacted codes.
Test settled, reverted-still-valid, expired-unused, used/mismatched nonce, insufficient
confirmations, exact/mismatched payment and refund candidates, lowercase/case-variant
transaction reuse, sufficient/insufficient funding, wrong chain, and zero real network access.

Only in `cdp-testnet`, `control-plane.mjs` constructs a viem public client with
`baseSepolia` and
`http(env.WALLET_KERNEL_BASE_SEPOLIA_RPC_URL, { timeout: 10_000, retryCount: 0 })`,
then runs observer preflight before either listener. Inject the observer as Task 11's
trusted payment resolver, the independent chain half of the composite refund resolver,
and the funding-status source for operator Overview and testnet evidence. A chain-only
refund match can never confirm a refund. `dependencies.publicClient` replaces live construction in tests.
Deterministic mode never constructs a live RPC client or calls an observer unless an
explicit deterministic fake is injected.

- [ ] **Step 6b: Implement signed seller evidence resolution**

Create `seller-evidence-resolver.mjs`:

```text
createSellerEvidenceResolver({ fetchImpl, mode, now, limits }) -> {
  observeExecution(persistedBinding),
  observeRefund(persistedBinding),
}
```

Each persisted binding contains the exact immutable PolicyVersion ID/hash and seller
projection used for the payment. Revalidate that PolicyVersion, select its exact
seller origin, and construct the endpoint only from that origin plus its canonical
`evidencePath`; never read an evidence URL from the mutable route file or a request.
Each method independently matches the persisted seller origin, resource path, intent,
and settled transaction before it sends one
redirect-disabled bounded `Content-Type: application/json` POST with
one of these exact closed bodies:

```js
{ schemaVersion: 1, kind: 'execution', sellerOrigin, intentHash, transactionId }
{ schemaVersion: 1, kind: 'refund', sellerOrigin, intentHash,
  originalTransactionId, refundTransactionId }
```

Every value is loaded from persistence; the request contains no bearer, cookie, or
other authentication header because trust comes from the pinned response signer. It
never sends a body/prompt, payment
payload/header, agent/operator credential, approval ID, filesystem path, or provider
secret. Require same-origin HTTPS in `cdp-testnet`; the deterministic exception accepts
HTTP only for a literal canonical `127.0.0.1` or `[::1]` seller origin. Enforce a
5-second total deadline, 16-KiB
response ceiling, one JSON response, and no retry.

Validate the exact execution/refund shapes from Task 11, remove `signature`, canonicalize
the remaining closed object with its declared domain, and use viem
`recoverMessageAddress()` to require the immutable PolicyVersion's respective
`executionSigner` or `refundSigner`. Validate issue/expiry against the injected clock
and independently match every persisted binding, including the refund attestation's
exact PolicyVersion `refundSource`. Return only the closed verified
attestation projection with `signature` removed plus its hash, or `unknown` with a
stable redacted reason; never return or persist raw response/error/signature text.
Require both the declared `signer` and recovered signer to equal the pinned policy
address. Tests mutate every field/signature, replay across
intent/origin/kind, exceed deadline/size, redirect, and inject provider exceptions.

In `control-plane.mjs`, compose one trusted resolver whose payment method delegates to
the chain observer, whose execution method delegates to seller evidence, and whose
refund method returns success only when both the verified refund attestation and the
independent chain observer proof match the same persisted refund binding. Partial
success remains `unknown`. Offline process fixtures inject both fake providers; live
construction uses the immutable PolicyVersion seller binding and ordinary bounded
`fetch`.

- [ ] **Step 7: Run both adapter suites offline**

```bash
node --test spikes/pi-wielder/tests/config.test.mjs \
  spikes/pi-wielder/tests/wallet-adapter-contract.test.mjs \
  spikes/pi-wielder/tests/wallet-adapter-deterministic.test.mjs \
  spikes/pi-wielder/tests/wallet-adapter-cdp.test.mjs \
  spikes/pi-wielder/tests/base-sepolia-observer.test.mjs \
  spikes/pi-wielder/tests/seller-evidence-resolver.test.mjs
```

Expected: deterministic and CDP adapters pass the same contract with zero network
access and no credential values in output.

- [ ] **Step 8: Commit the customer-wallet adapter**

```bash
git add spikes/pi-wielder/.env.example \
  spikes/pi-wielder/src/config.mjs \
  spikes/pi-wielder/src/adapters/cdp-wallet-adapter.mjs \
  spikes/pi-wielder/src/adapters/base-sepolia-observer.mjs \
  spikes/pi-wielder/src/adapters/seller-evidence-resolver.mjs \
  spikes/pi-wielder/tests/config.test.mjs \
  spikes/pi-wielder/tests/wallet-adapter-cdp.test.mjs \
  spikes/pi-wielder/tests/base-sepolia-observer.test.mjs \
  spikes/pi-wielder/tests/seller-evidence-resolver.test.mjs
git commit -m "feat: adapt customer CDP wallets"
```

### Task 13: Build the authenticated local operator plane

**Files:**

- Create: `spikes/pi-wielder/src/operator/auth.mjs`
- Create: `spikes/pi-wielder/src/operator/api.mjs`
- Create: `spikes/pi-wielder/src/operator/cli.mjs`
- Create: `spikes/pi-wielder/src/operator/console.mjs`
- Create: `spikes/pi-wielder/src/kernel/release-integrity.mjs`
- Create: `spikes/pi-wielder/src/agent/isolation-preflight.mjs`
- Create: `spikes/pi-wielder/scripts/build-release-manifest.mjs`
- Create: `spikes/pi-wielder/scripts/render-systemd-units.mjs`
- Create: `spikes/pi-wielder/scripts/inspect-systemd-effective.mjs`
- Create: `spikes/pi-wielder/scripts/preflight-live-deployment.mjs`
- Create: `spikes/pi-wielder/scripts/prelaunch-kernel-reader.mjs`
- Create: `spikes/pi-wielder/scripts/preflight-agent-isolation.mjs`
- Create: `spikes/pi-wielder/scripts/agent-isolation-probe-worker.mjs`
- Create: `spikes/pi-wielder/deploy/systemd/wallet-kernel.service`
- Create: `spikes/pi-wielder/deploy/systemd/wallet-kernel-console.socket`
- Create: `.github/workflows/pi-wielder-systemd.yml`
- Modify: `spikes/pi-wielder/package.json`
- Create: `spikes/pi-wielder/operator-console/index.html`
- Create: `spikes/pi-wielder/operator-console/app.mjs`
- Create: `spikes/pi-wielder/operator-console/styles.css`
- Create: `spikes/pi-wielder/tests/operator-auth.test.mjs`
- Create: `spikes/pi-wielder/tests/operator-api.test.mjs`
- Create: `spikes/pi-wielder/tests/operator-cli.test.mjs`
- Create: `spikes/pi-wielder/tests/operator-console.test.mjs`
- Create: `spikes/pi-wielder/tests/release-integrity.test.mjs`
- Create: `spikes/pi-wielder/tests/systemd-units.test.mjs`
- Create: `spikes/pi-wielder/tests/agent-isolation.test.mjs`

- [ ] **Step 1: Write failing owner-credential tests**

Create `operator-auth.test.mjs`. Generate a token file through the public API and
assert it is an owner-only regular file outside the checkout, contains 32 random bytes
encoded as base64url, is reused rather than overwritten, and is rejected when symlinked,
wrong-owner-like, or permissive.
Require exactly 43 ASCII characters matching `/^[A-Za-z0-9_-]{43}$/`, an exact
32-byte base64url decode, and encode/decode round-trip equality; newline, trimming,
padding, or an alternate encoding is invalid and never repaired.

Assert bearer validation uses fixed-length SHA-256 digests and
`crypto.timingSafeEqual()`. Missing, malformed, short, wrong, duplicated, query-string,
or cookie bearer credentials produce only `OPERATOR_UNAUTHORIZED`; no response or log
contains the supplied value.

Exercise the browser launch exchange:

```text
POST /operator/v1/browser-launch on the authenticated admin channel
  -> one random 32-byte, single-use, 60-second capability
  -> exact http://127.0.0.1:8405/operator/#launch=<base64url capability>
browser loads static app, app removes fragment with history.replaceState()
POST /operator/v1/session with body { launchToken }
  -> 204 + HttpOnly; SameSite=Strict; Path=/operator; Secure only when TLS is configured
  -> bounded in-memory session + CSRF value in response header
subsequent mutation -> exact loopback Origin + session cookie + X-CSRF-Token
DELETE /operator/v1/session -> invalidate server-side session and clear cookie
```

The owner token never enters browser memory, storage, URL, HTML, cookie, or TCP. The
launch capability exists only in Kernel memory, is deleted on first exchange, and is
invalid after expiry/restart; the fragment is not sent in the initial HTTP request.
Session expiry, replay, restart, changed origin, missing CSRF, and cross-site requests
fail closed. The static console has no owner-token input.

For live auth, create a Kernel-owned Unix-domain socket under a Kernel-owned `0700`
parent and set the socket mode to `0600` before readiness. The CLI validates the
parent and socket with single-FD/lstat discipline, connects by `socketPath`, and sends
the owner bearer only on that channel. It must run as the Kernel/operator UID. A
wrong-owner, group/other-writable, symlink, regular-file, stale-active, or parent-swap
socket fails closed. After the authority lock proves no other daemon is active, startup
may unlink only a stale same-UID socket inode under that exact parent; it never removes
an arbitrary path. Separately, the root service manager owns and continuously holds
the exact loopback console listener and passes its verified listening FD to the Kernel;
application code never calls `listen(host, port)` for live console authority. A
dropped-Pi-UID fixture must fail to traverse/replace/bind the admin socket and must get
`EADDRINUSE` trying to claim 8405 while the socket unit is active. Missing inherited
FD, wrong socket address/type, or a service-manager restart that drops reservation
blocks live startup. The CLI sends the owner bearer only over UDS; `console launch`
prints the one-time fragment URL.

- [ ] **Step 2: Write the failing operator API contract**

Create an injected service fake and assert these exact routes and methods:

```text
[admin channel only]              POST   /operator/v1/browser-launch
[console channel only]            POST   /operator/v1/session
[console channel only]            DELETE /operator/v1/session
GET    /operator/v1/overview
GET    /operator/v1/policies
POST   /operator/v1/policies/validate
POST   /operator/v1/policies/apply
POST   /operator/v1/agents/:agentInstanceId/revoke
POST   /operator/v1/sessions/:sessionId/transition-policy
POST   /operator/v1/sessions/:sessionId/close
GET    /operator/v1/approvals?state=pending
POST   /operator/v1/approvals/:approvalId/approve
POST   /operator/v1/approvals/:approvalId/deny
GET    /operator/v1/receipts
GET    /operator/v1/receipts/:receiptId
POST   /operator/v1/reconciliations/:intentId/:kind
POST   /operator/v1/reconciliations/:intentId/:kind/abandon-candidate
GET    /operator/v1/exports/:sessionId
GET    /operator/v1/receipt-public-key
```

The admin browser-launch route requires the owner bearer on Unix in live mode (fixed
loopback demo transport only in deterministic mode), mints the Step 1 capability, and
never accepts a cookie. Session POST accepts only that capability plus exact Origin;
DELETE requires the browser session, Origin, and CSRF. Every other route requires a
Unix bearer on the live admin app or an authenticated browser session on the inherited
console app; channel-inappropriate auth is rejected. All mutation bodies use closed schemas and bounded byte
reads. Unknown route, query, body field, state, identifier, or pagination value is
rejected. Approval endpoints accept only operator intent plus a bounded reason code;
they cannot change amount, wallet, quote, policy, challenge, expiry, or request. The
approve and deny handlers call only Task 10's `approvePending()` and `denyPending()`
aggregate services; `operator/api.mjs` is never handed ApprovalQueue itself. The
policy validation body is exactly `{ document }`; it returns the normalized public
policy plus its canonical hash. Policy apply is stateless and accepts exactly
`{ document, expectedPolicyHash }`: it revalidates/recanonicalizes the document and
requires the recomputed hash to equal the displayed validation hash before calling
Task 10's coordinated `applyPolicy()` facade. It never receives Task 3's mutable
repository and never trusts a filename, cached browser object, or
caller-supplied normalized projection. The running API additionally requires the
document wallet to equal the already-loaded adapter identity; a wallet change returns
`WALLET_ROTATION_REQUIRES_OFFLINE_RESTART`. Only after guarded close and Task 13's
verified socket-plus-service maintenance quiesce may the lock-owning offline apply
accept a different wallet, before closed configuration and the adapter are restarted
together. Approval bodies
require the displayed intent hash; reconciliation bodies require the displayed intent
hash plus the applicable displayed case hash, and `kind` is exactly `payment`,
`execution`, or `refund-observation`. Execution accepts no financial evidence and
invokes only the trusted seller resolver. Payment additionally accepts either no
candidate (post-expiry unused-authorization check only) or one canonical public
`paymentTransactionId`; refund observation requires one canonical public
`refundTransactionId`. They reject every receipt/log/block/amount/nonce/wallet/payee/
status or generic evidence field, persist the public candidate before observation,
and require a fresh case hash before replacing a terminally rejected or explicitly
abandoned candidate. The abandon-candidate route accepts only `kind` equal to
`payment` or `refund-observation` and the exact body
`{ expectedIntentHash, expectedCaseHash }`; it preserves the hold/outcome, performs no
resolver call, and returns the newly rotated case hash. Execution has no candidate to
abandon.
Agent revocation accepts exactly `expectedEnrollmentHash`, marks only the active
enrollment revoked through Task 10's coordinated `revokeAgent()` facade, and
immediately removes agent admission. The operator API never receives Task 4's mutable
repository. Revocation does not close or resolve its session; it returns the bound
session IDs that still
need safe operator reconciliation/close.
The session transition body contains exactly `targetPolicyHash` and
`expectedSessionHash`; the target must be active and the Kernel enforces Task 10's
safe-transition blockers. Applying policy returns blocked session summaries, so a
tighter policy is never presented as active-for-agent until each session is either
transitioned or visibly blocked from spending.
The session close body contains exactly `expectedSessionHash`; it uses the same
monetary blockers, never creates a replacement session, and returns an explicit
stop/reconfigure/restart requirement for wallet rotation.

Assert `/agent/v1/*` rejects operator tokens and `/operator/v1/*` rejects agent
traffic. The API receives narrow service functions, never the raw SQLite store, wallet
adapter, permit authority, signer, SDK client, or environment object.

- [ ] **Step 3: Write the failing CLI contract**

Capture stdout/stderr/exit codes for:

```text
wallet-kernel preflight
wallet-kernel agent enroll DESCRIPTOR --confirm DESCRIPTOR_HASH
wallet-kernel isolation attest REPORT --confirm REPORT_HASH
wallet-kernel agent revoke AGENT_INSTANCE_ID --confirm ENROLLMENT_HASH
wallet-kernel console launch
wallet-kernel policy validate FILE
wallet-kernel policy apply FILE --confirm POLICY_HASH
wallet-kernel sessions transition SESSION_ID --to-policy POLICY_HASH \
  --confirm SESSION_HASH
wallet-kernel sessions close SESSION_ID --confirm SESSION_HASH
wallet-kernel approvals list [--state pending]
wallet-kernel approvals approve APPROVAL_ID --confirm INTENT_HASH
wallet-kernel approvals deny APPROVAL_ID --confirm INTENT_HASH --reason OPERATOR_DENIED
wallet-kernel receipts list
wallet-kernel receipts verify RECEIPT_ID
wallet-kernel reconcile payment INTENT_ID --confirm INTENT_HASH \
  --confirm-case PAYMENT_CASE_HASH [--payment-transaction PAYMENT_TRANSACTION_ID]
wallet-kernel reconcile execution INTENT_ID --confirm INTENT_HASH \
  --confirm-case EXECUTION_CASE_HASH
wallet-kernel reconcile refund-observation INTENT_ID --confirm INTENT_HASH \
  --confirm-case REFUND_CASE_HASH --refund-transaction REFUND_TRANSACTION_ID
wallet-kernel reconcile abandon-candidate INTENT_ID \
  --kind payment|refund-observation --confirm INTENT_HASH --confirm-case CASE_HASH
wallet-kernel export SESSION_ID --output FILE
```

`--json` returns one closed machine-readable object; default output is compact text.
Unknown flags and missing operands exit `2`; authenticated API errors exit `1`; success
exits `0`. In `cdp-testnet`, the CLI reads the token file locally and sends it only as
an HTTP bearer over the prevalidated owner-only Unix socket; it never opens TCP. In
deterministic/demo mode only, the injected loopback adapter may send it to the fixed
loopback operator origin. It never prints the token, credentials, payment signature,
or raw content.
`console launch` is UDS-only in live mode, prints only the one-time fragment URL (or a
closed JSON object with URL/expiry), and never invokes a browser/GUI itself. The human
opens it. Tests prove expiry, one-use replay rejection, restart invalidation, and that
neither output nor server state contains the owner bearer.
API/CLI tests prove a tighter policy immediately reports the old session as blocked,
a stale confirmation cannot transition it, unresolved/signed work remains safely
blocked, and a successful transition returns the new session/policy hashes without
exposing the agent credential or accepting a session ID from Pi.
They also prove guarded close leaves the live agent unbound and cannot be used as a
hot wallet-rotation shortcut, and prove revocation immediately rejects the leaked
credential while leaving every unresolved monetary row untouched.

Bootstrap is deliberately offline: `preflight`, `agent enroll`, `policy validate
FILE`, `policy apply FILE`, and `isolation attest` do not require a running listener.
The privileged probe runs after enrollment/policy setup and before attestation import,
as fixed by the exact clean-install sequence below. Agent enrollment
validates the descriptor's exact hash, closed schema, canonical different Pi UID in
live mode, uniqueness, and absence of any raw token before inserting the immutable
active `agent_enrollments` row. These commands validate the owner token,
call `acquireAuthorityLock({ databasePath, role: 'bootstrap', pathTrust })`, prove no Kernel
writer owns the SQLite authority, perform only the requested operation, close/fsync,
and release the lock. Approval, receipt, reconciliation, and export commands remain
authenticated Unix-socket API clients in live mode and loopback clients only in the
deterministic demo. Add tests that a live Kernel or competing
bootstrap process makes offline apply fail with `AUTHORITY_BUSY` and no partial policy
row/event.

Every bootstrap command that can mutate SQLite first opens the receipt signer and runs
the same integrity, semantic, event-chain, missing-receipt repair, signature, and global
receipt-parity checks as startup while still holding the bootstrap lock. Only after
that audit returns healthy may it perform its one requested mutation. If repair
signing or any audit fails, it makes zero enrollment/policy/attestation changes and
returns `AUTHORITY_RECOVERY_REQUIRED`. Tests seed a domain-commit/receipt gap and prove
offline apply/enroll/attest either repairs exact parity first or performs no requested
write; no bootstrap path can advance authority past a missing receipt.

The final clean-install order is exact: privileged immutable release/unit install;
Kernel `preflight`; Pi-side `credential init`; offline `agent enroll`; offline `policy
apply`; `systemctl daemon-reload`; `systemctl enable wallet-kernel-console.socket`
without starting it; effective-config inspection and release-manifest creation;
privileged isolation probe bound to that enrollment/manifest; offline `isolation
attest`; explicit socket start; then service start. Any failure after enablement runs a
root cleanup that disables/stops the socket again; even an abrupt reboot in that short
window remains fail-closed because live preflight cannot find the matching fresh
attestation.

Normal replacement uses guarded session close, authenticated `agent revoke --confirm
ENROLLMENT_HASH`, then a privileged maintenance quiesce in this exact order:
`systemctl disable --now wallet-kernel-console.socket`, `systemctl stop
wallet-kernel.service`, and verification that both units are `inactive`, the socket is
`disabled`, both `Job` values are empty, `MainPID=0`, no listener remains at
127.0.0.1:8405, and a role-`bootstrap` authority-lock probe succeeds. Only then may a
new Pi credential/descriptor, offline replacement enrollment/configuration, and fresh
probe/attestation run. Restore performs `daemon-reload`, enables the socket without
starting it, rechecks the complete effective-config projection, imports the fresh
attestation, starts the socket, and starts the service. A failed maintenance step
leaves the socket disabled and service stopped; it never silently resumes an old
binding. A dropped-Pi connection-storm integration test runs throughout quiesce and
proves that, after socket disablement completes, traffic cannot reactivate the service,
acquire the authority lock, or interfere with the offline mutation.

If compromise requires revocation before a close
that unresolved money blocks, revoke first, remain in operator-only recovery, reconcile
and close, then stop/enroll. Tests cover both orders and prove no second active row is
created. No step edits SQLite by hand.

There are two distinct one-way handoff parents, never one shared writable directory.
`enrollmentInboxPath` is Pi-owned mode `0755`: the Pi helper publishes the untrusted
enrollment descriptor there as canonical JSON plus newline, mode exactly `0644`, and
the Kernel UID has traverse/read but no write permission. `agentRunOutboxPath` is
Kernel-owned mode `0755`: the Kernel publishes bounded public testnet run descriptors
there as `0644`, and the Pi UID has traverse/read but no write permission. The paths
must be distinct, outside both the Pi `0700` credential parent and Kernel `0700`
authority tree, with non-symlink parents whose own parents are not Pi-writable.
Wrong-direction create/rename/delete attempts under dropped Kernel/Pi identities must
fail with `EACCES`.

The raw credential remains `0600` under its Pi-owned `0700` parent. Never put
the descriptor beside the credential. `agent enroll` preflights the handoff parent,
then opens the descriptor once with
`O_RDONLY | O_NOFOLLOW`, then `fstat`s that same descriptor: regular file, link count
one, exact configured nonzero Pi UID/GID, exact mode, and at most 1 KiB. It reads and
hashes only that descriptor, re-`fstat`s to reject size/inode/mtime changes, requires
the confirmed hash and exact canonical five-field bytes, then inserts under the
bootstrap authority transaction. It never resolves ownership from descriptor fields
or reopens by path. Tests cover symlink/hardlink, wrong owner/mode, oversize,
noncanonical bytes, raw-token fields, descriptor swap/race, and mutation after the
human confirmation; all fail without an enrollment row.

Implement `isolation-preflight.mjs` with a pure metadata validator for nonzero
distinct Kernel/agent UIDs and pinned primary GIDs, Kernel-owned `0700` authority
paths, and a Pi-owned `0600` credential outside that tree. The privileged
`preflight-agent-isolation.mjs` launches `agent-isolation-probe-worker.mjs`; the worker
calls `setgroups([])`, then `setgid()`/`setuid()` to the exact target identity with an
empty environment. It must read the Pi credential but receive OS `EACCES`/`EPERM` for
the authority directory, database, operator token, receipt key, and Kernel-only
sentinel. Reject root targets, symlinks, permissive bits, path swaps, and unexpected
readability. A shared primary GID is allowed for macOS only when group permission bits
are zero and this real probe passes.

After the dropped-identity worker exits, the privileged installer process
exclusive-creates a Kernel-UID-owned `0600` report in a preflighted Kernel `0700`
staging parent. Its canonical JSON plus one newline has exactly this closed shape:

```js
const isolationReport = Object.freeze({
  schemaVersion: 1,
  enrollmentHash,
  kernelUid: String(kernelUid),
  kernelGid: String(kernelGid),
  agentUid: String(agentUid),
  agentGid: String(agentGid),
  authorityMetadataHash: `sha256:${'66'.repeat(32)}`,
  credentialMetadataHash: `sha256:${'77'.repeat(32)}`,
  releaseManifestHash: `sha256:${'88'.repeat(32)}`,
  releaseTreeHash: `sha256:${'99'.repeat(32)}`,
  nodeExecutableHash: `sha256:${'aa'.repeat(32)}`,
  serviceArtifactsHash: `sha256:${'bb'.repeat(32)}`,
  systemdEffectiveConfigHash: `sha256:${'cc'.repeat(32)}`,
  environmentMetadataHash: `sha256:${'dd'.repeat(32)}`,
  probeResults: Object.freeze({
    authorityDirectory: 'EACCES',
    database: 'EACCES',
    operatorToken: 'EACCES',
    receiptKey: 'EACCES',
    kernelEnvironment: 'EACCES',
    agentCredential: 'READABLE',
    releaseTreeWrite: 'EACCES',
    dependencyTreeWrite: 'EACCES',
    serviceArtifactsWrite: 'EACCES',
    kernelEnvironmentParentWrite: 'EACCES',
  }),
  probedAt: '2026-07-31T12:00:00.000Z',
  expiresAt: '2026-07-31T12:15:00.000Z',
});
const reportHash = sha256(canonicalJson(isolationReport));
```

The authority and credential metadata hashes cover the closed, ordered ancestor-chain
projections from Task 2—`(role, depth, device, inode, uid, gid, mode)`—plus the leaf
projection, not paths, file contents, mutable size/mtime, or secrets. This binds every
Kernel private/writable root and the Pi credential root to a chain Pi cannot rename.
Validate canonical nonzero
UID/GID strings, the exact active enrollment hash, every deployment hash, all ten
literal result codes,
`probedAt <= now < expiresAt`, and a maximum 15-minute interval. Print only
`reportHash`.

`isolation-preflight.mjs` also exports this durable repository contract:

```text
createIsolationAttestationRepository({ store, now, idFactory }) -> {
  importCurrent({ reportBytes, expectedReportHash, operatorIdHash }),
  currentFor({ enrollmentHash, authorityMetadataHash, releaseManifestHash,
    expectedReportHash }),
}
```

`isolation attest REPORT --confirm REPORT_HASH` opens and hashes the report once under
the bootstrap lock using the descriptor's single-FD discipline. `importCurrent()`
revalidates the closed canonical bytes, requires the current active enrollment hash,
atomically supersedes any prior `current` row, inserts the exact report/hash and public
timestamps into `isolation_attestations`, and appends one redacted import event. Exact
replay is idempotent; a different report needs its own displayed hash. `currentFor()`
accepts no report bytes, returns only an unexpired `current` row whose enrollment and
freshly recomputed Kernel-accessible authority metadata hash match, and never treats a
superseded row as live. The stored `credentialMetadataHash` is the privileged probe's
short-lived attestation, not a value the Kernel recomputes: the Kernel UID must remain
unable to traverse or stat the Pi-owned `0700` credential parent. A real-UID test proves
normal live startup validates the imported report while direct Kernel-identity
credential traversal still receives `EACCES`; passing a caller-supplied or copied
credential metadata hash is not part of the API.
It also requires the freshly verified release-manifest hash to equal the report's
deployment binding; an otherwise valid isolation report for different code cannot
admit the agent. `expectedReportHash` is recomputed from the configured owner-only
report artifact opened once by the Kernel; it must equal the exact current row imported
into SQLite.
Recovery treats malformed JSON/hash, two current rows, enrollment mismatch, inverted
timestamps, or an impossible result code as `AUTHORITY_SEMANTIC_CORRUPTION` before
listeners. Tests inject stat/spawn, exercise import/reopen/expiry/supersede/corruption,
and keep an optional POSIX integration test for human-supplied safe test identities. A
host administrator, root/capability escape, or failed/missing probe is outside the
pilot trust boundary and blocks live admission.

Live executable integrity is part of the same host boundary. `cdp-testnet` may run only
from an installed release such as `/opt/wallet-kernel/releases/<commit>`, never a
developer checkout or Pi-writable workspace. Every ancestor from the configured
trusted prefix through `releaseRoot`, every directory/file under it (including
`src/`, `package.json`, `package-lock.json`, `node_modules/`, launcher, and preflight
scripts), the absolute Node executable, and the service/socket definitions are
root-owned and have no group/other write bit. The Kernel and Pi UIDs can read/execute
what they need but cannot create, modify, rename, or delete any component. Writable
SQLite, keys, sockets, logs, temporary files, and evidence live under separate
Kernel-owned paths and are never children of `releaseRoot`.

`build-release-manifest.mjs` runs only during the privileged install from an exact clean
commit, after `npm ci` and before service start. It exclusive-creates canonical JSON
plus newline under the root-owned release with this closed schema (the manifest itself
is excluded from its tree hash):

```js
{
  schemaVersion: 1,
  commit: '<40 lowercase hex>',
  createdAt: '<canonical UTC timestamp>',
  entrypoint: 'src/control-plane.mjs',
  packageLockHash: 'sha256:<64 lowercase hex>',
  releaseTreeHash: 'sha256:<64 lowercase hex>',
  kernelIdentity: {
    uid: '<canonical positive decimal>',
    gid: '<canonical positive decimal>',
  },
  node: {
    version: 'v24.18.1',
    executablePathHash: 'sha256:<64 lowercase hex>',
    executableSha256: 'sha256:<64 lowercase hex>',
    uid: '0', gid: '<canonical nonnegative gid>', mode: '<canonical octal>',
  },
  environment: {
    environmentMetadataHash: 'sha256:<64 lowercase hex>',
  },
  serviceArtifacts: [{
    role: 'kernel-service' | 'console-socket',
    pathHash: 'sha256:<64 lowercase hex>',
    sha256: 'sha256:<64 lowercase hex>',
    uid: '0', gid: '<canonical nonnegative gid>', mode: '<canonical octal>',
  }],
  systemd: {
    managerVersion: '<bounded canonical systemd version>',
    systemctlVersion: '<bounded canonical systemctl version>',
    systemctlExecutablePathHash: 'sha256:<64 lowercase hex>',
    systemctlExecutableSha256: 'sha256:<64 lowercase hex>',
    effectiveConfigHash: 'sha256:<64 lowercase hex>',
  },
  entries: [{
    path: '<canonical relative path>',
    kind: 'directory' | 'file' | 'symlink',
    uid: '0', gid: '<canonical nonnegative gid>', mode: '<canonical octal>',
    bytes: null | '<canonical decimal>',
    sha256: null | 'sha256:<64 lowercase hex>',
    target: null | '<canonical in-root relative target>',
  }],
}
```

Entries are sorted by canonical relative path and cover the entire release tree except
the manifest. Reject absolute/dot/duplicate paths, devices/FIFOs/sockets, escaping or
dangling symlinks, hard-linked regular files, missing/extra entries, mutable
directories/files, a package-lock mismatch, an entrypoint outside the tree, or a Node
version outside the exact pinned runtime. `kernelIdentity` is the install-time,
root-owned source of truth for the dedicated Kernel's numeric UID/GID; both values
must be canonical positive decimals, must differ from the Pi identity, and may never
be inferred later from an account name, environment variable, report, or mutable
configuration. `serviceArtifacts` is closed, sorted by
`role`, contains exactly one `kernel-service` and one `console-socket` row for the
systemd pilot, and rejects duplicates, missing/extra roles, or path reuse. Its
domain-separated canonical aggregate hash is `serviceArtifactsHash` in the isolation
report. The environment metadata hash covers only
`(device,inode,uid,gid,mode)` for the Kernel-owned `0600` environment file under its
Kernel-owned `0700` parent, never secret contents or its path. Both the service
definition and socket-activation definition are root-owned, content-hashed public
configuration; neither can be omitted merely because the service manager uses two
files.

The install does not equate those file hashes with PID1's loaded configuration.
Before manifest creation it runs the fixed root-owned `/usr/bin/systemctl
daemon-reload`, enables (without starting) `wallet-kernel-console.socket`, and invokes
`inspect-systemd-effective.mjs`. That inspector verifies the absolute `systemctl`
inode/owner/mode and hashes its bytes, accepts bounded output, and invokes only closed
argument arrays—never a shell. For both units it requires `LoadState=loaded`, the
exact installed `FragmentPath`, empty `DropInPaths`, `NeedDaemonReload=no`,
`Transient=no`, and the expected `UnitFileState` (`static` for the socket-triggered
service and `enabled` for the socket). Masked, generated, transient, alias, linked,
runtime-enabled, stale, or overridden units fail.

The inspector requests exactly this security-relevant property set with `systemctl
show --all --no-pager --property=...`, rejects duplicate/missing keys and unbounded or
malformed values, and splits each line only at its first `=`:

```text
both: Id LoadState FragmentPath DropInPaths NeedDaemonReload Transient UnitFileState
service: User Group SupplementaryGroups EnvironmentFiles ExecStartPreEx ExecStartEx
  Restart RestartUSec UMask NoNewPrivileges CapabilityBoundingSet AmbientCapabilities
  ProtectSystem ProtectHome PrivateTmp PrivateDevices ProtectKernelTunables
  ProtectKernelModules ProtectControlGroups LockPersonality RestrictAddressFamilies
  ReadWritePaths UnsetEnvironment Requires After
socket: Listen Accept Service FileDescriptorName ReusePort
```

It canonicalizes scalar values and sorted sets directly. `ExecStartPreEx` and
`ExecStartEx` use a closed parser for systemd's flag-bearing command structure: retain
and hash only the static executable path, exact argv array, and sorted flags array.
Require the preflight flags to equal exactly `['privileged']` (the loaded form of
the unit's `+` prefix) and the main command flags to equal `[]`; `ignore-failure` or
any other flag is forbidden. Explicitly recognize but exclude the runtime-only start/exit timestamp,
PID, result code, and status fields from the hash, and reject any unknown structural
field instead of silently discarding it. The inspector then requires every value
represented by the rendered templates:
numeric Kernel UID/GID, empty supplementary/capability sets, exact environment and
command paths/argv, the complete sandbox and write-path sets, the service's socket
dependency/order, one exact loopback stream, `Accept=no`, exact target service and FD
name, and `ReusePort=no`. It separately records PID1's exact bounded `Version` manager
property and the bounded first `systemctl --version` client line, plus the root-owned
executable path hash/byte hash and domain-separated normalized projection hash, in the manifest's
closed `systemd` object. `build-release-manifest.mjs` accepts that result
only from this post-reload inspection and rechecks it against the renderer output.
The privileged live preflight repeats the same PID1 query and requires byte-for-byte
canonical projection/hash equality with the manifest before it drops identity. Thus a
drop-in, stale manager cache, alternate fragment, runtime property, changed
executable, or skipped daemon reload blocks startup even when the two unit files on
disk still hash correctly.

`preflight-live-deployment.mjs` is invoked by the root-owned service manager before the
Kernel service. Using the pinned absolute root-owned Node binary, the root phase
verifies only root-owned facts: release manifest/tree, Node executable, launcher, both
service artifacts, the freshly loaded PID1 effective-config projection, loader
environment allowlist, Task 2 ancestor chains, and the
dropped-Pi write/create/rename denial probes. It never imports `secure-storage.mjs` or
`authority-lock.mjs`, never opens the Kernel-owned authority/database/report/token/key,
and never relaxes their exact-current-UID owner checks merely because it is root.
Its closed command line contains absolute `--release-manifest`, canonical numeric
`--kernel-uid`, and canonical numeric `--kernel-gid` values rendered into the unit.
Before spawning a child, the root phase requires those values to equal the manifest's
`kernelIdentity`, parses the hashed installed service artifact to require the same
literal numeric `User=`/`Group=` directives, and rejects account names, remapping,
unknown/repeated arguments, or a manifest/argument/unit disagreement.

Authority/report comparison runs in `prelaunch-kernel-reader.mjs`. That file statically
imports built-ins only, starts under the privileged preflight process, immediately
calls `process.setgroups([])`, then `setgid(exactKernelGid)` and
`setuid(exactKernelUid)`, verifies the resulting real/effective identity and empty
supplementary groups, and only then dynamically imports the trusted-path,
secure-storage, authority-lock, and read-only SQLite code. It signals readiness over a
dedicated IPC channel with a root-generated nonce. The root phase spawns the pinned
Node binary with only the reader path plus the manifest-verified numeric
`--kernel-uid`/`--kernel-gid` arguments and `stdio: ['ignore', 'pipe', 'pipe', 'ipc']`;
the child validates that closed argv before dropping. The parent then sends one closed
canonical request containing the same UID/GID, validated public paths, expected
release/ancestor hashes, and current probe-result codes—never CDP credentials, owner
bearer, receipt key, environment contents, or open authority descriptors. The child
must cross-check the two identity copies and reject unknown IPC fields, a second
request, wrong nonce/parent PID, wrong UID/GID, or inherited loader variables. It does
not assert a total descriptor count because Node/libuv owns internal descriptors;
instead the production spawn passes no explicit descriptor beyond stdio plus IPC.
Tests open identifiable regular-file and listening-socket sentinels in the parent and
prove neither is inherited or usable in the normal child. A tampered spawn that adds a
sentinel to an explicit stdio slot, or an IPC request that names any authority,
listener, secret, or extra descriptor, must fail bootstrap before project imports.

Under the exact Kernel UID, the child calls
`acquireAuthorityLock({ databasePath, role: 'prelaunch', pathTrust })`, opens the main
authority strictly read-only, and inspects only the active-enrollment/current-
attestation keys. With one active enrollment, it single-FD opens the already
human-confirmed `isolationReportPath`, requires its hash to equal SQLite's exact
current attestation, requires its `kernelUid`/`kernelGid` to equal the manifest and
fixed bootstrap identity, revalidates its unexpired static bindings and full ancestor-chain
metadata, and requires the root phase's fresh probe codes/hashes to equal that
artifact. It returns only a closed canonical status/digest object, closes SQLite,
releases the lock, and exits; the root parent verifies the nonce/status and exits too
before `ExecStart` begins. Neither phase generates, rewrites, imports, supersedes,
timestamps, or mutates a report/database. Only `preflight-agent-isolation.mjs`
generates a report, and only confirmed offline `isolation attest` imports it. With zero
active enrollment, the dropped child still validates ownership/deployment and returns
explicit `recovery_only`; it skips agent-credential report matching so the operator
plane can start closed to agent spend.

Tests prove a root-direct `secure-storage`/authority open fails owner validation; a
child that remains root, drops to the wrong UID/GID, retains a supplementary group,
or imports project code before dropping cannot return green. A barrier keeps the
dropped child holding `prelaunch` and proves Kernel/bootstrap contenders receive
`AUTHORITY_BUSY`; killing it releases the OS lock. Ancestor swap attempts before and
after the root phase, between IPC readiness and the child open, and after child exit
are either OS-denied to the Pi UID or detected by the child's independently repeated
fd-walk/hash comparison. Root/capability mutation remains outside the pilot threat
boundary.

The dropped-identity worker must receive `EACCES`/`EPERM` for
write/create/rename attempts against the release root, representative source,
lockfile, dependency, launcher, service definitions, environment file/parent, and
Kernel writable roots. Readability of public code is not a failure; writability is.
The previously imported privileged report binds `releaseManifestHash`, `releaseTreeHash`,
`nodeExecutableHash`, `serviceArtifactsHash`, `systemdEffectiveConfigHash`, and
`environmentMetadataHash` alongside
the enrollment/isolation facts.

The service launches with a closed environment and live startup rejects `NODE_OPTIONS`,
`NODE_PATH`, every `LD_*`/`DYLD_*` variable, `GCONV_PATH`, `GLIBC_TUNABLES`, and any unrecognized code-loader
or `WALLET_KERNEL_` field. `release-integrity.mjs` runs again inside the Kernel before
opening SQLite, requires `import.meta.url`/the process entrypoint inside the attested
release, requires `process.getuid()`/`process.getgid()` to equal the manifest's numeric
`kernelIdentity`, and recomputes the complete manifest/external artifact hashes. After it opens
and recovers SQLite, normal admission single-FD hashes the same configured report
artifact and requires `currentFor()` to match its exact DB row and release hash. This
runtime check supplements rather than replaces
the root prelaunch gate. Tests mutate every component/manifest field, inject each
loader variable, add an extra file, swap a parent, and run real dropped-UID negative
write probes; all block before a credential, database, or listener is opened. Restart
tests cover the exact same imported artifact, expiry, DB/artifact hash mismatch,
release-hash mismatch, and zero-active operator recovery without any implicit import.

- [ ] **Step 3a: Pin the Linux systemd service and socket-activation contract**

The two committed files under `deploy/systemd/` are strict templates, not units that
silently discover a checkout. `render-systemd-units.mjs` accepts one closed canonical
install document with canonical positive numeric `kernelUid`/`kernelGid`, concrete immutable
`releaseRoot`, pinned absolute Node executable, owner-only environment file, authority/
evidence/runtime/directional-handoff roots, and installed unit output paths. It rejects unknown fields,
relative paths, shell metacharacters/newlines, a mutable executable/release, same/root
Pi and Kernel identities, or output overwrite. It substitutes every template marker,
fails if any marker remains, and returns the exact service/socket bytes and their
hashes; the privileged installer exclusive-creates the installed units root-owned
`0644`, fsyncs them and their parent, then supplies those two installed paths to
`build-release-manifest.mjs`. No executable path comes from the Kernel environment
file, `PATH`, a `current` symlink, or shell expansion. The renderer accepts UID/GID
numbers only—never account or group names—and writes the same pair into the manifest
input, `User=`/`Group=`, and fixed preflight arguments. Installation may verify that a
human-provisioned account currently resolves to that pair for operator ergonomics,
but the account name is not persisted as authority and a later NSS name remap cannot
change the unit identity.

The rendered `wallet-kernel.service` must contain, and the static test must parse:

```text
[Unit]
Requires=wallet-kernel-console.socket
After=network-online.target wallet-kernel-console.socket

[Service]
Type=simple
User=<exact numeric Kernel UID>
Group=<exact numeric Kernel GID>
SupplementaryGroups=
EnvironmentFile=<absolute owner-only Kernel environment file>
ExecStartPre=+<absolute pinned Node> <immutable release>/scripts/preflight-live-deployment.mjs --release-manifest <absolute immutable manifest> --kernel-uid <exact numeric Kernel UID> --kernel-gid <exact numeric Kernel GID>
ExecStart=<absolute pinned Node> <immutable release>/src/control-plane.mjs
Restart=on-failure
RestartSec=2s
UMask=0077
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
LockPersonality=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
ReadWritePaths=<exact authority root> <exact evidence root> <exact runtime root> <exact Kernel outbox parent>
UnsetEnvironment=NODE_OPTIONS NODE_PATH LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT LD_DEBUG LD_PROFILE GLIBC_TUNABLES GCONV_PATH
```

The renderer emits absolute tokens as individual systemd arguments and rejects
whitespace rather than relying on shell quoting. The environment file remains subject
to the closed configuration allowlist, may not contain any `NODE_*` loader control,
`LD_*`, `DYLD_*`, `GCONV_PATH`, or `GLIBC_TUNABLES`, and is metadata-bound into the
report. The `UnsetEnvironment` defense is applied after all systemd environment
sources; runtime repeats the rejection before dynamic SDK imports. `ExecStartPre=+`
is the only privileged command; systemd's `+` execution deliberately bypasses the
per-command UID/capability/filesystem restrictions for that root preflight, while the
plain `ExecStart` receives empty bounding and ambient capability sets. The integration
test proves it can perform the exact
drop choreography above under the unit's sandbox; the long-running `ExecStart` has the
configured non-root UID/GID, no supplementary groups/capabilities, and write access
only to the four declared roots (the Pi-owned enrollment inbox remains read-only). A directive that weakens this list, grants release/
unit/environment writes, invokes a shell, or derives executable paths from environment
fails the test.

Host provisioning must also make the dedicated Kernel account a member of no
supplementary group in NSS/userdb; the empty `SupplementaryGroups=` directive prevents
unit-added groups but is not treated as proof that host membership is empty. Before
opening secrets or SQLite, live runtime parses `/proc/self/status`, requires the
`Groups:` set to contain no GID other than the exact primary GID (or to be empty under
the platform's representation), and fails closed otherwise. The Linux integration adds
the fixture Kernel user to an extra group, proves startup refusal, removes it, and then
proves green startup.
The same early `/proc/self/status` gate requires `CapInh`, `CapPrm`, `CapEff`, and
`CapAmb` all equal zero for the main process. Unit tests inject each nonzero field and
fail before secrets/SQLite; the root-prefixed preflight is tested separately and is
never mistaken for the long-running Kernel identity.

The rendered `wallet-kernel-console.socket` must contain exactly one
`ListenStream=127.0.0.1:8405`, `Accept=no`,
`Service=wallet-kernel.service`, `FileDescriptorName=wallet-kernel-console`, and
`ReusePort=no`, followed by the exact install section
`[Install]` + `WantedBy=sockets.target`; it is installed/enabled separately under
`sockets.target` and has no
`PartOf=wallet-kernel.service`, so systemd retains the listener across service crashes.
The main process accepts exactly `LISTEN_PID === process.pid`, `LISTEN_FDS === 1`, and
`LISTEN_FDNAMES === 'wallet-kernel-console'`, adopts descriptor 3, verifies it is a
listening `AF_INET/SOCK_STREAM` socket bound to exact `127.0.0.1:8405`, clears the
activation variables, and never calls bind/listen by address. `ExecStartPre` does not
consume or pretend to validate `LISTEN_PID`; the non-root main process performs the
descriptor check before either application listener is admitted.

Create `systemd-units.test.mjs` to render a synthetic immutable release, check both
installed artifact hashes appear in `serviceArtifacts`, run
`inspect-systemd-effective.mjs` after a real daemon reload, require its hash in the
manifest/report, and run `systemd-analyze
verify` plus `systemd-socket-activate --fdname=wallet-kernel-console` in mandatory
Linux CI. The inherited-FD fixture proves descriptor 3/name/address validation, then
crashes/restarts the service while a competing bind still gets `EADDRINUSE`. Static
negative cases remove/change every required directive, add a second listener, insert
an environment-derived executable/shell, make either installed unit mutable, or omit
either artifact from the manifest; all fail. Identity negatives pass an account name,
remap an NSS name after rendering, or alter one UID/GID copy in the unit, preflight
argv, manifest, isolation report, or runtime process fixture: name input is rejected,
remapping has no effect on the numeric unit, and every numeric disagreement fails
before secrets, SQLite, or listeners. A macOS local run reports this Linux
integration as explicitly skipped, never passed; `cdp-testnet` completion requires the
recorded Linux/systemd job to pass.

Effective-config negatives install a drop-in, point `FragmentPath` at an alternate
unit, apply a runtime property, edit a fragment without `daemon-reload`, leave either
unit masked/transient/runtime-enabled, or change every security-relevant projected
property one at a time. They prove `DropInPaths`, fragment/state checks,
`NeedDaemonReload`, or the manifest hash rejects each case before the dropped child or
main process opens authority. A lifecycle fixture records the manifest projection
before first start, starts and cleanly restarts the service, and proves the effective
hash remains identical while the excluded Exec runtime timestamps/PID/status change;
altering any static executable/argv/flag field still changes the hash and blocks. The
fixture cleanup removes all unit/drop-in/enablement
artifacts and reloads PID1 even after a failed assertion.

The Linux integration installs both synthetic units, runs `daemon-reload`, enables the
socket without starting it, and requires `systemctl is-enabled` to report `enabled`
with the exact root-owned `sockets.target.wants/wallet-kernel-console.socket` symlink.
It then starts the socket, proves activation survives a service crash and a simulated
target stop/start cycle, and fails if `[Install]`, `WantedBy=sockets.target`, the
enablement link, or the post-reload effective projection is absent or stale.

Add `test:systemd` to `spikes/pi-wielder/package.json` for the systemd, release-
integrity, and agent-isolation files, and create
`.github/workflows/pi-wielder-systemd.yml`. The workflow has read-only repository
permissions, no secrets, `ubuntu-24.04`, exact Node `24.18.1`, `npm ci`, and actions
pinned to reviewed full commit SHAs. Its privileged step creates two disposable
non-root fixture identities, runs only the dedicated systemd integration wrapper under
`sudo -- /usr/bin/env -i PATH=/usr/bin:/bin` with a closed environment, then removes
the fixture units/users.
The job must not install/enable the real pilot units, contact CDP/Base Sepolia, upload
authority artifacts, or treat a skipped test as success. Task 16 records the workflow
run URL and commit alongside local verification before any `cdp-testnet` claim.

`agent revoke` is an authenticated operator mutation over the Unix admin channel or
browser session, so a compromised Pi capability
can be disabled without first stopping the Kernel; it never authorizes replacement
enrollment until the old binding is safely closed.

- [ ] **Step 4: Write the failing four-view console and activation tests**

Parse the static HTML and assert exactly these navigation views and data scopes:

```text
Overview  -> wallet public identity, agent enrollment/revocation, health, budgets, reserved/unresolved amounts
Policies  -> active version, local validation result, immutable history, guarded transition/close
Approvals -> pending/approved/denied/expired/cancelled exact request metadata and actions
Receipts  -> settled/failed/refunded/unresolved summaries, displayed case hashes, and bounded reconciliation actions
```

Assert all assets are local, no inline script/style, no raw prompt/output element, no
CDN/analytics/font URL, and no form can edit financial binding fields. HTTP tests must
verify CSP `default-src 'self'; connect-src 'self'; frame-ancestors 'none'`,
`X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, and no caching of
authenticated JSON.
The live test starts a real temporary Unix admin socket plus an already-listening
loopback FD that stands in for root socket activation. It exercises CLI
`console launch`, fragment exchange, session/CSRF mutation, restart invalidation, and
one authenticated CLI request. Missing/wrong inherited FD or self-bind attempts fail;
a rogue Pi-identity bind cannot displace the reserved console socket and never receives
the owner bearer.

- [ ] **Step 5: Run the operator and isolation tests and observe missing modules/files**

```bash
node --test spikes/pi-wielder/tests/operator-auth.test.mjs \
  spikes/pi-wielder/tests/operator-api.test.mjs \
  spikes/pi-wielder/tests/operator-cli.test.mjs \
  spikes/pi-wielder/tests/operator-console.test.mjs \
  spikes/pi-wielder/tests/agent-isolation.test.mjs \
  spikes/pi-wielder/tests/release-integrity.test.mjs \
  spikes/pi-wielder/tests/systemd-units.test.mjs
```

Expected: FAIL until the operator modules and static console exist.

- [ ] **Step 6: Implement token/session authentication**

Create `operator/auth.mjs` with:

```text
export function loadOrCreateOperatorToken({ filePath, randomBytes = crypto.randomBytes }) {}
export function createOperatorAuth({ token, mode, origin, now, sessionTtlMs = 900_000 }) {
  return Object.freeze({
    authenticateBearer(request, { transport }),
    issueBrowserLaunch({ transport }),
    exchangeBrowserSession(request),
    authenticateBrowser(request, { mutation }),
    revokeBrowserSession(request),
  });
}
```

Use `loadOrInitializePrivateFile()`, cryptographically random opaque session and CSRF values,
bounded in-memory session count, strict expiry, and constant-time digest comparison.
Restart invalidates all browser launch capabilities/sessions but not the owner token.
`issueBrowserLaunch()` is reachable only after bearer authentication on the admin
channel, stores only a digest plus expiry, and returns the one-time fragment URL.
`authenticateBearer()` requires `transport === 'unix'` in `cdp-testnet` and
rejects any forwarded/channel header that attempts to claim a Unix origin.
The operator-token initializer writes exactly the validated 43-character encoding
with no newline. It never trims, rewrites, or regenerates an existing token; Task 2's
atomic no-replace publication and crash/race tests apply unchanged.
Derive one stable `operatorIdHash` as SHA-256 over a domain separator plus the owner
token bytes. Authenticated services inject that hash into approvals/reconciliations;
HTTP bodies cannot supply it, and raw operator identity/token bytes never enter SQLite,
receipts, projections, evidence, or logs.

- [ ] **Step 7: Implement the narrow API and CLI**

Create `operator/api.mjs`:

```js
export function createOperatorApp({ auth, services, bodyLimits, mode, transport, origin }) {
  // Return a Hono app containing only the routes listed in Step 2.
}
```

Implement `release-integrity.mjs`, `build-release-manifest.mjs`,
`render-systemd-units.mjs`, `inspect-systemd-effective.mjs`,
`preflight-live-deployment.mjs`, and
`prelaunch-kernel-reader.mjs` against the exact manifest/prelaunch contracts above.
All filesystem tests inject a temporary synthetic release; the optional real-UID test
uses only human-supplied safe fixture identities and never changes the developer
checkout.

Create `operator/cli.mjs` with exported `runOperatorCli({ argv, env, requestImpl,
stdout, stderr })` for tests and a direct-execution guard for the binary. `requestImpl`
accepts exactly `{ socketPath, origin, method, path, headers, body }`; the live adapter
uses `node:http.request({ socketPath, ... })`, while the deterministic test adapter may
use fixed-origin TCP. Node's standard `fetch()` is not treated as Unix-socket capable.
Parse commands
without shell interpolation. Write exports with exclusive create, mode `0600`, and
refuse symlink/overwrite unless an explicit safe output path does not yet exist.
Implement the bootstrap commands through a separate
`runOfflineBootstrap({ command, config, operatorToken })` helper that acquires the
same shared role-`bootstrap` process-lifetime authority lock before opening SQLite; it
must not construct an HTTP app or expose a general store
handle. This makes the documented sequence—preflight, Pi credential initialization,
agent enrollment, initial policy apply, privileged isolation probe, attestation import,
then Kernel start—executable without a circular bootstrap
listener.

- [ ] **Step 8: Implement the self-contained local console**

Create `operator/console.mjs` to serve the three static files and browser-authenticated
API. In `cdp-testnet` it accepts only the already-listening root service-manager FD,
validates its socket address/type and activation name, and never self-binds; deterministic
mode may bind its fixed loopback demo port. `app.mjs` reads the launch capability only
from the URL fragment, immediately removes the fragment, exchanges it once, drops the
value, and keeps only the CSRF value in memory. It has no owner-token field. Render
with DOM text properties, never `innerHTML`. Approval confirmation
shows the immutable seller, resource, request hash, amount ceiling, wallet, policy
reason, and expiry immediately before the one-time action.
Reconciliation forms display the immutable local binding and current case hash, accept
only the optional payment or required refund transaction candidate allowed above, and
refresh after every conflict/rejected candidate. They expose a separately confirmed
abandon action for the exact pending payment/refund candidate; its warning states that
the hold remains and only a fresh case hash can name a replacement. They never expose
raw evidence.

- [ ] **Step 9: Run operator tests**

```bash
node --test spikes/pi-wielder/tests/operator-*.test.mjs \
  spikes/pi-wielder/tests/agent-isolation.test.mjs \
  spikes/pi-wielder/tests/release-integrity.test.mjs \
  spikes/pi-wielder/tests/systemd-units.test.mjs
```

Expected: authentication, exact routes, CLI exits, CSP, activated four-view console,
and release/prelaunch integrity all pass.

- [ ] **Step 10: Commit the operator plane**

```bash
git add spikes/pi-wielder/src/operator \
  spikes/pi-wielder/src/kernel/release-integrity.mjs \
  spikes/pi-wielder/src/agent/isolation-preflight.mjs \
  spikes/pi-wielder/scripts/build-release-manifest.mjs \
  spikes/pi-wielder/scripts/render-systemd-units.mjs \
  spikes/pi-wielder/scripts/inspect-systemd-effective.mjs \
  spikes/pi-wielder/scripts/preflight-live-deployment.mjs \
  spikes/pi-wielder/scripts/prelaunch-kernel-reader.mjs \
  spikes/pi-wielder/scripts/preflight-agent-isolation.mjs \
  spikes/pi-wielder/scripts/agent-isolation-probe-worker.mjs \
  spikes/pi-wielder/deploy/systemd/wallet-kernel.service \
  spikes/pi-wielder/deploy/systemd/wallet-kernel-console.socket \
  .github/workflows/pi-wielder-systemd.yml \
  spikes/pi-wielder/package.json \
  spikes/pi-wielder/operator-console \
  spikes/pi-wielder/tests/operator-auth.test.mjs \
  spikes/pi-wielder/tests/operator-api.test.mjs \
  spikes/pi-wielder/tests/operator-cli.test.mjs \
  spikes/pi-wielder/tests/operator-console.test.mjs \
  spikes/pi-wielder/tests/agent-isolation.test.mjs \
  spikes/pi-wielder/tests/release-integrity.test.mjs \
  spikes/pi-wielder/tests/systemd-units.test.mjs
git commit -m "feat: add authenticated local wallet operations"
```

### Task 14: Put Pi behind the route-mapped Spend Control proxy

**Files:**

- Create: `spikes/pi-wielder/routes/base-sepolia.example.json`
- Create: `spikes/pi-wielder/pi-extension/agent.env.example`
- Create: `spikes/pi-wielder/src/agent/credential.mjs`
- Create: `spikes/pi-wielder/src/agent/credential-cli.mjs`
- Create: `spikes/pi-wielder/src/agent/auth.mjs`
- Create: `spikes/pi-wielder/src/spend-control-proxy.mjs`
- Create: `spikes/pi-wielder/src/control-plane.mjs`
- Create: `spikes/pi-wielder/tests/agent-credential.test.mjs`
- Create: `spikes/pi-wielder/tests/agent-auth.test.mjs`
- Modify: `spikes/pi-wielder/tests/agent-isolation.test.mjs`
- Create: `spikes/pi-wielder/tests/spend-control-proxy.test.mjs`
- Create: `spikes/pi-wielder/tests/control-plane.test.mjs`
- Modify: `spikes/pi-wielder/pi-extension/x402.ts:57-138`
- Modify: `spikes/pi-wielder/tests/pi-extension-contract.test.mjs`

- [ ] **Step 1: Write the fixed route map and proxy rejection tests**

Create `routes/base-sepolia.example.json`:

```json
{
  "schemaVersion": 1,
  "routes": [
    {
      "id": "example-model",
      "kind": "openai-chat",
      "method": "POST",
      "upstreamUrl": "https://seller.example/paid/chat/completions",
      "resourceDescription": "Wallet Kernel example model route",
      "resourceMimeType": "application/json",
      "purposeLabel": "model.infer",
      "requestContentTypes": ["application/json"],
      "maximumRequestBytes": 262144,
      "maximumResponseBytes": 1048576
    },
    {
      "id": "example-skill",
      "kind": "tool",
      "method": "POST",
      "upstreamUrl": "https://seller.example/paid/skill",
      "resourceDescription": "Wallet Kernel example Skill route",
      "resourceMimeType": "application/json",
      "purposeLabel": "skill.invoke",
      "requestContentTypes": ["application/json"],
      "maximumRequestBytes": 262144,
      "maximumResponseBytes": 1048576
    }
  ]
}
```

Create the raw capability only under the Pi OS identity, never in Kernel composition.
`credential.mjs` uses Task 2's atomic initializer to publish canonical JSON plus one
newline with exact closed shape `{ schemaVersion: 1, agentInstanceId, token }`: the
instance ID is random 16-byte base64url and token is independent random 32-byte
base64url. Its validator enforces exact 22/43-character round trips, owner UID, `0600`,
no symlink/padding/trimming/unknown fields, and crash/race reuse. It separately writes
an exclusive-create non-secret descriptor:

```js
{
  schemaVersion: 1,
  agentInstanceId,
  credentialDigest: sha256(tokenBytes),
  agentUid: String(process.getuid()),
  agentGid: String(process.getgid()),
}
```

`credential-cli.mjs init --credential FILE --enrollment FILE` runs without any Kernel
token, database, environment, or listener access, prints only the descriptor SHA-256,
and refuses an enrollment overwrite. Validate the digest as exactly one
`sha256:<64 lowercase hex>` value—never double-prefix it. The operator imports that descriptor with Task
13's offline confirmed `agent enroll`; the raw credential file never crosses into the
Kernel identity. Only the per-request bearer reaches bounded authentication memory,
and it never reaches SQLite, logs, receipts, or evidence. Create
`pi-extension/agent.env.example` containing only blank Pi-side route/origin/credential
variables; the Kernel `.env.example` contains no raw agent path.

Implement the Kernel-side boundary in `src/agent/auth.mjs`:

```text
export function createAgentAuth({ store, intents, walletIdentity, activePolicy,
  kernelUid, kernelGid, expectedAgentUid, expectedAgentGid, mode }) {
  return Object.freeze({
    authenticate(request),
    resolveBoundSession(authenticatedAgent),
  });
}
```

`authenticate()` parses exactly `Authorization: WalletKernelAgent <token>`, hashes the
decoded 32 bytes immediately, zeroes the temporary token buffer, and constant-time
compares only fixed-length digests against one active `agent_enrollments` row. It
returns only instance ID, digest, and enrolled UID/GID; it never stores/returns the token
or accepts a session ID. Missing, malformed, duplicate, operator, query/cookie, wrong,
or revoked credentials fail before body parsing. Multiple active enrollments, UID/GID
config mismatch, root identity, or shared Kernel UID fails startup before either
listener with `AGENT_ENROLLMENT_AMBIGUOUS` or the exact identity error. Zero active
enrollment enters explicit `recovery_only` mode: start the authenticated operator plane
and a closed-denial agent listener that returns `AGENT_ENROLLMENT_REQUIRED` before body
or route parsing, create no Spend Session or permit authority, and expose no signing
service. This preserves reconciliation and guarded-close access after a revocation plus
process crash. Initial/replacement enrollment remains an offline bootstrap step, so the
operator stops this recovery-only daemon before importing a replacement.
The recovery-only operator service allowlist is exact: health/Overview, receipt
read/verify, export, payment/execution/refund reconciliation, and guarded session close.
Approval decisions, policy apply/transition, agent enrollment/revocation, session
open/rebind, and every signing/spend route return
`RECOVERY_ONLY_OPERATION_FORBIDDEN` before mutation. In particular,
`transitionSessionPolicy()` cannot create a replacement session for a revoked
enrollment. Route/API tests invoke every normal mutation endpoint in recovery-only mode
and prove only reconciliation/close can write and session-create/permit/signer counts
remain zero.
`resolveBoundSession()` is a read-only exact lookup of the current `open` or
`policy_blocked` binding for that enrollment; it creates nothing and returns
`AGENT_SESSION_UNAVAILABLE` after guarded close.

During composition and before either listener, load zero or one active enrollment—not
the Pi credential file. With zero, enter the recovery-only composition above, preserve
all revoked bindings for operator work, and call no open/create/signing method. With
one, inspect its binding before opening agent admission. With no binding, call Task
10's coordinated `kernel.openOrResumeSession({ agentInstanceId, walletAddress,
policyVersionId: activePolicy.id })`. With one exact `open` binding, require its wallet
and policy to equal the active configuration, then call that same Kernel facade using
the already-pinned policy only to obtain the idempotent existing row. With one
`policy_blocked` binding, do not call an open/create method: preserve it for operator
recovery/status and reject every
agent execute/retry as `POLICY_TRANSITION_REQUIRED`; Task 10's explicit safe transition
must close the old session and atomically rebind the same agent to the active policy.
Any revoked-enrollment binding is retained as history but cannot be selected by an
active replacement enrollment. Two candidate bindings, an
`open` binding on a non-active policy, or any wallet/digest mismatch fails closed.
Task 4's paired repository operations remain the sole underlying
creators/replacers/closers of session and binding rows; live composition reaches them
only through the shared-coordinator Kernel facade and never inserts a binding
separately.
Restart with the same credential therefore reuses the exact session and pending intent
without restoring spend admission; concurrent starts converge.
An enrollment/digest/UID/GID mismatch, multiple open bindings, closed/missing referenced session,
wallet/policy mismatch, or attempted implicit token rotation fails closed before
transport or signing. Tests restart the app over the same authority and prove a
pending approval is found through the same session/fingerprint; an unauthorized local
process, a fresh credential, or a guessed instance ID cannot read, approve, retry, or
spend from it. `agent-isolation.test.mjs` also proves live same-UID composition fails
before either listener and an injected deterministic same-UID fixture is labeled
`simulated`, never `verified`.

In `spend-control-proxy.test.mjs`, call only:

```text
POST /agent/v1/openai/example-model/chat/completions
POST /agent/v1/invoke/example-skill
GET  /agent/v1/intents/:requestId
GET  /agent/v1/receipts/:receiptId
```

The proxy owns one durable Kernel Spend Session for the authenticated Pi identity.
Assert Pi cannot
choose a target URL, method, upstream headers, wallet, session ID, approval ID,
idempotency key, payment header, policy, amount, or payee. Reject unknown route IDs,
wrong methods/content types, oversized bodies, forbidden headers, URL-like path
segments, and operator paths.

Load the route file only through Task 12's shared `validateRouteMap()`; do not add a
second parser. In `cdp-testnet`, `upstreamUrl` is absolute HTTPS. In
`deterministic`, HTTPS is accepted and plain HTTP is accepted only for literal
`127.0.0.1` or `[::1]`; hostnames are ineligible for this exception, and any redirect
fails. Every mode forbids credentials,
fragments, and queries. `resourceDescription` and `resourceMimeType` are bounded public
constants. A 402 resource must match all three exactly before policy selection/signing.
Pi cannot add path segments or query parameters, and seller error or resource free text
is never copied into the payment payload. Unit tests exercise the same validator used
by `control-plane.mjs` in both modes.

Forward only normalized `accept`, `content-type`, and `user-agent` headers. Strip
`authorization`, `cookie`, `host`, `connection`, `proxy-*`, `forwarded`, `x-forwarded-*`,
and every hop-by-hop header before seller contact; tests seed each credential-bearing
header and prove the seller never sees it. Scope intent and receipt lookups to the
proxy-owned Spend Session so a guessed public ID from another session returns `404`.

The tool route uses these stable public envelopes:

```js
{ status: 'completed', requestId, resource: {
  httpStatus, contentType, body,
}, receipt: {
  id, hash, sellerOrigin, chargedAtomic, remainingSessionAtomic,
  terminalState, transactionPrefix,
} }
{ status: 'payment_approval_required', requestId, approval: {
  expiresAt, amountAtomic, sellerOrigin, purposeLabel,
} }
{ status: 'payment_denied', requestId, reasonCode, receipt }
{ status: 'payment_failed', requestId, reasonCode, receipt }
{ status: 'payment_unresolved', requestId, reasonCode, receipt }
{ status: 'payment_rejected', requestId, reasonCode, receipt }
{ status: 'upstream_failed', requestId, reasonCode, receipt }
{ status: 'execution_failed', requestId, reasonCode, receipt }
{ status: 'execution_unknown', requestId, reasonCode, receipt }
{ status: 'refunded', requestId, reasonCode, receipt }
```

Map `completed` to `200`, approval-required to `409`, denial to `403`, definite
pre-sign `payment_failed` to `502`, unresolved to `503`, trusted post-expiry
`payment_rejected` to `402`, and post-hoc `refunded` status to `200` with no invented
resource body. Pre-payment
`upstream_failed` to `502`, settled execution failure to the received upstream status
only for 4xx/5xx (a settled 3xx maps to `502` and never forwards `Location`), and
settled-but-undeliverable `execution_unknown` to `502`.
Both execution outcomes retain the committed-payment receipt. The resource body is the
byte-bounded upstream output held only in process memory; return only its declared content type and no upstream cookies, authorization,
or hop-by-hop headers. Never journal that body or return raw signed bytes, approval ID,
operator identity, provider error, or internal database identifier. An exact ordinary
retry after approval resolves via the proxy’s durable credential-bound session and request
fingerprint. Agent receipt/status lookup is restricted to the proxy-owned current
Spend Session and uses opaque identifiers.

The OpenAI-compatible route passes through a bounded valid OpenAI response body only
after terminal settlement/receipt commit. It adds compact
`X-Wallet-Receipt-Id`, `X-Wallet-Terminal-State`, `X-Wallet-Charged-Atomic`,
`X-Wallet-Session-Remaining-Atomic`, and `X-Wallet-Transaction-Prefix` response
headers. Approval, denial, and unresolved responses use the same stable JSON statuses
above and never masquerade as a model completion.
The agent-scoped GET intent/receipt routes project every `BUYER_OUTCOMES` value,
including reconciliation revisions, and never expose candidate rows, case hashes,
operator identity, or internal IDs.

- [ ] **Step 2: Run the proxy test and observe missing modules**

```bash
node --test spikes/pi-wielder/tests/spend-control-proxy.test.mjs \
  spikes/pi-wielder/tests/control-plane.test.mjs
```

Expected: FAIL with `ERR_MODULE_NOT_FOUND`.

- [ ] **Step 3: Implement the agent-only proxy and environment composition**

Create `spend-control-proxy.mjs`:

```js
export function createSpendControlProxy({ agentAuth, kernel, routes, maximumRequestBytes }) {
  // Return a Hono app with only the four /agent/v1 routes above.
}
```

Create `control-plane.mjs`:

```js
export async function createControlPlane({ env = process.env, dependencies = {} }) {
  // Validate all configuration, secure/open authority, recover, construct adapter,
  // Kernel, agent app, operator app, and close function without starting listeners.
}

export async function startControlPlane(options = {}) {
  // After recovery: live binds operator UDS, attaches activated console FD, then agent
  // loopback; deterministic binds separate operator/agent loopback demo listeners.
}
```

After exclusive startup recovery restores receipt parity, `createControlPlane()` owns
one mutable in-memory admission state and one synchronous
`markAuthorityUnhealthy(code)` closure. That closure changes the gate from `open` to
`closed` before scheduling listener shutdown and is idempotent for the first stable
reason. Construct exactly one Task 7 `createAuthorityMutationCoordinator({
assertAdmissionOpen, markAuthorityUnhealthy })` instance, then inject that exact object
identity and callback into both `createWalletKernel()` and `createReconciler()`. The
operator API receives those two facades and no mutable repository, so every live
operator mutation shares the same FIFO. Agent routes receive only the Kernel facade.
Neither facade, recovery, a route, nor a repository constructs another coordinator.

In `control-plane.test.mjs`, inject spying Kernel/Reconciler factories and a coordinator
factory, assert the coordinator factory is called once, and assert strict object and
callback identity at both constructors. Queue one Kernel terminal receipt-gap fixture,
one reconciliation candidate write/network/resolution fixture, and one operator
mutation: prove FIFO order for each lease, prove the resolver runs only between two
released Reconciler leases, and prove a fail-stop from either facade closes the one
gate before every queued callback. A second coordinator construction, direct mutable
repository exposure to either HTTP app, or live composition without both injections
fails construction.

In `cdp-testnet`, `createControlPlane()` first runs Task 13's in-process release
verification; this occurs before reading any secret, opening SQLite, or constructing
an SDK client and yields the recomputed release-manifest hash. After authority recovery,
`currentFor()` must bind that hash to the imported privileged report before agent
admission. Deterministic composition records `deployment: simulated` and cannot
satisfy this gate.

`createControlPlane()` then acquires `role: 'kernel'` before opening the main database,
loads zero or one active non-secret agent enrollment, and always completes authority
recovery before constructing listeners. Zero selects `recovery_only`, with operator
services plus the closed-denial agent app and no session/signer admission. One loads
its zero-or-one exact binding and follows Task 14 Step 1's
no-binding/open/policy-blocked startup algorithm before constructing the normal proxy
closure. It calls `kernel.openOrResumeSession()` only for the first two legal binding
cases and never for `policy_blocked`; it never opens the Pi credential file. The authenticated agent identity and read-only session
resolver remain inside that closure; each admitted request resolves the current
binding, so a guarded policy transition takes effect without a daemon restart. The
session ID is never returned to Pi or read from an HTTP request, and startup does not
regenerate it merely because the process restarted. Add a file-backed two-start test
with a pending approval: the second start has the same session/intent IDs, exactly one
`session.started` event, and one approval. Add a live transition test proving the next
request resolves only the replacement session, while a safely closed/unbound agent is
denied before route lookup or body parsing.
Add a revocation-crash test: revoke the sole enrollment, abort/restart, enter
`recovery_only`, reconcile/close its retained binding through the operator API, stop,
then complete offline replacement enrollment and fresh isolation attestation before a
normal restart. Assert zero signer/permit/session-create calls in recovery-only mode.
Construct the intent repository with `allowLoopbackHttp: mode === 'deterministic'`;
the proxy passes the selected immutable route ID separately to the Kernel, and the
agent can never place a route ID inside a Kernel request object.

Reject port collisions, non-loopback host configuration, old JSONL passed as SQLite,
wallet/policy mismatch, unknown mode, CDP mode outside Base Sepolia, invalid routes,
failed recovery, and dirty authority before either listener starts. Deterministic mode
is allowed only for offline test/evidence composition. In `cdp-testnet`, bind the
preflighted owner-only operator Unix socket and verify its final inode/mode before
publishing readiness, then attach the browser console only to the verified inherited
root socket-activation FD; never self-bind its port. Start the agent listener only
after both operator channels and the startup report are ready. In deterministic mode,
bind the loopback demo console directly. Shutdown stops admission, waits for
in-flight unsigned work, preserves signed/ambiguous holds, closes the agent listener,
console server, then admin socket, safely unlinks only its own Unix socket inode (the
service manager retains the console reservation), then
closes SQLite and finally releases the process-lifetime authority lock. Acquire that
same role=`kernel` lock before opening the main database or running recovery and retain
it across wallet initialization and both listeners; any offline bootstrap or second
Kernel must receive `AUTHORITY_BUSY` before it can mutate authority state.

In normal `cdp-testnet` admission, preflight also requires non-root distinct
Kernel/agent UIDs, pinned nonzero GIDs, exact enrollment/config identity agreement,
Task 2's independently revalidated full trusted-ancestor chains for every configured
Kernel/config/report/evidence/socket/handoff path, exact terminal modes, and
`currentFor()` returning the unexpired stored
isolation-attestation row for the exact active enrollment and freshly recomputed
Kernel-accessible authority metadata, including the privileged report's attested Pi
credential metadata and successful denial results imported from Task 13's
`spawn`/credential-switch probe. The installer runs that probe
before dropping to the Kernel service account; ordinary runtime code never pretends it
can prove another UID by inspecting mode bits alone. A missing, expired, or
metadata-mismatched attestation blocks normal agent admission. Recovery-only mode has
no active agent identity to attest and therefore skips this admission gate, but still
requires authority recovery, operator authentication, wallet public-identity match,
and the read-only observer needed for reconciliation; it cannot construct or expose a
signing service. Deterministic composition injects `isolation: simulated`, which
is surfaced in health/evidence and cannot satisfy the live gate.

At startup, cross-check every configured route's method, seller origin, and resource
path against the one unique canonical-origin seller entry in the active immutable
PolicyVersion and require the path to match at least one of that entry's canonical
prefixes. Reject a
route/policy mismatch rather than exposing a permanently denied or differently trusted
route. Also reject any non-HTTPS policy seller/evidence binding in `cdp-testnet`; only
deterministic mode may use the literal-loopback HTTP exception.

In `cdp-testnet`, startup must also have the configured Base Sepolia observer from
Task 12 and pass its read-only preflight; missing observer/RPC configuration fails
before wallet signing or admission.

`cdp-testnet` routes require HTTPS. `deterministic` may use plain HTTP only for literal
`127.0.0.1` or `[::1]`; this exception exists solely for the
separate-process offline suite and cannot be selected in CDP mode.

- [ ] **Step 4: Update Pi to remain a thin ordinary HTTP client**

Modify `pi-extension/x402.ts` so its provider points at
`${WALLET_KERNEL_ORIGIN}/agent/v1/openai/${WALLET_KERNEL_MODEL_ROUTE}` and its Skill
tool calls only
`${WALLET_KERNEL_ORIGIN}/agent/v1/invoke/${WALLET_KERNEL_SKILL_ROUTE}`. Both send
ordinary OpenAI/tool JSON plus `Content-Type` and the local-only
`Authorization: WalletKernelAgent <token>` loaded from the owner-only credential file;
the proxy authenticates then strips that header before seller contact. Neither sets any
forbidden payment, idempotency, approval, session, or wallet header. The extension
receives only `WALLET_KERNEL_AGENT_CREDENTIAL_FILE`, opens it once with `O_NOFOLLOW`,
validates the credential file's regular-file/current-owner/`0600` state, parses the closed
credential from those bounded bytes, and keeps the token in memory. It never validates
a path and then reopens it.
Provider/model names and route IDs come from bounded token environment values with
documented local defaults; none may be a URL.

Before reading the credential, require `WALLET_KERNEL_ORIGIN` to use exactly the
`http:` scheme and be an exact queryless, fragmentless, credential-free loopback
origin using literal `127.0.0.1` or `[::1]` and a valid explicit port. Reject every
hostname, non-loopback address, path, and alternate scheme before the token enters
memory. Contract tests prove a hostile origin cannot
receive or cause a read of the credential.

Render `payment_approval_required` with seller, amount, purpose, and expiry, then tell
the Wielder to retry the same tool call after an operator decision. Render denial and
definite payment failure separately from unresolved reason codes, with a compact
receipt ID/hash. Never auto-poll, auto-retry, or
open the operator console.

Extend `pi-extension-contract.test.mjs` to scan the extension source for all forbidden
headers and imports, assert the fixed `/agent/v1/openai/` and `/agent/v1/invoke/`
prefixes, and test response
rendering for approval, denial, expiry, definite payment failure, upstream failure,
completed receipt, trusted `payment_rejected`, post-hoc `refunded`, and unresolved
outcomes. Tests also prove the credential value never reaches seller
fixtures, output, diagnostics, or persisted events.
The extension requires the credential file owner to equal its own nonzero
`process.getuid()`; a Kernel-owned, root-owned, or permissive credential is rejected.

Add `RAW_PROMPT_SENTINEL` in an agent body/query attempt and
`PROVIDER_EXCEPTION_SENTINEL` in challenge free text and thrown adapter/transport
errors. Reopen SQLite and scan every text column/event plus captured logs and receipts;
neither sentinel may occur. The body/query attempt still yields only hashes or a stable
query rejection, and provider failures yield only stable reason codes.

- [ ] **Step 5: Run proxy, Pi, and legacy proxy tests**

```bash
node --test spikes/pi-wielder/tests/agent-credential.test.mjs \
  spikes/pi-wielder/tests/agent-auth.test.mjs \
  spikes/pi-wielder/tests/agent-isolation.test.mjs \
  spikes/pi-wielder/tests/spend-control-proxy.test.mjs \
  spikes/pi-wielder/tests/control-plane.test.mjs \
  spikes/pi-wielder/tests/pi-extension-contract.test.mjs
node --test spikes/pi-wielder/tests/proxy-trust.test.mjs \
  spikes/pi-wielder/tests/runtime-boundaries.test.mjs
```

Expected: the new Pi path can reach only configured routes, and the legacy proxy
security suite remains green.

- [ ] **Step 6: Commit the Pi cutover surface**

```bash
git add spikes/pi-wielder/routes/base-sepolia.example.json \
  spikes/pi-wielder/pi-extension/agent.env.example \
  spikes/pi-wielder/src/agent/credential.mjs \
  spikes/pi-wielder/src/agent/credential-cli.mjs \
  spikes/pi-wielder/src/agent/auth.mjs \
  spikes/pi-wielder/src/spend-control-proxy.mjs \
  spikes/pi-wielder/src/control-plane.mjs \
  spikes/pi-wielder/tests/agent-credential.test.mjs \
  spikes/pi-wielder/tests/agent-auth.test.mjs \
  spikes/pi-wielder/tests/agent-isolation.test.mjs \
  spikes/pi-wielder/tests/spend-control-proxy.test.mjs \
  spikes/pi-wielder/tests/control-plane.test.mjs \
  spikes/pi-wielder/pi-extension/x402.ts \
  spikes/pi-wielder/tests/pi-extension-contract.test.mjs
git commit -m "feat: route Pi spending through wallet kernel"
```

### Task 15: Prove the product slice across real processes and pinned Pi

**Files:**

- Create: `spikes/pi-wielder/tests/fixtures/x402-v2-seller-process.mjs`
- Create: `spikes/pi-wielder/tests/fixtures/pi-model-process.mjs`
- Create: `spikes/pi-wielder/tests/fixtures/pi-client-process.mjs`
- Create: `spikes/pi-wielder/tests/fixtures/control-plane-process.mjs`
- Create: `spikes/pi-wielder/tests/fixtures/loopback-only-preload.cjs`
- Create: `spikes/pi-wielder/scripts/lib/spend-control-process-runner.mjs`
- Create: `spikes/pi-wielder/tests/spend-control-process-e2e.test.mjs`
- Create: `spikes/pi-wielder/spend-control-e2e.mjs`
- Modify: `spikes/pi-wielder/package.json`

- [ ] **Step 1: Add exact package scripts**

Add:

```json
{
  "scripts": {
    "test:kernel": "node --test tests/kernel-*.test.mjs tests/wallet-*.test.mjs tests/eip3009-exact.test.mjs tests/x402-v2-transport.test.mjs tests/base-sepolia-observer.test.mjs tests/seller-evidence-resolver.test.mjs tests/config.test.mjs tests/projection-exporter.test.mjs tests/agent-*.test.mjs tests/operator-*.test.mjs tests/spend-control-proxy.test.mjs tests/control-plane.test.mjs",
    "e2e:spend-control": "node spend-control-e2e.mjs",
    "verify:spend-control": "npm test && npm run e2e && npm run e2e:spend-control",
    "control-plane": "node src/control-plane.mjs",
    "operator": "node src/operator/cli.mjs"
  }
}
```

Merge these keys into the existing scripts object; do not replace legacy scripts.

- [ ] **Step 2: Build separate-process fixtures**

`x402-v2-seller-process.mjs` starts a deterministic x402 v2 resource on
`127.0.0.1` and reports its assigned port over IPC. It has routes that simulate
settled success, settled HTTP 302/404/500, valid settlement followed by 2xx body loss, pre-header
paid-response loss, explicit rejection, malformed settlement, delayed response, and
refund observation. Its paid model route forwards
only the ordinary body to `pi-model-process`; its paid Skill route returns the scripted
tool result. It validates one exact `PAYMENT-SIGNATURE` per attempt and keeps counted
state in a supplied owner-only file. Its fixed evidence endpoint returns deterministic
domain-separated execution/refund attestations signed by a test-only derived seller
account matching the fixture PolicyVersion. The refund fixture also exposes a public
payment/refund transaction IDs plus separate RPC-shaped transfer proofs; tests mutate the
operator-supplied ID, each attestation, signature, and every observed chain field
independently and never treat local intent/quote hashes as RPC facts.

`pi-model-process.mjs` implements the minimal local OpenAI-compatible streaming API
needed by the pinned Pi binary. The first deterministic response requests the fixed
`invoke_skill` tool once; the second summarizes the tool result and emits
`PI_WALLET_OK`. The Pi extension registers provider `wallet-kernel-e2e`, model
`scripted-local`, and points that provider through the Kernel's fixed
`/agent/v1/openai/example-model` route. Thus both model turns and the tool request are
ordinary Pi HTTP traffic governed by the Wallet Kernel. The model fixture makes no
network call.

`loopback-only-preload.cjs` wraps Node socket/DNS entry points and throws
`EXTERNAL_EGRESS_FORBIDDEN` for any destination other than `127.0.0.1`, `::1`, or
`localhost`. Apply it through `NODE_OPTIONS=--require=<absolute path>` to Pi and every
fixture process; record attempted destinations without credentials and assert the log
is empty.

`control-plane-process.mjs` is the only Kernel child entrypoint. It invokes
`startControlPlane()` in deterministic mode against supplied owner-only authority,
policy, route, and already-enrolled non-secret agent identity, with test-only injected listen overrides for
ephemeral loopback ports. After authority locking, recovery, session resumption, and
both listeners are ready, send one closed IPC message
`{ type: 'ready', agentOrigin, operatorOrigin, walletAddress, receiptPublicKey }`.
Never send the operator/agent token, store handle, environment, signed bytes, or
provider errors. `{ type: 'shutdown' }`, SIGINT, and SIGTERM perform bounded graceful
close; startup failure sends `{ type: 'fatal', code }` and exits `1`. Ephemeral-port
overrides exist only through injected deterministic test dependencies, never
`cdp-testnet` environment configuration.

Create `scripts/lib/spend-control-process-runner.mjs` with this reusable API:

```text
runSpendControlProcessAcceptance({
  authorityDirectory,
  piExecutable,
  nodeExecutable = process.execPath,
}) -> Promise<{ summary, evidenceInput, cleanup }>
```

The caller supplies an empty `0700` authority directory and owns its eventual removal.
The runner creates the Pi credential and enrollment descriptor through the real Pi-side
helper, imports only the descriptor through the real offline bootstrap path, and never
passes the credential path/token to the control-plane child. Because the process suite
runs as one CI UID, it injects the deterministic-only same-identity allowance and
records `isolation: simulated`; this suite cannot produce live-isolation evidence. The
runner writes closed `0600` policy/route/config inputs, starts model, seller,
control-plane, and Pi children with IPC readiness and deadlines, drives all acceptance
scenarios through agent/operator HTTP, restarts the control-plane child over the same
SQLite authority, and obtains the final sanitized projection, normalized events,
receipt envelopes, and public keys before shutdown. It always terminates children in
`finally`; returned `cleanup()` is idempotent and removes only runner-owned temporary
process artifacts, not the caller's directory. Child environments are allowlisted and
use the loopback preload. `evidenceInput` contains no absolute paths, request/response
bodies, payment payload/header, tokens, credentials, or provider errors.

`pi-client-process.mjs` launches the repository-local binary only:

```js
const piBin = path.resolve('node_modules/.bin/pi');
spawn(piBin, [
  '-p', scriptedPrompt,
  '--no-session',
  '--no-context-files',
  '--no-skills',
  '--no-prompt-templates',
  '--no-themes',
  '--no-extensions',
  '--no-builtin-tools',
  '--no-approve',
  '--offline',
  '-e', path.resolve('pi-extension/x402.ts'),
  '--provider', 'wallet-kernel-e2e',
  '--model', 'scripted-local',
], {
  cwd: path.resolve('.'),
  env: {
    ...minimalEnvironment,
    PI_OFFLINE: '1',
    PI_CODING_AGENT_DIR: temporaryPiDirectory,
    WALLET_KERNEL_ORIGIN: `http://127.0.0.1:${kernelPort}`,
    WALLET_KERNEL_AGENT_CREDENTIAL_FILE: agentCredentialFile,
    WALLET_KERNEL_PROVIDER_NAME: 'wallet-kernel-e2e',
    WALLET_KERNEL_MODEL_NAME: 'scripted-local',
    WALLET_KERNEL_MODEL_ROUTE: 'example-model',
    WALLET_KERNEL_SKILL_ROUTE: 'example-skill',
    NODE_OPTIONS: `--require=${loopbackOnlyPreload}`,
  },
  stdio: ['ignore', 'pipe', 'pipe'],
});
```

Resolve `piBin` from `spikes/pi-wielder`; assert `pi --version` is exactly `0.80.6`
before the test. Pass an allowlisted minimal environment, not `process.env`, so CDP,
wallet, and unrelated developer credentials cannot leak into fixtures.
Give every child a 30-second total deadline. On expiry send `SIGTERM`, wait at most two
seconds, then `SIGKILL` the isolated process group and fail with `PROCESS_DEADLINE`.

- [ ] **Step 3: Write process-level commercial acceptance tests**

In `spend-control-process-e2e.test.mjs`, create a temporary `0700` authority directory,
call `runSpendControlProcessAcceptance()` once, independently inspect its persisted
outcomes and `evidenceInput`, and remove only the caller-owned directory in `t.after()`.
The shared runner spawns seller, Kernel/operator, scripted model, and real pinned Pi as
separate children on dynamically assigned loopback ports. Drive and assert:

```text
1. policy-allowed exact payment settles once and returns a verifiable receipt
2. untrusted seller and over-budget request deny before signer call
3. approval-needed survives Kernel restart; operator approves; exact Pi retry settles
4. operator denial and approval expiry never sign
5. a changed challenge after approval terminalizes the old approval and never signs it
6. table-driven settled HTTP 302/404/500 commits spend, opens refund-pending, never follows redirect, and blocks new wallet spend
7. valid settlement followed by body loss opens execution reconciliation; a signed execution attestation resolves once and revises the receipt
8. pre-settlement paid-response loss holds budget, blocks the wallet, and never blindly retries
9. a second 402 or `PAYMENT-RESPONSE success:false` after signature is unresolved, never treated as rejection
10. operator-named trusted settlement reconciliation commits once but remains execution-blocked until a signed seller execution attestation resolves and revises the receipt
11. a confirmed wrong refund candidate becomes rejected without release; a freshly confirmed operator-named, seller-attested, RPC-confirmed full refund then releases once and revises the receipt
12. fresh process verifies SQLite event chain, projection, and every receipt
13. Pi request contains none of the forbidden authority headers
14. every child records zero non-loopback egress attempts
15. unauthenticated/wrong-agent local calls fail before body read or signer invocation
16. the same agent credential reattaches to the same Spend Session after Kernel restart
17. tighter policy apply blocks old session immediately and guarded transition rebinds it
18. enrollment revocation rejects the old token; crash/restart with zero active enrollment enters signer-free recovery-only mode so the operator can reconcile and guarded-close the retained session; confirmed replacement enrollment plus fresh isolation attestation and clean restart create one fresh same-policy session without resetting wallet history
```

Assert exact process exit codes, HTTP counts, signer counts, transaction uniqueness,
and persisted states—not just console text. Kill children in `t.after()` and retain
stdout/stderr only on failure with secret redaction.

- [ ] **Step 4: Create the one-command offline runner**

`spend-control-e2e.mjs` creates a fresh `0700` temporary authority directory, calls
`runSpendControlProcessAcceptance()` directly (never shells out to `node --test`),
prints only `result.summary`, invokes cleanup, and removes the directory in `finally`.
It exits nonzero unless every invariant passes:

```json
{
  "mode": "offline-deterministic",
  "piVersion": "0.80.6",
  "x402Version": 2,
  "network": "eip155:84532",
  "isolation": "simulated",
  "tests": 18,
  "passed": 18,
  "liveCdp": "not-run",
  "testnetTransaction": "not-run"
}
```

Do not label the output “on-chain”; it is protocol-shaped deterministic evidence.

- [ ] **Step 5: Run focused and full offline acceptance**

```bash
npm run test:kernel --prefix spikes/pi-wielder
npm run e2e:spend-control --prefix spikes/pi-wielder
npm run e2e --prefix spikes/pi-wielder
npm test --prefix spikes/pi-wielder
npm test --prefix prototype
```

Expected: all new tests pass; the legacy baseline remains at least 237/237 unit,
41/41 offline e2e, and 23/23 prototype. Loopback tests require an environment that
permits `127.0.0.1` listeners.

- [ ] **Step 6: Commit process acceptance**

```bash
git add spikes/pi-wielder/package.json \
  spikes/pi-wielder/tests/fixtures/x402-v2-seller-process.mjs \
  spikes/pi-wielder/tests/fixtures/pi-model-process.mjs \
  spikes/pi-wielder/tests/fixtures/pi-client-process.mjs \
  spikes/pi-wielder/tests/fixtures/control-plane-process.mjs \
  spikes/pi-wielder/tests/fixtures/loopback-only-preload.cjs \
  spikes/pi-wielder/scripts/lib/spend-control-process-runner.mjs \
  spikes/pi-wielder/tests/spend-control-process-e2e.test.mjs \
  spikes/pi-wielder/spend-control-e2e.mjs
git commit -m "test: prove wallet kernel across real processes"
```

### Task 16: Produce recomputable evidence, operating docs, and the release handoff

**Files:**

- Create: `spikes/pi-wielder/src/evidence-bundle.mjs`
- Create: `spikes/pi-wielder/scripts/run-evidence.mjs`
- Create: `spikes/pi-wielder/scripts/run-testnet-agent.mjs`
- Create: `spikes/pi-wielder/scripts/verify-evidence.mjs`
- Create: `spikes/pi-wielder/scripts/verify-no-tracked-secrets.mjs`
- Create: `spikes/pi-wielder/tests/evidence-bundle.test.mjs`
- Create: `spikes/pi-wielder/tests/testnet-agent-runner.test.mjs`
- Create: `spikes/pi-wielder/tests/no-tracked-secrets.test.mjs`
- Modify: `spikes/pi-wielder/package.json`
- Modify: `spikes/pi-wielder/README.md`
- Modify: `spikes/pi-wielder/RUNBOOK.md`
- Modify: `spikes/pi-wielder/.env.example`
- Create: `docs/handoffs/2026-07-31-agent-spend-control-release-handoff.md`

- [ ] **Step 1: Write failing evidence-bundle tests**

Generate an offline bundle in a temporary directory containing exactly:

```text
manifest.json
events.jsonl
summary.json
report.md
README.md
```

The manifest’s closed schema is:

```js
{
  schemaVersion: 1,
  createdAt,
  mode: 'offline-deterministic' | 'base-sepolia-testnet',
  git: { commit, dirty },
  runtime: { nodeVersion, piVersion },
  protocol: { x402Version: 2, network: 'eip155:84532', asset: BASE_SEPOLIA_USDC },
  wallet: { provider, walletIdHash, address },
  isolation: {
    status: 'simulated' | 'enforced',
    preflightDigest: null | 'sha256:<64 lowercase hex>',
    kernelIdentityHash: 'sha256:<64 lowercase hex>',
    agentIdentityHash: 'sha256:<64 lowercase hex>',
  },
  deployment: {
    status: 'simulated' | 'enforced',
    releaseManifestDigest: null | 'sha256:<64 lowercase hex>',
    releaseTreeHash: null | 'sha256:<64 lowercase hex>',
    serviceArtifactsHash: null | 'sha256:<64 lowercase hex>',
    systemdEffectiveConfigHash: null | 'sha256:<64 lowercase hex>',
  },
  inputs: { policyHash, routeMapHash, configHash },
  source: {
    authorityEventHeadHash,
    signedProjectionHash,
    receiptKeys: [{ keyId, algorithm: 'Ed25519', publicKeyPem }],
  },
  files: [{ path, sha256, bytes }],
  status: { liveCdp, walletFunded, testnetTransaction },
}
```

`files` contains exactly `events.jsonl`, `summary.json`, `report.md`, and `README.md`.
It deliberately excludes `manifest.json`, avoiding a self-referential hash. The
builder returns the manifest's own SHA-256 as an external trust-anchor value; the
verifier must receive that expected value from outside the bundle.

Assert `verifyEvidenceBundle(directory, { expectedManifestSha256 })` first hashes the
exact manifest bytes and fails unless they match the required external digest, then
recomputes every listed file hash, normalized
event count, decision count, amount total, transaction uniqueness, receipt signature,
receipt revision link, and normalized evidence-chain head from `events.jsonl`; it never
trusts `summary.json`. It verifies the signed projection in `summary.json` against the
manifest public keys and proves its authority-event-head anchor equals
`source.authorityEventHeadHash`. It does not claim to recompute the private SQLite
event chain from redacted evidence. Mutate each file independently and assert
verification fails. Also mutate a manifest-only field, substitute a new receipt public
key/signature pair, and replace all files plus recomputed embedded hashes; each must
still fail against the original expected manifest digest. Missing or malformed
`expectedManifestSha256` always fails closed.
The verifier requires `offline-deterministic -> isolation.status = simulated` with a
null digest and `base-sepolia-testnet -> isolation.status = enforced` with a valid
unexpired imported preflight digest. Identity hashes are domain-separated hashes over
the pinned UID/GID pair, never raw local identity/path values. No offline bundle may
claim enforced isolation. The same mode relation applies to `deployment`: offline has
four null hashes, while testnet must match the root-owned release manifest/tree,
aggregate service-artifact hash, and PID1 effective-config hash bound into the
imported privileged report.

Recursively scan the entire bundle for raw bodies, prompts, responses, payment
signatures/payloads, agent credentials, operator token/raw identity, provider exceptions, and
absolute paths. Synthetic tests write only under the test temporary directory and
never modify committed evidence.

- [ ] **Step 2: Run the test and observe missing modules**

```bash
node --test spikes/pi-wielder/tests/evidence-bundle.test.mjs \
  spikes/pi-wielder/tests/testnet-agent-runner.test.mjs
```

Expected: FAIL with `ERR_MODULE_NOT_FOUND`.

- [ ] **Step 3: Implement build and independent verification**

Create `evidence-bundle.mjs`:

```js
export function buildEvidenceBundle({ outputDirectory, manifestInput, events, receipts }) {}
export function verifyEvidenceBundle(outputDirectory, { expectedManifestSha256 }) {}
```

Use canonical JSON plus newline for JSON files and one closed sanitized event per JSONL
line. Each normalized event contains only sequence, event type, entity hash, decision,
canonical atomic amount when relevant, public transaction ID when settled, receipt
hash/signature, and its own normalized predecessor/event hashes. It never contains the
authoritative `data_json`, payment payload/header, raw request/response, or local path.
Sort events by durable sequence and file entries by path. Generate summary/report from
normalized events. Verification replays that normalized evidence chain and verifies
the signed authority projection and receipts with manifest public keys; it does not
open SQLite or call a network.

Import the exact `runSpendControlProcessAcceptance()` runner created in Task 15; do not
fork a second orchestration path. Offline `run-evidence.mjs` creates the caller-owned
`0700` authority directory, calls the runner once, builds from its in-memory signed
projection, normalized events, receipt envelopes, public keys, and runtime summary,
and finishes writing/re-verifying before calling `cleanup()` and removing the authority
directory. A `finally` path still stops child processes, but temporary authority cannot
be removed while evidence construction needs it.
`buildEvidenceBundle()` returns `{ manifestSha256 }` after fsyncing the files and parent
directory. `run-evidence.mjs` passes that in-memory value directly into the verifier
before cleanup, prints it in its final canonical result, and writes the digest plus
newline to a required `--anchor-output` owner-only exclusive-create file outside the
bundle directory. It fsyncs that file and its parent and never reloads an "expected"
digest from the bundle it is verifying. Refuse an anchor path inside the bundle, a
symlink, or an overwrite.

Create `run-evidence.mjs` with explicit `--mode offline-deterministic` and
`--mode base-sepolia-testnet`. Offline mode invokes the deterministic process runner.
Testnet mode must enforce all of these gates before constructing a real adapter:

```text
attested root-owned release manifest/tree re-verifies and supplies exact commit/hash
explicit new output directory under configured Kernel-owned `evidenceRoot` as
  YYYY-MM-DD-agent-spend-control-RUN_ID/ and it does not exist
validated public configuration network equals eip155:84532
active policy wallet equals CDP wallet
operator preflight green
imported agent-isolation preflight is unexpired, metadata-matched, and `enforced`
`baseSepoliaObserver.fundingStatus({ walletAddress,
requiredAtomic: runIntent.maximumTotalAtomic })` reports `sufficient` at a recorded block
--confirm-sha256 equals SHA-256 of canonical run intent
```

For testnet, `manifest.git.commit` comes from the attested release manifest and
`git.dirty: false` means the installed tree exactly reverified against that manifest;
the live command never runs `git status` in a checkout. Offline/developer evidence
still records the actual Git worktree state.

The run intent contains release manifest/tree/service-artifact/effective-systemd
hashes, commit, wallet address, policy hash, route hash, maximum total
atomic amount, exact seller routes, and expiry. Print its digest and exit `2` without
the exact human-provided confirmation. Never request faucet funds, transfer funds,
select mainnet, overwrite an evidence directory, or infer authorization from an
environment variable. Do not execute testnet mode during implementation.

Testnet evidence preserves OS separation. The Kernel-side command never reads or
spawns with the Pi credential. After confirmation it exclusive-creates a public,
bounded synthetic agent-run descriptor in the Kernel-owned `0755`
`agentRunOutboxPath`, mode `0644`, using no-follow/no-overwrite single-FD checks, and
waits on a
bounded authority-event completion condition. The human separately runs
`run-testnet-agent.mjs --run-intent FILE --confirm-sha256 DIGEST` under the enrolled Pi
UID/GID; that script validates the descriptor, its own UID/GID and `0600` credential,
opens the run descriptor once with `O_RDONLY | O_NOFOLLOW`, and verifies the exact
Kernel owner/mode/hash before use,
then drives only the listed ordinary agent routes. It has no operator token/CDP
environment and emits no credential. `testnet-agent-runner.test.mjs` proves the split
with fake loopback services, wrong-identity/hash/parent-mode rejection, Pi write/rename
denial in the outbox, Kernel write/rename denial in the Pi-owned enrollment inbox, and
zero Kernel-side credential reads. Timeout leaves the evidence run `not-run`/incomplete and does not
weaken the spend ceiling.

Observer preflight, funding availability, and the human digest gate must all pass
before any intent can reach the signer. An insufficient/unavailable balance observation
exits without signing. The observer has no mutation/funding method, and the command
never faucets, funds, transfers, or silently lowers the run-intent maximum.

Only testnet mode writes under the configured Kernel-owned `0700` `evidenceRoot`
outside the immutable release, and it records normalized per-request evidence plus Base
Sepolia transaction links. The Pi UID must receive `EACCES` there. Offline mode
requires an explicit temporary output path and may not write into or replace any
existing evidence directory. Copying a verified sanitized testnet bundle into the
repository is a separate human-reviewed release step: verify against the out-of-band
anchor first, copy to a new immutable path, and commit from a developer checkout. The
live process never writes into its source/release tree.

- [ ] **Step 4: Add evidence scripts**

Add:

```json
{
  "scripts": {
    "evidence:offline": "node scripts/run-evidence.mjs --mode offline-deterministic",
    "evidence:verify": "node scripts/verify-evidence.mjs",
    "verify:no-secrets": "node scripts/verify-no-tracked-secrets.mjs"
  }
}
```

`verify-evidence.mjs` requires one directory argument plus
`--expect-manifest-sha256 <64-lowercase-hex>`, prints canonical JSON, and exits `0`
only when the external anchor and all recomputation succeed. Public verification must
obtain that digest from the release handoff, signed release metadata, or another
out-of-band channel—never from a file inside the bundle being verified.

`verify-no-tracked-secrets.mjs` obtains paths with `git ls-files -z`, rejects tracked
authority/key/token/agent-credential/local-enrollment filenames and common private-key encodings, then compares every
configured environment secret value of at least eight bytes against tracked file bytes.
It also safely reads the configured owner-only receipt-key, operator-token, and
CDP secret values available to the Kernel identity and performs the same comparison.
It must not read the Pi-owned agent credential, which the Kernel UID is required to be
unable to access. An optional separate `--agent-credential FILE` Pi-side invocation
runs under the Pi identity and scans that one token against tracked bytes without
granting the Kernel access. It prints
only the environment variable name and offending path—never the candidate value—and
exits nonzero on a match. `no-tracked-secrets.test.mjs` uses synthetic marker values to
prove exact, multiline, and base64-like values fail while variable names in example
files pass.

- [ ] **Step 5: Update the runbook and package README honestly**

Document:

- supported POSIX host requirements, Node 24.18.1+ for deterministic development,
  exact Node 24.18.1 for the attested live release, and `npm ci`;
- privileged install from a clean commit into the root-owned immutable release tree,
  systemd-unit rendering to exact immutable paths, release-manifest creation/
  verification, mandatory daemon reload, PID1 effective-config hash verification,
  `[Install] WantedBy=sockets.target`, enabling the console socket independently,
  root-to-Kernel-child prelaunch choreography, forbidden loader environment, and
  separate Kernel-writable data/evidence/runtime roots;
- owner-only authority directory creation outside the checkout, the configured
  root-owned trusted ancestor, full descriptor-walk validation for every private/
  writable/config/handoff path, and explicit rejection of sticky writable ancestors;
- distinct non-root Kernel/Pi UID provisioning, pinned GID, cleared supplementary
  groups, isolation probe/attestation, and the same-UID live startup refusal;
- policy and route validation before start;
- deterministic offline startup and one-command acceptance;
- CDP credential provisioning without values or shell-history examples;
- customer-owned wallet identity check and human-only Base Sepolia funding;
- Pi-owned credential creation, non-secret enrollment handoff/import, revocation,
  safe replacement, and restart-stable session binding;
- the two directional handoff parents and wrong-direction write denial;
- the exact clean bootstrap and replacement order from Task 13, including persistent
  socket disablement before service stop, both-unit/job/listener/authority-lock
  quiescence checks, failure-stays-disabled behavior, connection-storm verification,
  and fresh isolation-attestation import before each live start;
- operator token location/mode, live Unix admin CLI, root socket-activated loopback
  console, exact daemon-reload + `systemctl enable wallet-kernel-console.socket` +
  effective-config check + `systemctl start wallet-kernel-console.socket` sequence
  before service start, one-time `console launch` flow, crash-retained listener verification, and
  deterministic fallback;
- approval, denial, expiry, reconciliation, and full-refund observation procedures;
- backup/restore as an offline SQLite file operation with integrity verification;
- incident response for unresolved signing/payment, execution-evidence, and
  seller-attested/on-chain refund states;
- exact shutdown/restart behavior;
- fresh evidence generation under the external Kernel evidence root, verification,
  out-of-band anchor handling, optional human-reviewed repo copy, and
  immutable-directory policy;
- an explicit statement that mainnet, custody, hosted policy authority, automated
  funding, live CDP payment, and public website claims are out of scope.

Keep current results labeled `measured offline` and live CDP/Base Sepolia labeled
`not-run` until a human authorizes and runs the testnet command.
The runbook must also distinguish local macOS deterministic tests from the mandatory
Linux/systemd CI result; a skipped systemd test can never satisfy the live-host gate.

- [ ] **Step 6: Commit evidence tooling and operating documentation**

Commit implementation/docs before generating release evidence so the tested commit is
clean and non-self-referential:

```bash
git add spikes/pi-wielder/src/evidence-bundle.mjs \
  spikes/pi-wielder/scripts/run-evidence.mjs \
  spikes/pi-wielder/scripts/run-testnet-agent.mjs \
  spikes/pi-wielder/scripts/verify-evidence.mjs \
  spikes/pi-wielder/scripts/verify-no-tracked-secrets.mjs \
  spikes/pi-wielder/tests/evidence-bundle.test.mjs \
  spikes/pi-wielder/tests/testnet-agent-runner.test.mjs \
  spikes/pi-wielder/tests/no-tracked-secrets.test.mjs \
  spikes/pi-wielder/package.json \
  spikes/pi-wielder/README.md \
  spikes/pi-wielder/RUNBOOK.md \
  spikes/pi-wielder/.env.example
git commit -m "feat: add wallet kernel evidence pipeline"
```

- [ ] **Step 7: Request an independent code and security review**

Use `superpowers:requesting-code-review` against `07c3549..HEAD`. Require the reviewer
to check the approved design section-by-section, especially permit forgery,
persist-before-retry, crash ambiguity, local auth, testnet gating, receipt redaction,
x402 interoperability, and preservation of v1 regressions. Fix every Critical or
Important finding, commit the fixes, and repeat review until no such finding remains.

- [ ] **Step 8: Run the complete clean-commit verification story**

Run from repo root:

```bash
git status --short
git rev-parse HEAD
npm run verify:spend-control --prefix spikes/pi-wielder
evidence_parent="$(mktemp -d /tmp/pi-wielder-evidence.XXXXXX)"
npm run evidence:offline --prefix spikes/pi-wielder -- \
  --output "$evidence_parent/bundle" \
  --anchor-output "$evidence_parent/manifest.sha256"
manifest_sha256="$(tr -d '\n' < "$evidence_parent/manifest.sha256")"
npm run evidence:verify --prefix spikes/pi-wielder -- "$evidence_parent/bundle" \
  --expect-manifest-sha256 "$manifest_sha256"
npm run verify:no-secrets --prefix spikes/pi-wielder
npm test --prefix prototype
git diff --check
git status --short
git diff --exit-code HEAD -- CONTEXT.md docs/PRD.md docs/adr
git diff --exit-code 07c3549..HEAD -- CONTEXT.md docs/PRD.md docs/adr
```

Expected:

- new and legacy test suites pass;
- evidence verification reports `valid: true`, `mode: offline-deterministic`, and
  live/testnet status `not-run`, while the release handoff records the exact
  `manifest_sha256` as the bundle's external trust anchor;
- protected corpus diff is empty;
- fail-closed tracked-secret verification passes without echoing candidates;
- `docs/superpowers/plans/marketing-assets/` remains untracked and untouched.

The initial and final `git status --short` must be empty in the isolated implementation
worktree. Record the printed `git rev-parse HEAD` as `TESTED_IMPLEMENTATION_COMMIT`.
The evidence builder itself must continue to reject overwrite.

- [ ] **Step 9: Write the release handoff against the tested commit**

Only after Step 8 passes, create
`docs/handoffs/2026-07-31-agent-spend-control-release-handoff.md` with:

```text
branch and TESTED_IMPLEMENTATION_COMMIT from Step 8
scope delivered
automated command/result table
temporary offline evidence path, manifest hash, and verification result
live CDP and testnet status
agent isolation status and preflight digest (`simulated` is not live-ready)
deployment status, release-manifest/tree/service-artifact/PID1-effective hashes, and socket-activation status
known limitations and unresolved records
agent-doable follow-ups
human-only CDP credential, wallet funding, testnet authorization, and commercialization items
website gate: no reframe until fresh qualifying testnet evidence exists
historical n=48 quarantine remains in force
```

The handoff explicitly calls its hash the tested implementation commit, not the future
handoff commit. Do not edit `CONTEXT.md`, `docs/PRD.md`, or `docs/adr/`; propose any
durable doctrine change in the handoff instead. Preserve corpus language: Pi is the
Wielder; Agent and Operator are local control-plane security roles.

- [ ] **Step 10: Commit only the release handoff**

```bash
git add docs/handoffs/2026-07-31-agent-spend-control-release-handoff.md
git commit -m "docs: hand off wallet kernel pilot"
git status --short
```

Expected: the handoff commit succeeds and the isolated implementation worktree is
clean. Report its final commit hash externally; do not amend the handoff to refer to
itself.

## Approved-design coverage map

| Approved design area | Implemented and proved in |
|---|---|
| Roles, distinct-identity isolation, enrollment/revocation, and agent/operator separation | Tasks 2, 4, 10, 12–16 |
| Canonical records and durable SQLite journal | Tasks 1, 2, 4–7, 10, 11 |
| Pure policy and all four budget ceilings | Tasks 3, 5 |
| Exact one-time approval and AuthorizedPermit | Tasks 6, 8, 10 |
| x402 v2 `exact`, Base Sepolia, CDP customer wallet | Tasks 8, 9, 12 |
| Persist-before-retry lifecycle and separate execution state | Tasks 9, 10 |
| Crash ambiguity, operator-named candidates, execution/refund reconciliation, receipt revision | Tasks 5, 7, 10, 11, 15 |
| Pi experience, Unix admin CLI, socket-activated loopback console, and customer-hosted operation | Tasks 13–15 |
| Privacy, filesystem security, redaction, and no hosted write path | Tasks 2, 7–14, 16 |
| Offline proof, real pinned Pi, and human-gated testnet evidence | Tasks 1, 8–10, 12, 15, 16 |
| Commercial pilot boundary and website-after-evidence gate | Task 16 and the completion boundary below |

## Completion boundary

This plan is complete only when the offline product slice passes through the pinned Pi
binary in separate processes, recovery invariants pass at every monetary crash point,
and a recomputable sanitized offline evidence bundle verifies. That proves the
customer-hosted spending-control product path; it does **not** prove live CDP signing,
testnet settlement, a particular host's enforced UID/container isolation, production
readiness, compliance readiness, or market demand. It also does not prove a live host
until that host's root-owned release/prelaunch and socket-activation attestations pass.
The deterministic bundle must say
`isolation: simulated`; live admission/evidence remains blocked until the separate
host probe and imported attestation pass.

The next human-authorized milestone is one bounded Base Sepolia evidence run using the
customer’s CDP wallet and test USDC. Only after that fresh bundle verifies should a
separate plan reframe the public README/site around the commercial Wallet Kernel. That
future public work must keep the historical `n=48` claim quarantined and may expose
read-only sanitized evidence only—never the operator authority or spending controls.
