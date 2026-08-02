import assert from 'node:assert/strict';
import test from 'node:test';

import { authorizationTypes } from '@x402/evm';
import { getAddress, keccak256, toBytes } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';

import { canonicalJson, sha256 } from '../src/kernel/canonical.mjs';
import { projectPaymentRequired } from '../src/kernel/policy-engine.mjs';
import {
  assertPermitMatchesPayment,
  WalletSigningError,
  createDeadlineRunner,
  executeAuthorizedSigning,
  validatePaymentPayload,
  validateWalletIdentity,
} from '../src/adapters/wallet-adapter-contract.mjs';

const WALLET_ADDRESS = '0x918B63a7fD486d8BD57FECF388CafbfB5dd8D84C';
const PERSISTED_WALLET_ADDRESS = WALLET_ADDRESS.toLowerCase();
const ASSET = '0x036cbd53842c5426634e7929541ec2318f3dcf7e';
const PAY_TO = '0x2000000000000000000000000000000000000000';
const SECP256K1_N = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');
const SECP256K1_HALF_N = BigInt(
  '0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0',
);

function paymentRequired() {
  return {
    x402Version: 2,
    resource: {
      url: 'https://seller.example/paid/infer',
      description: 'offline fixture',
      mimeType: 'application/json',
    },
    accepts: [{
      scheme: 'exact',
      network: 'eip155:84532',
      asset: ASSET,
      amount: '50000',
      payTo: PAY_TO,
      maxTimeoutSeconds: 60,
      extra: { name: 'USDC', version: '2' },
    }],
  };
}

function signingBinding(overrides = {}, challenge = paymentRequired()) {
  const challengeHash = sha256(canonicalJson(projectPaymentRequired(challenge)));
  return {
    intentId: 'intent-1',
    intentHash: `sha256:${'11'.repeat(32)}`,
    challengeHash,
    quoteId: sha256(canonicalJson({ challengeHash, acceptedIndex: 0 })),
    acceptedIndex: 0,
    requestUrl: challenge.resource.url,
    resourceDescription: challenge.resource.description,
    resourceMimeType: challenge.resource.mimeType,
    scheme: 'exact',
    network: 'eip155:84532',
    asset: ASSET,
    walletAddress: PERSISTED_WALLET_ADDRESS,
    payTo: PAY_TO,
    amountAtomic: '50000',
    validAfter: '0',
    validBefore: '1785502860',
    nonce: `0x${'01'.repeat(32)}`,
    policyVersionId: 'policy-1',
    ...overrides,
  };
}

const fixtureAccount = privateKeyToAccount(
  keccak256(toBytes('wallet-kernel-contract-test-only')),
);

function typedDataFixture(binding) {
  return {
    domain: {
      name: 'USDC',
      version: '2',
      chainId: 84532,
      verifyingContract: getAddress(binding.asset),
    },
    types: authorizationTypes,
    primaryType: 'TransferWithAuthorization',
    message: {
      from: getAddress(binding.walletAddress),
      to: getAddress(binding.payTo),
      value: BigInt(binding.amountAtomic),
      validAfter: BigInt(binding.validAfter),
      validBefore: BigInt(binding.validBefore),
      nonce: binding.nonce,
    },
  };
}

function paymentPayloadFixture(signature, binding, challenge = paymentRequired()) {
  return {
    x402Version: 2,
    resource: {
      url: binding.requestUrl,
      description: binding.resourceDescription,
      mimeType: binding.resourceMimeType,
    },
    accepted: structuredClone(challenge.accepts[binding.acceptedIndex]),
    payload: {
      signature,
      authorization: {
        from: binding.walletAddress,
        to: binding.payTo,
        value: binding.amountAtomic,
        validAfter: binding.validAfter,
        validBefore: binding.validBefore,
        nonce: binding.nonce,
      },
    },
  };
}

function signatureWith(signature, { r, s, v }) {
  const nextR = (r ?? BigInt(`0x${signature.slice(2, 66)}`)).toString(16).padStart(64, '0');
  const nextS = (s ?? BigInt(`0x${signature.slice(66, 130)}`)).toString(16).padStart(64, '0');
  const nextV = (v ?? Number.parseInt(signature.slice(130, 132), 16))
    .toString(16)
    .padStart(2, '0');
  return `0x${nextR}${nextS}${nextV}`;
}

export {
  paymentRequired as createWalletContractPaymentRequired,
  paymentPayloadFixture as createWalletContractPaymentPayload,
  signingBinding as createWalletContractSigningBinding,
  typedDataFixture as createWalletContractTypedData,
};

/**
 * Reusable contract for every Wallet Adapter implementation.
 *
 * `factory({ failureMode } = {})` returns the base fixture documented in Task 8:
 * adapter/identity fields, paymentRequired, permit, signCalls(), signAuthorized(),
 * and genuineMismatchedPermit(field). Failure modes let each implementation inject
 * failures without exposing provider exceptions through the adapter boundary.
 */
export function walletAdapterContract(name, factory) {
  test(`${name}: exposes identity and exact signing only`, async () => {
    const fixture = factory();
    assert.deepEqual(Object.keys(fixture.adapter).sort(), ['signX402Exact', 'walletIdentity']);
    assert.deepEqual(await fixture.adapter.walletIdentity(), {
      provider: fixture.provider,
      walletId: fixture.walletId,
      address: fixture.address.toLowerCase(),
      network: 'eip155:84532',
    });
  });

  test(`${name}: rejects forged, consumed, and mismatched permits before signing`, async () => {
    const forgedFixture = factory();
    await assert.rejects(
      () => forgedFixture.adapter.signX402Exact(
        { kind: 'AuthorizedPermit', intentId: 'intent-1' },
        forgedFixture.paymentRequired,
      ),
      /forged|rejected|invalid/i,
    );
    assert.equal(forgedFixture.signCalls(), 0);

    const consumedFixture = factory();
    await consumedFixture.signAuthorized();
    assert.equal(consumedFixture.signCalls(), 1);
    await assert.rejects(
      () => consumedFixture.adapter.signX402Exact(
        consumedFixture.permit,
        consumedFixture.paymentRequired,
      ),
      /consumed|rejected|invalid/i,
    );
    assert.equal(consumedFixture.signCalls(), 1);

    for (const field of [
      'challengeHash',
      'acceptedIndex',
      'amountAtomic',
      'payTo',
      'network',
      'asset',
      'walletAddress',
      'validBefore',
      'nonce',
    ]) {
      const fixture = factory();
      const mismatch = fixture.genuineMismatchedPermit(field);
      const mismatchedPermit = Object.hasOwn(mismatch, 'permit') ? mismatch.permit : mismatch;
      const mismatchedPayment = Object.hasOwn(mismatch, 'paymentRequired')
        ? mismatch.paymentRequired
        : fixture.paymentRequired;
      await assert.rejects(
        () => fixture.adapter.signX402Exact(mismatchedPermit, mismatchedPayment),
        /forged|mismatch|rejected|invalid/i,
        field,
      );
      assert.equal(fixture.signCalls(), 0, field);
    }
  });

  test(`${name}: never returns or serializes key material`, async () => {
    const fixture = factory();
    const result = await fixture.signAuthorized();
    assert.deepEqual(Object.keys(result), ['paymentPayload']);
    assert.ok(Object.isFrozen(result));
    assert.ok(Object.isFrozen(result.paymentPayload));
    assert.doesNotMatch(
      JSON.stringify({ identity: await fixture.adapter.walletIdentity(), result }),
      /private|secret|seed|mnemonic|api.key/i,
    );
  });

  test(`${name}: classifies pre-sign rejection as definitely unsigned`, async () => {
    const fixture = factory({ failureMode: 'pre-sign' });
    await assert.rejects(
      () => fixture.adapter.signX402Exact(fixture.permit, fixture.paymentRequired),
      (error) => {
        assert.ok(error instanceof WalletSigningError);
        assert.equal(error.code, 'WALLET_PRE_SIGN_REJECTED');
        assert.equal(error.signatureMayExist, false);
        assert.equal(error.cause, undefined);
        return true;
      },
    );
    assert.equal(fixture.signCalls(), 0);
  });

  for (const failureMode of [
    'untyped-error',
    'sync-throw',
    'async-reject',
    'never-settle',
    'malformed-signature',
    'high-s-signature',
    'zero-one-v-signature',
    'compact-signature',
    'assemble-failure',
    'post-sign-mismatch',
  ]) {
    test(`${name}: ${failureMode} after entering the signer is ambiguous`, async () => {
      const fixture = factory({ failureMode });
      await assert.rejects(
        () => fixture.adapter.signX402Exact(fixture.permit, fixture.paymentRequired),
        (error) => {
          assert.ok(error instanceof WalletSigningError);
          assert.equal(error.code, 'WALLET_SIGNATURE_AMBIGUOUS');
          assert.equal(error.signatureMayExist, true);
          assert.equal(error.cause, undefined);
          assert.doesNotMatch(JSON.stringify(error), /private|secret|provider/i);
          return true;
        },
      );
      assert.equal(fixture.signCalls(), 1);
    });
  }
}

test('WalletSigningError exposes only the stable signing boundary classification', () => {
  const error = new WalletSigningError(
    'WALLET_PRE_SIGN_REJECTED',
    'wallet rejected before signing',
    { signatureMayExist: false },
  );

  assert.equal(error.name, 'WalletSigningError');
  assert.equal(error.code, 'WALLET_PRE_SIGN_REJECTED');
  assert.equal(error.signatureMayExist, false);
  assert.equal(error.cause, undefined);
  assert.equal(WalletSigningError.isExact(
    error,
    'WALLET_PRE_SIGN_REJECTED',
    false,
  ), true);

  const nativePrototypeForgery = Object.assign(new Error('forged native error'), {
    code: 'WALLET_PRE_SIGN_REJECTED',
    signatureMayExist: false,
  });
  Object.setPrototypeOf(nativePrototypeForgery, WalletSigningError.prototype);
  assert.equal(WalletSigningError.isExact(
    nativePrototypeForgery,
    'WALLET_PRE_SIGN_REJECTED',
    false,
  ), false);

  class DerivedSigningError extends WalletSigningError {}
  const derived = new DerivedSigningError(
    'WALLET_PRE_SIGN_REJECTED',
    'derived error',
    { signatureMayExist: false },
  );
  assert.equal(WalletSigningError.isExact(
    derived,
    'WALLET_PRE_SIGN_REJECTED',
    false,
  ), false);
  Object.setPrototypeOf(derived, WalletSigningError.prototype);
  assert.equal(WalletSigningError.isExact(
    derived,
    'WALLET_PRE_SIGN_REJECTED',
    false,
  ), false);

  let proxyTraps = 0;
  const proxy = new Proxy(error, {
    getPrototypeOf() {
      proxyTraps += 1;
      throw new Error('must not inspect hostile proxy');
    },
  });
  assert.equal(WalletSigningError.isExact(
    proxy,
    'WALLET_PRE_SIGN_REJECTED',
    false,
  ), false);
  assert.equal(proxyTraps, 0);
  assert.equal(Object.isFrozen(WalletSigningError), true);
});

test('createDeadlineRunner arms the deadline before invoking and clears it on settlement', async () => {
  const events = [];
  const timer = Object.freeze({ id: 1 });
  const runWithDeadline = createDeadlineRunner({
    setTimeoutImpl(callback, timeoutMs) {
      events.push(['armed', timeoutMs, callback]);
      return timer;
    },
    clearTimeoutImpl(value) {
      events.push(['cleared', value]);
    },
  });

  const result = await runWithDeadline({
    phase: 'pre-sign',
    timeoutMs: 5_000,
    operation() {
      events.push(['operation']);
      return 'prepared';
    },
  });

  assert.equal(result, 'prepared');
  assert.deepEqual(events.slice(0, 2), [
    ['armed', 5_000, events[0][2]],
    ['operation'],
  ]);
  assert.deepEqual(events.at(-1), ['cleared', timer]);
});

test('createDeadlineRunner never invokes an operation when the armed deadline already fired', async () => {
  let operationCalls = 0;
  const runWithDeadline = createDeadlineRunner({
    setTimeoutImpl(callback) {
      callback();
      return Object.freeze({ id: 'expired' });
    },
    clearTimeoutImpl() {},
  });

  await assert.rejects(
    () => runWithDeadline({
      phase: 'signer',
      timeoutMs: 15_000,
      operation() {
        operationCalls += 1;
      },
    }),
    (error) => error.code === 'WALLET_SIGNER_TIMEOUT',
  );
  await Promise.resolve();
  assert.equal(operationCalls, 0);
});

test('createDeadlineRunner bounds a never-settling promise and clears its one-shot timer', async () => {
  let fireDeadline;
  const cleared = [];
  const timer = Object.freeze({ id: 'signer-timer' });
  const runWithDeadline = createDeadlineRunner({
    setTimeoutImpl(callback, timeoutMs) {
      assert.equal(timeoutMs, 15_000);
      fireDeadline = callback;
      return timer;
    },
    clearTimeoutImpl(value) {
      cleared.push(value);
    },
  });

  const pending = runWithDeadline({
    phase: 'signer',
    timeoutMs: 15_000,
    operation: () => new Promise(() => {}),
  });
  await Promise.resolve();
  fireDeadline();

  await assert.rejects(pending, (error) => {
    assert.equal(error.code, 'WALLET_SIGNER_TIMEOUT');
    assert.doesNotMatch(error.message, /private|secret|provider/i);
    return true;
  });
  assert.deepEqual(cleared, [timer]);
});

test('createDeadlineRunner clears the timer when an operation rejects', async () => {
  const timer = Object.freeze({ id: 'rejection-timer' });
  const cleared = [];
  const providerFailure = Object.freeze({ secret: 'opaque-provider-value' });
  const runWithDeadline = createDeadlineRunner({
    setTimeoutImpl() { return timer; },
    clearTimeoutImpl(value) { cleared.push(value); },
  });

  await assert.rejects(
    () => runWithDeadline({
      phase: 'pre-sign',
      timeoutMs: 5_000,
      operation: async () => { throw providerFailure; },
    }),
    (error) => {
      assert.notEqual(error, providerFailure);
      assert.equal(error.code, 'WALLET_PRE_SIGN_OPERATION_FAILED');
      assert.equal(error.cause, undefined);
      assert.doesNotMatch(JSON.stringify(error), /opaque-provider-value|secret/);
      return true;
    },
  );
  assert.deepEqual(cleared, [timer]);
});

test('deadline configuration and requests reject proxies and accessors inertly', async () => {
  let configGetterCalls = 0;
  const config = { clearTimeoutImpl() {} };
  Object.defineProperty(config, 'setTimeoutImpl', {
    enumerable: true,
    get() {
      configGetterCalls += 1;
      return setTimeout;
    },
  });
  assert.throws(
    () => createDeadlineRunner(config),
    (error) => error.code === 'WALLET_DEADLINE_CONFIG',
  );
  assert.equal(configGetterCalls, 0);

  const runWithDeadline = createDeadlineRunner();
  let requestGetterCalls = 0;
  const request = { phase: 'pre-sign', timeoutMs: 5_000 };
  Object.defineProperty(request, 'operation', {
    enumerable: true,
    get() {
      requestGetterCalls += 1;
      return () => 'unsafe';
    },
  });
  await assert.rejects(
    () => runWithDeadline(request),
    (error) => error.code === 'WALLET_DEADLINE_REQUEST',
  );
  assert.equal(requestGetterCalls, 0);
});

test('deadline phases use an own-property allowlist rather than inherited object names', async () => {
  const runWithDeadline = createDeadlineRunner();
  for (const phase of ['__proto__', 'constructor', 'toString']) {
    let operationCalls = 0;
    await assert.rejects(
      () => runWithDeadline({
        phase,
        timeoutMs: 5_000,
        operation() {
          operationCalls += 1;
          return 'unsafe';
        },
      }),
      (error) => error.code === 'WALLET_DEADLINE_PHASE',
      phase,
    );
    assert.equal(operationCalls, 0, phase);
  }
});

test('deadline setup and cleanup failures cannot leak values or leave work unbounded', async () => {
  let operationCalls = 0;
  const setupFailure = createDeadlineRunner({
    setTimeoutImpl() { throw Object.freeze({ providerSecret: 'setup-leak' }); },
    clearTimeoutImpl() {},
  });
  await assert.rejects(
    () => setupFailure({
      phase: 'pre-sign',
      timeoutMs: 5_000,
      operation() {
        operationCalls += 1;
      },
    }),
    (error) => {
      assert.equal(error.code, 'WALLET_DEADLINE_SETUP_FAILED');
      assert.equal(error.cause, undefined);
      assert.doesNotMatch(JSON.stringify(error), /setup-leak|providerSecret/);
      return true;
    },
  );
  assert.equal(operationCalls, 0);

  const cleanupFailure = createDeadlineRunner({
    setTimeoutImpl() { return Object.freeze({ id: 'timer' }); },
    clearTimeoutImpl() { throw new Error('cleanup failure'); },
  });
  assert.equal(await cleanupFailure({
    phase: 'pre-sign',
    timeoutMs: 5_000,
    operation: async () => 'settled',
  }), 'settled');
});

test('createDeadlineRunner preserves the first timeout when an injected timer fires then throws', async () => {
  let operationCalls = 0;
  const runWithDeadline = createDeadlineRunner({
    setTimeoutImpl(callback) {
      callback();
      throw new Error('late timer setup failure');
    },
    clearTimeoutImpl() {},
  });

  await assert.rejects(
    () => runWithDeadline({
      phase: 'signer',
      timeoutMs: 15_000,
      operation() {
        operationCalls += 1;
      },
    }),
    (error) => error.code === 'WALLET_SIGNER_TIMEOUT',
  );
  assert.equal(operationCalls, 0);
});

test('executeAuthorizedSigning maps prepare failures to definite pre-sign rejection', async () => {
  const providerFailure = Object.freeze({ privateKey: 'must-not-leak' });

  await assert.rejects(
    () => executeAuthorizedSigning({
      prepare: async () => { throw providerFailure; },
      invokeSigner: async () => 'not-called',
      finalize: async () => 'not-called',
      runWithDeadline: createDeadlineRunner(),
      preSignTimeoutMs: 5_000,
      signerTimeoutMs: 15_000,
    }),
    (error) => {
      assert.ok(error instanceof WalletSigningError);
      assert.equal(error.code, 'WALLET_PRE_SIGN_REJECTED');
      assert.equal(error.signatureMayExist, false);
      assert.equal(error.cause, undefined);
      assert.doesNotMatch(JSON.stringify(error), /must-not-leak|privateKey/);
      return true;
    },
  );
});

test('executeAuthorizedSigning supplies bounded defaults and completes both zones', async () => {
  const events = [];
  const result = await executeAuthorizedSigning({
    prepare: async () => {
      events.push('prepared');
      return Object.freeze({ typedData: 'ready' });
    },
    invokeSigner: async (prepared) => {
      events.push(`signed:${prepared.typedData}`);
      return '0xsignature';
    },
    finalize: async (prepared, signature) => {
      events.push(`finalized:${prepared.typedData}`);
      return Object.freeze({ signature });
    },
  });

  assert.deepEqual(result, { signature: '0xsignature' });
  assert.deepEqual(events, ['prepared', 'signed:ready', 'finalized:ready']);
});

test('executeAuthorizedSigning uses the stable 5s pre-sign and 15s may-exist deadlines', async () => {
  const calls = [];
  await executeAuthorizedSigning({
    prepare: async () => 'prepared',
    invokeSigner: async () => 'signature',
    finalize: async () => 'done',
    async runWithDeadline(input) {
      calls.push([input.phase, input.timeoutMs]);
      return await input.operation();
    },
  });
  assert.deepEqual(calls, [['pre-sign', 5_000], ['signer', 15_000]]);
});

test('executeAuthorizedSigning treats every signer and post-sign failure as ambiguous', async () => {
  const failureModes = [
    ['synchronous signer throw', () => { throw Object.freeze({ secret: 'sync-provider-value' }); },
      async () => 'unreachable'],
    ['asynchronous signer rejection', async () => {
      throw Object.freeze({ secret: 'async-provider-value' });
    }, async () => 'unreachable'],
    ['malformed returned signature', async () => 'malformed', async () => {
      throw new Error('malformed signature');
    }],
    ['assemble failure', async () => '0xsignature', async () => {
      throw new Error('assemble provider secret');
    }],
    ['post-sign payload mismatch', async () => '0xsignature', async () => {
      throw new Error('post-sign mismatch');
    }],
  ];

  for (const [label, invokeSigner, finalize] of failureModes) {
    let signCalls = 0;
    await assert.rejects(
      () => executeAuthorizedSigning({
        prepare: async () => Object.freeze({ ready: true }),
        invokeSigner: async (prepared) => {
          assert.equal(prepared.ready, true);
          signCalls += 1;
          return await invokeSigner();
        },
        finalize,
      }),
      (error) => {
        assert.ok(error instanceof WalletSigningError, label);
        assert.equal(error.code, 'WALLET_SIGNATURE_AMBIGUOUS', label);
        assert.equal(error.signatureMayExist, true, label);
        assert.equal(error.cause, undefined, label);
        assert.doesNotMatch(JSON.stringify(error), /provider|secret|malformed|mismatch/i, label);
        return true;
      },
    );
    assert.equal(signCalls, 1, label);
  }
});

test('executeAuthorizedSigning makes a never-settling signer ambiguous after its deadline', async () => {
  let fireSignerDeadline;
  let signCalls = 0;
  const runWithDeadline = createDeadlineRunner({
    setTimeoutImpl(callback, timeoutMs) {
      if (timeoutMs === 15_000) fireSignerDeadline = callback;
      return Object.freeze({ timeoutMs });
    },
    clearTimeoutImpl() {},
  });
  const pending = executeAuthorizedSigning({
    prepare: async () => 'prepared',
    invokeSigner: () => {
      signCalls += 1;
      return new Promise(() => {});
    },
    finalize: async () => 'unreachable',
    runWithDeadline,
  });
  for (let turn = 0; turn < 10
    && (typeof fireSignerDeadline !== 'function' || signCalls !== 1); turn += 1) {
    await Promise.resolve();
  }
  assert.equal(typeof fireSignerDeadline, 'function');
  assert.equal(signCalls, 1);
  fireSignerDeadline();

  await assert.rejects(pending, (error) => {
    assert.equal(error.code, 'WALLET_SIGNATURE_AMBIGUOUS');
    assert.equal(error.signatureMayExist, true);
    return true;
  });
  assert.equal(signCalls, 1);
});

test('executeAuthorizedSigning keeps finalization inside the bounded may-exist zone', async () => {
  let fireSignerDeadline;
  let finalizeCalls = 0;
  const runWithDeadline = createDeadlineRunner({
    setTimeoutImpl(callback, timeoutMs) {
      if (timeoutMs === 15_000) fireSignerDeadline = callback;
      return Object.freeze({ timeoutMs });
    },
    clearTimeoutImpl() {},
  });
  const pending = executeAuthorizedSigning({
    prepare: async () => 'prepared',
    invokeSigner: async () => 'signature',
    finalize: () => {
      finalizeCalls += 1;
      return new Promise(() => {});
    },
    runWithDeadline,
  });
  for (let turn = 0; turn < 10
    && (typeof fireSignerDeadline !== 'function' || finalizeCalls !== 1); turn += 1) {
    await Promise.resolve();
  }
  assert.equal(finalizeCalls, 1);
  fireSignerDeadline();
  await assert.rejects(pending, (error) => error.code === 'WALLET_SIGNATURE_AMBIGUOUS'
    && error.signatureMayExist === true);
});

test('executeAuthorizedSigning rejects hostile outer input before signer entry', async () => {
  let prepareGetterCalls = 0;
  let signCalls = 0;
  const request = {
    invokeSigner: async () => {
      signCalls += 1;
      return 'signature';
    },
    finalize: async () => 'done',
  };
  Object.defineProperty(request, 'prepare', {
    enumerable: true,
    get() {
      prepareGetterCalls += 1;
      return async () => 'prepared';
    },
  });

  await assert.rejects(
    () => executeAuthorizedSigning(request),
    (error) => error instanceof WalletSigningError
      && error.code === 'WALLET_PRE_SIGN_REJECTED'
      && error.signatureMayExist === false,
  );
  assert.equal(prepareGetterCalls, 0);
  assert.equal(signCalls, 0);
});

test('executeAuthorizedSigning never lets an injected deadline runner invoke the signer twice', async () => {
  let signCalls = 0;
  let secondInvocationError;
  const result = await executeAuthorizedSigning({
    prepare: async () => 'prepared',
    invokeSigner: async () => {
      signCalls += 1;
      return 'signature';
    },
    finalize: async (_prepared, signature) => ({ signature }),
    async runWithDeadline({ phase, operation }) {
      if (phase === 'pre-sign') return await operation();
      const first = await operation();
      try {
        await operation();
      } catch (error) {
        secondInvocationError = error;
      }
      return first;
    },
  });

  assert.deepEqual(result, { signature: 'signature' });
  assert.equal(signCalls, 1);
  assert.equal(secondInvocationError?.code, 'WALLET_SIGNER_REENTRY');
});

test('validateWalletIdentity enforces a closed Base Sepolia identity and returns an inert copy', () => {
  const source = {
    provider: 'deterministic-test',
    walletId: 'wallet-1',
    address: WALLET_ADDRESS,
    network: 'eip155:84532',
  };
  const identity = validateWalletIdentity(source);

  assert.deepEqual(identity, { ...source, address: source.address.toLowerCase() });
  assert.notEqual(identity, source);
  assert.ok(Object.isFrozen(identity));
  const persistedBinding = assertPermitMatchesPayment(signingBinding(), paymentRequired(), 0);
  assert.equal(persistedBinding.walletAddress, WALLET_ADDRESS.toLowerCase());
  assert.equal(getAddress(identity.address), getAddress(persistedBinding.walletAddress));

  for (const candidate of [
    { ...source, network: 'eip155:1' },
    { ...source, address: '0x0000000000000000000000000000000000000000' },
    { ...source, injected: true },
    { provider: source.provider, walletId: source.walletId, address: source.address },
  ]) {
    assert.throws(
      () => validateWalletIdentity(candidate),
      (error) => error.code === 'WALLET_IDENTITY',
    );
  }
});

test('validateWalletIdentity rejects proxies and accessors without invoking attacker code', () => {
  let getterCalls = 0;
  const accessor = { walletId: 'wallet-1', address: WALLET_ADDRESS, network: 'eip155:84532' };
  Object.defineProperty(accessor, 'provider', {
    enumerable: true,
    get() {
      getterCalls += 1;
      return 'deterministic-test';
    },
  });

  assert.throws(() => validateWalletIdentity(accessor), (error) => error.code === 'WALLET_IDENTITY');
  assert.equal(getterCalls, 0);
  assert.throws(
    () => validateWalletIdentity(new Proxy({}, { get() { throw new Error('trap'); } })),
    (error) => error.code === 'WALLET_IDENTITY',
  );
});

test('assertPermitMatchesPayment validates the full closed binding and canonical challenge', () => {
  const challenge = paymentRequired();
  const binding = signingBinding({}, challenge);
  const normalized = assertPermitMatchesPayment(binding, challenge, 0);

  assert.deepEqual(normalized, binding);
  assert.notEqual(normalized, binding);
  assert.ok(Object.isFrozen(normalized));

  const mutations = [
    ['challengeHash', `sha256:${'22'.repeat(32)}`],
    ['quoteId', `sha256:${'33'.repeat(32)}`],
    ['acceptedIndex', 1],
    ['requestUrl', 'https://seller.example/paid/other'],
    ['resourceDescription', 'different'],
    ['resourceMimeType', 'text/plain'],
    ['scheme', 'upto'],
    ['network', 'eip155:1'],
    ['asset', '0x1000000000000000000000000000000000000000'],
    ['payTo', '0x3000000000000000000000000000000000000000'],
    ['amountAtomic', '50001'],
    ['validAfter', '1'],
    ['validBefore', '01785502860'],
    ['nonce', `0x${'AA'.repeat(32)}`],
  ];
  for (const [field, value] of mutations) {
    assert.throws(
      () => assertPermitMatchesPayment({ ...binding, [field]: value }, challenge, 0),
      (error) => error.code === 'WALLET_BINDING',
      field,
    );
  }

  assert.throws(
    () => assertPermitMatchesPayment({ ...binding, injected: true }, challenge, 0),
    (error) => error.code === 'WALLET_BINDING',
  );
});

test('assertPermitMatchesPayment rejects hostile binding and challenge values inertly', () => {
  let getterCalls = 0;
  const binding = signingBinding();
  const accessor = { ...binding };
  Object.defineProperty(accessor, 'nonce', {
    enumerable: true,
    get() {
      getterCalls += 1;
      return binding.nonce;
    },
  });

  assert.throws(
    () => assertPermitMatchesPayment(accessor, paymentRequired(), 0),
    (error) => error.code === 'WALLET_BINDING',
  );
  assert.equal(getterCalls, 0);
  assert.throws(
    () => assertPermitMatchesPayment(binding, new Proxy({}, { get() { throw new Error('trap'); } }), 0),
    (error) => error.code === 'WALLET_BINDING',
  );
});

test('validatePaymentPayload enforces closed x402 v2 equality and recovers the bound signer', async () => {
  const challenge = paymentRequired();
  const binding = signingBinding({ walletAddress: fixtureAccount.address.toLowerCase() }, challenge);
  const typedData = typedDataFixture(binding);
  const signature = await fixtureAccount.signTypedData(typedData);
  const source = paymentPayloadFixture(signature, binding, challenge);

  const validated = await validatePaymentPayload({
    paymentPayload: source,
    binding,
    paymentRequired: challenge,
    typedData,
  });

  assert.deepEqual(validated, source);
  assert.notEqual(validated, source);
  assert.ok(Object.isFrozen(validated));
  assert.ok(Object.isFrozen(validated.resource));
  assert.ok(Object.isFrozen(validated.accepted.extra));
  assert.ok(Object.isFrozen(validated.payload.authorization));
});

test('validatePaymentPayload enforces Circle canonical EOA signature boundaries', async () => {
  const challenge = paymentRequired();
  const fixtureForParity = async (targetV) => {
    for (let marker = 1; marker <= 255; marker += 1) {
      const binding = signingBinding({
        walletAddress: fixtureAccount.address.toLowerCase(),
        nonce: `0x${marker.toString(16).padStart(2, '0').repeat(32)}`,
      }, challenge);
      const typedData = typedDataFixture(binding);
      const signature = await fixtureAccount.signTypedData(typedData);
      if (Number.parseInt(signature.slice(130, 132), 16) === targetV) {
        return { binding, signature, typedData };
      }
    }
    throw new Error(`could not construct deterministic v=${targetV} fixture`);
  };
  const validateSignature = async ({ binding, signature, typedData }) => await validatePaymentPayload({
    paymentPayload: paymentPayloadFixture(signature, binding, challenge),
    binding,
    paymentRequired: challenge,
    typedData,
  });

  const v27 = await fixtureForParity(27);
  const v28 = await fixtureForParity(28);
  assert.equal((await validateSignature(v27)).payload.signature, v27.signature);
  assert.equal((await validateSignature(v28)).payload.signature, v28.signature);

  const base = v27;
  const baseS = BigInt(`0x${base.signature.slice(66, 130)}`);
  const highS = signatureWith(base.signature, {
    s: SECP256K1_N - baseS,
    v: 28,
  });
  const zeroOneV = signatureWith(base.signature, { v: 0 });
  const compact = `0x${base.signature.slice(2, 66)}${(
    baseS | (0n << 255n)
  ).toString(16).padStart(64, '0')}`;

  for (const [label, fixture, signature] of [
    ['r zero', base, signatureWith(base.signature, { r: 0n })],
    ['r at curve order', base, signatureWith(base.signature, { r: SECP256K1_N })],
    ['s zero', base, signatureWith(base.signature, { s: 0n })],
    ['s one above half order', base, signatureWith(base.signature, { s: SECP256K1_HALF_N + 1n })],
    ['high-s malleation', base, highS],
    ['v zero', base, zeroOneV],
    ['v one', v28, signatureWith(v28.signature, { v: 1 })],
    ['v other', base, signatureWith(base.signature, { v: 2 })],
  ]) {
    await assert.rejects(
      () => validateSignature({ ...fixture, signature }),
      (error) => error.code === 'WALLET_PAYMENT_PAYLOAD'
        && /canonical EOA signature/.test(error.message),
      label,
    );
  }

  await assert.rejects(
    () => validateSignature({
      ...base,
      signature: signatureWith(base.signature, { s: SECP256K1_HALF_N }),
    }),
    (error) => error.code === 'WALLET_PAYMENT_PAYLOAD'
      && error.message === 'signed payment was not produced by the authorized wallet',
  );
  await assert.rejects(
    () => validateSignature({ ...base, signature: compact }),
    (error) => error.code === 'WALLET_PAYMENT_PAYLOAD',
  );
});

test('validatePaymentPayload rejects every post-sign field substitution', async () => {
  const challenge = paymentRequired();
  const binding = signingBinding({ walletAddress: fixtureAccount.address.toLowerCase() }, challenge);
  const typedData = typedDataFixture(binding);
  const signature = await fixtureAccount.signTypedData(typedData);
  const base = paymentPayloadFixture(signature, binding, challenge);
  const cases = [
    ['resource.url', { ...base, resource: { ...base.resource, url: 'https://seller.example/other' } }],
    ['resource.description', { ...base, resource: { ...base.resource, description: 'changed' } }],
    ['resource.mimeType', { ...base, resource: { ...base.resource, mimeType: 'text/plain' } }],
    ['accepted.scheme', { ...base, accepted: { ...base.accepted, scheme: 'upto' } }],
    ['accepted.network', { ...base, accepted: { ...base.accepted, network: 'eip155:1' } }],
    ['accepted.asset', { ...base, accepted: { ...base.accepted, asset: PAY_TO } }],
    ['accepted.amount', { ...base, accepted: { ...base.accepted, amount: '50001' } }],
    ['accepted.payTo', { ...base, accepted: { ...base.accepted, payTo: ASSET } }],
    ['accepted.maxTimeoutSeconds', {
      ...base,
      accepted: { ...base.accepted, maxTimeoutSeconds: 61 },
    }],
    ['accepted.extra.name', {
      ...base,
      accepted: { ...base.accepted, extra: { ...base.accepted.extra, name: 'USD Coin' } },
    }],
    ['accepted.extra.version', {
      ...base,
      accepted: { ...base.accepted, extra: { ...base.accepted.extra, version: '1' } },
    }],
    ['authorization.from', {
      ...base,
      payload: {
        ...base.payload,
        authorization: { ...base.payload.authorization, from: PAY_TO },
      },
    }],
    ['authorization.to', {
      ...base,
      payload: {
        ...base.payload,
        authorization: { ...base.payload.authorization, to: ASSET },
      },
    }],
    ['authorization.value', {
      ...base,
      payload: {
        ...base.payload,
        authorization: { ...base.payload.authorization, value: '50001' },
      },
    }],
    ['authorization.validAfter', {
      ...base,
      payload: {
        ...base.payload,
        authorization: { ...base.payload.authorization, validAfter: '1' },
      },
    }],
    ['authorization.validBefore', {
      ...base,
      payload: {
        ...base.payload,
        authorization: { ...base.payload.authorization, validBefore: '1785502861' },
      },
    }],
    ['authorization.nonce', {
      ...base,
      payload: {
        ...base.payload,
        authorization: { ...base.payload.authorization, nonce: `0x${'02'.repeat(32)}` },
      },
    }],
    ['signature', {
      ...base,
      payload: { ...base.payload, signature: `0x${'00'.repeat(65)}` },
    }],
  ];

  for (const [label, paymentPayload] of cases) {
    await assert.rejects(
      () => validatePaymentPayload({ paymentPayload, binding, paymentRequired: challenge, typedData }),
      (error) => error.code === 'WALLET_PAYMENT_PAYLOAD',
      label,
    );
  }
});

test('validatePaymentPayload rejects unknown fields, mismatched typed data, proxies, and accessors', async () => {
  const challenge = paymentRequired();
  const binding = signingBinding({ walletAddress: fixtureAccount.address.toLowerCase() }, challenge);
  const typedData = typedDataFixture(binding);
  const signature = await fixtureAccount.signTypedData(typedData);
  const base = paymentPayloadFixture(signature, binding, challenge);
  const unknownShapes = [
    { ...base, injected: true },
    { ...base, resource: { ...base.resource, injected: true } },
    { ...base, accepted: { ...base.accepted, injected: true } },
    { ...base, accepted: { ...base.accepted, extra: { ...base.accepted.extra, injected: true } } },
    { ...base, payload: { ...base.payload, injected: true } },
    {
      ...base,
      payload: {
        ...base.payload,
        authorization: { ...base.payload.authorization, injected: true },
      },
    },
  ];
  for (const paymentPayload of unknownShapes) {
    await assert.rejects(
      () => validatePaymentPayload({ paymentPayload, binding, paymentRequired: challenge, typedData }),
      (error) => error.code === 'WALLET_PAYMENT_PAYLOAD',
    );
  }

  await assert.rejects(
    () => validatePaymentPayload({
      paymentPayload: base,
      binding,
      paymentRequired: challenge,
      typedData: { ...typedData, message: { ...typedData.message, value: 50001n } },
    }),
    (error) => error.code === 'WALLET_PAYMENT_PAYLOAD',
  );

  let getterCalls = 0;
  const accessor = { ...base };
  Object.defineProperty(accessor, 'payload', {
    enumerable: true,
    get() {
      getterCalls += 1;
      return base.payload;
    },
  });
  await assert.rejects(
    () => validatePaymentPayload({
      paymentPayload: accessor,
      binding,
      paymentRequired: challenge,
      typedData,
    }),
    (error) => error.code === 'WALLET_PAYMENT_PAYLOAD',
  );
  assert.equal(getterCalls, 0);
  await assert.rejects(
    () => validatePaymentPayload({
      paymentPayload: new Proxy({}, { get() { throw new Error('provider secret'); } }),
      binding,
      paymentRequired: challenge,
      typedData,
    }),
    (error) => {
      assert.equal(error.code, 'WALLET_PAYMENT_PAYLOAD');
      assert.doesNotMatch(error.message, /provider secret/);
      return true;
    },
  );

  let bindingGetterCalls = 0;
  const hostileBinding = { ...binding };
  Object.defineProperty(hostileBinding, 'acceptedIndex', {
    enumerable: true,
    get() {
      bindingGetterCalls += 1;
      return binding.acceptedIndex;
    },
  });
  await assert.rejects(
    () => validatePaymentPayload({
      paymentPayload: base,
      binding: hostileBinding,
      paymentRequired: challenge,
      typedData,
    }),
    (error) => error.code === 'WALLET_PAYMENT_PAYLOAD',
  );
  assert.equal(bindingGetterCalls, 0);

  let requestGetterCalls = 0;
  const hostileRequest = { binding, paymentRequired: challenge, typedData };
  Object.defineProperty(hostileRequest, 'paymentPayload', {
    enumerable: true,
    get() {
      requestGetterCalls += 1;
      return base;
    },
  });
  await assert.rejects(
    () => validatePaymentPayload(hostileRequest),
    (error) => error.code === 'WALLET_PAYMENT_PAYLOAD',
  );
  assert.equal(requestGetterCalls, 0);
});
