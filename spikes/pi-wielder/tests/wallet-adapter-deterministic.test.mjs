import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';

import { getAddress, keccak256, toBytes } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';

import { createDeterministicWalletAdapter } from '../src/adapters/deterministic-wallet-adapter.mjs';
import { createAgentEnrollmentRepository } from '../src/kernel/agent-enrollment.mjs';
import { createPermitAuthority, deriveAuthorizationWindow } from '../src/kernel/authorized-permit.mjs';
import { canonicalJson, sha256 } from '../src/kernel/canonical.mjs';
import { createIntentRepository } from '../src/kernel/intent-builder.mjs';
import { evaluateSpendPolicy } from '../src/kernel/policy-engine.mjs';
import { createPolicyRepository } from '../src/kernel/policy-repository.mjs';
import { openKernelStore } from '../src/kernel/sqlite-store.mjs';
import { walletAdapterContract } from './wallet-adapter-contract.test.mjs';

const FIXED_NOW_MS = 1_785_502_800_000;
const NOW = '2026-07-31T13:00:00.000Z';
const NETWORK = 'eip155:84532';
const ASSET = '0x036cbd53842c5426634e7929541ec2318f3dcf7e';
const PAY_TO = '0x2000000000000000000000000000000000000000';
const SECP256K1_N = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');
const ROUTE_URL = 'https://seller.example/paid/infer';
const ROUTE_METADATA = Object.freeze({
  'example-skill': Object.freeze({
    description: 'offline fixture',
    mimeType: 'application/json',
  }),
});
const DESCRIPTOR = Object.freeze({
  schemaVersion: 1,
  agentInstanceId: 'AAAAAAAAAAAAAAAAAAAAAA',
  credentialDigest: `sha256:${'ab'.repeat(32)}`,
  agentUid: '501',
  agentGid: '20',
});
const DESCRIPTOR_HASH = sha256(canonicalJson(DESCRIPTOR));
const OPERATOR_HASH = `sha256:${'cd'.repeat(32)}`;
const fixtureAccount = privateKeyToAccount(
  keccak256(toBytes('wallet-kernel-deterministic-adapter-test-only')),
);
const otherAccount = privateKeyToAccount(
  keccak256(toBytes('wallet-kernel-deterministic-adapter-other-test-only')),
);
const PERSISTED_WALLET_ADDRESS = fixtureAccount.address.toLowerCase();
const BASE_POLICY = JSON.parse(fs.readFileSync(
  new URL('../policies/base-sepolia.example.json', import.meta.url),
  'utf8',
));

function highSSignature(signature) {
  const s = BigInt(`0x${signature.slice(66, 130)}`);
  const v = Number.parseInt(signature.slice(130, 132), 16);
  return `0x${signature.slice(2, 66)}${(SECP256K1_N - s).toString(16).padStart(64, '0')}${
    (v === 27 ? 28 : 27).toString(16)
  }`;
}

function zeroOneVSignature(signature) {
  const v = Number.parseInt(signature.slice(130, 132), 16);
  return `${signature.slice(0, 130)}${(v - 27).toString(16).padStart(2, '0')}`;
}

function compactSignature(signature) {
  const r = signature.slice(2, 66);
  const s = BigInt(`0x${signature.slice(66, 130)}`);
  const v = Number.parseInt(signature.slice(130, 132), 16);
  const yParityAndS = s | (BigInt(v - 27) << 255n);
  return `0x${r}${yParityAndS.toString(16).padStart(64, '0')}`;
}

function deepFrozen(value, seen = new Set()) {
  if (!value || typeof value !== 'object' || seen.has(value)) return true;
  seen.add(value);
  return Object.isFrozen(value)
    && Reflect.ownKeys(value).every((key) => deepFrozen(value[key], seen));
}

function sequenceIds() {
  const counts = new Map();
  return (kind) => {
    const next = (counts.get(kind) ?? 0) + 1;
    counts.set(kind, next);
    return `${kind}-${next}`;
  };
}

function acceptedRequirement(overrides = {}) {
  return {
    scheme: 'exact',
    network: NETWORK,
    asset: ASSET,
    amount: '50000',
    payTo: PAY_TO,
    maxTimeoutSeconds: 60,
    extra: { name: 'USDC', version: '2' },
    ...overrides,
  };
}

function paymentChallenge(accepted = acceptedRequirement()) {
  return {
    x402Version: 2,
    error: 'seller prose is outside the signed projection',
    resource: {
      url: ROUTE_URL,
      description: ROUTE_METADATA['example-skill'].description,
      mimeType: ROUTE_METADATA['example-skill'].mimeType,
    },
    accepts: [accepted],
  };
}

function createRealAuthorityFixture({ paymentRequired = paymentChallenge() } = {}) {
  const store = openKernelStore({
    filePath: ':memory:',
    allowMemory: true,
    now: () => NOW,
  });
  try {
    const policyDocument = structuredClone(BASE_POLICY);
    policyDocument.wallet = PERSISTED_WALLET_ADDRESS;
    const policies = createPolicyRepository(store);
    const activePolicy = policies.apply(policyDocument, NOW).policyVersion;
    createAgentEnrollmentRepository({ store, now: () => NOW }).enroll({
      descriptor: DESCRIPTOR,
      expectedDescriptorHash: DESCRIPTOR_HASH,
      operatorIdHash: OPERATOR_HASH,
      mode: 'deterministic',
      kernelUid: 501,
      kernelGid: 20,
      expectedAgentUid: 501,
      expectedAgentGid: 20,
    });
    const intents = createIntentRepository({
      store,
      idFactory: sequenceIds(),
      now: () => NOW,
      routeMetadata: ROUTE_METADATA,
    });
    const session = intents.openOrResumeSession({
      agentInstanceId: DESCRIPTOR.agentInstanceId,
      walletAddress: PERSISTED_WALLET_ADDRESS,
      policyVersionId: activePolicy.id,
    });
    const persistedIntent = intents.captureIntent({
      sessionId: session.id,
      routeId: 'example-skill',
      method: 'POST',
      requestUrl: ROUTE_URL,
      headers: { accept: 'application/json', 'content-type': 'application/json' },
      bodyBytes: Buffer.from('{"prompt":"hash-only fixture"}'),
      purposeLabel: 'skill.invoke',
      correlationId: 'pi-call-001',
    });
    const attachedIntent = intents.attachChallenge({
      intentId: persistedIntent.id,
      paymentRequired,
      challengeReceivedAt: NOW,
    });
    const policyDecision = evaluateSpendPolicy({
      policy: activePolicy.policy,
      policyVersion: { id: activePolicy.id, hash: activePolicy.hash },
      intent: {
        id: attachedIntent.id,
        method: attachedIntent.method,
        requestUrl: ROUTE_URL,
        sellerOrigin: attachedIntent.sellerOrigin,
        resourcePath: attachedIntent.resourcePath,
        walletAddress: attachedIntent.walletAddress,
      },
      wallet: {
        provider: 'deterministic-test',
        walletId: 'wallet-1',
        address: PERSISTED_WALLET_ADDRESS,
        network: NETWORK,
      },
      paymentRequired,
      challengeReceivedAtMs: FIXED_NOW_MS,
      nowMs: FIXED_NOW_MS,
      budgetSnapshot: {
        sellerSessionExposureAtomic: '0',
        sessionExposureAtomic: '0',
        rolling24hExposureAtomic: '0',
        pendingApprovalCount: 0,
      },
    });
    assert.equal(policyDecision.decision, 'allow');
    const persistedDecision = store.transaction((token) => policies.recordDecisionInTransaction(
      token,
      {
        intentId: attachedIntent.id,
        policyVersionId: activePolicy.id,
        evaluation: policyDecision,
        decidedAt: NOW,
      },
    ));
    const authorizationWindow = deriveAuthorizationWindow({
      nowMs: FIXED_NOW_MS,
      challengeReceivedAtMs: FIXED_NOW_MS,
      challengeMaxAgeMs: activePolicy.policy.challengeMaxAgeMs,
      approvalExpiresAt: null,
      maxTimeoutSeconds: paymentRequired.accepts[persistedDecision.acceptedIndex]
        .maxTimeoutSeconds,
      randomBytes(size) {
        assert.equal(size, 32);
        return Buffer.alloc(32, 0x01);
      },
    });
    const binding = Object.freeze({
      intentId: attachedIntent.id,
      intentHash: attachedIntent.intentHash,
      challengeHash: persistedDecision.challengeHash,
      quoteId: persistedDecision.quoteId,
      acceptedIndex: persistedDecision.acceptedIndex,
      requestUrl: ROUTE_URL,
      resourceDescription: ROUTE_METADATA['example-skill'].description,
      resourceMimeType: ROUTE_METADATA['example-skill'].mimeType,
      scheme: 'exact',
      network: NETWORK,
      asset: ASSET,
      walletAddress: PERSISTED_WALLET_ADDRESS,
      payTo: PAY_TO,
      amountAtomic: '50000',
      validAfter: authorizationWindow.validAfter,
      validBefore: authorizationWindow.validBefore,
      nonce: authorizationWindow.nonce,
      policyVersionId: activePolicy.id,
    });
    const permitAuthority = createPermitAuthority();
    const permit = permitAuthority.issue(binding);
    return Object.freeze({
      attachedIntent,
      binding,
      paymentRequired,
      permit,
      permitAuthority,
      persistedDecision,
    });
  } finally {
    store.close();
  }
}

function changedBinding(binding, field) {
  const changes = {
    challengeHash: `sha256:${'22'.repeat(32)}`,
    acceptedIndex: 1,
    amountAtomic: '50001',
    payTo: '0x3000000000000000000000000000000000000000',
    walletAddress: '0x4000000000000000000000000000000000000000',
    validBefore: '1785502859',
    nonce: `0x${'02'.repeat(32)}`,
  };
  const result = { ...binding, [field]: changes[field] };
  if (field === 'challengeHash' || field === 'acceptedIndex') {
    result.quoteId = sha256(canonicalJson({
      challengeHash: result.challengeHash,
      acceptedIndex: result.acceptedIndex,
    }));
  }
  return result;
}

function createContractFixture({ failureMode } = {}) {
  const authority = createRealAuthorityFixture();
  let signCalls = 0;
  const signTypedData = (typedData) => {
    signCalls += 1;
    if (failureMode === 'untyped-error') throw Object.freeze({ secret: 'provider-value' });
    if (failureMode === 'sync-throw') throw new Error('provider sync failure');
    if (failureMode === 'async-reject') return Promise.reject(new Error('provider rejection'));
    if (failureMode === 'never-settle') return new Promise(() => {});
    if (failureMode === 'malformed-signature') return 'not-a-signature';
    if (failureMode === 'high-s-signature') {
      return fixtureAccount.signTypedData(typedData).then(highSSignature);
    }
    if (failureMode === 'zero-one-v-signature') {
      return fixtureAccount.signTypedData(typedData).then(zeroOneVSignature);
    }
    if (failureMode === 'compact-signature') {
      return fixtureAccount.signTypedData(typedData).then(compactSignature);
    }
    if (failureMode === 'assemble-failure') {
      return otherAccount.signTypedData(typedData);
    }
    if (failureMode === 'post-sign-mismatch') {
      return fixtureAccount.signTypedData({
        ...typedData,
        message: { ...typedData.message, value: typedData.message.value + 1n },
      });
    }
    return fixtureAccount.signTypedData(typedData);
  };
  const runWithDeadline = async ({ phase, operation }) => {
    if (phase !== 'signer' || failureMode !== 'never-settle') return await operation();
    void operation();
    await Promise.resolve();
    throw new Error('deterministic signer deadline');
  };
  const adapter = createDeterministicWalletAdapter({
    identity: {
      provider: 'deterministic-test',
      walletId: 'wallet-1',
      address: fixtureAccount.address,
      network: NETWORK,
    },
    verifyAndConsume(permit) {
      if (failureMode === 'pre-sign') throw new Error('fixture pre-sign rejection');
      return authority.permitAuthority.verifyAndConsume(permit);
    },
    signTypedData,
    runWithDeadline,
    nowMs: () => FIXED_NOW_MS,
  });

  return {
    adapter,
    provider: 'deterministic-test',
    walletId: 'wallet-1',
    address: fixtureAccount.address.toLowerCase(),
    paymentRequired: authority.paymentRequired,
    permit: authority.permit,
    signCalls: () => signCalls,
    signAuthorized: () => adapter.signX402Exact(authority.permit, authority.paymentRequired),
    genuineMismatchedPermit(field) {
      const foreignAuthority = createPermitAuthority();
      if (field === 'network' || field === 'asset') {
        const permit = authority.permitAuthority.issue(authority.binding);
        const accepted = {
          ...acceptedRequirement(),
          [field]: field === 'network'
            ? 'eip155:1'
            : '0x5000000000000000000000000000000000000000',
        };
        return { permit, paymentRequired: paymentChallenge(accepted) };
      }
      return foreignAuthority.issue(changedBinding(authority.binding, field));
    },
  };
}

walletAdapterContract('deterministic', createContractFixture);

test('deterministic adapter signs exact Kernel-issued authority offline and deeply freezes output', async (t) => {
  const originalFetch = globalThis.fetch;
  let networkCalls = 0;
  globalThis.fetch = async () => {
    networkCalls += 1;
    throw new Error('network forbidden in deterministic adapter');
  };
  t.after(() => { globalThis.fetch = originalFetch; });

  const fixture = createContractFixture();
  const result = await fixture.signAuthorized();

  assert.equal(fixture.signCalls(), 1);
  assert.equal(result.paymentPayload.payload.authorization.from, PERSISTED_WALLET_ADDRESS);
  assert.equal(result.paymentPayload.payload.authorization.value, '50000');
  assert.equal(result.paymentPayload.payload.authorization.nonce, `0x${'01'.repeat(32)}`);
  assert.ok(deepFrozen(result));
  assert.equal(networkCalls, 0);
});

test('deterministic adapter forwards injected pre-sign and signer deadlines exactly once', async () => {
  const authority = createRealAuthorityFixture();
  const calls = [];
  let signerCalls = 0;
  const adapter = createDeterministicWalletAdapter({
    identity: {
      provider: 'deterministic-test',
      walletId: 'wallet-1',
      address: fixtureAccount.address,
      network: NETWORK,
    },
    verifyAndConsume: authority.permitAuthority.verifyAndConsume,
    async signTypedData(typedData) {
      signerCalls += 1;
      return await fixtureAccount.signTypedData(typedData);
    },
    async runWithDeadline({ phase, timeoutMs, operation }) {
      calls.push([phase, timeoutMs]);
      return await operation();
    },
    preSignTimeoutMs: 111,
    signerTimeoutMs: 222,
    nowMs: () => FIXED_NOW_MS,
  });

  await adapter.signX402Exact(authority.permit, authority.paymentRequired);

  assert.deepEqual(calls, [['pre-sign', 111], ['signer', 222]]);
  assert.equal(signerCalls, 1);
});

test('deterministic adapter rejects expired and beyond-timeout permits before signing', async () => {
  for (const [label, validBefore] of [
    ['expired', '1785502800'],
    ['beyond timeout', '1785502861'],
    ['far future', '999999999999999999999999'],
  ]) {
    const authority = createRealAuthorityFixture();
    const permit = authority.permitAuthority.issue({ ...authority.binding, validBefore });
    let signerCalls = 0;
    const adapter = createDeterministicWalletAdapter({
      identity: {
        provider: 'deterministic-test',
        walletId: 'wallet-1',
        address: fixtureAccount.address,
        network: NETWORK,
      },
      verifyAndConsume: authority.permitAuthority.verifyAndConsume,
      signTypedData: async () => {
        signerCalls += 1;
        return await fixtureAccount.signTypedData({});
      },
      nowMs: () => FIXED_NOW_MS,
    });

    await assert.rejects(
      () => adapter.signX402Exact(permit, authority.paymentRequired),
      (error) => error.code === 'WALLET_PRE_SIGN_REJECTED'
        && error.signatureMayExist === false,
      label,
    );
    assert.equal(signerCalls, 0, label);
    assert.throws(
      () => authority.permitAuthority.verifyAndConsume(permit),
      /consumed/,
      label,
    );
  }
});

test('deterministic adapter validates its clock before consuming a permit', async () => {
  const invalidClocks = [
    () => '1785502800000',
    () => -1,
    () => 1.5,
    () => Number.MAX_SAFE_INTEGER + 1,
    () => { throw new Error('clock failure'); },
    null,
  ];
  for (const nowMs of invalidClocks) {
    const authority = createRealAuthorityFixture();
    let consumeCalls = 0;
    let signerCalls = 0;
    const adapter = createDeterministicWalletAdapter({
      identity: {
        provider: 'deterministic-test',
        walletId: 'wallet-1',
        address: fixtureAccount.address,
        network: NETWORK,
      },
      verifyAndConsume(permit) {
        consumeCalls += 1;
        return authority.permitAuthority.verifyAndConsume(permit);
      },
      signTypedData: async () => {
        signerCalls += 1;
        return 'unreachable';
      },
      nowMs,
    });

    await assert.rejects(
      () => adapter.signX402Exact(authority.permit, authority.paymentRequired),
      (error) => error.code === 'WALLET_PRE_SIGN_REJECTED'
        && error.signatureMayExist === false,
    );
    assert.equal(consumeCalls, 0);
    assert.equal(signerCalls, 0);
    assert.deepEqual(
      authority.permitAuthority.verifyAndConsume(authority.permit),
      authority.binding,
    );
  }
});

test('deterministic adapter captures one signing-time snapshot for build and assembly', async () => {
  const authority = createRealAuthorityFixture();
  let clockCalls = 0;
  const adapter = createDeterministicWalletAdapter({
    identity: {
      provider: 'deterministic-test',
      walletId: 'wallet-1',
      address: fixtureAccount.address,
      network: NETWORK,
    },
    verifyAndConsume: authority.permitAuthority.verifyAndConsume,
    signTypedData: (typedData) => fixtureAccount.signTypedData(typedData),
    nowMs() {
      clockCalls += 1;
      if (clockCalls > 1) throw new Error('signing clock was resampled');
      return FIXED_NOW_MS;
    },
  });

  await adapter.signX402Exact(authority.permit, authority.paymentRequired);
  assert.equal(clockCalls, 1);
});

test('deterministic adapter keeps mode selection and CDP dependencies outside its module', () => {
  const source = fs.readFileSync(
    new URL('../src/adapters/deterministic-wallet-adapter.mjs', import.meta.url),
    'utf8',
  );

  assert.doesNotMatch(source, /WALLET_KERNEL_MODE|process\.env|coinbase|cdp-sdk/i);
  assert.match(source, /createDeterministicWalletAdapter/);
});

test('deterministic identity comparison accepts checksum-equivalent public address only', async () => {
  const authority = createRealAuthorityFixture();
  const adapter = createDeterministicWalletAdapter({
    identity: {
      provider: 'deterministic-test',
      walletId: 'wallet-1',
      address: getAddress(PERSISTED_WALLET_ADDRESS),
      network: NETWORK,
    },
    verifyAndConsume: authority.permitAuthority.verifyAndConsume,
    signTypedData: (typedData) => fixtureAccount.signTypedData(typedData),
    nowMs: () => FIXED_NOW_MS,
  });

  const result = await adapter.signX402Exact(authority.permit, authority.paymentRequired);
  assert.equal(result.paymentPayload.payload.authorization.from, PERSISTED_WALLET_ADDRESS);
});

test('deterministic adapter validates hostile verifier output without invoking accessors or signer', async () => {
  const authority = createRealAuthorityFixture();
  let acceptedIndexGetterCalls = 0;
  let signerCalls = 0;
  const hostileBinding = { ...authority.binding };
  Object.defineProperty(hostileBinding, 'acceptedIndex', {
    enumerable: true,
    get() {
      acceptedIndexGetterCalls += 1;
      return 0;
    },
  });
  const adapter = createDeterministicWalletAdapter({
    identity: {
      provider: 'deterministic-test',
      walletId: 'wallet-1',
      address: fixtureAccount.address,
      network: NETWORK,
    },
    verifyAndConsume: () => hostileBinding,
    signTypedData: async () => {
      signerCalls += 1;
      return 'unreachable';
    },
    nowMs: () => FIXED_NOW_MS,
  });

  await assert.rejects(
    () => adapter.signX402Exact(authority.permit, authority.paymentRequired),
    (error) => error.code === 'WALLET_PRE_SIGN_REJECTED'
      && error.signatureMayExist === false,
  );
  assert.equal(acceptedIndexGetterCalls, 0);
  assert.equal(signerCalls, 0);
});
