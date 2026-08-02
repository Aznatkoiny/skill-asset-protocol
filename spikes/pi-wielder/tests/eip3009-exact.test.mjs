import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';

import { decodePaymentSignatureHeader, encodePaymentSignatureHeader } from '@x402/core/http';
import { PaymentPayloadV2Schema } from '@x402/core/schemas';
import { authorizationTypes } from '@x402/evm';
import { ExactEvmScheme } from '@x402/evm/exact/client';
import { getAddress, keccak256, toBytes } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';

import {
  BASE_SEPOLIA_CAIP2,
  BASE_SEPOLIA_USDC,
  BASE_SEPOLIA_USDC_EIP712_NAME,
  BASE_SEPOLIA_USDC_EIP712_VERSION,
  buildEip3009Exact,
} from '../src/adapters/eip3009-exact.mjs';
import { createAgentEnrollmentRepository } from '../src/kernel/agent-enrollment.mjs';
import { createPermitAuthority, deriveAuthorizationWindow } from '../src/kernel/authorized-permit.mjs';
import { canonicalJson, sha256 } from '../src/kernel/canonical.mjs';
import { createIntentRepository } from '../src/kernel/intent-builder.mjs';
import { evaluateSpendPolicy } from '../src/kernel/policy-engine.mjs';
import { createPolicyRepository } from '../src/kernel/policy-repository.mjs';
import { openKernelStore } from '../src/kernel/sqlite-store.mjs';

const FIXED_NOW_MS = 1_785_502_800_000;
const NOW = '2026-07-31T13:00:00.000Z';
const PAY_TO = '0x2000000000000000000000000000000000000000';
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
  keccak256(toBytes('wallet-kernel-eip3009-golden-test-only')),
);
const PERSISTED_WALLET_ADDRESS = fixtureAccount.address.toLowerCase();
const BASE_POLICY = JSON.parse(fs.readFileSync(
  new URL('../policies/base-sepolia.example.json', import.meta.url),
  'utf8',
));

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

function acceptedRequirement(extra = { name: 'USDC', version: '2' }) {
  return {
    scheme: 'exact',
    network: BASE_SEPOLIA_CAIP2,
    asset: BASE_SEPOLIA_USDC,
    amount: '50000',
    payTo: PAY_TO,
    maxTimeoutSeconds: 60,
    extra,
  };
}

function paymentChallenge({ accepted = acceptedRequirement(), ...overrides } = {}) {
  return {
    x402Version: 2,
    error: 'seller prose must never enter signed or persisted payment bytes',
    resource: {
      url: ROUTE_URL,
      description: ROUTE_METADATA['example-skill'].description,
      mimeType: ROUTE_METADATA['example-skill'].mimeType,
    },
    accepts: [accepted],
    ...overrides,
  };
}

function createAuthorityFixture(t, {
  paymentRequired = paymentChallenge(),
  deriveWindow = true,
} = {}) {
  const store = openKernelStore({
    filePath: ':memory:',
    allowMemory: true,
    now: () => NOW,
  });
  t.after(() => store.close());

  const policyDocument = structuredClone(BASE_POLICY);
  policyDocument.wallet = PERSISTED_WALLET_ADDRESS;
  const policies = createPolicyRepository(store);
  const activePolicy = policies.apply(policyDocument, NOW).policyVersion;
  createAgentEnrollmentRepository({ store, now: () => NOW }).enroll({
    descriptor: DESCRIPTOR,
    expectedDescriptorHash: DESCRIPTOR_HASH,
    operatorIdHash: OPERATOR_HASH,
    mode: 'cdp-testnet',
    kernelUid: 502,
    kernelGid: 502,
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
      network: BASE_SEPOLIA_CAIP2,
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
  const persistedDecision = store.transaction((token) => policies.recordDecisionInTransaction(
    token,
    {
      intentId: attachedIntent.id,
      policyVersionId: activePolicy.id,
      evaluation: policyDecision,
      decidedAt: NOW,
    },
  ));

  let authorizationWindow = null;
  let signingBinding = null;
  let permit = null;
  let permitAuthority = null;
  if (deriveWindow && policyDecision.decision === 'allow') {
    authorizationWindow = deriveAuthorizationWindow({
      nowMs: FIXED_NOW_MS,
      challengeReceivedAtMs: FIXED_NOW_MS,
      challengeMaxAgeMs: activePolicy.policy.challengeMaxAgeMs,
      approvalExpiresAt: null,
      maxTimeoutSeconds: paymentRequired.accepts[policyDecision.acceptedIndex].maxTimeoutSeconds,
      randomBytes(size) {
        assert.equal(size, 32);
        return Buffer.alloc(32, 0x01);
      },
    });
    signingBinding = Object.freeze({
      intentId: attachedIntent.id,
      intentHash: attachedIntent.intentHash,
      requestUrl: ROUTE_URL,
      resourceDescription: ROUTE_METADATA['example-skill'].description,
      resourceMimeType: ROUTE_METADATA['example-skill'].mimeType,
      challengeHash: persistedDecision.challengeHash,
      quoteId: persistedDecision.quoteId,
      acceptedIndex: persistedDecision.acceptedIndex,
      scheme: 'exact',
      network: BASE_SEPOLIA_CAIP2,
      asset: BASE_SEPOLIA_USDC,
      walletAddress: PERSISTED_WALLET_ADDRESS,
      payTo: PAY_TO,
      amountAtomic: '50000',
      nonce: authorizationWindow.nonce,
      validAfter: authorizationWindow.validAfter,
      validBefore: authorizationWindow.validBefore,
      policyVersionId: activePolicy.id,
    });
    permitAuthority = createPermitAuthority();
    permit = permitAuthority.issue(signingBinding);
  }

  return Object.freeze({
    activePolicy,
    attachedIntent,
    authorizationWindow,
    paymentRequired,
    permit,
    permitAuthority,
    persistedDecision,
    policyDecision,
    signingBinding,
  });
}

function expectedTypedData(binding) {
  return {
    domain: {
      name: BASE_SEPOLIA_USDC_EIP712_NAME,
      version: BASE_SEPOLIA_USDC_EIP712_VERSION,
      chainId: 84532,
      verifyingContract: getAddress(BASE_SEPOLIA_USDC),
    },
    types: authorizationTypes,
    primaryType: 'TransferWithAuthorization',
    message: {
      from: getAddress(binding.walletAddress),
      to: getAddress(binding.payTo),
      value: 50000n,
      validAfter: 0n,
      validBefore: 1785502860n,
      nonce: `0x${'01'.repeat(32)}`,
    },
  };
}

test('builds and validates the exact pinned EIP-3009 payload from real Kernel authority', async (t) => {
  let networkCalls = 0;
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => {
    networkCalls += 1;
    throw new Error('network forbidden in exact adapter test');
  };
  t.after(() => { globalThis.fetch = originalFetch; });

  const fixture = createAuthorityFixture(t);
  assert.equal(fixture.policyDecision.decision, 'allow');
  assert.equal(fixture.attachedIntent.challengeHash, fixture.persistedDecision.challengeHash);
  assert.equal(fixture.signingBinding.intentHash, fixture.attachedIntent.intentHash);
  assert.equal(fixture.signingBinding.walletAddress, fixtureAccount.address.toLowerCase());
  assert.equal(fixture.authorizationWindow.validBefore, '1785502860');

  const consumedBinding = fixture.permitAuthority.verifyAndConsume(fixture.permit);
  const exact = buildEip3009Exact({
    binding: consumedBinding,
    paymentRequired: fixture.paymentRequired,
    nowMs: FIXED_NOW_MS,
  });
  assert.deepEqual(exact.typedData, expectedTypedData(consumedBinding));
  assert.ok(deepFrozen(exact.typedData));
  assert.ok(Object.isFrozen(exact));

  const fixtureSignature = await fixtureAccount.signTypedData(exact.typedData);
  const paymentPayload = await exact.assemble(fixtureSignature);
  assert.deepEqual(paymentPayload, {
    x402Version: 2,
    resource: {
      url: ROUTE_URL,
      description: 'offline fixture',
      mimeType: 'application/json',
    },
    accepted: acceptedRequirement(),
    payload: {
      signature: fixtureSignature,
      authorization: {
        from: PERSISTED_WALLET_ADDRESS,
        to: PAY_TO,
        value: '50000',
        validAfter: '0',
        validBefore: '1785502860',
        nonce: `0x${'01'.repeat(32)}`,
      },
    },
  });
  assert.ok(deepFrozen(paymentPayload));
  assert.equal(JSON.stringify(paymentPayload).includes('seller prose'), false);
  assert.equal(networkCalls, 0);
});

test('authorization validity is live and bounded by the selected protocol timeout', (t) => {
  const fixture = createAuthorityFixture(t);
  const exactBoundary = buildEip3009Exact({
    binding: fixture.signingBinding,
    paymentRequired: fixture.paymentRequired,
    nowMs: FIXED_NOW_MS,
  });
  assert.equal(exactBoundary.typedData.message.validBefore, 1_785_502_860n);

  for (const [label, validBefore] of [
    ['already expired', '1785502800'],
    ['one second beyond the protocol maximum', '1785502861'],
    ['far beyond the protocol maximum', '999999999999999999999999'],
  ]) {
    assert.throws(
      () => buildEip3009Exact({
        binding: { ...fixture.signingBinding, validBefore },
        paymentRequired: fixture.paymentRequired,
        nowMs: FIXED_NOW_MS,
      }),
      (error) => error.code === 'WALLET_BINDING',
      label,
    );
  }
});

test('captures an inert closed challenge snapshot and rejects invalid direct construction', async (t) => {
  const fixture = createAuthorityFixture(t);
  const exact = buildEip3009Exact({
    binding: fixture.signingBinding,
    paymentRequired: fixture.paymentRequired,
    nowMs: FIXED_NOW_MS,
  });
  const signature = await fixtureAccount.signTypedData(exact.typedData);
  fixture.paymentRequired.resource.description = 'mutated after construction';
  fixture.paymentRequired.accepts[0].amount = '999999';
  const assembled = await exact.assemble(signature);
  assert.equal(assembled.resource.description, 'offline fixture');
  assert.equal(assembled.accepted.amount, '50000');

  const validChallenge = paymentChallenge();
  for (const [label, binding, challenge] of [
    ['wrong challenge', { ...fixture.signingBinding, challengeHash: `sha256:${'00'.repeat(32)}` }, validChallenge],
    ['wrong quote', { ...fixture.signingBinding, quoteId: `sha256:${'00'.repeat(32)}` }, validChallenge],
    ['wrong chain', fixture.signingBinding, paymentChallenge({
      accepted: { ...acceptedRequirement(), network: 'eip155:1' },
    })],
    ['wrong asset', fixture.signingBinding, paymentChallenge({
      accepted: { ...acceptedRequirement(), asset: PAY_TO },
    })],
    ['malformed nonce', { ...fixture.signingBinding, nonce: `0x${'AA'.repeat(32)}` }, validChallenge],
    ['noncanonical validity', { ...fixture.signingBinding, validBefore: '01785502860' }, validChallenge],
    ['extension-bearing resource', fixture.signingBinding, paymentChallenge({
      resource: {
        url: ROUTE_URL,
        description: 'offline fixture',
        mimeType: 'application/json',
        serviceName: 'untrusted extension',
      },
    })],
    ['extension-bearing accepted', fixture.signingBinding, paymentChallenge({
      accepted: { ...acceptedRequirement(), facilitator: 'untrusted extension' },
    })],
  ]) {
    assert.throws(
      () => buildEip3009Exact({ binding, paymentRequired: challenge, nowMs: FIXED_NOW_MS }),
      (error) => typeof error.code === 'string',
      label,
    );
  }

  const otherAccount = privateKeyToAccount(keccak256(toBytes('other-wallet-test-only')));
  const wrongSignature = await otherAccount.signTypedData(exact.typedData);
  await assert.rejects(
    () => exact.assemble(wrongSignature),
    (error) => error.code === 'WALLET_PAYMENT_PAYLOAD',
  );
});

test('the real policy path denies permit2 and token-domain mutations before permit or signer use', async (t) => {
  const cases = [
    ['permit2', { name: 'USDC', version: '2', assetTransferMethod: 'permit2' }, 'SCHEME_UNSUPPORTED'],
    ['wrong name', { name: 'USD Coin', version: '2' }, 'ASSET_MISMATCH'],
    ['wrong version', { name: 'USDC', version: '1' }, 'ASSET_MISMATCH'],
  ];
  for (const [label, extra, reasonCode] of cases) {
    let signerCalls = 0;
    const fixture = createAuthorityFixture(t, {
      paymentRequired: paymentChallenge({ accepted: acceptedRequirement(extra) }),
    });
    if (fixture.permit !== null) {
      const binding = fixture.permitAuthority.verifyAndConsume(fixture.permit);
      const exact = buildEip3009Exact({
        binding,
        paymentRequired: fixture.paymentRequired,
        nowMs: FIXED_NOW_MS,
      });
      signerCalls += 1;
      await fixtureAccount.signTypedData(exact.typedData);
    }
    assert.equal(fixture.policyDecision.decision, 'deny', label);
    assert.equal(fixture.policyDecision.reasonCode, reasonCode, label);
    assert.equal(fixture.permit, null, label);
    assert.equal(fixture.permitAuthority, null, label);
    assert.equal(signerCalls, 0, label);
  }
});

test('matches the pinned official x402 EIP-3009 golden and v2 HTTP codec', async (t) => {
  const originalNow = Date.now;
  const originalCrypto = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
  Date.now = () => FIXED_NOW_MS;
  Object.defineProperty(globalThis, 'crypto', {
    configurable: true,
    enumerable: true,
    value: Object.freeze({
      getRandomValues(bytes) {
        bytes.fill(0x01);
        return bytes;
      },
    }),
  });
  t.after(() => {
    Date.now = originalNow;
    Object.defineProperty(globalThis, 'crypto', originalCrypto);
  });

  for (const extra of [
    { name: 'USDC', version: '2' },
    { name: 'USDC', version: '2', assetTransferMethod: 'eip3009' },
  ]) {
    const fixture = createAuthorityFixture(t, {
      paymentRequired: paymentChallenge({ accepted: acceptedRequirement(extra) }),
    });
    const exact = buildEip3009Exact({
      binding: fixture.signingBinding,
      paymentRequired: fixture.paymentRequired,
      nowMs: FIXED_NOW_MS,
    });
    const fixtureSignature = await fixtureAccount.signTypedData(exact.typedData);
    const assembled = await exact.assemble(fixtureSignature);
    let signerCalls = 0;
    let recordedTypedData = null;
    const official = new ExactEvmScheme(Object.freeze({
      address: PERSISTED_WALLET_ADDRESS,
      async signTypedData(typedData) {
        signerCalls += 1;
        recordedTypedData = typedData;
        return await fixtureAccount.signTypedData(typedData);
      },
    }));
    const officialResult = await official.createPaymentPayload(
      2,
      fixture.paymentRequired.accepts[0],
    );

    assert.equal(signerCalls, 1);
    assert.deepEqual(recordedTypedData, exact.typedData);
    assert.deepEqual(officialResult.payload, assembled.payload);
    assert.deepEqual(PaymentPayloadV2Schema.parse(assembled), assembled);
    assert.deepEqual(
      decodePaymentSignatureHeader(encodePaymentSignatureHeader(assembled)),
      assembled,
    );
  }
});
