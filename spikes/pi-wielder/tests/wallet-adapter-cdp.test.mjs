import assert from 'node:assert/strict';
import test from 'node:test';

import { keccak256, toBytes } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';

import { createCdpWalletAdapter } from '../src/adapters/cdp-wallet-adapter.mjs';
import { WalletSigningError } from '../src/adapters/wallet-adapter-contract.mjs';
import { createPermitAuthority } from '../src/kernel/authorized-permit.mjs';
import { canonicalJson, sha256 } from '../src/kernel/canonical.mjs';
import {
  createWalletContractPaymentRequired,
  createWalletContractSigningBinding,
  walletAdapterContract,
} from './wallet-adapter-contract.test.mjs';

const FIXED_NOW_MS = 1_785_502_800_000;
const NETWORK = 'eip155:84532';
const WALLET_NAME = 'pilot-wallet';
const SECP256K1_N = BigInt(
  '0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141',
);
const fixtureAccount = privateKeyToAccount(
  keccak256(toBytes('wallet-kernel-cdp-adapter-test-only')),
);
const otherAccount = privateKeyToAccount(
  keccak256(toBytes('wallet-kernel-cdp-adapter-other-test-only')),
);

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

function changedBinding(binding, field) {
  const replacements = {
    challengeHash: `sha256:${'22'.repeat(32)}`,
    acceptedIndex: 1,
    amountAtomic: '50001',
    payTo: '0x3000000000000000000000000000000000000000',
    network: 'eip155:1',
    asset: '0x5000000000000000000000000000000000000000',
    walletAddress: '0x4000000000000000000000000000000000000000',
    validBefore: '1785502859',
    nonce: `0x${'02'.repeat(32)}`,
  };
  const next = { ...binding, [field]: replacements[field] };
  if (field === 'challengeHash' || field === 'acceptedIndex') {
    next.quoteId = sha256(canonicalJson({
      challengeHash: next.challengeHash,
      acceptedIndex: next.acceptedIndex,
    }));
  }
  return next;
}

function createContractFixture({ failureMode } = {}) {
  const paymentRequired = createWalletContractPaymentRequired();
  const binding = createWalletContractSigningBinding({
    walletAddress: fixtureAccount.address.toLowerCase(),
  }, paymentRequired);
  const permitAuthority = createPermitAuthority();
  const permit = permitAuthority.issue(binding);
  let accountCalls = 0;
  let signCalls = 0;

  const account = Object.freeze({
    address: fixtureAccount.address.toLowerCase(),
    signTypedData(typedData) {
      signCalls += 1;
      if (failureMode === 'untyped-error') {
        throw Object.freeze({ secret: 'provider-value' });
      }
      if (failureMode === 'sync-throw') throw new Error('provider sync failure');
      if (failureMode === 'async-reject') {
        return Promise.reject(new Error('provider rejection'));
      }
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
    },
  });
  const cdpClient = Object.freeze({
    evm: Object.freeze({
      async getAccount({ name }) {
        accountCalls += 1;
        assert.equal(name, WALLET_NAME);
        if (failureMode === 'account-reject') {
          throw new Error('provider response containing secret material');
        }
        return account;
      },
    }),
  });
  const runWithDeadline = async ({ phase, operation }) => {
    if (phase !== 'signer' || failureMode !== 'never-settle') return await operation();
    void operation();
    await Promise.resolve();
    throw new Error('CDP signer deadline');
  };
  const adapter = createCdpWalletAdapter({
    cdpClient,
    walletName: WALLET_NAME,
    verifyAndConsume(value) {
      if (failureMode === 'pre-sign') throw new Error('fixture pre-sign rejection');
      return permitAuthority.verifyAndConsume(value);
    },
    runWithDeadline,
    nowMs: () => FIXED_NOW_MS,
  });

  return {
    adapter,
    provider: 'coinbase-cdp',
    walletId: WALLET_NAME,
    address: fixtureAccount.address,
    paymentRequired,
    permit,
    account,
    cdpClient,
    accountCalls: () => accountCalls,
    signCalls: () => signCalls,
    signAuthorized: () => adapter.signX402Exact(permit, paymentRequired),
    genuineMismatchedPermit(field) {
      if (field === 'network' || field === 'asset') {
        const mismatchedPayment = structuredClone(paymentRequired);
        mismatchedPayment.accepts[0][field] = field === 'network'
          ? 'eip155:1'
          : '0x5000000000000000000000000000000000000000';
        return {
          permit: permitAuthority.issue(binding),
          paymentRequired: mismatchedPayment,
        };
      }
      return createPermitAuthority().issue(changedBinding(binding, field));
    },
  };
}

walletAdapterContract('cdp', createContractFixture);

test('CDP adapter signs exactly the Kernel-issued EIP-3009 authorization', async () => {
  const fixture = createContractFixture();
  const result = await fixture.signAuthorized();

  assert.equal(fixture.accountCalls(), 1);
  assert.equal(fixture.signCalls(), 1);
  assert.deepEqual(result.paymentPayload.payload.authorization, {
    from: fixtureAccount.address.toLowerCase(),
    to: '0x2000000000000000000000000000000000000000',
    value: '50000',
    validAfter: '0',
    validBefore: '1785502860',
    nonce: `0x${'01'.repeat(32)}`,
  });
});

test('CDP account initialization is shared across concurrent callers', async () => {
  const paymentRequired = createWalletContractPaymentRequired();
  const binding = createWalletContractSigningBinding({
    walletAddress: fixtureAccount.address.toLowerCase(),
  }, paymentRequired);
  const permits = createPermitAuthority();
  let releaseAccount;
  let accountCalls = 0;
  const pendingAccount = new Promise((resolve) => { releaseAccount = resolve; });
  const adapter = createCdpWalletAdapter({
    cdpClient: {
      evm: {
        getAccount({ name }) {
          accountCalls += 1;
          assert.equal(name, WALLET_NAME);
          return pendingAccount;
        },
      },
    },
    walletName: WALLET_NAME,
    verifyAndConsume: permits.verifyAndConsume,
    nowMs: () => FIXED_NOW_MS,
  });

  const requests = Array.from({ length: 8 }, () => adapter.walletIdentity());
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(accountCalls, 1);
  releaseAccount({
    address: fixtureAccount.address,
    signTypedData: (typedData) => fixtureAccount.signTypedData(typedData),
  });
  const identities = await Promise.all(requests);
  assert.equal(accountCalls, 1);
  assert.ok(identities.every((identity) => identity.walletId === WALLET_NAME));

  const result = await adapter.signX402Exact(permits.issue(binding), paymentRequired);
  assert.equal(result.paymentPayload.payload.authorization.value, '50000');
  assert.equal(accountCalls, 1);
});

test('CDP adapter exposes neither provider handles nor account provisioning methods', async () => {
  const fixture = createContractFixture();
  const identity = await fixture.adapter.walletIdentity();
  const result = await fixture.signAuthorized();

  assert.deepEqual(Object.keys(fixture.cdpClient.evm), ['getAccount']);
  assert.equal('createAccount' in fixture.cdpClient.evm, false);
  assert.equal('getOrCreateAccount' in fixture.cdpClient.evm, false);
  assert.notEqual(identity, fixture.account);
  assert.notEqual(result, fixture.account);
  assert.notEqual(result, fixture.cdpClient);
  assert.doesNotMatch(JSON.stringify({ identity, result }), /provider response|secret material/i);
});

test('CDP account lookup rejection is definitely pre-sign and redacted', async () => {
  const fixture = createContractFixture({ failureMode: 'account-reject' });
  await assert.rejects(
    () => fixture.signAuthorized(),
    (error) => {
      assert.ok(error instanceof WalletSigningError);
      assert.equal(error.code, 'WALLET_PRE_SIGN_REJECTED');
      assert.equal(error.signatureMayExist, false);
      assert.equal(error.cause, undefined);
      assert.doesNotMatch(JSON.stringify(error), /provider response|secret material/i);
      return true;
    },
  );
  assert.equal(fixture.accountCalls(), 1);
  assert.equal(fixture.signCalls(), 0);
});

test('CDP adapter rejects a live account address mismatch before signing', async () => {
  const paymentRequired = createWalletContractPaymentRequired();
  const binding = createWalletContractSigningBinding({
    walletAddress: fixtureAccount.address.toLowerCase(),
  }, paymentRequired);
  const permits = createPermitAuthority();
  let signCalls = 0;
  const adapter = createCdpWalletAdapter({
    cdpClient: {
      evm: {
        async getAccount() {
          return {
            address: otherAccount.address,
            signTypedData() {
              signCalls += 1;
              throw new Error('must not be reached');
            },
          };
        },
      },
    },
    walletName: WALLET_NAME,
    verifyAndConsume: permits.verifyAndConsume,
    nowMs: () => FIXED_NOW_MS,
  });

  await assert.rejects(
    () => adapter.signX402Exact(permits.issue(binding), paymentRequired),
    (error) => error.code === 'WALLET_PRE_SIGN_REJECTED'
      && error.signatureMayExist === false,
  );
  assert.equal(signCalls, 0);
});

test('CDP identity and signing operations use their injected bounded phases', async () => {
  const paymentRequired = createWalletContractPaymentRequired();
  const binding = createWalletContractSigningBinding({
    walletAddress: fixtureAccount.address.toLowerCase(),
  }, paymentRequired);
  const permits = createPermitAuthority();
  const calls = [];
  const adapter = createCdpWalletAdapter({
    cdpClient: {
      evm: {
        async getAccount() {
          return {
            address: fixtureAccount.address,
            signTypedData: (typedData) => fixtureAccount.signTypedData(typedData),
          };
        },
      },
    },
    walletName: WALLET_NAME,
    verifyAndConsume: permits.verifyAndConsume,
    async runWithDeadline({ phase, timeoutMs, operation }) {
      calls.push([phase, timeoutMs]);
      return await operation();
    },
    preSignTimeoutMs: 111,
    signerTimeoutMs: 222,
    nowMs: () => FIXED_NOW_MS,
  });

  await adapter.walletIdentity();
  await adapter.signX402Exact(permits.issue(binding), paymentRequired);
  assert.deepEqual(calls, [
    ['wallet_identity', 111],
    ['pre-sign', 111],
    ['signer', 222],
  ]);
});
