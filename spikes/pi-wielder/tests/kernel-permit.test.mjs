import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import test from 'node:test';

import { canonicalJson, KernelError, sha256 } from '../src/kernel/canonical.mjs';
import {
  createPermitAuthority,
  deriveAuthorizationWindow,
} from '../src/kernel/authorized-permit.mjs';

const INTENT_HASH = sha256(canonicalJson({ fixture: 'intent-1' }));
const CHALLENGE_HASH = sha256(canonicalJson({ fixture: 'challenge-1' }));
const QUOTE_ID = sha256(canonicalJson({ challengeHash: CHALLENGE_HASH, acceptedIndex: 0 }));
const PERMIT_FIELDS = Object.freeze([
  'intentId',
  'intentHash',
  'challengeHash',
  'quoteId',
  'acceptedIndex',
  'requestUrl',
  'resourceDescription',
  'resourceMimeType',
  'scheme',
  'network',
  'asset',
  'walletAddress',
  'payTo',
  'amountAtomic',
  'validAfter',
  'validBefore',
  'nonce',
  'policyVersionId',
]);
const BINDING = Object.freeze({
  intentId: 'intent-1',
  intentHash: INTENT_HASH,
  challengeHash: CHALLENGE_HASH,
  quoteId: QUOTE_ID,
  acceptedIndex: 0,
  requestUrl: 'https://seller.example/paid/infer',
  resourceDescription: 'offline fixture',
  resourceMimeType: 'application/json',
  scheme: 'exact',
  network: 'eip155:84532',
  asset: '0x036cbd53842c5426634e7929541ec2318f3dcf7e',
  walletAddress: '0x1000000000000000000000000000000000000000',
  payTo: '0x2000000000000000000000000000000000000000',
  amountAtomic: '50000',
  validAfter: '0',
  validBefore: '1785502860',
  nonce: `0x${'01'.repeat(32)}`,
  policyVersionId: 'policy-1',
});

function assertKernelError(operation, expectedCode) {
  assert.throws(operation, (error) => {
    assert.equal(error instanceof KernelError, true);
    assert.equal(error.code, expectedCode);
    return true;
  });
}

function issueAndConsume(binding = BINDING) {
  const authority = createPermitAuthority();
  return authority.verifyAndConsume(authority.issue(binding));
}

test('issues a minimal frozen permit and consumes its deeply frozen exact binding once', () => {
  const authority = createPermitAuthority();
  const source = { ...BINDING };

  const permit = authority.issue(source);
  source.amountAtomic = '999999';

  assert.equal(Object.isFrozen(authority), true);
  assert.deepEqual(Object.keys(authority), ['issue', 'verifyAndConsume']);
  assert.equal(Object.isFrozen(permit), true);
  assert.deepEqual(Object.keys(permit), ['kind', 'intentId']);
  assert.deepEqual(permit, { kind: 'AuthorizedPermit', intentId: 'intent-1' });
  assert.equal(JSON.stringify(permit), '{"kind":"AuthorizedPermit","intentId":"intent-1"}');

  const { verifyAndConsume } = authority;
  const verified = verifyAndConsume(permit);
  assert.notEqual(verified, source);
  assert.deepEqual(Object.keys(verified), PERMIT_FIELDS);
  assert.deepEqual(verified, BINDING);
  assert.equal(Object.isFrozen(verified), true);
  assert.throws(() => {
    verified.amountAtomic = '1';
  }, TypeError);
  assert.throws(
    () => verifyAndConsume(permit),
    /AuthorizedPermit already consumed/,
  );
});

test('rejects copied, serialized, cloned, plain, cross-authority, and proxy permit forgeries', () => {
  const authority = createPermitAuthority();
  const permit = authority.issue(BINDING);
  const otherAuthorityPermit = createPermitAuthority().issue(BINDING);
  const copies = [
    Object.freeze({ ...permit }),
    JSON.parse(JSON.stringify(permit)),
    structuredClone(permit),
    { kind: 'AuthorizedPermit', intentId: 'intent-1' },
    otherAuthorityPermit,
    null,
    'AuthorizedPermit',
  ];

  for (const copy of copies) {
    assert.throws(() => authority.verifyAndConsume(copy), /AuthorizedPermit is forged/);
  }

  let trapCalls = 0;
  const proxy = new Proxy({ kind: 'AuthorizedPermit', intentId: 'intent-1' }, {
    get() {
      trapCalls += 1;
      return Reflect.get(...arguments);
    },
    getPrototypeOf() {
      trapCalls += 1;
      return Reflect.getPrototypeOf(...arguments);
    },
  });
  assert.throws(() => authority.verifyAndConsume(proxy), /AuthorizedPermit is forged/);
  assert.equal(trapCalls, 0);

  assert.deepEqual(authority.verifyAndConsume(permit), BINDING);
});

test('WeakMap and WeakSet prototype poisoning cannot forge or revive a permit', () => {
  const targets = [
    [WeakMap.prototype, 'set'],
    [WeakMap.prototype, 'get'],
    [WeakMap.prototype, 'delete'],
    [WeakSet.prototype, 'has'],
    [WeakSet.prototype, 'add'],
  ];
  const originals = targets.map(([prototype, name]) => Object.freeze({
    descriptor: Object.getOwnPropertyDescriptor(prototype, name),
    name,
    prototype,
  }));
  let verified;
  let replayError;
  let forgedError;
  try {
    Object.defineProperty(WeakMap.prototype, 'set', {
      ...Object.getOwnPropertyDescriptor(WeakMap.prototype, 'set'),
      value() { return this; },
    });
    Object.defineProperty(WeakMap.prototype, 'get', {
      ...Object.getOwnPropertyDescriptor(WeakMap.prototype, 'get'),
      value() { return BINDING; },
    });
    Object.defineProperty(WeakMap.prototype, 'delete', {
      ...Object.getOwnPropertyDescriptor(WeakMap.prototype, 'delete'),
      value() { return true; },
    });
    Object.defineProperty(WeakSet.prototype, 'has', {
      ...Object.getOwnPropertyDescriptor(WeakSet.prototype, 'has'),
      value() { return false; },
    });
    Object.defineProperty(WeakSet.prototype, 'add', {
      ...Object.getOwnPropertyDescriptor(WeakSet.prototype, 'add'),
      value() { return this; },
    });

    const authority = createPermitAuthority();
    const permit = authority.issue(BINDING);
    verified = authority.verifyAndConsume(permit);
    try {
      authority.verifyAndConsume(permit);
    } catch (error) {
      replayError = error;
    }
    try {
      authority.verifyAndConsume(Object.freeze({ ...permit }));
    } catch (error) {
      forgedError = error;
    }
  } finally {
    for (const { descriptor, name, prototype } of originals) {
      Object.defineProperty(prototype, name, descriptor);
    }
  }

  assert.deepEqual(verified, BINDING);
  assert.match(replayError?.message ?? '', /AuthorizedPermit already consumed/);
  assert.match(forgedError?.message ?? '', /AuthorizedPermit is forged/);
  for (const { descriptor, name, prototype } of originals) {
    assert.deepEqual(Object.getOwnPropertyDescriptor(prototype, name), descriptor);
  }
});

test('a permit serialized by a fresh process is forged in this process', () => {
  const moduleUrl = new URL('../src/kernel/authorized-permit.mjs', import.meta.url).href;
  const child = spawnSync(process.execPath, [
    '--input-type=module',
    '--eval',
    `import { createPermitAuthority } from ${JSON.stringify(moduleUrl)};
     const authority = createPermitAuthority();
     process.stdout.write(JSON.stringify(authority.issue(${JSON.stringify(BINDING)})));`,
  ], { encoding: 'utf8' });

  assert.equal(child.status, 0, child.stderr);
  assert.equal(child.stderr, '');
  const foreignPermit = JSON.parse(child.stdout);
  const authority = createPermitAuthority();
  assert.throws(
    () => authority.verifyAndConsume(foreignPermit),
    /AuthorizedPermit is forged/,
  );
});

test('the authority copies a reordered binding into one canonical closed surface', () => {
  const reversed = Object.fromEntries(Object.entries(BINDING).reverse());
  const verified = issueAndConsume(reversed);

  assert.deepEqual(Object.keys(verified), PERMIT_FIELDS);
  assert.deepEqual(verified, BINDING);
  assert.equal(Object.isFrozen(verified), true);
});

test('permit identity binds resource metadata and policy identity against substitution', () => {
  const authority = createPermitAuthority();
  const source = { ...BINDING };
  const permit = authority.issue(source);
  const alternate = {
    ...BINDING,
    resourceDescription: 'substituted fixture',
    resourceMimeType: 'application/cbor',
    policyVersionId: 'policy-2',
  };
  const alternatePermit = authority.issue(alternate);

  source.resourceDescription = alternate.resourceDescription;
  source.resourceMimeType = alternate.resourceMimeType;
  source.policyVersionId = alternate.policyVersionId;

  assert.throws(() => authority.verifyAndConsume(Object.freeze({
    ...permit,
    resourceDescription: alternate.resourceDescription,
  })), /AuthorizedPermit is forged/);
  assert.deepEqual(authority.verifyAndConsume(permit), BINDING);
  assert.deepEqual(authority.verifyAndConsume(alternatePermit), alternate);
});

test('rejects non-plain, accessor, missing, extra, and noncanonical permit bindings', () => {
  let getterCalls = 0;
  const accessor = { ...BINDING };
  Object.defineProperty(accessor, 'intentId', {
    enumerable: true,
    get() {
      getterCalls += 1;
      return 'intent-1';
    },
  });
  const inherited = Object.assign(Object.create({ secret: 'value' }), BINDING);
  const withSymbol = { ...BINDING, [Symbol('secret')]: 'value' };
  const nonenumerable = Object.defineProperty({ ...BINDING }, 'secret', {
    enumerable: false,
    value: 'value',
  });
  const missing = { ...BINDING };
  delete missing.quoteId;
  const missingResourceDescription = { ...BINDING };
  delete missingResourceDescription.resourceDescription;
  const missingResourceMimeType = { ...BINDING };
  delete missingResourceMimeType.resourceMimeType;
  const missingPolicyVersionId = { ...BINDING };
  delete missingPolicyVersionId.policyVersionId;

  for (const binding of [
    null,
    [],
    accessor,
    inherited,
    withSymbol,
    nonenumerable,
    missing,
    missingResourceDescription,
    missingResourceMimeType,
    missingPolicyVersionId,
    { ...BINDING, extra: true },
  ]) {
    assertKernelError(() => createPermitAuthority().issue(binding), 'PERMIT_BINDING');
  }
  assert.equal(getterCalls, 0);

  const invalidFields = [
    ['intentId', ''],
    ['intentId', '-intent'],
    ['intentHash', `sha256:${'AB'.repeat(32)}`],
    ['challengeHash', `sha256:${'0g'.repeat(32)}`],
    ['quoteId', 'quote-1'],
    ['acceptedIndex', -1],
    ['acceptedIndex', 0.5],
    ['acceptedIndex', '0'],
    ['requestUrl', 'http://seller.example/paid/infer'],
    ['requestUrl', 'https://user@seller.example/paid/infer'],
    ['requestUrl', 'https://seller.example/paid/../infer'],
    ['requestUrl', 'https://seller.example/paid/infer#fragment'],
    ['resourceDescription', ''],
    ['resourceDescription', 'control\ntext'],
    ['resourceDescription', 'x'.repeat(1_025)],
    ['resourceMimeType', 'application'],
    ['resourceMimeType', 'application/json; charset=utf-8'],
    ['resourceMimeType', 'x'.repeat(201)],
    ['scheme', 'EXACT'],
    ['network', 'base-sepolia'],
    ['asset', `0x${'AB'.repeat(20)}`],
    ['walletAddress', `0x${'01'.repeat(19)}`],
    ['payTo', `0x${'gg'.repeat(20)}`],
    ['amountAtomic', '0'],
    ['amountAtomic', '050000'],
    ['validAfter', '1'],
    ['validBefore', '01785502860'],
    ['validBefore', '0'],
    ['nonce', `0x${'AB'.repeat(32)}`],
    ['nonce', `0x${'01'.repeat(31)}`],
    ['policyVersionId', ''],
    ['policyVersionId', '-policy'],
  ];
  for (const [field, value] of invalidFields) {
    assertKernelError(
      () => createPermitAuthority().issue({ ...BINDING, [field]: value }),
      'PERMIT_BINDING',
    );
  }
});

test('issue and consume emit no logs and expose no persistence or transport hooks', () => {
  const originalLog = console.log;
  const originalError = console.error;
  const calls = [];
  console.log = (...parts) => calls.push(['log', ...parts]);
  console.error = (...parts) => calls.push(['error', ...parts]);
  try {
    const authority = createPermitAuthority();
    const permit = authority.issue(BINDING);
    assert.deepEqual(authority.verifyAndConsume(permit), BINDING);
    assert.deepEqual(Object.keys(authority), ['issue', 'verifyAndConsume']);
    assert.deepEqual(Object.keys(permit), ['kind', 'intentId']);
  } finally {
    console.log = originalLog;
    console.error = originalError;
  }
  assert.deepEqual(calls, []);
});

test('derives the protocol, challenge, or approval deadline as the exact minimum', () => {
  const cases = [
    {
      label: 'protocol',
      input: {
        nowMs: 100_000,
        challengeReceivedAtMs: 90_000,
        challengeMaxAgeMs: 120_000,
        approvalExpiresAt: '1970-01-01T00:03:50.000Z',
        maxTimeoutSeconds: 60,
      },
      validBefore: '160',
    },
    {
      label: 'challenge',
      input: {
        nowMs: 100_900,
        challengeReceivedAtMs: 90_100,
        challengeMaxAgeMs: 30_000,
        approvalExpiresAt: '1970-01-01T00:02:10.000Z',
        maxTimeoutSeconds: 60,
      },
      validBefore: '120',
    },
    {
      label: 'approval',
      input: {
        nowMs: 100_000,
        challengeReceivedAtMs: 90_000,
        challengeMaxAgeMs: 120_000,
        approvalExpiresAt: '1970-01-01T00:01:55.999Z',
        maxTimeoutSeconds: 60,
      },
      validBefore: '115',
    },
  ];

  for (const fixture of cases) {
    let calls = 0;
    const random = Buffer.from('01'.repeat(32), 'hex');
    const result = deriveAuthorizationWindow({
      ...fixture.input,
      randomBytes: (size) => {
        calls += 1;
        assert.equal(size, 32, fixture.label);
        return random;
      },
    });
    random.fill(0xff);

    assert.deepEqual(result, {
      nonce: `0x${'01'.repeat(32)}`,
      validAfter: '0',
      validBefore: fixture.validBefore,
    }, fixture.label);
    assert.equal(Object.isFrozen(result), true, fixture.label);
    assert.equal(calls, 1, fixture.label);
  }
});

test('authorization seconds truncate subsecond values and the no-approval fixture stays plus 60', () => {
  let calls = 0;
  const result = deriveAuthorizationWindow({
    nowMs: 1_785_502_800_999,
    challengeReceivedAtMs: 1_785_502_800_999,
    challengeMaxAgeMs: 60_000,
    approvalExpiresAt: null,
    maxTimeoutSeconds: 60,
    randomBytes(size) {
      calls += 1;
      assert.equal(size, 32);
      return new Uint8Array(32).fill(2);
    },
  });

  assert.deepEqual(result, {
    nonce: `0x${'02'.repeat(32)}`,
    validAfter: '0',
    validBefore: '1785502860',
  });
  assert.equal(calls, 1);
});

test('rejects exhausted windows before requesting randomness', () => {
  for (const input of [
    {
      nowMs: 120_000,
      challengeReceivedAtMs: 90_000,
      challengeMaxAgeMs: 30_999,
      approvalExpiresAt: null,
      maxTimeoutSeconds: 60,
    },
    {
      nowMs: 120_999,
      challengeReceivedAtMs: 120_000,
      challengeMaxAgeMs: 60_000,
      approvalExpiresAt: '1970-01-01T00:02:00.999Z',
      maxTimeoutSeconds: 60,
    },
  ]) {
    let calls = 0;
    assertKernelError(() => deriveAuthorizationWindow({
      ...input,
      randomBytes() {
        calls += 1;
        return Buffer.alloc(32);
      },
    }), 'AUTHORIZATION_WINDOW');
    assert.equal(calls, 0);
  }
});

test('rejects wrong-length or non-byte randomness after exactly one call', () => {
  const randomValues = [Buffer.alloc(31), Buffer.alloc(33), new Uint8Array(31), '00'.repeat(32)];
  for (const randomValue of randomValues) {
    let calls = 0;
    assertKernelError(() => deriveAuthorizationWindow({
      nowMs: 100_000,
      challengeReceivedAtMs: 100_000,
      challengeMaxAgeMs: 60_000,
      approvalExpiresAt: null,
      maxTimeoutSeconds: 60,
      randomBytes(size) {
        calls += 1;
        assert.equal(size, 32);
        return randomValue;
      },
    }), 'AUTHORIZATION_RANDOMNESS');
    assert.equal(calls, 1);
  }
});

test('authorization-window input is closed, inert, and canonical', () => {
  const valid = {
    nowMs: 100_000,
    challengeReceivedAtMs: 100_000,
    challengeMaxAgeMs: 60_000,
    approvalExpiresAt: null,
    maxTimeoutSeconds: 60,
    randomBytes: () => Buffer.alloc(32, 3),
  };
  let getterCalls = 0;
  const accessor = { ...valid };
  Object.defineProperty(accessor, 'nowMs', {
    enumerable: true,
    get() {
      getterCalls += 1;
      return 100_000;
    },
  });
  const missing = { ...valid };
  delete missing.randomBytes;

  for (const input of [null, [], accessor, missing, { ...valid, extra: true }]) {
    assertKernelError(() => deriveAuthorizationWindow(input), 'AUTHORIZATION_WINDOW');
  }
  assert.equal(getterCalls, 0);

  const invalidFields = [
    ['nowMs', -1],
    ['nowMs', 1.5],
    ['nowMs', Number.MAX_SAFE_INTEGER + 1],
    ['challengeReceivedAtMs', -1],
    ['challengeReceivedAtMs', 100_001],
    ['challengeMaxAgeMs', 0],
    ['challengeMaxAgeMs', 1.5],
    ['approvalExpiresAt', '1970-01-01T00:02:40Z'],
    ['approvalExpiresAt', 'not-a-time'],
    ['maxTimeoutSeconds', 0],
    ['maxTimeoutSeconds', 3601],
    ['maxTimeoutSeconds', 1.5],
    ['maxTimeoutSeconds', '60'],
    ['randomBytes', null],
  ];
  for (const [field, value] of invalidFields) {
    assertKernelError(
      () => deriveAuthorizationWindow({ ...valid, [field]: value }),
      'AUTHORIZATION_WINDOW',
    );
  }
});
