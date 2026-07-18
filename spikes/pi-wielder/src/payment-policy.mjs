import crypto from 'node:crypto';

export const BASE_SEPOLIA_NETWORK = 'base-sepolia';
export const BASE_SEPOLIA_CHAIN_ID = 84532;
export const BASE_SEPOLIA_USDC = '0x036cbd53842c5426634e7929541ec2318f3dcf7e';

export class PaymentPolicyError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'PaymentPolicyError';
    this.code = code;
  }
}

const fail = (code, message) => { throw new PaymentPolicyError(code, message); };

function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactObject(value, keys, code, label) {
  if (!isPlainObject(value)) fail(code, `${label} must be a plain object`);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    fail(code, `${label} must contain exactly: ${expected.join(', ')}`);
  }
  return value;
}

function optionalExactObject(value, required, optional, code, label) {
  if (!isPlainObject(value)) fail(code, `${label} must be a plain object`);
  const actual = Object.keys(value);
  if (required.some((key) => !actual.includes(key))
      || actual.some((key) => !required.includes(key) && !optional.includes(key))) {
    fail(code, `${label} contains missing or unknown fields`);
  }
  return value;
}

function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

function frozenCopy(value) {
  return deepFreeze(structuredClone(value));
}

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalize(value[key])]));
  }
  return value;
}

function canonicalJson(value) {
  return JSON.stringify(canonicalize(value));
}

function hashJson(value) {
  return `sha256:${crypto.createHash('sha256').update(canonicalJson(value)).digest('hex')}`;
}

function canonicalAtomic(value, label, code = 'AMOUNT_FORMAT') {
  if (typeof value !== 'string' || !/^(0|[1-9]\d*)$/.test(value)) {
    fail(code, `${label} must be a canonical non-negative integer string`);
  }
  return { text: value, value: BigInt(value) };
}

function canonicalAddress(value, label, code) {
  if (typeof value !== 'string' || !/^0x[0-9a-f]{40}$/.test(value)) {
    fail(code, `${label} must be one canonical lowercase 20-byte hex address`);
  }
  return value;
}

function canonicalHash(value, label, code = 'HASH_FORMAT') {
  if (typeof value !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(value)) {
    fail(code, `${label} must be a canonical SHA-256 identifier`);
  }
  return value;
}

function canonicalBytes32(value, label, code) {
  if (typeof value !== 'string' || !/^0x[0-9a-f]{64}$/.test(value)) {
    fail(code, `${label} must be a canonical lowercase 32-byte hex value`);
  }
  return value;
}

function canonicalSignature(value) {
  if (typeof value !== 'string' || !/^0x[0-9a-f]{130}$/.test(value)) {
    fail('SIGNATURE_FORMAT', 'signature must be a canonical lowercase 65-byte hex value');
  }
  return value;
}

function canonicalReason(value) {
  if (typeof value !== 'string' || !/^[A-Z][A-Z0-9_]{1,63}$/.test(value)) {
    fail('REASON_CODE', 'reasonCode must be a stable uppercase identifier');
  }
  return value;
}

function canonicalMethod(value) {
  if (typeof value !== 'string' || !/^[A-Z][A-Z0-9_-]*$/.test(value)) {
    fail('REQUEST_METHOD', 'request method must be a canonical uppercase token');
  }
  return value;
}

function exactBodyBytes(value) {
  if (typeof value === 'string') return Buffer.from(value, 'utf8');
  if (value instanceof Uint8Array) return Buffer.from(value);
  if (value === null) return Buffer.alloc(0);
  fail('REQUEST_BODY', 'request body must be a string, Uint8Array, or null');
}

function resourceUrl(value) {
  if (typeof value !== 'string') fail('RESOURCE_URL', 'resource URL must be a string');
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    fail('RESOURCE_URL', 'resource URL is invalid');
  }
  if (!['http:', 'https:'].includes(parsed.protocol)
      || parsed.username || parsed.password || parsed.search || parsed.hash
      || parsed.href !== value
      || /[%\\]/.test(parsed.pathname)
      || parsed.pathname.includes('//')) {
    fail('RESOURCE_URL', 'resource URL violates the canonical HTTP(S) boundary');
  }
  return parsed;
}

function sellerOrigin(value) {
  if (typeof value !== 'string') fail('SELLER_ORIGIN', 'seller origin must be a string');
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    fail('SELLER_ORIGIN', 'seller origin is invalid');
  }
  if (!['http:', 'https:'].includes(parsed.protocol)
      || parsed.username || parsed.password || parsed.search || parsed.hash
      || value !== parsed.origin || parsed.pathname !== '/') {
    fail('SELLER_ORIGIN', 'seller origin must be one exact canonical origin without a trailing slash');
  }
  return parsed.origin;
}

function sellerPathPrefix(value) {
  if (typeof value !== 'string' || !value.startsWith('/')
      || value.includes('?') || value.includes('#') || /[%\\]/.test(value)
      || value.includes('//') || value.split('/').includes('..') || value.split('/').includes('.')) {
    fail('SELLER_PATH', 'seller pathPrefix must be a canonical absolute path');
  }
  const normalized = value.length > 1 && value.endsWith('/') ? value.slice(0, -1) : value;
  if (normalized === '') fail('SELLER_PATH', 'seller pathPrefix cannot be empty');
  return normalized;
}

function routeMatches(pathname, prefix) {
  return prefix === '/' || pathname === prefix || pathname.startsWith(`${prefix}/`);
}

function canonicalTimestamp(value, label) {
  if (typeof value !== 'string') fail('QUOTE_EXPIRY', `${label} must be an ISO timestamp`);
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value) {
    fail('QUOTE_EXPIRY', `${label} must be a canonical ISO timestamp`);
  }
  return milliseconds;
}

function offerSchema(value) {
  exactObject(value, [
    'scheme', 'network', 'maxAmountRequired', 'resource', 'description', 'mimeType',
    'payTo', 'maxTimeoutSeconds', 'asset', 'extra',
  ], 'OFFER_SCHEMA', 'x402 offer');
  exactObject(value.extra, [
    'name', 'version', 'requestHash', 'quoteId', 'issuedAt', 'expiresAt',
  ], 'OFFER_EXTRA_SCHEMA', 'x402 offer extra');
  if (typeof value.description !== 'string' || typeof value.mimeType !== 'string') {
    fail('OFFER_SCHEMA', 'offer description and mimeType must be strings');
  }
  return value;
}

function challengeSchema(value) {
  exactObject(value, ['x402Version', 'error', 'accepts'], 'CHALLENGE_SCHEMA', 'x402 challenge');
  if (value.x402Version !== 1 || typeof value.error !== 'string'
      || !Array.isArray(value.accepts) || value.accepts.length !== 1) {
    fail('CHALLENGE_SCHEMA', 'x402 challenge must contain exactly one v1 offer');
  }
  return offerSchema(value.accepts[0]);
}

function authorizationSchema(value) {
  exactObject(value, ['from', 'to', 'value', 'validAfter', 'validBefore', 'nonce'],
    'AUTHORIZATION_SCHEMA', 'payment authorization');
  canonicalAddress(value.from, 'authorization.from', 'AUTHORIZATION_SCHEMA');
  canonicalAddress(value.to, 'authorization.to', 'AUTHORIZATION_SCHEMA');
  canonicalAtomic(value.value, 'authorization.value', 'AUTHORIZATION_SCHEMA');
  canonicalAtomic(value.validAfter, 'authorization.validAfter', 'AUTHORIZATION_SCHEMA');
  canonicalAtomic(value.validBefore, 'authorization.validBefore', 'AUTHORIZATION_SCHEMA');
  canonicalBytes32(value.nonce, 'authorization.nonce', 'AUTHORIZATION_SCHEMA');
  return value;
}

function decodeCanonicalBase64Json(value) {
  if (typeof value !== 'string' || value.length === 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) {
    fail('PAYMENT_ENCODING', 'X-PAYMENT must be canonical base64');
  }
  const bytes = Buffer.from(value, 'base64');
  if (bytes.toString('base64') !== value) fail('PAYMENT_ENCODING', 'X-PAYMENT must be canonical base64');
  try {
    return JSON.parse(bytes.toString('utf8'));
  } catch {
    fail('PAYMENT_ENCODING', 'X-PAYMENT must contain JSON');
  }
}

function paymentEnvelopeSchema(value) {
  exactObject(value, ['x402Version', 'scheme', 'network', 'payload'],
    'PAYMENT_SCHEMA', 'X-PAYMENT envelope');
  exactObject(value.payload, ['signature', 'authorization'], 'PAYMENT_SCHEMA', 'X-PAYMENT payload');
  canonicalSignature(value.payload.signature);
  authorizationSchema(value.payload.authorization);
  return value;
}

const SETTLEMENT_FIELDS = [
  'success', 'authorizationId', 'idempotencyKey', 'network', 'chainId', 'asset', 'payTo',
  'payer', 'value', 'nonce', 'settlementReference', 'requestHash', 'quoteId', 'transaction',
];

function settlementSchema(value, code = 'SETTLEMENT_SCHEMA') {
  exactObject(value, SETTLEMENT_FIELDS, code, 'settlement evidence');
  if (value.success !== true || value.network !== BASE_SEPOLIA_NETWORK
      || value.chainId !== BASE_SEPOLIA_CHAIN_ID) {
    fail(code, 'settlement evidence has unsupported protocol values');
  }
  if (typeof value.authorizationId !== 'string' || typeof value.idempotencyKey !== 'string') {
    fail(code, 'settlement authorization identifiers must be strings');
  }
  canonicalAddress(value.asset, 'settlement.asset', code);
  canonicalAddress(value.payTo, 'settlement.payTo', code);
  canonicalAddress(value.payer, 'settlement.payer', code);
  canonicalAtomic(value.value, 'settlement.value', code);
  canonicalBytes32(value.nonce, 'settlement.nonce', code);
  canonicalBytes32(value.settlementReference, 'settlement.settlementReference', code);
  canonicalHash(value.requestHash, 'settlement.requestHash', code);
  canonicalHash(value.quoteId, 'settlement.quoteId', code);
  canonicalBytes32(value.transaction, 'settlement.transaction', code);
  return value;
}

function rejectionEvidenceSchema(value, code = 'RECONCILIATION_SCHEMA') {
  exactObject(value, SETTLEMENT_FIELDS, code, 'rejection evidence');
  if (value.success !== false || value.network !== BASE_SEPOLIA_NETWORK
      || value.chainId !== BASE_SEPOLIA_CHAIN_ID) {
    fail(code, 'rejection evidence has unsupported protocol values');
  }
  if (typeof value.authorizationId !== 'string' || typeof value.idempotencyKey !== 'string') {
    fail(code, 'rejection authorization identifiers must be strings');
  }
  canonicalAddress(value.asset, 'rejection.asset', code);
  canonicalAddress(value.payTo, 'rejection.payTo', code);
  canonicalAddress(value.payer, 'rejection.payer', code);
  canonicalAtomic(value.value, 'rejection.value', code);
  canonicalBytes32(value.nonce, 'rejection.nonce', code);
  canonicalBytes32(value.settlementReference, 'rejection.settlementReference', code);
  canonicalHash(value.requestHash, 'rejection.requestHash', code);
  canonicalHash(value.quoteId, 'rejection.quoteId', code);
  if (value.transaction !== null) {
    canonicalBytes32(value.transaction, 'rejection.transaction', code);
  }
  return value;
}

function reconciliationSchema(value, outcome) {
  exactObject(value, [
    ...SETTLEMENT_FIELDS, 'outcome', 'trustToken', ...(outcome === 'rejected' ? ['reasonCode'] : []),
  ], 'RECONCILIATION_SCHEMA', 'reconciliation proof');
  if (value.outcome !== outcome || typeof value.trustToken !== 'string' || value.trustToken.length === 0) {
    fail('RECONCILIATION_SCHEMA', 'reconciliation proof has an invalid outcome or trust token');
  }
  if (outcome === 'rejected') canonicalReason(value.reasonCode);
  const evidence = Object.fromEntries(SETTLEMENT_FIELDS.map((field) => [field, value[field]]));
  if (outcome === 'settled') settlementSchema(evidence, 'RECONCILIATION_SCHEMA');
  else rejectionEvidenceSchema(evidence, 'RECONCILIATION_SCHEMA');
  return evidence;
}

export function canonicalRequestHash({ method, requestUrl, bodyBytes }) {
  const verb = canonicalMethod(method);
  const target = resourceUrl(requestUrl).href;
  const body = exactBodyBytes(bodyBytes);
  return `sha256:${crypto.createHash('sha256')
    .update(Buffer.concat([Buffer.from(`${verb}\n${target}\n`, 'utf8'), body]))
    .digest('hex')}`;
}

export function createPaymentPolicy(config) {
  const capturedConfig = Object.freeze({ ...(config ?? {}) });
  optionalExactObject(capturedConfig,
    ['network', 'chainId', 'asset', 'sessionBudgetAtomic', 'maxQuoteAgeMs',
      'maxAuthorizationSeconds', 'sellers'],
    ['now', 'verifySettlementProof', 'verifyRejectionProof'],
    'POLICY_SCHEMA', 'payment policy');
  if (capturedConfig.network !== BASE_SEPOLIA_NETWORK) fail('NETWORK_CONFIG', 'only Base Sepolia is supported');
  if (capturedConfig.chainId !== BASE_SEPOLIA_CHAIN_ID) fail('CHAIN_CONFIG', 'only Base Sepolia chain ID 84532 is supported');
  if (capturedConfig.asset !== BASE_SEPOLIA_USDC) fail('ASSET_CONFIG', 'only canonical Base Sepolia USDC is supported');
  const budget = canonicalAtomic(capturedConfig.sessionBudgetAtomic, 'sessionBudgetAtomic').value;
  const maxQuoteAgeMs = capturedConfig.maxQuoteAgeMs;
  const maxAuthorizationSeconds = capturedConfig.maxAuthorizationSeconds;
  if (!Number.isSafeInteger(maxQuoteAgeMs) || maxQuoteAgeMs < 0) {
    fail('FRESHNESS_CONFIG', 'maxQuoteAgeMs must be a non-negative safe integer');
  }
  if (!Number.isSafeInteger(maxAuthorizationSeconds) || maxAuthorizationSeconds <= 0) {
    fail('TIMEOUT_CONFIG', 'maxAuthorizationSeconds must be a positive safe integer');
  }
  const sellerInputs = capturedConfig.sellers;
  if (!Array.isArray(sellerInputs) || sellerInputs.length === 0) {
    fail('SELLER_CONFIG', 'at least one trusted seller is required');
  }
  const now = capturedConfig.now ?? (() => Date.now());
  if (typeof now !== 'function') fail('CLOCK_CONFIG', 'now must be an injected clock function');
  const verifySettlementProof = capturedConfig.verifySettlementProof ?? (() => false);
  const verifyRejectionProof = capturedConfig.verifyRejectionProof ?? (() => false);
  if (typeof verifySettlementProof !== 'function' || typeof verifyRejectionProof !== 'function') {
    fail('PROOF_CONFIG', 'proof verifiers must be injected functions');
  }

  const rules = [...sellerInputs].map((input) => {
    exactObject(input, ['origin', 'pathPrefix', 'payTo', 'maxPerCallAtomic'],
      'SELLER_SCHEMA', 'seller rule');
    const capturedInput = frozenCopy(input);
    const rule = {
      origin: sellerOrigin(capturedInput.origin),
      pathPrefix: sellerPathPrefix(capturedInput.pathPrefix),
      payTo: canonicalAddress(capturedInput.payTo, 'seller.payTo', 'SELLER_PAYEE'),
      maxPerCallAtomic: canonicalAtomic(capturedInput.maxPerCallAtomic, 'maxPerCallAtomic').text,
    };
    if (BigInt(rule.maxPerCallAtomic) <= 0n) fail('SELLER_LIMIT', 'seller per-call cap must be positive');
    return deepFreeze(rule);
  }).sort((left, right) => right.pathPrefix.length - left.pathPrefix.length);
  const ruleKeys = new Set();
  for (const rule of rules) {
    const key = `${rule.origin}${rule.pathPrefix}`;
    if (ruleKeys.has(key)) fail('SELLER_CONFIG', 'seller routes must be unique');
    ruleKeys.add(key);
  }
  deepFreeze(rules);

  const receiptTokens = new WeakSet();
  const records = new Map();
  const authorizationNonces = new Map();
  const settlementTransactions = new Map();
  const activeMonetaryTransitions = new Map();
  let reservedAtomic = 0n;
  let spentAtomic = 0n;

  function commitBudget({ reservedDelta = 0n, spentDelta = 0n }) {
    const nextReserved = reservedAtomic + reservedDelta;
    const nextSpent = spentAtomic + spentDelta;
    const nextRemaining = budget - nextReserved - nextSpent;
    if (nextReserved < 0n || nextSpent < 0n || nextRemaining < 0n
        || nextReserved + nextSpent + nextRemaining !== budget) {
      fail('BUDGET_INVARIANT', 'payment transition would violate budget conservation');
    }
    reservedAtomic = nextReserved;
    spentAtomic = nextSpent;
  }

  function beginMonetaryTransition(record) {
    const active = activeMonetaryTransitions.get(record.authorizationId);
    if (active) {
      active.reentered = true;
      fail('TRANSITION_REENTRANCY', 'reentrant monetary transition is forbidden');
    }
    const transition = {
      record,
      expectedState: record.state,
      reentered: false,
    };
    activeMonetaryTransitions.set(record.authorizationId, transition);
    return transition;
  }

  function assertMonetaryTransition(transition) {
    if (transition.reentered
        || activeMonetaryTransitions.get(transition.record.authorizationId) !== transition
        || records.get(transition.record.authorizationId) !== transition.record
        || transition.record.state !== transition.expectedState) {
      fail('TRANSITION_DRIFT', 'authorization changed during a trusted monetary callback');
    }
  }

  function endMonetaryTransition(transition) {
    if (activeMonetaryTransitions.get(transition.record.authorizationId) === transition) {
      activeMonetaryTransitions.delete(transition.record.authorizationId);
    }
  }

  function trustedNow() {
    const value = now();
    if (!Number.isSafeInteger(value) || value < 0) fail('CLOCK_VALUE', 'trusted clock returned an invalid millisecond value');
    return value;
  }

  function captureReceivedAt() {
    const token = Object.freeze({ receivedAtMs: trustedNow() });
    receiptTokens.add(token);
    return token;
  }

  function validateOffer({ requestUrl, method, bodyBytes, challenge, receivedAt }) {
    if (!receivedAt || !receiptTokens.has(receivedAt)) {
      fail('RECEIVED_AT', 'receivedAt must come directly from this policy trusted clock');
    }
    receiptTokens.delete(receivedAt);
    const target = resourceUrl(requestUrl);
    const seller = rules.find((rule) => rule.origin === target.origin
      && routeMatches(target.pathname, rule.pathPrefix));
    if (!seller) fail('SELLER_UNTRUSTED', 'request URL is outside every trusted seller route');
    const candidate = frozenCopy(challengeSchema(challenge));
    if (candidate.scheme !== 'exact') fail('SCHEME_UNSUPPORTED', "x402 scheme must be 'exact'");
    if (candidate.network !== BASE_SEPOLIA_NETWORK) fail('NETWORK_MISMATCH', 'x402 network must be Base Sepolia');
    if (candidate.asset !== BASE_SEPOLIA_USDC) fail('ASSET_MISMATCH', 'x402 asset must be canonical Base Sepolia USDC');
    canonicalAddress(candidate.asset, 'offer.asset', 'ASSET_MISMATCH');
    canonicalAddress(candidate.payTo, 'offer.payTo', 'PAYEE_MISMATCH');
    if (candidate.payTo !== seller.payTo) fail('PAYEE_MISMATCH', 'x402 payee does not match the seller rule');
    if (candidate.resource !== target.href) fail('RESOURCE_MISMATCH', 'x402 resource must exactly match the request URL');
    resourceUrl(candidate.resource);
    const requestHash = canonicalRequestHash({ method, requestUrl: target.href, bodyBytes });
    if (candidate.extra.requestHash !== requestHash) fail('REQUEST_HASH_MISMATCH', 'offer does not bind exact request bytes');
    if (candidate.extra.name !== 'USDC' || candidate.extra.version !== '2') {
      fail('EIP712_DOMAIN', 'offer must use the canonical USDC v2 EIP-712 domain');
    }
    canonicalHash(candidate.extra.requestHash, 'requestHash', 'REQUEST_HASH_MISMATCH');
    canonicalHash(candidate.extra.quoteId, 'quoteId', 'QUOTE_ID');
    const issuedAtMs = canonicalTimestamp(candidate.extra.issuedAt, 'issuedAt');
    const expiresAtMs = canonicalTimestamp(candidate.extra.expiresAt, 'expiresAt');
    const receivedAtMs = receivedAt.receivedAtMs;
    const validationTimeMs = trustedNow();
    if (issuedAtMs > receivedAtMs || receivedAtMs - issuedAtMs > maxQuoteAgeMs
        || expiresAtMs <= receivedAtMs || expiresAtMs <= validationTimeMs
        || issuedAtMs >= expiresAtMs) {
      fail('QUOTE_EXPIRY', 'x402 quote is stale, future-issued, expired, or inverted');
    }
    if (validationTimeMs < receivedAtMs || validationTimeMs < issuedAtMs
        || validationTimeMs - receivedAtMs > maxQuoteAgeMs
        || validationTimeMs - issuedAtMs > maxQuoteAgeMs) {
      fail('QUOTE_FRESHNESS', 'x402 quote exceeded local receipt or issue age after parsing');
    }
    const amount = canonicalAtomic(candidate.maxAmountRequired, 'maxAmountRequired');
    if (amount.value <= 0n) fail('AMOUNT_ZERO', 'x402 amount must be positive');
    if (amount.value > BigInt(seller.maxPerCallAtomic)) fail('PER_CALL_LIMIT', 'x402 amount exceeds per-call policy');
    if (!Number.isSafeInteger(candidate.maxTimeoutSeconds) || candidate.maxTimeoutSeconds <= 0
        || candidate.maxTimeoutSeconds > maxAuthorizationSeconds) {
      fail('TIMEOUT_LIMIT', 'x402 timeout exceeds local policy');
    }
    const receivedSeconds = Math.floor(receivedAtMs / 1_000);
    const expiresSeconds = Math.floor(expiresAtMs / 1_000);
    const validAfter = Math.max(0, receivedSeconds - 60).toString();
    const validBefore = Math.min(
      expiresSeconds,
      receivedSeconds + candidate.maxTimeoutSeconds,
    ).toString();
    if (BigInt(validBefore) <= BigInt(validAfter)) fail('TIMEOUT_LIMIT', 'authorization validity window is empty');
    return {
      amountAtomic: amount.text,
      requestUrl: target.href,
      method: canonicalMethod(method),
      requestHash,
      quoteId: candidate.extra.quoteId,
      offerFingerprint: hashJson(candidate),
      offer: candidate,
      receivedAtMs,
      validAfter,
      validBefore,
    };
  }

  function id(value) {
    if (typeof value !== 'string' || !/^[A-Za-z0-9._:-]{1,200}$/.test(value)) {
      fail('AUTHORIZATION_ID', 'authorizationId must be a bounded canonical token');
    }
    return value;
  }

  function get(authorizationId) {
    const record = records.get(id(authorizationId));
    if (!record) fail('AUTHORIZATION_UNKNOWN', 'authorization does not exist');
    return record;
  }

  function publicRecord(record) {
    return frozenCopy(record);
  }

  function reserveAuthorization(input) {
    exactObject(input, ['authorizationId', 'requestUrl', 'method', 'bodyBytes', 'challenge', 'receivedAt'],
      'RESERVATION_SCHEMA', 'authorization reservation');
    const authorizationId = id(input.authorizationId);
    const validated = validateOffer(input);
    const existing = records.get(authorizationId);
    if (existing) {
      if (existing.offerFingerprint !== validated.offerFingerprint
          || existing.requestUrl !== validated.requestUrl
          || existing.method !== validated.method
          || existing.requestHash !== validated.requestHash) {
        fail('AUTHORIZATION_CONFLICT', 'authorizationId already binds different request or offer bytes');
      }
      return publicRecord(existing);
    }
    const amount = BigInt(validated.amountAtomic);
    if (spentAtomic + reservedAtomic + amount > budget) {
      fail('SESSION_BUDGET', 'offer exceeds remaining one-process session budget');
    }
    const record = {
      authorizationId,
      ...validated,
      state: 'reserved',
      retryCount: 0,
      txHash: null,
      reasonCode: null,
      authorization: null,
      signature: null,
      xPayment: null,
    };
    commitBudget({ reservedDelta: amount });
    records.set(authorizationId, record);
    return publicRecord(record);
  }

  function claimSignature(authorizationId, input) {
    exactObject(input, ['offerFingerprint'], 'SIGNATURE_CLAIM_SCHEMA', 'signature claim');
    const record = get(authorizationId);
    if (input.offerFingerprint !== record.offerFingerprint) {
      fail('AUTHORIZATION_CONFLICT', 'signature claim does not match the frozen offer');
    }
    if (record.state !== 'reserved') return Object.freeze({ claimed: false, authorization: publicRecord(record) });
    record.state = 'signing';
    return Object.freeze({ claimed: true, authorization: publicRecord(record) });
  }

  function releaseUnsigned(authorizationId, input) {
    const transition = frozenCopy(exactObject(
      input, ['reasonCode'], 'UNSIGNED_RELEASE_SCHEMA', 'unsigned release',
    ));
    const reasonCode = canonicalReason(transition.reasonCode);
    const record = get(authorizationId);
    if (!['reserved', 'signing'].includes(record.state)) {
      fail('UNSIGNED_RELEASE_STATE', 'only an authorization that cannot have produced a signature may be released');
    }
    commitBudget({ reservedDelta: -BigInt(record.amountAtomic) });
    record.state = 'released';
    record.reasonCode = reasonCode;
    return publicRecord(record);
  }

  function markPotentiallySigned(authorizationId, input) {
    const transition = frozenCopy(exactObject(
      input, ['reasonCode'], 'UNRESOLVED_SCHEMA', 'potential signature result',
    ));
    const reasonCode = canonicalReason(transition.reasonCode);
    const record = get(authorizationId);
    if (record.state !== 'signing') fail('POTENTIAL_SIGNATURE_STATE', 'potential signature requires a signing claim');
    record.state = 'unresolved';
    record.reasonCode = reasonCode;
    return publicRecord(record);
  }

  function persistSignedAuthorization(authorizationId, input) {
    const transition = frozenCopy(exactObject(
      input,
      ['authorization', 'signature', 'xPayment'],
      'SIGNED_AUTHORIZATION_SCHEMA',
      'signed authorization',
    ));
    const record = get(authorizationId);
    if (record.state !== 'signing') fail('SIGNED_STATE', 'signed authorization can only follow one signature claim');
    const authorization = authorizationSchema(transition.authorization);
    const signature = canonicalSignature(transition.signature);
    const envelope = paymentEnvelopeSchema(decodeCanonicalBase64Json(transition.xPayment));
    if (envelope.x402Version !== 1 || envelope.scheme !== 'exact'
        || envelope.network !== BASE_SEPOLIA_NETWORK
        || canonicalJson(envelope.payload.authorization) !== canonicalJson(authorization)
        || envelope.payload.signature !== signature) {
      fail('PAYMENT_MISMATCH', 'X-PAYMENT does not exactly contain the persisted authorization');
    }
    if (authorization.to !== record.offer.payTo
        || authorization.value !== record.amountAtomic
        || authorization.validAfter !== record.validAfter
        || authorization.validBefore !== record.validBefore) {
      fail('AUTHORIZATION_MISMATCH', 'signed authorization differs from the frozen offer or validity window');
    }
    const nonceOwner = authorizationNonces.get(authorization.nonce);
    if (nonceOwner && nonceOwner !== record.authorizationId) {
      fail('NONCE_REUSE', 'EIP-3009 nonce is already bound to another authorization');
    }
    authorizationNonces.set(authorization.nonce, record.authorizationId);
    record.authorization = authorization;
    record.signature = signature;
    record.xPayment = transition.xPayment;
    record.state = 'signed';
    record.reasonCode = null;
    return publicRecord(record);
  }

  function requestIdentity({ requestUrl, method, bodyBytes }) {
    const target = resourceUrl(requestUrl).href;
    const verb = canonicalMethod(method);
    return {
      requestUrl: target,
      method: verb,
      requestHash: canonicalRequestHash({ method: verb, requestUrl: target, bodyBytes }),
    };
  }

  function recoverSignedAuthorization(input) {
    exactObject(input, ['authorizationId', 'requestUrl', 'method', 'bodyBytes'],
      'RECOVERY_SCHEMA', 'signed authorization recovery');
    const record = get(input.authorizationId);
    const identity = requestIdentity(input);
    if (record.requestUrl !== identity.requestUrl || record.method !== identity.method
        || record.requestHash !== identity.requestHash) {
      fail('RECOVERY_REQUEST_MISMATCH', 'recovery request does not match persisted exact request bytes');
    }
    if (!record.authorization || !record.signature || !record.xPayment
        || !['signed', 'retrying', 'unresolved', 'settled'].includes(record.state)) {
      fail('SIGNED_AUTHORIZATION_UNAVAILABLE', 'no exact persisted signed authorization is recoverable');
    }
    return publicRecord(record);
  }

  function beginRetry(authorizationId) {
    const record = get(authorizationId);
    if (record.state !== 'signed' || record.retryCount !== 0 || !record.xPayment) {
      fail('RETRY_LIMIT', 'authorization permits exactly one paid retry');
    }
    record.retryCount = 1;
    record.state = 'retrying';
    return publicRecord(record);
  }

  function assertAuthorizationFresh(authorizationId) {
    const record = get(authorizationId);
    const currentTimeMs = trustedNow();
    const issuedAtMs = canonicalTimestamp(record.offer.extra.issuedAt, 'issuedAt');
    const expiresAtMs = canonicalTimestamp(record.offer.extra.expiresAt, 'expiresAt');
    const currentTimeSeconds = BigInt(Math.floor(currentTimeMs / 1_000));
    if (currentTimeMs >= expiresAtMs || currentTimeSeconds >= BigInt(record.validBefore)) {
      fail('QUOTE_EXPIRY', 'x402 quote or signed authorization expired before the paid retry');
    }
    if (currentTimeMs < record.receivedAtMs || currentTimeMs < issuedAtMs
        || currentTimeMs - record.receivedAtMs > maxQuoteAgeMs
        || currentTimeMs - issuedAtMs > maxQuoteAgeMs) {
      fail('QUOTE_FRESHNESS', 'x402 quote exceeded local receipt or issue age before retry');
    }
    return publicRecord(record);
  }

  function assertRetryChallenge(authorizationId, secondChallenge) {
    const record = get(authorizationId);
    let second;
    try {
      second = challengeSchema(secondChallenge);
    } catch {
      fail('QUOTE_CHANGED', 'second payment challenge is malformed or changed');
    }
    if (hashJson(second) !== record.offerFingerprint) fail('QUOTE_CHANGED', 'seller changed the frozen offer');
    return publicRecord(record);
  }

  function markUnresolved(authorizationId, input) {
    const transition = frozenCopy(exactObject(
      input, ['reasonCode'], 'UNRESOLVED_SCHEMA', 'unresolved transition',
    ));
    const reasonCode = canonicalReason(transition.reasonCode);
    const record = get(authorizationId);
    if (record.state === 'unresolved') return publicRecord(record);
    if (!['signing', 'signed', 'retrying'].includes(record.state)) {
      fail('UNRESOLVED_STATE', 'only a potentially signed authorization can become unresolved');
    }
    record.state = 'unresolved';
    record.reasonCode = reasonCode;
    return publicRecord(record);
  }

  function assertSettlementMatches(record, evidence, code = 'SETTLEMENT_MISMATCH') {
    if (!record.authorization
        || evidence.authorizationId !== record.authorizationId
        || evidence.idempotencyKey !== record.authorizationId
        || evidence.network !== BASE_SEPOLIA_NETWORK
        || evidence.chainId !== BASE_SEPOLIA_CHAIN_ID
        || evidence.asset !== record.offer.asset
        || evidence.payTo !== record.authorization.to
        || evidence.payer !== record.authorization.from
        || evidence.value !== record.authorization.value
        || evidence.nonce !== record.authorization.nonce
        || evidence.settlementReference !== record.authorization.nonce
        || evidence.requestHash !== record.requestHash
        || evidence.quoteId !== record.quoteId) {
      fail(code, 'settlement or reconciliation evidence does not match the signed authorization');
    }
  }

  function settle(record, evidence, transition) {
    assertMonetaryTransition(transition);
    if (record.state === 'settled') {
      if (record.txHash !== evidence.transaction) fail('SETTLEMENT_CONFLICT', 'authorization already binds another transaction');
      return publicRecord(record);
    }
    const transactionOwner = settlementTransactions.get(evidence.transaction);
    if (transactionOwner && transactionOwner !== record.authorizationId) {
      fail('TRANSACTION_REUSE', 'settlement transaction is already bound to another authorization');
    }
    if (!['signed', 'retrying', 'unresolved'].includes(record.state)) {
      fail('SETTLEMENT_STATE', 'authorization is not in a settleable state');
    }
    commitBudget({
      reservedDelta: -BigInt(record.amountAtomic),
      spentDelta: BigInt(record.amountAtomic),
    });
    settlementTransactions.set(evidence.transaction, record.authorizationId);
    record.state = 'settled';
    record.txHash = evidence.transaction;
    record.reasonCode = null;
    return publicRecord(record);
  }

  function acceptSettlement(authorizationId, input) {
    const capturedAuthorizationId = id(authorizationId);
    const evidence = settlementSchema(frozenCopy(input));
    const record = get(capturedAuthorizationId);
    if (!['retrying', 'settled'].includes(record.state)) {
      fail('SETTLEMENT_STATE', 'only the immediate paid retry response can settle without trusted reconciliation');
    }
    assertSettlementMatches(record, evidence);
    const transition = beginMonetaryTransition(record);
    try {
      return settle(record, evidence, transition);
    } finally {
      endMonetaryTransition(transition);
    }
  }

  function verifierAccepted(verifier, record, proof) {
    const result = verifier({ authorization: publicRecord(record), proof });
    if (result && typeof result.then === 'function') fail('PROOF_ASYNC', 'proof verifier must be a synchronous trust capability');
    return result === true;
  }

  function reconcileSettlement(authorizationId, proof) {
    const capturedAuthorizationId = id(authorizationId);
    const capturedProof = frozenCopy(proof);
    const evidence = reconciliationSchema(capturedProof, 'settled');
    const record = get(capturedAuthorizationId);
    if (!['signed', 'retrying', 'unresolved', 'settled'].includes(record.state)) {
      fail('RECONCILIATION_STATE', 'settlement reconciliation requires a signed authorization');
    }
    assertSettlementMatches(record, evidence, 'RECONCILIATION_MISMATCH');
    const transition = beginMonetaryTransition(record);
    try {
      if (!verifierAccepted(verifySettlementProof, record, capturedProof)) {
        fail('SETTLEMENT_PROOF', 'trusted settlement proof verifier rejected evidence');
      }
      assertMonetaryTransition(transition);
      return settle(record, evidence, transition);
    } finally {
      endMonetaryTransition(transition);
    }
  }

  function reconcileRejection(authorizationId, proof) {
    const capturedAuthorizationId = id(authorizationId);
    const capturedProof = frozenCopy(proof);
    const evidence = reconciliationSchema(capturedProof, 'rejected');
    const record = get(capturedAuthorizationId);
    if (!['signed', 'retrying', 'unresolved'].includes(record.state)) {
      fail('RECONCILIATION_STATE', 'rejection reconciliation requires a nonterminal signed authorization');
    }
    assertSettlementMatches(record, evidence, 'RECONCILIATION_MISMATCH');
    const transition = beginMonetaryTransition(record);
    try {
      if (!verifierAccepted(verifyRejectionProof, record, capturedProof)) {
        fail('REJECTION_PROOF', 'trusted rejection proof verifier rejected evidence');
      }
      assertMonetaryTransition(transition);
      commitBudget({ reservedDelta: -BigInt(record.amountAtomic) });
      record.state = 'rejected';
      record.reasonCode = capturedProof.reasonCode;
      return publicRecord(record);
    } finally {
      endMonetaryTransition(transition);
    }
  }

  function snapshot() {
    return frozenCopy({
      sessionBudgetAtomic: budget.toString(),
      reservedAtomic: reservedAtomic.toString(),
      spentAtomic: spentAtomic.toString(),
      remainingAtomic: (budget - reservedAtomic - spentAtomic).toString(),
      authorizations: [...records.values()]
        .sort((left, right) => left.authorizationId.localeCompare(right.authorizationId))
        .map(({ authorizationId, amountAtomic, state, retryCount, txHash, reasonCode }) => ({
          authorizationId, amountAtomic, state, retryCount, txHash, reasonCode,
        })),
    });
  }

  return Object.freeze({
    captureReceivedAt,
    validateOffer,
    reserveAuthorization,
    claimSignature,
    releaseUnsigned,
    markPotentiallySigned,
    persistSignedAuthorization,
    recoverSignedAuthorization,
    assertAuthorizationFresh,
    beginRetry,
    assertRetryChallenge,
    markUnresolved,
    acceptSettlement,
    reconcileSettlement,
    reconcileRejection,
    snapshot,
  });
}
