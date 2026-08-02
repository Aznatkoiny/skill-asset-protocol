import {
  canonicalAtomic,
  canonicalJson,
  canonicalToken,
  exactRecord,
  frozenCopy,
  KernelError,
  sha256,
} from './canonical.mjs';

const BASE_SEPOLIA = 'eip155:84532';
const BASE_SEPOLIA_USDC = '0x036cbd53842c5426634e7929541ec2318f3dcf7e';
const DECISIONS = new Set(['allow', 'approval_required', 'deny']);
const PRESELECTION_DENIALS = new Set([
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
]);
const SELECTED_DENIALS = new Set([
  'CHALLENGE_EXPIRED',
  'PER_REQUEST_LIMIT',
  'SELLER_SESSION_LIMIT',
  'SESSION_LIMIT',
  'ROLLING_24H_LIMIT',
  'APPROVAL_CAPACITY',
]);
const HASH_PATTERN = /^sha256:[0-9a-f]{64}$/;
const ADDRESS_PATTERN = /^0x[0-9a-fA-F]{40}$/;
const CANONICAL_ADDRESS_PATTERN = /^0x[0-9a-f]{40}$/;
const ENCODED_PATH_SEPARATOR = /%(?:2f|5c)/i;
const POLICY_FIELDS = Object.freeze([
  'schemaVersion',
  'network',
  'asset',
  'wallet',
  'methods',
  'sellers',
  'sessionMaxAtomic',
  'rolling24hMaxAtomic',
  'challengeMaxAgeMs',
  'approvalTtlMs',
  'maxPendingApprovals',
  'defaultAction',
]);
const SELLER_FIELDS = Object.freeze([
  'origin',
  'pathPrefixes',
  'payTo',
  'evidencePath',
  'executionSigner',
  'refundSigner',
  'refundSource',
  'perRequestMaxAtomic',
  'autoApproveAtomic',
  'humanApproveAtomic',
  'sellerSessionMaxAtomic',
]);
const INPUT_FIELDS = Object.freeze([
  'policy',
  'policyVersion',
  'intent',
  'wallet',
  'paymentRequired',
  'challengeReceivedAtMs',
  'nowMs',
  'budgetSnapshot',
]);

function fail(code, message) {
  throw new KernelError(code, message);
}

function boundedString(value, label, code, maximum = 1_024) {
  if (typeof value !== 'string'
      || value.length === 0
      || Buffer.byteLength(value, 'utf8') > maximum) {
    fail(code, `${label} must be one nonempty bounded string`);
  }
  return value;
}

function canonicalAddress(value, label, code = 'POLICY_ADDRESS') {
  if (typeof value !== 'string' || !ADDRESS_PATTERN.test(value)) {
    fail(code, `${label} must be one canonical EVM address`);
  }
  return value.toLowerCase();
}

function canonicalHash(value, label, code = 'HASH_FORMAT') {
  if (typeof value !== 'string' || !HASH_PATTERN.test(value)) {
    fail(code, `${label} must be one canonical SHA-256 hash`);
  }
  return value;
}

function atomicText(value, label, code) {
  try {
    return canonicalAtomic(value, label);
  } catch (error) {
    if (error instanceof KernelError) fail(code, `${label} must be canonical atomic text`);
    throw error;
  }
}

function positiveSafeInteger(value, label, code, maximum = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
    fail(code, `${label} must be a positive safe integer`);
  }
  return value;
}

function nonnegativeSafeInteger(value, label, code) {
  if (!Number.isSafeInteger(value) || value < 0) {
    fail(code, `${label} must be a nonnegative safe integer`);
  }
  return value;
}

function isCanonicalLiteralLoopbackHttp(value, parsed) {
  if (parsed.protocol !== 'http:' || !value.startsWith('http://')) return false;
  const authority = value.slice('http://'.length).split(/[/?#]/u, 1)[0];
  if (!/^(?:127\.0\.0\.1|\[::1\])(?::[1-9][0-9]{0,4})?$/.test(authority)) {
    return false;
  }
  return parsed.origin === `http://${authority}`;
}

function normalizeOrigin(value, code = 'POLICY_SELLER_ORIGIN') {
  boundedString(value, 'seller origin', code, 2_048);
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    return fail(code, 'seller origin must be an absolute canonical origin');
  }
  if (parsed.username !== ''
      || parsed.password !== ''
      || parsed.pathname !== '/'
      || parsed.search !== ''
      || parsed.hash !== ''
      || parsed.origin === 'null') {
    fail(code, 'seller origin must contain only scheme, host, and optional port');
  }
  if (parsed.protocol !== 'https:' && !isCanonicalLiteralLoopbackHttp(value, parsed)) {
    fail(code, 'seller origin must be HTTPS or literal loopback HTTP');
  }
  return parsed.origin;
}

function canonicalPath(value, origin, label, code) {
  boundedString(value, label, code, 2_048);
  if (!value.startsWith('/')
      || value.startsWith('//')
      || value.includes('?')
      || value.includes('#')
      || value.includes('\\')
      || ENCODED_PATH_SEPARATOR.test(value)) {
    fail(code, `${label} must be one queryless canonical absolute path`);
  }
  let parsed;
  try {
    parsed = new URL(value, `${origin}/`);
  } catch {
    return fail(code, `${label} must be one queryless canonical absolute path`);
  }
  if (parsed.origin !== origin
      || parsed.pathname !== value
      || parsed.search !== ''
      || parsed.hash !== '') {
    fail(code, `${label} must preserve its exact origin and pathname`);
  }
  return value;
}

function canonicalResourceUrl(value, code = 'CHALLENGE_RESOURCE') {
  boundedString(value, 'resource URL', code, 4_096);
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    return fail(code, 'resource URL must be absolute and canonical');
  }
  if ((parsed.protocol !== 'https:' && !isCanonicalLiteralLoopbackHttp(value, parsed))
      || parsed.username !== ''
      || parsed.password !== ''
      || parsed.search !== ''
      || parsed.hash !== ''
      || parsed.href !== value
      || parsed.pathname.startsWith('//')
      || parsed.pathname.includes('\\')
      || ENCODED_PATH_SEPARATOR.test(parsed.pathname)) {
    fail(code, 'resource URL must be one exact queryless HTTPS or loopback URL');
  }
  return Object.freeze({
    href: value,
    origin: parsed.origin,
    pathname: parsed.pathname,
  });
}

function protocolToken(value, label, code) {
  if (typeof value !== 'string'
      || value.length > 200
      || !/^[A-Za-z0-9][A-Za-z0-9._:+-]*$/.test(value)) {
    fail(code, `${label} must be one bounded protocol token`);
  }
  return value;
}

function validatePolicySeller(value) {
  const seller = exactRecord(
    value,
    SELLER_FIELDS,
    [],
    'POLICY_SCHEMA',
    'policy seller',
  );
  const origin = normalizeOrigin(seller.origin);
  if (!Array.isArray(seller.pathPrefixes)
      || seller.pathPrefixes.length < 1
      || seller.pathPrefixes.length > 100) {
    fail('POLICY_RESOURCE_PATH', 'seller pathPrefixes must be one bounded nonempty array');
  }
  const pathPrefixes = seller.pathPrefixes.map((entry) => canonicalPath(
    entry,
    origin,
    'seller path prefix',
    'POLICY_RESOURCE_PATH',
  ));
  if (new Set(pathPrefixes).size !== pathPrefixes.length) {
    fail('POLICY_PATH_DUPLICATE', 'seller path prefixes must be unique');
  }
  const perRequest = atomicText(
    seller.perRequestMaxAtomic,
    'seller per-request maximum',
    'POLICY_ATOMIC',
  );
  const automatic = atomicText(
    seller.autoApproveAtomic,
    'seller automatic-approval maximum',
    'POLICY_ATOMIC',
  );
  const human = atomicText(
    seller.humanApproveAtomic,
    'seller human-approval maximum',
    'POLICY_ATOMIC',
  );
  const sellerSession = atomicText(
    seller.sellerSessionMaxAtomic,
    'seller session maximum',
    'POLICY_ATOMIC',
  );
  if (perRequest.value <= 0n || sellerSession.value <= 0n
      || automatic.value > human.value
      || human.value > perRequest.value) {
    fail('POLICY_LIMIT_ORDER', 'seller spend limits are inconsistent');
  }
  return {
    origin,
    pathPrefixes,
    payTo: canonicalAddress(seller.payTo, 'seller payee'),
    evidencePath: canonicalPath(
      seller.evidencePath,
      origin,
      'seller evidence path',
      'POLICY_EVIDENCE_PATH',
    ),
    executionSigner: canonicalAddress(seller.executionSigner, 'execution signer'),
    refundSigner: canonicalAddress(seller.refundSigner, 'refund signer'),
    refundSource: canonicalAddress(seller.refundSource, 'refund source'),
    perRequestMaxAtomic: perRequest.text,
    autoApproveAtomic: automatic.text,
    humanApproveAtomic: human.text,
    sellerSessionMaxAtomic: sellerSession.text,
  };
}

export function validatePolicyDocument(document) {
  const policy = exactRecord(
    document,
    POLICY_FIELDS,
    [],
    'POLICY_SCHEMA',
    'policy',
  );
  if (policy.schemaVersion !== 1) {
    fail('POLICY_SCHEMA_VERSION', 'policy schemaVersion must equal 1');
  }
  if (policy.network !== BASE_SEPOLIA) {
    fail('POLICY_NETWORK', 'pilot policy network must be Base Sepolia');
  }
  const asset = canonicalAddress(policy.asset, 'policy asset');
  if (asset !== BASE_SEPOLIA_USDC) {
    fail('POLICY_ASSET', 'pilot policy asset must be Base Sepolia USDC');
  }
  if (!Array.isArray(policy.methods)
      || policy.methods.length < 1
      || policy.methods.length > 32
      || policy.methods.some((method) => typeof method !== 'string'
        || !/^[A-Z][A-Z0-9-]{0,31}$/.test(method))
      || new Set(policy.methods).size !== policy.methods.length) {
    fail('POLICY_METHODS', 'policy methods must be unique canonical HTTP method tokens');
  }
  if (!Array.isArray(policy.sellers)
      || policy.sellers.length < 1
      || policy.sellers.length > 100) {
    fail('POLICY_SELLERS', 'policy sellers must be one bounded nonempty array');
  }
  const sellers = policy.sellers.map(validatePolicySeller);
  const origins = sellers.map((seller) => seller.origin);
  if (new Set(origins).size !== origins.length) {
    fail('POLICY_SELLER_DUPLICATE', 'policy seller origins must be unique');
  }
  const session = atomicText(policy.sessionMaxAtomic, 'session maximum', 'POLICY_ATOMIC');
  const rolling = atomicText(
    policy.rolling24hMaxAtomic,
    'rolling 24-hour maximum',
    'POLICY_ATOMIC',
  );
  if (session.value <= 0n || rolling.value <= 0n) {
    fail('POLICY_LIMIT_ORDER', 'session and rolling limits must be positive');
  }
  positiveSafeInteger(
    policy.challengeMaxAgeMs,
    'challenge maximum age',
    'POLICY_TIME',
  );
  positiveSafeInteger(policy.approvalTtlMs, 'approval TTL', 'POLICY_TIME');
  positiveSafeInteger(
    policy.maxPendingApprovals,
    'pending approval maximum',
    'POLICY_APPROVAL_CAPACITY',
  );
  if (policy.defaultAction !== 'deny') {
    fail('POLICY_DEFAULT', 'policy defaultAction must be deny');
  }
  return frozenCopy({
    schemaVersion: 1,
    network: BASE_SEPOLIA,
    asset,
    wallet: canonicalAddress(policy.wallet, 'policy wallet'),
    methods: [...policy.methods],
    sellers,
    sessionMaxAtomic: session.text,
    rolling24hMaxAtomic: rolling.text,
    challengeMaxAgeMs: policy.challengeMaxAgeMs,
    approvalTtlMs: policy.approvalTtlMs,
    maxPendingApprovals: policy.maxPendingApprovals,
    defaultAction: 'deny',
  });
}

function validateIntent(value) {
  const intent = exactRecord(value, [
    'id',
    'method',
    'requestUrl',
    'sellerOrigin',
    'resourcePath',
    'walletAddress',
  ], [], 'INPUT_SCHEMA', 'spend intent');
  const id = canonicalToken(intent.id, 'intent ID');
  if (typeof intent.method !== 'string'
      || !/^[A-Z][A-Z0-9-]{0,31}$/.test(intent.method)) {
    fail('INPUT_SCHEMA', 'intent method must be one canonical HTTP method');
  }
  const request = canonicalResourceUrl(intent.requestUrl, 'INPUT_SCHEMA');
  const sellerOrigin = normalizeOrigin(intent.sellerOrigin, 'INPUT_SCHEMA');
  const resourcePath = canonicalPath(
    intent.resourcePath,
    sellerOrigin,
    'intent resource path',
    'INPUT_SCHEMA',
  );
  if (request.origin !== sellerOrigin || request.pathname !== resourcePath) {
    fail('INPUT_SCHEMA', 'intent URL, seller origin, and resource path must agree');
  }
  return Object.freeze({
    id,
    method: intent.method,
    requestUrl: request.href,
    sellerOrigin,
    resourcePath,
    walletAddress: canonicalAddress(intent.walletAddress, 'intent wallet', 'INPUT_SCHEMA'),
  });
}

function validateWallet(value) {
  const wallet = exactRecord(value, [
    'provider',
    'walletId',
    'address',
    'network',
  ], [], 'INPUT_SCHEMA', 'wallet identity');
  return Object.freeze({
    provider: canonicalToken(wallet.provider, 'wallet provider'),
    walletId: canonicalToken(wallet.walletId, 'wallet ID'),
    address: canonicalAddress(wallet.address, 'wallet address', 'INPUT_SCHEMA'),
    network: protocolToken(wallet.network, 'wallet network', 'INPUT_SCHEMA'),
  });
}

function validateCandidate(value) {
  const candidate = exactRecord(value, [
    'scheme',
    'network',
    'asset',
    'amount',
    'payTo',
    'maxTimeoutSeconds',
    'extra',
  ], [], 'CHALLENGE_SCHEMA', 'payment requirement');
  const extra = exactRecord(
    candidate.extra,
    ['name', 'version'],
    ['assetTransferMethod'],
    'CHALLENGE_SCHEMA',
    'payment requirement extra',
  );
  const amount = atomicText(candidate.amount, 'challenge amount', 'CHALLENGE_AMOUNT');
  if (amount.value <= 0n) {
    fail('CHALLENGE_AMOUNT', 'challenge amount must be positive');
  }
  positiveSafeInteger(
    candidate.maxTimeoutSeconds,
    'challenge maximum timeout',
    'CHALLENGE_TIMEOUT',
    3_600,
  );
  if (typeof candidate.asset !== 'string'
      || !CANONICAL_ADDRESS_PATTERN.test(candidate.asset)
      || typeof candidate.payTo !== 'string'
      || !CANONICAL_ADDRESS_PATTERN.test(candidate.payTo)) {
    fail(
      'CHALLENGE_SCHEMA',
      'challenge asset and payee must be canonical lowercase EVM addresses',
    );
  }
  const assetTransferMethod = Object.hasOwn(extra, 'assetTransferMethod')
    ? boundedString(
      extra.assetTransferMethod,
      'asset transfer method',
      'CHALLENGE_SCHEMA',
      100,
    )
    : undefined;
  return frozenCopy({
    scheme: protocolToken(candidate.scheme, 'challenge scheme', 'CHALLENGE_SCHEMA'),
    network: protocolToken(candidate.network, 'challenge network', 'CHALLENGE_SCHEMA'),
    asset: candidate.asset,
    amount: amount.text,
    payTo: candidate.payTo,
    maxTimeoutSeconds: candidate.maxTimeoutSeconds,
    extra: {
      name: boundedString(extra.name, 'EIP-712 name', 'CHALLENGE_SCHEMA', 100),
      version: boundedString(extra.version, 'EIP-712 version', 'CHALLENGE_SCHEMA', 100),
      ...(assetTransferMethod === undefined ? {} : { assetTransferMethod }),
    },
  });
}

function validatePaymentRequired(value) {
  const payment = exactRecord(
    value,
    ['x402Version', 'resource', 'accepts'],
    ['error'],
    'CHALLENGE_SCHEMA',
    'PaymentRequired',
  );
  if (!Number.isSafeInteger(payment.x402Version) || payment.x402Version < 1) {
    fail('CHALLENGE_SCHEMA', 'x402Version must be a positive safe integer');
  }
  if (Object.hasOwn(payment, 'error')) {
    boundedString(payment.error, 'seller error', 'CHALLENGE_SCHEMA', 2_048);
  }
  const resource = exactRecord(
    payment.resource,
    ['url', 'description', 'mimeType'],
    [],
    'CHALLENGE_SCHEMA',
    'payment resource',
  );
  const parsedResource = canonicalResourceUrl(resource.url);
  const description = boundedString(
    resource.description,
    'resource description',
    'CHALLENGE_SCHEMA',
    1_024,
  );
  const mimeType = boundedString(
    resource.mimeType,
    'resource MIME type',
    'CHALLENGE_SCHEMA',
    200,
  );
  if (!/^[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]*\/[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]*$/.test(mimeType)) {
    fail('CHALLENGE_SCHEMA', 'resource MIME type must be canonical');
  }
  if (!Array.isArray(payment.accepts) || payment.accepts.length > 100) {
    fail('CHALLENGE_SCHEMA', 'accepts must be one bounded ordered array');
  }
  const accepts = payment.accepts.map(validateCandidate);
  return frozenCopy({
    x402Version: payment.x402Version,
    ...(Object.hasOwn(payment, 'error') ? { error: payment.error } : {}),
    resource: {
      url: parsedResource.href,
      description,
      mimeType,
    },
    accepts,
  });
}

function validatePolicyVersion(value) {
  const version = exactRecord(
    value,
    ['id', 'hash'],
    [],
    'INPUT_SCHEMA',
    'policy version',
  );
  return Object.freeze({
    id: canonicalToken(version.id, 'policy version ID'),
    hash: canonicalHash(version.hash, 'policy version hash', 'POLICY_HASH_MISMATCH'),
  });
}

function validateBudgetSnapshot(value) {
  const snapshot = exactRecord(value, [
    'sellerSessionExposureAtomic',
    'sessionExposureAtomic',
    'rolling24hExposureAtomic',
    'pendingApprovalCount',
  ], [], 'INPUT_SCHEMA', 'budget snapshot');
  return Object.freeze({
    sellerSessionExposure: atomicText(
      snapshot.sellerSessionExposureAtomic,
      'seller session exposure',
      'BUDGET_SNAPSHOT',
    ),
    sessionExposure: atomicText(
      snapshot.sessionExposureAtomic,
      'session exposure',
      'BUDGET_SNAPSHOT',
    ),
    rolling24hExposure: atomicText(
      snapshot.rolling24hExposureAtomic,
      'rolling 24-hour exposure',
      'BUDGET_SNAPSHOT',
    ),
    pendingApprovalCount: nonnegativeSafeInteger(
      snapshot.pendingApprovalCount,
      'pending approval count',
      'BUDGET_SNAPSHOT',
    ),
  });
}

function challengeProjection(paymentRequired) {
  return {
    x402Version: paymentRequired.x402Version,
    resource: {
      urlHash: sha256(paymentRequired.resource.url),
      description: paymentRequired.resource.description,
      mimeType: paymentRequired.resource.mimeType,
    },
    accepts: paymentRequired.accepts.map((candidate) => ({
      scheme: candidate.scheme,
      network: candidate.network,
      asset: candidate.asset,
      amount: candidate.amount,
      payTo: candidate.payTo,
      maxTimeoutSeconds: candidate.maxTimeoutSeconds,
      extra: { ...candidate.extra },
    })),
  };
}

export function projectPaymentRequired(value) {
  return frozenCopy(challengeProjection(validatePaymentRequired(value)));
}

export function validateChallengeProjection(value) {
  const projection = exactRecord(
    value,
    ['x402Version', 'resource', 'accepts'],
    [],
    'CHALLENGE_PROJECTION_SCHEMA',
    'challenge projection',
  );
  if (!Number.isSafeInteger(projection.x402Version) || projection.x402Version < 1) {
    fail(
      'CHALLENGE_PROJECTION_SCHEMA',
      'challenge projection version must be a positive safe integer',
    );
  }
  const resource = exactRecord(
    projection.resource,
    ['urlHash', 'description', 'mimeType'],
    [],
    'CHALLENGE_PROJECTION_SCHEMA',
    'challenge projection resource',
  );
  const urlHash = canonicalHash(
    resource.urlHash,
    'challenge projection resource URL hash',
    'CHALLENGE_PROJECTION_SCHEMA',
  );
  const description = boundedString(
    resource.description,
    'challenge projection resource description',
    'CHALLENGE_PROJECTION_SCHEMA',
    1_024,
  );
  const mimeType = boundedString(
    resource.mimeType,
    'challenge projection resource MIME type',
    'CHALLENGE_PROJECTION_SCHEMA',
    200,
  );
  if (!/^[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]*\/[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]*$/.test(
    mimeType,
  )) {
    fail('CHALLENGE_PROJECTION_SCHEMA', 'challenge projection MIME type must be canonical');
  }
  if (!Array.isArray(projection.accepts) || projection.accepts.length > 100) {
    fail(
      'CHALLENGE_PROJECTION_SCHEMA',
      'challenge projection accepts must be one bounded ordered array',
    );
  }
  let accepts;
  try {
    accepts = projection.accepts.map(validateCandidate);
  } catch (error) {
    if (error instanceof KernelError) {
      fail('CHALLENGE_PROJECTION_SCHEMA', 'challenge projection candidate is invalid');
    }
    throw error;
  }
  return frozenCopy({
    x402Version: projection.x402Version,
    resource: { urlHash, description, mimeType },
    accepts,
  });
}

function sellerFor(policy, intent) {
  return policy.sellers.find((seller) => seller.origin === intent.sellerOrigin) ?? null;
}

function candidateAnalysis(policy, intent, paymentRequired) {
  const scheme = paymentRequired.accepts.filter((candidate) => candidate.scheme === 'exact'
    && (!Object.hasOwn(candidate.extra, 'assetTransferMethod')
      || candidate.extra.assetTransferMethod === 'eip3009'));
  const network = scheme.filter((candidate) => candidate.network === policy.network);
  const asset = network.filter((candidate) => candidate.asset === policy.asset
    && candidate.extra.name === 'USDC'
    && candidate.extra.version === '2');
  const seller = sellerFor(policy, intent);
  const payee = seller
    ? asset.filter((candidate) => candidate.payTo === seller.payTo)
    : [];
  return Object.freeze({ scheme, network, asset, seller, payee });
}

function selectValidatedCandidate(policy, intent, paymentRequired) {
  const analysis = candidateAnalysis(policy, intent, paymentRequired);
  let reasonCode = null;
  if (paymentRequired.x402Version !== 2) reasonCode = 'X402_VERSION';
  else if (analysis.scheme.length === 0) reasonCode = 'SCHEME_UNSUPPORTED';
  else if (analysis.network.length === 0) reasonCode = 'NETWORK_MISMATCH';
  else if (analysis.asset.length === 0) reasonCode = 'ASSET_MISMATCH';
  else if (!analysis.seller) reasonCode = 'SELLER_UNTRUSTED';
  else if (!analysis.seller.pathPrefixes.some((prefix) => intent.resourcePath.startsWith(prefix))) {
    reasonCode = 'RESOURCE_PATH';
  } else if (paymentRequired.resource.url !== intent.requestUrl) reasonCode = 'RESOURCE_PATH';
  else if (analysis.payee.length === 0) reasonCode = 'PAYEE_MISMATCH';
  else if (analysis.payee.length > 1) reasonCode = 'PAYMENT_OPTIONS_AMBIGUOUS';

  if (reasonCode) {
    return Object.freeze({ acceptedIndex: null, accepted: null, reasonCode });
  }
  const accepted = analysis.payee[0];
  const acceptedIndex = paymentRequired.accepts.indexOf(accepted);
  return Object.freeze({ acceptedIndex, accepted, reasonCode: null });
}

export function selectExactCandidate(value) {
  const input = exactRecord(
    value,
    ['policy', 'intent', 'paymentRequired'],
    [],
    'INPUT_SCHEMA',
    'candidate selection input',
  );
  const normalizedPolicy = validatePolicyDocument(input.policy);
  const normalizedIntent = validateIntent(input.intent);
  const normalizedPayment = validatePaymentRequired(input.paymentRequired);
  return selectValidatedCandidate(normalizedPolicy, normalizedIntent, normalizedPayment);
}

function decision({
  decision: outcome,
  reasonCode,
  policyHash,
  challengeHash,
  selection,
}) {
  if (!DECISIONS.has(outcome)) fail('DECISION_SCHEMA', 'unknown policy decision');
  const acceptedIndex = selection?.acceptedIndex ?? null;
  const quoteId = acceptedIndex === null
    ? null
    : sha256(canonicalJson({ challengeHash, acceptedIndex }));
  return Object.freeze({
    decision: outcome,
    reasonCode,
    policyHash,
    challengeHash,
    quoteId,
    amountCeilingAtomic: selection?.accepted?.amount ?? '0',
    acceptedIndex,
  });
}

export function evaluateSpendPolicy(value) {
  const input = exactRecord(
    value,
    INPUT_FIELDS,
    [],
    'INPUT_SCHEMA',
    'policy evaluation input',
  );
  const policy = validatePolicyDocument(input.policy);
  const policyVersion = validatePolicyVersion(input.policyVersion);
  const intent = validateIntent(input.intent);
  const wallet = validateWallet(input.wallet);
  const paymentRequired = validatePaymentRequired(input.paymentRequired);
  const budget = validateBudgetSnapshot(input.budgetSnapshot);
  nonnegativeSafeInteger(
    input.challengeReceivedAtMs,
    'challenge received time',
    'CHALLENGE_TIME',
  );
  nonnegativeSafeInteger(input.nowMs, 'decision time', 'CHALLENGE_TIME');
  if (input.nowMs < input.challengeReceivedAtMs) {
    fail('CHALLENGE_TIME', 'decision time must not precede challenge receipt');
  }
  const policyHash = sha256(canonicalJson(policy));
  if (policyVersion.hash !== policyHash) {
    fail('POLICY_HASH_MISMATCH', 'policy version hash does not match canonical policy');
  }
  const challengeHash = sha256(canonicalJson(challengeProjection(paymentRequired)));
  const analysis = candidateAnalysis(policy, intent, paymentRequired);
  const preselectionDeny = (reasonCode) => decision({
    decision: 'deny',
    reasonCode,
    policyHash,
    challengeHash,
    selection: null,
  });

  if (paymentRequired.x402Version !== 2) return preselectionDeny('X402_VERSION');
  if (analysis.scheme.length === 0) return preselectionDeny('SCHEME_UNSUPPORTED');
  if (analysis.network.length === 0 || wallet.network !== policy.network) {
    return preselectionDeny('NETWORK_MISMATCH');
  }
  if (analysis.asset.length === 0) return preselectionDeny('ASSET_MISMATCH');
  if (intent.walletAddress !== policy.wallet || wallet.address !== policy.wallet) {
    return preselectionDeny('WALLET_MISMATCH');
  }
  if (!policy.methods.includes(intent.method)) return preselectionDeny('METHOD_UNSUPPORTED');
  if (!analysis.seller) return preselectionDeny('SELLER_UNTRUSTED');
  if (!analysis.seller.pathPrefixes.some((prefix) => intent.resourcePath.startsWith(prefix))
      || paymentRequired.resource.url !== intent.requestUrl) {
    return preselectionDeny('RESOURCE_PATH');
  }
  if (analysis.payee.length === 0) return preselectionDeny('PAYEE_MISMATCH');
  if (analysis.payee.length > 1) return preselectionDeny('PAYMENT_OPTIONS_AMBIGUOUS');

  const accepted = analysis.payee[0];
  const selection = Object.freeze({
    accepted,
    acceptedIndex: paymentRequired.accepts.indexOf(accepted),
  });
  const selectedDeny = (reasonCode) => decision({
    decision: 'deny',
    reasonCode,
    policyHash,
    challengeHash,
    selection,
  });
  if (input.nowMs - input.challengeReceivedAtMs > policy.challengeMaxAgeMs) {
    return selectedDeny('CHALLENGE_EXPIRED');
  }
  const amount = BigInt(accepted.amount);
  const perRequest = BigInt(analysis.seller.perRequestMaxAtomic);
  const humanMaximum = BigInt(analysis.seller.humanApproveAtomic);
  if (amount > perRequest || amount > humanMaximum) return selectedDeny('PER_REQUEST_LIMIT');
  if (budget.sellerSessionExposure.value + amount
      > BigInt(analysis.seller.sellerSessionMaxAtomic)) {
    return selectedDeny('SELLER_SESSION_LIMIT');
  }
  if (budget.sessionExposure.value + amount > BigInt(policy.sessionMaxAtomic)) {
    return selectedDeny('SESSION_LIMIT');
  }
  if (budget.rolling24hExposure.value + amount > BigInt(policy.rolling24hMaxAtomic)) {
    return selectedDeny('ROLLING_24H_LIMIT');
  }
  if (amount > BigInt(analysis.seller.autoApproveAtomic)
      && budget.pendingApprovalCount >= policy.maxPendingApprovals) {
    return selectedDeny('APPROVAL_CAPACITY');
  }
  if (amount <= BigInt(analysis.seller.autoApproveAtomic)) {
    return decision({
      decision: 'allow',
      reasonCode: 'WITHIN_AUTO_LIMIT',
      policyHash,
      challengeHash,
      selection,
    });
  }
  return decision({
    decision: 'approval_required',
    reasonCode: 'HUMAN_APPROVAL_REQUIRED',
    policyHash,
    challengeHash,
    selection,
  });
}

export function validatePolicyEvaluation(value) {
  const evaluation = exactRecord(value, [
    'decision',
    'reasonCode',
    'policyHash',
    'challengeHash',
    'quoteId',
    'amountCeilingAtomic',
    'acceptedIndex',
  ], [], 'POLICY_DECISION_SCHEMA', 'policy evaluation');
  if (!DECISIONS.has(evaluation.decision)) {
    fail('POLICY_DECISION_SCHEMA', 'policy evaluation decision is invalid');
  }
  const reasonCode = canonicalToken(evaluation.reasonCode, 'policy reason code');
  const policyHash = canonicalHash(
    evaluation.policyHash,
    'evaluation policy hash',
    'POLICY_DECISION_SCHEMA',
  );
  const challengeHash = canonicalHash(
    evaluation.challengeHash,
    'evaluation challenge hash',
    'POLICY_DECISION_SCHEMA',
  );
  const amount = atomicText(
    evaluation.amountCeilingAtomic,
    'evaluation amount ceiling',
    'POLICY_DECISION_SCHEMA',
  );
  const indexIsNull = evaluation.acceptedIndex === null;
  if (!indexIsNull
      && (!Number.isSafeInteger(evaluation.acceptedIndex) || evaluation.acceptedIndex < 0)) {
    fail('POLICY_DECISION_SCHEMA', 'accepted index must be null or nonnegative');
  }
  if (indexIsNull) {
    if (evaluation.quoteId !== null
        || amount.value !== 0n
        || evaluation.decision !== 'deny'
        || !PRESELECTION_DENIALS.has(reasonCode)) {
      fail('POLICY_DECISION_SCHEMA', 'preselection denial fields are inconsistent');
    }
  } else {
    if (amount.value <= 0n) {
      fail('POLICY_DECISION_SCHEMA', 'selected policy decisions require a positive amount');
    }
    const expectedQuote = sha256(canonicalJson({
      challengeHash,
      acceptedIndex: evaluation.acceptedIndex,
    }));
    if (evaluation.quoteId !== expectedQuote) {
      fail('POLICY_DECISION_SCHEMA', 'quote ID does not match its challenge and index');
    }
    const reasonMatchesDecision = (evaluation.decision === 'allow'
        && reasonCode === 'WITHIN_AUTO_LIMIT')
      || (evaluation.decision === 'approval_required'
        && reasonCode === 'HUMAN_APPROVAL_REQUIRED')
      || (evaluation.decision === 'deny' && SELECTED_DENIALS.has(reasonCode));
    if (!reasonMatchesDecision) {
      fail('POLICY_DECISION_SCHEMA', 'policy decision and reason code are inconsistent');
    }
  }
  return Object.freeze({
    decision: evaluation.decision,
    reasonCode,
    policyHash,
    challengeHash,
    quoteId: evaluation.quoteId,
    amountCeilingAtomic: amount.text,
    acceptedIndex: evaluation.acceptedIndex,
  });
}
