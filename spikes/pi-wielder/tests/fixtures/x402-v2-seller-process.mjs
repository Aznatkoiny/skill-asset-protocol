import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';

import {
  decodePaymentSignatureHeader,
  encodePaymentRequiredHeader,
  encodePaymentResponseHeader,
} from '@x402/core/http';
import { keccak256, toBytes } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';

import { canonicalJson, sha256 } from '../../src/kernel/canonical.mjs';

const NETWORK = 'eip155:84532';
const ASSET = '0x036cbd53842c5426634e7929541ec2318f3dcf7e';
const PAY_TO = '0x2000000000000000000000000000000000000000';
const REFUND_SOURCE = '0x5000000000000000000000000000000000000000';
const MAXIMUM_BODY_BYTES = 1_048_576;
const EVIDENCE_PATH = '/.well-known/wallet-kernel/evidence';
const STATE_FILE = process.env.WALLET_KERNEL_FIXTURE_STATE_FILE;
const MODEL_ORIGIN = process.env.WALLET_KERNEL_FIXTURE_MODEL_ORIGIN;

const executionAccount = privateKeyToAccount(
  keccak256(toBytes('wallet-kernel-seller-execution-test-only')),
);
const refundAccount = privateKeyToAccount(
  keccak256(toBytes('wallet-kernel-seller-refund-test-only')),
);

function derivedTransaction(label) {
  return `0x${crypto.createHash('sha256').update(label, 'utf8').digest('hex')}`;
}

const WRONG_REFUND_TRANSACTION_ID = derivedTransaction('wallet-kernel-e2e:refund:wrong');

function refundTransactionIdFor(originalTransactionId) {
  return derivedTransaction(`wallet-kernel-e2e:refund:confirmed:${originalTransactionId}`);
}

function publicTransactions() {
  const paymentTransactionIds = [...new Set(state.transactionIds)];
  return Object.freeze({
    payments: Object.freeze(paymentTransactionIds.map((paymentTransactionId) => Object.freeze({
      paymentTransactionId,
      refundTransactionId: refundTransactionIdFor(paymentTransactionId),
    }))),
    wrongRefundTransactionId: WRONG_REFUND_TRANSACTION_ID,
  });
}

function fixtureError(code, message) {
  return Object.assign(new Error(message), { code });
}

function requireStateFile(filePath) {
  if (typeof filePath !== 'string' || !path.isAbsolute(filePath)
      || path.resolve(filePath) !== filePath) {
    throw fixtureError('FIXTURE_CONFIG', 'seller state path is invalid');
  }
  const descriptor = fs.openSync(filePath, fs.constants.O_RDWR | fs.constants.O_NOFOLLOW);
  const stat = fs.fstatSync(descriptor, { bigint: true });
  const uid = typeof process.getuid === 'function' ? BigInt(process.getuid()) : stat.uid;
  if (!stat.isFile() || stat.uid !== uid || (stat.mode & 0o7777n) !== 0o600n
      || stat.nlink !== 1n || stat.size > 262_144n) {
    fs.closeSync(descriptor);
    throw fixtureError('FIXTURE_AUTHORITY', 'seller state authority is invalid');
  }
  return descriptor;
}

function validateModelOrigin(value) {
  let parsed;
  try { parsed = new URL(value); } catch {
    throw fixtureError('FIXTURE_CONFIG', 'model origin is invalid');
  }
  if (parsed.protocol !== 'http:' || parsed.hostname !== '127.0.0.1'
      || parsed.port === '' || parsed.pathname !== '/' || parsed.search !== ''
      || parsed.hash !== '' || parsed.origin !== value) {
    throw fixtureError('FIXTURE_CONFIG', 'model origin must be exact IPv4 loopback');
  }
  return value;
}

const stateDescriptor = requireStateFile(STATE_FILE);
const modelOrigin = validateModelOrigin(MODEL_ORIGIN);
let sellerOrigin;
const evidenceResponses = new Map();
let state = Object.freeze({
  requestCount: 0,
  unpaidRequestCount: 0,
  paidRequestCount: 0,
  paymentSignatureCount: 0,
  duplicatePaymentSignatureCount: 0,
  forbiddenForwardedHeaderCount: 0,
  pathCounts: Object.freeze({}),
  paymentHeaderHashes: Object.freeze([]),
  transactionIds: Object.freeze([]),
  payments: Object.freeze({}),
  evidenceRequestCount: 0,
  refundProofRequestCount: 0,
});

function persistState() {
  const bytes = Buffer.from(`${JSON.stringify(state)}\n`, 'utf8');
  fs.ftruncateSync(stateDescriptor, 0);
  fs.writeSync(stateDescriptor, bytes, 0, bytes.length, 0);
  fs.fsyncSync(stateDescriptor);
  bytes.fill(0);
}

function nextState(patch) {
  state = Object.freeze({ ...state, ...patch });
  persistState();
}

function rawHeaderCount(request, target) {
  let count = 0;
  for (let index = 0; index < request.rawHeaders.length; index += 2) {
    if (request.rawHeaders[index].toLowerCase() === target) count += 1;
  }
  return count;
}

function forbiddenHeaderCount(request) {
  const forbidden = new Set([
    'authorization', 'cookie', 'cookie2', 'forwarded', 'proxy-authorization',
    'x-approval-id', 'x-forwarded-for', 'x-forwarded-host', 'x-forwarded-proto',
    'x-idempotency-key', 'x-session-id', 'x-spend-session', 'x-wallet-address',
    'x-wallet-policy',
  ]);
  return Object.keys(request.headers).reduce((count, name) => (
    forbidden.has(name) ? count + 1 : count
  ), 0);
}

async function readBody(request) {
  const chunks = [];
  let total = 0;
  for await (const chunk of request) {
    total += chunk.length;
    if (total > MAXIMUM_BODY_BYTES) throw fixtureError('FIXTURE_BODY_TOO_LARGE', 'body too large');
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

function routeDescription(pathname) {
  if (pathname === '/paid/chat/completions') return 'Wallet Kernel e2e model route';
  if (pathname === '/paid/skill') return 'Wallet Kernel e2e Skill route';
  return `Wallet Kernel e2e ${pathname.slice(pathname.lastIndexOf('/') + 1)} route`;
}

function scenarioFor(pathname) {
  if (pathname === '/paid/chat/completions') return 'model';
  if (pathname === '/paid/skill') return 'skill';
  if (pathname.startsWith('/paid/scenario/')) return pathname.slice('/paid/scenario/'.length);
  if (pathname.startsWith('/untrusted/')) return 'untrusted';
  return null;
}

function amountFor(scenario) {
  if (scenario === 'over-budget') return '600000';
  if (new Set(['approval', 'approval-model', 'changed-challenge']).has(scenario)) {
    return '200000';
  }
  return '50000';
}

function challengeFor(pathname, scenario) {
  const pathCount = state.pathCounts[pathname] ?? 0;
  const changed = scenario === 'changed-challenge' && pathCount >= 2;
  const amount = changed ? '200001' : amountFor(scenario);
  return Object.freeze({
    x402Version: 2,
    error: 'Payment required',
    resource: Object.freeze({
      url: `${sellerOrigin}${pathname}`,
      description: routeDescription(pathname),
      mimeType: 'application/json',
    }),
    accepts: Object.freeze([Object.freeze({
      scheme: 'exact',
      network: NETWORK,
      asset: ASSET,
      amount,
      payTo: scenario === 'untrusted'
        ? '0x9000000000000000000000000000000000000000'
        : PAY_TO,
      maxTimeoutSeconds: 60,
      extra: Object.freeze({ name: 'USDC', version: '2' }),
    })]),
  });
}

function sendJson(response, status, value, headers = {}) {
  response.writeHead(status, {
    'cache-control': 'no-store',
    'content-type': 'application/json',
    'x-content-type-options': 'nosniff',
    ...headers,
  });
  response.end(JSON.stringify(value));
}

function sendChallenge(response, challenge) {
  sendJson(response, 402, { error: 'PAYMENT_REQUIRED' }, {
    'payment-required': encodePaymentRequiredHeader(challenge),
  });
}

function capturePayment(request, challenge, pathname) {
  if (rawHeaderCount(request, 'payment-signature') !== 1) {
    throw fixtureError('PAYMENT_SIGNATURE_COUNT', 'paid request requires exactly one signature');
  }
  const rawHeader = request.headers['payment-signature'];
  if (typeof rawHeader !== 'string') {
    throw fixtureError('PAYMENT_SIGNATURE_INVALID', 'payment signature is invalid');
  }
  let payment;
  try { payment = decodePaymentSignatureHeader(rawHeader); } catch {
    throw fixtureError('PAYMENT_SIGNATURE_INVALID', 'payment signature is invalid');
  }
  const accepted = payment?.accepted;
  const authorization = payment?.payload?.authorization;
  if (payment?.x402Version !== 2
      || payment?.resource?.url !== challenge.resource.url
      || accepted?.scheme !== 'exact'
      || accepted?.network !== NETWORK
      || accepted?.asset?.toLowerCase() !== ASSET
      || accepted?.amount !== challenge.accepts[0].amount
      || accepted?.payTo?.toLowerCase() !== PAY_TO
      || authorization?.from?.toLowerCase() === undefined
      || authorization?.to?.toLowerCase() !== PAY_TO
      || authorization?.value !== challenge.accepts[0].amount
      || typeof authorization?.nonce !== 'string') {
    throw fixtureError('PAYMENT_SIGNATURE_BINDING', 'payment signature binding is invalid');
  }
  const paymentHeaderHash = sha256(Buffer.from(rawHeader, 'ascii'));
  const duplicate = state.paymentHeaderHashes.includes(paymentHeaderHash);
  const transactionId = derivedTransaction(
    `wallet-kernel-e2e:${pathname}:${paymentHeaderHash}`,
  );
  const record = Object.freeze({
    amountAtomic: accepted.amount,
    authorizationNonce: authorization.nonce.toLowerCase(),
    from: authorization.from.toLowerCase(),
    observedAt: new Date().toISOString(),
    paymentHeaderHash,
    to: authorization.to.toLowerCase(),
    transactionId,
  });
  nextState({
    paidRequestCount: state.paidRequestCount + 1,
    paymentSignatureCount: state.paymentSignatureCount + 1,
    duplicatePaymentSignatureCount: state.duplicatePaymentSignatureCount + (duplicate ? 1 : 0),
    paymentHeaderHashes: Object.freeze([...state.paymentHeaderHashes, paymentHeaderHash]),
    transactionIds: Object.freeze([...state.transactionIds, transactionId]),
    payments: Object.freeze({ ...state.payments, [transactionId]: record }),
  });
  return record;
}

function paymentResponse(payment, success = true) {
  return encodePaymentResponseHeader(success
    ? {
      success: true,
      transaction: payment.transactionId,
      network: NETWORK,
      payer: payment.from,
      amount: payment.amountAtomic,
    }
    : {
      success: false,
      transaction: payment.transactionId,
      network: NETWORK,
      errorReason: 'fixture rejection',
    });
}

async function forwardModel(body, response, settlementHeader) {
  const upstream = await fetch(`${modelOrigin}/chat/completions`, {
    method: 'POST',
    redirect: 'manual',
    credentials: 'omit',
    headers: { accept: 'text/event-stream', 'content-type': 'application/json' },
    body,
  });
  const bytes = Buffer.from(await upstream.arrayBuffer());
  const headers = {
    'cache-control': 'no-store',
    'content-type': upstream.headers.get('content-type') ?? 'text/event-stream; charset=utf-8',
    'x-content-type-options': 'nosniff',
  };
  if (typeof settlementHeader === 'string') headers['payment-response'] = settlementHeader;
  response.writeHead(upstream.status, headers);
  response.end(bytes);
}

function rpcProof(payment, transactionId) {
  return Object.freeze({
    jsonrpc: '2.0',
    id: 1,
    result: Object.freeze({
      source: 'base-sepolia-rpc',
      network: NETWORK,
      transactionId,
      blockHash: derivedTransaction(`block:${transactionId}`),
      blockNumber: '1234571',
      transactionStatus: 'success',
      confirmations: 3,
      transferLogIndex: 4,
      authorizationLogIndex: 5,
      tokenContract: ASSET,
      from: payment.from,
      to: payment.to,
      valueAtomic: payment.amountAtomic,
      authorizationNonce: payment.authorizationNonce,
      observedAt: payment.observedAt,
    }),
  });
}

async function evidenceResponse(body) {
  let request;
  try { request = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(body)); } catch {
    throw fixtureError('EVIDENCE_REQUEST_INVALID', 'evidence request is malformed');
  }
  if (request?.schemaVersion !== 1 || request?.sellerOrigin !== sellerOrigin
      || typeof request?.intentHash !== 'string') {
    throw fixtureError('EVIDENCE_REQUEST_INVALID', 'evidence request binding is invalid');
  }
  const cacheKey = canonicalJson(request);
  const cached = evidenceResponses.get(cacheKey);
  if (cached) return cached;
  const issuedAtMs = Date.now() - 1_000;
  const issuedAt = new Date(issuedAtMs).toISOString();
  const expiresAt = new Date(issuedAtMs + 10 * 60_000).toISOString();
  let unsigned;
  let account;
  if (request.kind === 'execution' && typeof request.transactionId === 'string') {
    const payment = state.payments[request.transactionId];
    if (!payment) throw fixtureError('EVIDENCE_NOT_FOUND', 'payment is unknown');
    unsigned = {
      schemaVersion: 1,
      domain: 'wallet-kernel.execution.v1',
      network: NETWORK,
      sellerOrigin,
      intentHash: request.intentHash,
      transactionId: request.transactionId,
      outcome: 'succeeded',
      httpStatus: 200,
      responseHash: sha256(Buffer.from('{"fixture":"execution-observed"}', 'utf8')),
      issuedAt,
      expiresAt,
      signer: executionAccount.address.toLowerCase(),
    };
    account = executionAccount;
  } else if (request.kind === 'refund'
      && typeof request.originalTransactionId === 'string'
      && request.refundTransactionId === refundTransactionIdFor(request.originalTransactionId)) {
    const payment = state.payments[request.originalTransactionId];
    if (!payment) throw fixtureError('EVIDENCE_NOT_FOUND', 'original payment is unknown');
    unsigned = {
      schemaVersion: 1,
      domain: 'wallet-kernel.refund.v1',
      network: NETWORK,
      sellerOrigin,
      intentHash: request.intentHash,
      originalTransactionId: request.originalTransactionId,
      refundTransactionId: request.refundTransactionId,
      asset: ASSET,
      originalPayer: payment.from,
      originalPayee: payment.to,
      refundSource: REFUND_SOURCE,
      amountAtomic: payment.amountAtomic,
      issuedAt,
      expiresAt,
      signer: refundAccount.address.toLowerCase(),
    };
    account = refundAccount;
  } else {
    throw fixtureError('EVIDENCE_NOT_FOUND', 'evidence is unavailable');
  }
  const signature = await account.signMessage({
    message: { raw: Buffer.from(canonicalJson(unsigned), 'utf8') },
  });
  const evidence = Object.freeze({ ...unsigned, signature });
  evidenceResponses.set(cacheKey, evidence);
  return evidence;
}

const server = http.createServer(async (request, response) => {
  try {
    const url = new URL(request.url, sellerOrigin ?? 'http://127.0.0.1');
    if (url.search !== '' || url.hash !== '') {
      sendJson(response, 400, { error: { code: 'FIXTURE_URL_INVALID' } });
      return;
    }
    if (request.method === 'GET' && url.pathname === '/fixture/v1/public-transactions') {
      sendJson(response, 200, publicTransactions());
      return;
    }
    if (request.method === 'GET' && url.pathname.startsWith('/fixture/v1/payment-proof/')) {
      const transactionId = url.pathname.slice('/fixture/v1/payment-proof/'.length);
      const payment = state.payments[transactionId];
      if (!payment) {
        sendJson(response, 404, { error: { code: 'FIXTURE_PAYMENT_NOT_FOUND' } });
        return;
      }
      sendJson(response, 200, rpcProof(payment, transactionId));
      return;
    }
    if (request.method === 'GET' && url.pathname.startsWith('/fixture/v1/refund-proof/')) {
      const transactionId = url.pathname.slice('/fixture/v1/refund-proof/'.length);
      nextState({ refundProofRequestCount: state.refundProofRequestCount + 1 });
      if (transactionId === WRONG_REFUND_TRANSACTION_ID) {
        const firstPayment = state.payments[state.transactionIds[0]];
        sendJson(response, 200, rpcProof({
          ...firstPayment,
          amountAtomic: '1',
          from: REFUND_SOURCE,
          to: firstPayment?.from ?? '0x1000000000000000000000000000000000000000',
        }, transactionId));
        return;
      }
      const originalTransactionId = Object.keys(state.payments).find(
        (candidate) => refundTransactionIdFor(candidate) === transactionId,
      );
      if (originalTransactionId !== undefined) {
        const payment = state.payments[originalTransactionId];
        sendJson(response, 200, rpcProof({
          ...payment,
          from: REFUND_SOURCE,
          to: payment.from,
        }, transactionId));
        return;
      }
      sendJson(response, 404, { error: { code: 'FIXTURE_REFUND_NOT_FOUND' } });
      return;
    }
    if (request.method === 'POST' && url.pathname === EVIDENCE_PATH) {
      const body = await readBody(request);
      nextState({ evidenceRequestCount: state.evidenceRequestCount + 1 });
      try {
        sendJson(response, 200, await evidenceResponse(body));
      } catch (error) {
        sendJson(response, error?.code === 'EVIDENCE_NOT_FOUND' ? 404 : 400, {
          error: { code: typeof error?.code === 'string' ? error.code : 'EVIDENCE_FAILED' },
        });
      }
      return;
    }

    const scenario = scenarioFor(url.pathname);
    if (request.method !== 'POST' || scenario === null) {
      sendJson(response, 404, { error: { code: 'FIXTURE_ROUTE_NOT_FOUND' } });
      return;
    }
    const body = await readBody(request);
    const signatureCount = rawHeaderCount(request, 'payment-signature');
    const pathCount = (state.pathCounts[url.pathname] ?? 0) + 1;
    nextState({
      requestCount: state.requestCount + 1,
      forbiddenForwardedHeaderCount: state.forbiddenForwardedHeaderCount
        + forbiddenHeaderCount(request),
      pathCounts: Object.freeze({ ...state.pathCounts, [url.pathname]: pathCount }),
      ...(signatureCount === 0 ? { unpaidRequestCount: state.unpaidRequestCount + 1 } : {}),
    });
    const challenge = challengeFor(url.pathname, scenario);
    if (signatureCount === 0) {
      if (scenario === 'free-model') {
        await forwardModel(body, response, null);
        return;
      }
      sendChallenge(response, challenge);
      return;
    }
    const payment = capturePayment(request, challenge, url.pathname);
    const settlementHeader = paymentResponse(payment, scenario !== 'success-false');

    if (scenario === 'pre-header-loss' || scenario === 'trusted-settlement') {
      request.socket.destroy();
      return;
    }
    if (scenario === 'delayed') {
      const timer = setTimeout(() => sendJson(response, 200, { delayed: true }, {
        'payment-response': settlementHeader,
      }), 10_000);
      timer.unref();
      return;
    }
    if (scenario === 'second-402') {
      sendChallenge(response, challenge);
      return;
    }
    if (scenario === 'malformed-settlement') {
      sendJson(response, 200, { malformed: true }, { 'payment-response': 'not-base64' });
      return;
    }
    if (scenario === 'success-false' || scenario === 'explicit-rejection') {
      sendJson(response, 402, { rejected: true }, { 'payment-response': paymentResponse(payment, false) });
      return;
    }
    if (scenario === 'body-loss' || scenario === 'delivery-loss') {
      response.writeHead(200, {
        'content-length': '128',
        'content-type': 'application/json',
        'payment-response': settlementHeader,
      });
      response.flushHeaders();
      response.write('{"partial":');
      const timer = setTimeout(() => response.destroy(), 25);
      timer.unref();
      return;
    }
    const status = new Map([
      ['settled-302', 302], ['settled-404', 404], ['settled-500', 500],
    ]).get(scenario) ?? 200;
    if (scenario === 'model' || scenario === 'approval-model') {
      await forwardModel(body, response, settlementHeader);
      return;
    }
    sendJson(response, status, scenario === 'skill'
      ? { output: 'SKILL_TOOL_OK' }
      : { scenario, settled: true }, {
      'payment-response': settlementHeader,
      ...(status === 302 ? { location: 'https://external.invalid/forbidden-redirect' } : {}),
    });
  } catch (error) {
    if (!response.headersSent) {
      sendJson(response, error?.code === 'FIXTURE_BODY_TOO_LARGE' ? 413 : 400, {
        error: { code: typeof error?.code === 'string' ? error.code : 'FIXTURE_REQUEST_FAILED' },
      });
    } else {
      response.destroy();
    }
  }
});

let closing = false;
async function close(code = 0) {
  if (closing) return;
  closing = true;
  await new Promise((resolve) => server.close(resolve));
  fs.closeSync(stateDescriptor);
  if (typeof process.disconnect === 'function' && process.connected) process.disconnect();
  process.exitCode = code;
}

process.on('message', (message) => {
  if (message && typeof message === 'object' && message.type === 'shutdown') void close(0);
});
process.once('SIGINT', () => { void close(0); });
process.once('SIGTERM', () => { void close(0); });
server.once('error', (error) => {
  if (typeof process.send === 'function') {
    process.send({ type: 'fatal', code: typeof error?.code === 'string' ? error.code : 'SELLER_LISTEN_FAILED' });
  }
  process.exitCode = 1;
});
server.listen(0, '127.0.0.1', () => {
  const address = server.address();
  if (!address || typeof address === 'string') {
    process.exitCode = 1;
    return;
  }
  sellerOrigin = `http://127.0.0.1:${address.port}`;
  if (typeof process.send === 'function') {
    process.send({
      type: 'ready',
      origin: sellerOrigin,
      executionSigner: executionAccount.address.toLowerCase(),
      refundSigner: refundAccount.address.toLowerCase(),
      refundSource: REFUND_SOURCE,
    });
  }
});
