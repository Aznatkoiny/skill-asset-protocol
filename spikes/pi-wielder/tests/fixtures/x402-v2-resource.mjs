import crypto from 'node:crypto';

import {
  encodePaymentRequiredHeader,
  encodePaymentResponseHeader,
  encodePaymentSignatureHeader,
} from '@x402/core/http';

function deepFreeze(value, seen = new WeakSet()) {
  if (value && typeof value === 'object' && !seen.has(value)) {
    seen.add(value);
    for (const key of Reflect.ownKeys(value)) deepFreeze(value[key], seen);
    Object.freeze(value);
  }
  return value;
}

function digestAscii(value) {
  return `sha256:${crypto.createHash('sha256').update(Buffer.from(value, 'ascii')).digest('hex')}`;
}

export const PAYMENT_REQUIRED = deepFreeze({
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

export const PAYMENT_PAYLOAD = deepFreeze({
  x402Version: 2,
  resource: {
    url: PAYMENT_REQUIRED.resource.url,
    description: PAYMENT_REQUIRED.resource.description,
    mimeType: PAYMENT_REQUIRED.resource.mimeType,
  },
  accepted: PAYMENT_REQUIRED.accepts[0],
  payload: {
    signature: `0x${'11'.repeat(65)}`,
    authorization: {
      from: '0x1000000000000000000000000000000000000000',
      to: PAYMENT_REQUIRED.accepts[0].payTo,
      value: PAYMENT_REQUIRED.accepts[0].amount,
      validAfter: '0',
      validBefore: '1785502860',
      nonce: `0x${'01'.repeat(32)}`,
    },
  },
});

export const PAYMENT_RESPONSE = deepFreeze({
  success: true,
  transaction: `0x${'AB'.repeat(32)}`,
  network: PAYMENT_REQUIRED.accepts[0].network,
  payer: PAYMENT_PAYLOAD.payload.authorization.from.toUpperCase().replace('0X', '0x'),
  amount: PAYMENT_REQUIRED.accepts[0].amount,
});

export const PAYMENT_REQUIRED_HEADER = encodePaymentRequiredHeader(PAYMENT_REQUIRED);
export const PAYMENT_SIGNATURE_HEADER = encodePaymentSignatureHeader(PAYMENT_PAYLOAD);
export const PAYMENT_RESPONSE_HEADER = encodePaymentResponseHeader(PAYMENT_RESPONSE);
export const PAYMENT_HASH = digestAscii(PAYMENT_SIGNATURE_HEADER);

export const SETTLEMENT = deepFreeze({
  source: 'x402-payment-response',
  headerHash: digestAscii(PAYMENT_RESPONSE_HEADER),
  success: true,
  transaction: PAYMENT_RESPONSE.transaction.toLowerCase(),
  network: PAYMENT_RESPONSE.network,
  payer: PAYMENT_PAYLOAD.payload.authorization.from,
  amountAtomic: PAYMENT_RESPONSE.amount,
  paymentHash: PAYMENT_HASH,
});

export const SETTLEMENT_FIXTURE = SETTLEMENT;

function requestBodyBytes(body) {
  if (body === undefined || body === null) return Buffer.alloc(0);
  if (typeof body === 'string') return Buffer.from(body);
  if (body instanceof Uint8Array) return Buffer.from(body);
  throw new TypeError('fixture received an unsupported request body');
}

export function createResourceFetch({
  status = 200,
  body = Buffer.from('{"ok":true}'),
  paymentResponseHeader = PAYMENT_RESPONSE_HEADER,
  challengeBody = Buffer.alloc(0),
} = {}) {
  const calls = [];
  const fetchImpl = async (url, init = {}) => {
    const headers = new Headers(init.headers);
    calls.push(Object.freeze({
      url: String(url),
      method: init.method,
      redirect: init.redirect,
      credentials: init.credentials,
      headers: Object.freeze(Object.fromEntries(headers.entries())),
      bodyBytes: requestBodyBytes(init.body),
    }));

    if (calls.length === 1) {
      if (headers.has('payment-signature')) {
        throw new Error('unpaid fixture request carried PAYMENT-SIGNATURE');
      }
      return new Response(challengeBody, {
        status: 402,
        headers: { 'PAYMENT-REQUIRED': PAYMENT_REQUIRED_HEADER },
      });
    }
    if (calls.length === 2) {
      if (headers.get('payment-signature') !== PAYMENT_SIGNATURE_HEADER) {
        throw new Error('paid fixture request did not carry the exact signature header');
      }
      return new Response(body, {
        status,
        headers: paymentResponseHeader === null
          ? {}
          : { 'PAYMENT-RESPONSE': paymentResponseHeader },
      });
    }
    throw new Error('x402 fixture forbids a third request');
  };

  return Object.freeze({
    fetchImpl,
    calls,
    callCount: () => calls.length,
  });
}
