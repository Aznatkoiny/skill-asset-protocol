import fs from 'node:fs';
import path from 'node:path';

import { authorizationTypes } from '@x402/evm';
import { encodePaymentRequiredHeader, encodePaymentResponseHeader } from '@x402/core/http';
import { hashTypedData } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';

import { assertHeldKernelAuthorityLock } from '../kernel/authority-lock.mjs';
import { canonicalJson, canonicalTimestamp, exactRecord, frozenCopy, KernelError, sha256 } from '../kernel/canonical.mjs';
import { preparePrivateFile, readPrivateInputFile } from '../kernel/secure-storage.mjs';
import { openTrustedParent } from '../kernel/trusted-path.mjs';

const PROFILE = 'offline-qualification';
const ORIGIN = 'https://seller.wallet-kernel.invalid';
const WALLET = '0xa267e4f15c979289993a95e22ca9cdf077b708ba';
const PAYEE = '0x2000000000000000000000000000000000000000';
const ASSET = '0x036cbd53842c5426634e7929541ec2318f3dcf7e';
const NETWORK = 'eip155:84532';
const JOURNAL_NAME = 'offline-qualification-provider.ndjson';
const MAXIMUM_JOURNAL_BYTES = 262_144;
const MAXIMUM_EVENTS = 512;
const OPEN_JOURNALS = new Set();
const ACCOUNT = privateKeyToAccount(`0x${'41'.repeat(32)}`); // Public synthetic fixture key; never a funded wallet.
const ENVIRONMENT = Object.freeze({
  CDP_API_KEY_ID: 'offline-qualification-api-id',
  CDP_API_KEY_SECRET: 'offline-qualification-api-secret',
  CDP_WALLET_SECRET: 'offline-qualification-wallet-secret',
  CDP_WALLET_NAME: 'offline-qualification-wallet',
  WALLET_KERNEL_BASE_SEPOLIA_RPC_URL: 'https://rpc.wallet-kernel.invalid',
});
const ROUTES = Object.freeze([
  ['allow', '50000'], ['approval', '250000'], ['charged-failure', '60000'],
  ['payment-unresolved', '70000'], ['signing-interruption', '80000'], ['retry-interruption', '90000'],
].map(([scenario, amountAtomic]) => Object.freeze({
  scenario, amountAtomic, id: `qualification-${scenario}`, kind: 'tool', method: 'POST',
  upstreamUrl: `${ORIGIN}/paid/${scenario}`,
  resourceDescription: `Offline qualification ${scenario}`, resourceMimeType: 'application/json',
  purposeLabel: 'qualification.invoke', requestContentTypes: Object.freeze(['application/json']),
  maximumRequestBytes: 262_144, maximumResponseBytes: 1_048_576,
})));

export const OFFLINE_QUALIFICATION = Object.freeze({
  profile: PROFILE, walletAddress: WALLET, payTo: PAYEE, asset: ASSET, network: NETWORK,
  sellerOrigin: ORIGIN, environment: ENVIRONMENT, journalName: JOURNAL_NAME, routes: ROUTES,
});

function fail(code = 'QUALIFICATION_INPUT') {
  throw new KernelError(code, 'Offline qualification fixture refused');
}

const EVENT_KINDS = new Set(['provider_opened', 'unpaid_requested', 'paid_requested',
  'signer_started', 'signer_completed', 'signer_blocked', 'retry_blocked']);

function journalProjection(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length > MAXIMUM_JOURNAL_BYTES
      || (bytes.length !== 0 && bytes.at(-1) !== 10)) fail('QUALIFICATION_JOURNAL');
  const events = [];
  let previousHash = null;
  const text = bytes.toString('utf8');
  if (!Buffer.from(text).equals(bytes)) fail('QUALIFICATION_JOURNAL');
  for (const line of text.length === 0 ? [] : text.slice(0, -1).split('\n')) {
    if (line.length === 0) fail('QUALIFICATION_JOURNAL');
    let event;
    try {event = exactRecord(JSON.parse(line), ['sequence', 'kind', 'routeId', 'requestHash',
      'recordedAt', 'previousHash', 'eventHash'], [], 'QUALIFICATION_JOURNAL', 'qualification record');}
    catch {fail('QUALIFICATION_JOURNAL');}
    const {eventHash, ...body} = event;
    if (canonicalJson(event) !== line || event.sequence !== events.length + 1
        || !EVENT_KINDS.has(event.kind) || event.previousHash !== previousHash
        || sha256(canonicalJson(body)) !== eventHash
        || (event.kind === 'provider_opened'
          ? event.routeId !== null || event.requestHash !== null
          : !ROUTES.some(route => route.id === event.routeId)
            || !/^sha256:[0-9a-f]{64}$/u.test(event.requestHash))) fail('QUALIFICATION_JOURNAL');
    try {canonicalTimestamp(event.recordedAt, 'qualification record time');} catch {fail('QUALIFICATION_JOURNAL');}
    previousHash = eventHash;
    events.push(event);
  }
  if (events.length > MAXIMUM_EVENTS) fail('QUALIFICATION_JOURNAL');
  return frozenCopy({schemaVersion:1, profile:PROFILE,
    counters:{providerOpens:events.filter(event=>event.kind === 'provider_opened').length,
      unpaidRequests:events.filter(event=>event.kind === 'unpaid_requested').length,
      signerCalls:events.filter(event=>event.kind === 'signer_started').length,
      signaturesProduced:events.filter(event=>event.kind === 'signer_completed').length,
      paidRequests:events.filter(event=>event.kind === 'paid_requested').length},
    lastEvent:events.at(-1) ?? null, events});
}

export function readOfflineQualificationJournal({databasePath, pathTrust}) {
  const bytes = readPrivateInputFile(path.join(path.dirname(databasePath), JOURNAL_NAME),
    'qualification journal', {pathTrust, maximumBytes:MAXIMUM_JOURNAL_BYTES});
  try {return journalProjection(bytes);} finally {bytes.fill(0);}
}

function openJournal({config, pathTrust, authorityLock}) {
  const filePath = path.join(path.dirname(config.databasePath), JOURNAL_NAME);
  if (OPEN_JOURNALS.has(filePath)) fail('QUALIFICATION_BUSY');
  assertHeldKernelAuthorityLock(authorityLock, {databasePath:config.databasePath});
  preparePrivateFile(filePath, 'qualification journal', {pathTrust});
  const guard = openTrustedParent({...pathTrust, targetFile:filePath,
    terminalOwnerUid:pathTrust.kernelUid, terminalMode:0o700, role:'kernel-private'});
  let descriptor;
  let closed = false;
  try {
    descriptor = guard.openLeaf(fs.constants.O_RDWR | fs.constants.O_APPEND | fs.constants.O_NOFOLLOW);
    let expected = fs.fstatSync(descriptor, {bigint:true});
    const assertCurrent = () => {
      if (closed) fail('QUALIFICATION_CLOSED');
      assertHeldKernelAuthorityLock(authorityLock, {databasePath:config.databasePath});
      guard.revalidate();
      const actual = fs.fstatSync(descriptor, {bigint:true});
      const named = fs.lstatSync(filePath, {bigint:true});
      if (!actual.isFile() || actual.uid !== BigInt(pathTrust.kernelUid)
          || actual.gid !== BigInt(process.getgid()) || (actual.mode & 0o7777n) !== 0o600n
          || actual.nlink !== 1n || actual.size > BigInt(MAXIMUM_JOURNAL_BYTES)
          || ['dev', 'ino', 'mode', 'uid', 'gid', 'nlink', 'size', 'mtimeNs', 'ctimeNs']
            .some(field => actual[field] !== expected[field] || actual[field] !== named[field])) fail('QUALIFICATION_JOURNAL');
    };
    assertCurrent();
    const original = fs.readFileSync(descriptor);
    let projection;
    try {projection = journalProjection(original);} finally {original.fill(0);}
    assertCurrent();
    const record = (kind, routeId = null, requestHash = null) => {
      assertCurrent();
      if (projection.events.length >= MAXIMUM_EVENTS) fail('QUALIFICATION_JOURNAL');
      const body = {sequence:projection.events.length + 1, kind, routeId, requestHash,
        recordedAt:new Date().toISOString(), previousHash:projection.lastEvent?.eventHash ?? null};
      const event = {...body, eventHash:sha256(canonicalJson(body))};
      const bytes = Buffer.from(`${canonicalJson(event)}\n`);
      if (Number(expected.size) + bytes.length > MAXIMUM_JOURNAL_BYTES) fail('QUALIFICATION_JOURNAL');
      try {
        let offset = 0;
        while (offset < bytes.length) {
          const count = fs.writeSync(descriptor, bytes, offset, bytes.length - offset);
          if (count <= 0) fail('QUALIFICATION_JOURNAL');
          offset += count;
        }
        fs.fsyncSync(descriptor);
        guard.fsyncParent();
        expected = fs.fstatSync(descriptor, {bigint:true});
        assertCurrent();
        projection = journalProjection(Buffer.from([...projection.events, event].map(canonicalJson).join('\n') + '\n'));
      } finally {bytes.fill(0);}
    };
    OPEN_JOURNALS.add(filePath);
    return Object.freeze({record, close() {
      if (closed) return;
      closed = true;
      try {fs.closeSync(descriptor);} finally {guard.close(); OPEN_JOURNALS.delete(filePath);}
    }});
  } catch (error) {
    if (descriptor !== undefined) fs.closeSync(descriptor);
    guard.close();
    throw error;
  }
}

/** Closed synthetic providers. This module has no network client or production fallback. */
export function createOfflineQualificationClients({environment, config, routes, pathTrust, authorityLock}) {
  if (config.mode !== 'cdp-testnet' || config.network !== NETWORK
      || config.cdpWalletName !== ENVIRONMENT.CDP_WALLET_NAME
      || Object.entries(ENVIRONMENT).some(([key, value]) => environment[key] !== value)
      || !Array.isArray(routes.routes) || routes.routes.length !== ROUTES.length
      || routes.routes.some(route => !ROUTES.some(expected => {
        const {scenario, amountAtomic, ...descriptor} = expected;
        return canonicalJson(descriptor) === canonicalJson(route);
      }))) fail();
  const journal = openJournal({config, pathTrust, authorityLock});
  const barriers = new Set();
  let closed = false;
  const assertOpen = () => {if (closed) fail('QUALIFICATION_CLOSED');};
  const interrupt = () => new Promise((_resolve, reject) => barriers.add(reject));
  const byUrl = new Map(ROUTES.map(route => [route.upstreamUrl, route]));
  const byAmount = new Map(ROUTES.map(route => [route.amountAtomic, route]));
  try {
    journal.record('provider_opened');
    const account = Object.freeze({address:WALLET, async signTypedData(input) {
      assertOpen();
      const message = input?.message;
      const route = byAmount.get(String(message?.value));
      if (!route || input.primaryType !== 'TransferWithAuthorization'
          || input.domain?.name !== 'USDC' || input.domain?.version !== '2'
          || input.domain?.chainId !== 84532 || input.domain?.verifyingContract?.toLowerCase() !== ASSET
          || message.from?.toLowerCase() !== WALLET || message.to?.toLowerCase() !== PAYEE
          || canonicalJson(input.types) !== canonicalJson(authorizationTypes)) fail();
      const requestHash = sha256(hashTypedData(input));
      journal.record('signer_started', route.id, requestHash);
      if (route.scenario === 'signing-interruption') {
        journal.record('signer_blocked', route.id, requestHash);
        return interrupt();
      }
      const signature = await ACCOUNT.signTypedData(input);
      journal.record('signer_completed', route.id, requestHash);
      return signature;
    }});
    const clients = Object.freeze({
      cdpClient:Object.freeze({evm:Object.freeze({async getAccount(input) {
        assertOpen();
        if (!input || Reflect.ownKeys(input).length !== 1 || input.name !== ENVIRONMENT.CDP_WALLET_NAME) fail();
        return account;
      }})}),
      publicClient:Object.freeze({
        async getChainId() {assertOpen(); return 84532;},
        async getBlockNumber() {assertOpen(); return BigInt(Math.floor(Date.now() / 1000));},
        async getBlock({blockNumber}) {
          assertOpen();
          if (typeof blockNumber !== 'bigint' || blockNumber <= 0n) fail();
          return {number:blockNumber, hash:`0x${sha256(`offline-block:${blockNumber}`).slice(7)}`, timestamp:blockNumber};
        },
        async getTransactionReceipt() {assertOpen(); return null;},
        async readContract({address, functionName}) {
          assertOpen();
          if (address?.toLowerCase() !== ASSET) fail();
          const values = {name:'USDC', version:'2', decimals:6, balanceOf:5_000_000n, authorizationState:false};
          if (!Object.hasOwn(values, functionName)) fail();
          return values[functionName];
        },
      }),
      async fetchImpl(url, init = {}) {
        assertOpen();
        const route = typeof url === 'string' ? byUrl.get(url) : null;
        if (!route || init.method !== 'POST') fail();
        if (!Buffer.from(init.body ?? '').equals(Buffer.from('{"qualification":true}'))) fail();
        const headers = new Headers(init.headers);
        if (headers.has('authorization') || headers.has('cookie')) fail();
        const paymentHeader = headers.get('payment-signature');
        if (paymentHeader === null) {
          journal.record('unpaid_requested', route.id, sha256(Buffer.from(init.body ?? '')));
          return new Response(null, {status:402, headers:{'PAYMENT-REQUIRED':encodePaymentRequiredHeader({
            x402Version:2, resource:{url:route.upstreamUrl, description:route.resourceDescription, mimeType:route.resourceMimeType},
            accepts:[{scheme:'exact', network:NETWORK, asset:ASSET, amount:route.amountAtomic,
              payTo:PAYEE, maxTimeoutSeconds:60, extra:{name:'USDC', version:'2'}}],
          })}});
        }
        const requestHash = sha256(paymentHeader);
        journal.record('paid_requested', route.id, requestHash);
        if (route.scenario === 'retry-interruption') {
          journal.record('retry_blocked', route.id, requestHash);
          return interrupt();
        }
        if (route.scenario === 'payment-unresolved') fail('QUALIFICATION_PAID_RESPONSE_LOST');
        return new Response(canonicalJson({offlineQualification:true, scenario:route.scenario}), {
          status:route.scenario === 'charged-failure' ? 500 : 200,
          headers:{'content-type':'application/json', 'PAYMENT-RESPONSE':encodePaymentResponseHeader({
            success:true, transaction:`0x${requestHash.slice(7)}`, network:NETWORK, payer:WALLET, amount:route.amountAtomic,
          })},
        });
      },
    });
    return Object.freeze({clients, close() {
      if (closed) return;
      closed = true;
      for (const reject of barriers) reject(new KernelError('QUALIFICATION_CLOSED', 'Offline qualification fixture closed'));
      barriers.clear();
      journal.close();
    }});
  } catch (error) {journal.close(); throw error;}
}
