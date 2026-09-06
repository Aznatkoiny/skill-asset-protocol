import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { authorizationTypes } from '@x402/evm';
import { decodePaymentRequiredHeader, decodePaymentResponseHeader } from '@x402/core/http';
import { getAddress, verifyTypedData } from 'viem';

import { createBaseSepoliaObserver } from '../src/adapters/base-sepolia-observer.mjs';
import { validateRouteMap } from '../src/config.mjs';
import { acquireAuthorityLock } from '../src/kernel/authority-lock.mjs';
import { createOfflineQualificationClients, OFFLINE_QUALIFICATION as Q, readOfflineQualificationJournal } from '../src/runtime/qualification-clients.mjs';

function fixture(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'wallet-kernel-qualification-'));
  fs.chmodSync(directory, 0o700);
  const config = {mode:'cdp-testnet', network:Q.network, cdpWalletName:Q.environment.CDP_WALLET_NAME,
    databasePath:path.join(directory, 'kernel.sqlite')};
  const pathTrust = Object.freeze({mode:'deterministic', trustedAncestor:directory,
    kernelUid:process.getuid(), agentUid:process.getuid()});
  const authorityLock = acquireAuthorityLock({databasePath:config.databasePath, role:'kernel', pathTrust});
  const routes = validateRouteMap({mode:'cdp-testnet', document:{schemaVersion:1,
    routes:Q.routes.map(({scenario, amountAtomic, ...route})=>route)}});
  const input = {config, pathTrust, authorityLock, routes, environment:{...Q.environment}};
  const opened = [];
  t.after(()=>{
    for (const provider of opened) provider.close();
    authorityLock.close();
    fs.rmSync(directory, {recursive:true, force:true});
  });
  return {input, journalPath:path.join(directory,Q.journalName),
    open() {const provider=createOfflineQualificationClients(input); opened.push(provider); return provider;},
    read:()=>readOfflineQualificationJournal({databasePath:config.databasePath,pathTrust})};
}

function typedData(scenario) {
  const route = Q.routes.find(item=>item.scenario === scenario);
  return {domain:{name:'USDC', version:'2', chainId:84532, verifyingContract:getAddress(Q.asset)},
    types:authorizationTypes, primaryType:'TransferWithAuthorization', message:{
      from:getAddress(Q.walletAddress), to:getAddress(Q.payTo), value:BigInt(route.amountAtomic),
      validAfter:0n, validBefore:BigInt(Math.floor(Date.now()/1000)+60), nonce:`0x${'81'.repeat(32)}`}};
}

function request(payment = false) {
  return {method:'POST', headers:{'content-type':'application/json',
    ...(payment ? {'payment-signature':'synthetic-header-for-provider-fixture'} : {})},
    body:Buffer.from('{"qualification":true}')};
}

test('qualification rejects non-synthetic credentials, wallet configuration, routes and missing real lock before creating journal', (t) => {
  const context = fixture(t);
  for (const key of Object.keys(Q.environment)) {
    assert.throws(()=>createOfflineQualificationClients({...context.input,
      environment:{...Q.environment,[key]:'must-never-be-used-real-credential'}}), {code:'QUALIFICATION_INPUT'});
  }
  assert.throws(()=>createOfflineQualificationClients({...context.input,
    config:{...context.input.config,cdpWalletName:'other-wallet'}}), {code:'QUALIFICATION_INPUT'});
  assert.throws(()=>createOfflineQualificationClients({...context.input,
    routes:{routes:[...context.input.routes.routes.slice(1)]}}), {code:'QUALIFICATION_INPUT'});
  assert.throws(()=>createOfflineQualificationClients({...context.input, authorityLock:{close(){}}}), {code:'AUTHORITY_LOCK_REQUIRED'});
  assert.equal(fs.existsSync(context.journalPath), false);
});

test('synthetic signer and seller counts are fsynced, hash-bound, private and preserved by reopen', async (t) => {
  const context = fixture(t);
  const provider = context.open();
  const route = Q.routes.find(item=>item.scenario === 'allow');
  const challenge = await provider.clients.fetchImpl(route.upstreamUrl, request());
  assert.equal(decodePaymentRequiredHeader(challenge.headers.get('payment-required')).accepts[0].amount, '50000');
  const account = await provider.clients.cdpClient.evm.getAccount({name:Q.environment.CDP_WALLET_NAME});
  const typed = typedData('allow');
  const signature = await account.signTypedData(typed);
  assert.equal(await verifyTypedData({...typed,address:Q.walletAddress,signature}), true);
  const paid = await provider.clients.fetchImpl(route.upstreamUrl, request(true));
  assert.equal(paid.status, 200);
  assert.equal(decodePaymentResponseHeader(paid.headers.get('payment-response')).amount, '50000');
  assert.deepEqual(context.read().counters, {providerOpens:1,unpaidRequests:1,signerCalls:1,signaturesProduced:1,paidRequests:1});
  assert.equal(fs.statSync(context.journalPath).mode & 0o777, 0o600);
  const content = fs.readFileSync(context.journalPath, 'utf8');
  assert.equal(content.includes(signature), false);
  assert.equal(content.includes('synthetic-header-for-provider-fixture'), false);
  assert.equal(content.includes('{"qualification":true}'), false);
  provider.close();
  const again = context.open();
  assert.deepEqual(context.read().counters, {providerOpens:2,unpaidRequests:1,signerCalls:1,signaturesProduced:1,paidRequests:1});
  again.close();
});

test('qualification network envelope has no fetch fallback and supplies stable synthetic observer facts', async (t) => {
  const context = fixture(t);
  let networkCalls = 0;
  t.mock.method(globalThis, 'fetch', async()=>{networkCalls++; throw Error('network forbidden');});
  const {clients} = context.open();
  for (const url of ['https://seller.example/paid/allow', 'https://rpc.wallet-kernel.invalid',
    'http://127.0.0.1/paid/allow', `${Q.sellerOrigin}/paid/unknown`]) {
    await assert.rejects(clients.fetchImpl(url, request()), {code:'QUALIFICATION_INPUT'});
  }
  await assert.rejects(clients.fetchImpl(Q.routes[0].upstreamUrl, {...request(),body:Buffer.from('{}')}), {code:'QUALIFICATION_INPUT'});
  const observer = createBaseSepoliaObserver({publicClient:clients.publicClient, now:()=>new Date().toISOString()});
  assert.equal((await observer.preflight()).network, Q.network);
  assert.equal(networkCalls, 0);
});

test('approval, charged failure and unresolved responses remain distinct synthetic outcomes', async (t) => {
  const context = fixture(t);
  const {clients} = context.open();
  const approval = Q.routes.find(item=>item.scenario === 'approval');
  const challenge = await clients.fetchImpl(approval.upstreamUrl, request());
  assert.equal(decodePaymentRequiredHeader(challenge.headers.get('payment-required')).accepts[0].amount, '250000');
  const failed = Q.routes.find(item=>item.scenario === 'charged-failure');
  const response = await clients.fetchImpl(failed.upstreamUrl, request(true));
  assert.equal(response.status, 500);
  assert.equal(decodePaymentResponseHeader(response.headers.get('payment-response')).success, true);
  const unresolved = Q.routes.find(item=>item.scenario === 'payment-unresolved');
  await assert.rejects(clients.fetchImpl(unresolved.upstreamUrl, request(true)), {code:'QUALIFICATION_PAID_RESPONSE_LOST'});
  assert.equal(context.read().counters.paidRequests, 2);
});

test('signing and paid-retry interruption publish durable barriers before blocking', async (t) => {
  const context = fixture(t);
  const provider = context.open();
  const account = await provider.clients.cdpClient.evm.getAccount({name:Q.environment.CDP_WALLET_NAME});
  const signing = account.signTypedData(typedData('signing-interruption'));
  assert.equal(context.read().lastEvent.kind, 'signer_blocked');
  assert.equal(context.read().counters.signaturesProduced, 0);
  const rejectSigning = assert.rejects(signing, {code:'QUALIFICATION_CLOSED'});
  provider.close();
  await rejectSigning;
  const reopened = context.open();
  const route = Q.routes.find(item=>item.scenario === 'retry-interruption');
  const retry = reopened.clients.fetchImpl(route.upstreamUrl, request(true));
  assert.equal(context.read().lastEvent.kind, 'retry_blocked');
  assert.equal(context.read().counters.signerCalls, 1);
  assert.equal(context.read().counters.paidRequests, 1);
  const rejectRetry = assert.rejects(retry, {code:'QUALIFICATION_CLOSED'});
  reopened.close();
  await rejectRetry;
});

test('qualification refuses a torn or modified journal and never resets counts', (t) => {
  const context = fixture(t);
  context.open().close();
  const original = fs.readFileSync(context.journalPath);
  for (const contents of [Buffer.concat([original,Buffer.from('\n')]),
    Buffer.concat([original,Buffer.from('{"torn":')]), Buffer.from(original.toString().replace('provider_opened','signer_started'))]) {
    fs.writeFileSync(context.journalPath, contents);
    assert.throws(context.open, {code:'QUALIFICATION_JOURNAL'});
    assert.deepEqual(fs.readFileSync(context.journalPath), contents);
  }
});
