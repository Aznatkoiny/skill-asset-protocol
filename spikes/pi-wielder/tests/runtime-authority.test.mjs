import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { encodePaymentRequiredHeader, encodePaymentResponseHeader } from '@x402/core/http';
import { privateKeyToAccount } from 'viem/accounts';

import { createControlPlane, startControlPlane } from '../src/control-plane.mjs';
import { validateRouteMap } from '../src/config.mjs';
import { createIsolationAttestationRepository, REQUIRED_ISOLATION_PROBE_RESULTS } from '../src/agent/isolation-preflight.mjs';
import { createAgentEnrollmentRepository } from '../src/kernel/agent-enrollment.mjs';
import { acquireAuthorityLock } from '../src/kernel/authority-lock.mjs';
import { canonicalJson, sha256 } from '../src/kernel/canonical.mjs';
import { createPolicyRepository } from '../src/kernel/policy-repository.mjs';
import { loadOrCreateReceiptSigner, verifySignedReceipt } from '../src/kernel/receipt-signing.mjs';
import { recoverKernelAuthority } from '../src/kernel/recovery.mjs';
import { openKernelStore } from '../src/kernel/sqlite-store.mjs';
import { loadOrCreateOperatorToken } from '../src/operator/auth.mjs';
import { openRuntimeAuthority } from '../src/runtime/authority.mjs';
import { listenLoopback } from '../src/runtime/listeners.mjs';

const BASE_POLICY = JSON.parse(fs.readFileSync(new URL('../policies/base-sepolia.example.json', import.meta.url)));
const ACCOUNT = privateKeyToAccount(`0x${'41'.repeat(32)}`); // Synthetic offline signing only.
const WALLET = ACCOUNT.address.toLowerCase();
const CREDENTIAL = Buffer.alloc(32, 0x42);
const OPERATOR_HASH = sha256('offline operator');
const ROUTE = Object.freeze({id:'paid-infer', kind:'tool', method:'POST',
  upstreamUrl:'https://seller.example/paid/infer', resourceDescription:'offline runtime proof',
  resourceMimeType:'application/json', purposeLabel:'tool.invoke', requestContentTypes:['application/json'],
  maximumRequestBytes:262_144, maximumResponseBytes:1_048_576});
const DOCUMENT = {schemaVersion:1, routes:[ROUTE]};

function fixture(t, {isolated = false, enrolled = true, attest = false, paidStatus = 200} = {}) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'kernel-runtime-authority-'));
  fs.chmodSync(directory, 0o700);
  t.after(() => fs.rmSync(directory, {recursive:true, force:true}));
  const pathTrust = Object.freeze({mode:'deterministic', trustedAncestor:directory,
    kernelUid:process.getuid(), agentUid:process.getuid()});
  const now = () => new Date().toISOString();
  const config = Object.freeze({mode:isolated ? 'cdp-testnet' : 'deterministic',
    agentHost:'127.0.0.1', agentPort:8402, operatorHost:'127.0.0.1', operatorPort:8405,
    operatorAdminTransport:isolated ? 'unix' : 'loopback-demo', operatorSocketPath:null,
    operatorConsoleTransport:isolated ? 'socket-activated-loopback' : 'loopback-demo',
    operatorConsoleActivationName:isolated ? 'wallet-kernel-console' : null,
    databasePath:path.join(directory, 'kernel.sqlite'), receiptKeyPath:path.join(directory, 'receipt.pem'),
    operatorTokenPath:path.join(directory, 'operator.token'), policyPath:path.join(directory, 'policy.json'),
    routePath:path.join(directory, 'route.json'), enrollmentInboxPath:null, agentRunOutboxPath:null,
    trustedAncestor:directory, releaseRoot:null, releaseManifestPath:null, serviceDefinitionPath:null,
    socketDefinitionPath:null, environmentFilePath:null, evidenceRoot:null, isolationReportPath:null,
    expectedAgentUid:process.getuid() + (isolated ? 1 : 0),
    expectedAgentGid:process.getgid() + (isolated ? 1 : 0),
    cdpWalletName:'offline-runtime-wallet', network:BASE_POLICY.network, observer:isolated ? 'base-sepolia-read-only' : 'deterministic'});
  const store = openKernelStore({filePath:config.databasePath, pathTrust, now});
  createPolicyRepository(store).apply({...BASE_POLICY, wallet:WALLET}, now());
  loadOrCreateReceiptSigner(config.receiptKeyPath, {pathTrust});
  const operatorToken = loadOrCreateOperatorToken({filePath:config.operatorTokenPath, pathTrust});
  let enrollment = null;
  if (enrolled) {
    const descriptor = {schemaVersion:1, agentInstanceId:Buffer.alloc(16, 0x42).toString('base64url'),
      credentialDigest:sha256(CREDENTIAL), agentUid:String(config.expectedAgentUid), agentGid:String(config.expectedAgentGid)};
    enrollment = createAgentEnrollmentRepository({store, now}).enroll({descriptor,
      expectedDescriptorHash:sha256(canonicalJson(descriptor)), operatorIdHash:OPERATOR_HASH,
      mode:config.mode, kernelUid:process.getuid(), kernelGid:process.getgid(),
      expectedAgentUid:config.expectedAgentUid, expectedAgentGid:config.expectedAgentGid});
  }
  const release = Object.freeze(Object.fromEntries(['releaseManifestHash', 'releaseTreeHash',
    'nodeExecutableHash', 'serviceArtifactsHash', 'systemdEffectiveConfigHash', 'environmentMetadataHash']
    .map(field => [field, sha256(`synthetic ${field}`)])));
  const report = isolated && enrollment ? {...release, schemaVersion:1,
    enrollmentHash:enrollment.enrollmentHash, kernelUid:String(process.getuid()), kernelGid:String(process.getgid()),
    agentUid:String(config.expectedAgentUid), agentGid:String(config.expectedAgentGid),
    authorityMetadataHash:sha256('synthetic authority metadata'), credentialMetadataHash:sha256('synthetic credential metadata'),
    probeResults:{...REQUIRED_ISOLATION_PROBE_RESULTS}, probedAt:now(),
    expiresAt:new Date(Date.now() + 5 * 60_000).toISOString()} : null;
  const reportHash = report ? sha256(canonicalJson(report)) : null;
  if (attest) createIsolationAttestationRepository({store, now, idFactory:()=> 'isolation:offline'})
    .importCurrent({reportBytes:Buffer.from(`${canonicalJson(report)}\n`), expectedReportHash:reportHash,
      operatorIdHash:OPERATOR_HASH});
  store.close();
  const counts = {wallet:0, signing:0, seller:0, rpc:0};
  const clients = {
    cdpClient:{evm:{async getAccount() {counts.wallet++; return {
      address:WALLET, async signTypedData(input) {counts.signing++; return ACCOUNT.signTypedData(input);},
    };}}},
    publicClient:{
      async getChainId() {counts.rpc++; return 84532;},
      async getBlockNumber() {counts.rpc++; return 100n;},
      async getBlock({blockNumber}) {counts.rpc++; return {number:blockNumber, hash:`0x${'51'.repeat(32)}`, timestamp:BigInt(Math.floor(Date.now()/1000))};},
      async getTransactionReceipt() {throw Error('unexpected offline transaction lookup');},
      async readContract({functionName}) {counts.rpc++; return {name:'USDC', version:'2', decimals:6}[functionName];},
    },
    async fetchImpl(url, init) {
      counts.seller++;
      assert.equal(String(url), ROUTE.upstreamUrl);
      const headers = new Headers(init.headers);
      assert.equal(headers.has('authorization'), false, 'Agent credential is never forwarded');
      if (!headers.has('payment-signature')) return new Response(null, {status:402,
        headers:{'PAYMENT-REQUIRED':encodePaymentRequiredHeader({x402Version:2,
          resource:{url:ROUTE.upstreamUrl, description:ROUTE.resourceDescription, mimeType:ROUTE.resourceMimeType},
          accepts:[{scheme:'exact', network:BASE_POLICY.network, asset:BASE_POLICY.asset, amount:'50000',
            payTo:BASE_POLICY.sellers[0].payTo, maxTimeoutSeconds:60, extra:{name:'USDC', version:'2'}}]})}});
      return new Response(paidStatus === 200 ? '{"ok":true}' : '{"error":"synthetic provider failure"}', {status:paidStatus,
        headers:{'PAYMENT-RESPONSE':encodePaymentResponseHeader({success:true,
          transaction:`0x${'61'.repeat(32)}`, network:BASE_POLICY.network, payer:WALLET, amount:'50000'})}});
    },
  };
  const routes = validateRouteMap({document:DOCUMENT, mode:config.mode});
  const open = () => openRuntimeAuthority({config, routes, pathTrust, clients, now});
  return {config, pathTrust, now, clients, counts, open, enrollment, report, reportHash, release, operatorToken};
}

function dependenciesFor(fixture, onOpen = () => {}) {
  return {loadConfig:()=>({publicConfig:fixture.config, assertCredentialPresence() {}}),
    readRouteDocument:()=>DOCUMENT,
    acquireAuthorityLock:({role})=>acquireAuthorityLock({databasePath:fixture.config.databasePath, role, pathTrust:fixture.pathTrust}),
    openAuthority:()=> {const result=fixture.open(); onOpen(result); return result.authority;},
    recoverAuthority:recoverKernelAuthority};
}

test('runtime graph signs once, persists a charged receipt, and reads the same authority through Operator services', async (t) => {
  const context = fixture(t);
  let composed;
  const plane = await createControlPlane({env:{WALLET_KERNEL_MODE:'deterministic'},
    dependencies:dependenciesFor(context, value=>composed=value)});
  t.after(()=>plane.close());
  await composed.assertObservation();
  assert.equal(context.counts.signing, 0, 'preflight cannot sign');
  const request = () => new Request('http://127.0.0.1:8402/agent/v1/invoke/paid-infer', {method:'POST',
    headers:{authorization:`WalletKernelAgent ${CREDENTIAL.toString('base64url')}`,
      'content-type':'application/json', 'x-agent-call-id':Buffer.alloc(32,0x43).toString('base64url')}, body:'{"input":"synthetic private prompt"}'});
  const response = await plane.apps.agent.fetch(request());
  const result = await response.json();
  assert.equal(response.status, 200, JSON.stringify(result));
  assert.equal(result.status, 'completed');
  assert.equal(result.receipt.chargedAtomic, '50000');
  assert.equal(context.counts.signing, 1);
  assert.equal(context.counts.seller, 2);
  const replay = await plane.apps.agent.fetch(request());
  assert.equal(replay.status, 409);
  assert.equal((await replay.json()).status, 'completed_replay');
  assert.equal(context.counts.signing, 1);
  assert.equal(context.counts.seller, 2);
  const overview = await composed.authority.operatorReads.overview();
  assert.equal(overview.receipts.length, 1);
  assert.equal(verifySignedReceipt(overview.receipts[0], await composed.authority.operatorReads.receiptPublicKey()), true);
  assert.equal(JSON.stringify(overview).includes('synthetic private prompt'), false);
  assert.equal(JSON.stringify(overview).includes(CREDENTIAL.toString('base64url')), false);
  const operator = await plane.apps.operatorConsole.request('http://127.0.0.1:8405/operator/v1/overview',
    {headers:{authorization:`Bearer ${context.operatorToken}`}});
  assert.equal(operator.status, 200, await operator.text());
  await plane.close();
  await plane.close();
  const reopened = context.open();
  try {assert.equal((await reopened.authority.operatorReads.listReceipts()).items.length, 1);}
  finally {await reopened.authority.close();}
});

test('runtime isolation admission requires exact persisted current report and enrollment parity', async (t) => {
  const context = fixture(t, {isolated:true, attest:true});
  const composed = context.open();
  t.after(()=>composed.authority.close());
  const admission = {isolation:'verified', report:context.report, reportHash:context.reportHash,
    authorityMetadataHash:context.report.authorityMetadataHash};
  const bindings = {enrollment:context.enrollment, release:context.release};
  assert.deepEqual(composed.assertIsolation(admission, bindings), {isolation:'verified'});
  assert.throws(()=>composed.assertIsolation({...admission, authorityMetadataHash:sha256('wrong metadata')}, bindings),
    {code:'ISOLATION_BINDING_MISMATCH'});
  // A freshly valid file with the same enrollment is insufficient if it differs from stored authority.
  const changed = {...context.report, credentialMetadataHash:sha256('different credential inode')};
  assert.throws(()=>composed.assertIsolation({...admission, report:changed, reportHash:sha256(canonicalJson(changed))}, bindings),
    {code:'ISOLATION_BINDING_MISMATCH'});
  const store = composed.authority.agentAuthDependencies.store;
  store.transaction(token=>store.within(token, ({db})=>db.prepare("UPDATE isolation_attestations SET state = 'superseded', superseded_at = ?").run(context.now())));
  assert.throws(()=>composed.assertIsolation(admission, bindings), {code:'ISOLATION_BINDING_MISMATCH'});
});

test('settled provider failure retains charged receipt and reconciliation case without another signing attempt', async (t) => {
  const context = fixture(t, {paidStatus:500});
  let composed;
  const plane = await createControlPlane({env:{WALLET_KERNEL_MODE:'deterministic'},
    dependencies:dependenciesFor(context, value=>composed=value)});
  t.after(()=>plane.close());
  const request = () => new Request('http://127.0.0.1:8402/agent/v1/invoke/paid-infer', {method:'POST',
    headers:{authorization:`WalletKernelAgent ${CREDENTIAL.toString('base64url')}`,
      'content-type':'application/json', 'x-agent-call-id':Buffer.alloc(32,0x44).toString('base64url')}, body:'{}'});
  const response = await plane.apps.agent.fetch(request());
  const result = await response.json();
  assert.equal(response.status, 500, JSON.stringify(result));
  assert.equal(result.status, 'execution_failed');
  assert.equal(result.receipt.chargedAtomic, '50000');
  const replay = await plane.apps.agent.fetch(request());
  assert.equal((await replay.json()).receipt.hash, result.receipt.hash);
  assert.equal(context.counts.signing, 1);
  assert.equal(context.counts.seller, 2);
  const overview = await composed.authority.operatorReads.overview();
  assert.equal(verifySignedReceipt(overview.receipts[0], await composed.authority.operatorReads.receiptPublicKey()), true);
  assert.ok(overview.reconciliations.length > 0);
});

test('runtime refuses missing bootstrap artifacts and mismatched wallet identity before any signing', async (t) => {
  const context = fixture(t);
  context.clients.cdpClient.evm.getAccount = async()=>({address:BASE_POLICY.sellers[0].payTo});
  const composed = context.open();
  await assert.rejects(composed.assertObservation(), {code:'CDP_WALLET_IDENTITY_MISMATCH'});
  await composed.authority.close();
  assert.equal(context.counts.signing, 0);
  assert.equal(context.counts.rpc, 0);
  const prior = fs.readFileSync(context.config.receiptKeyPath);
  fs.unlinkSync(context.config.receiptKeyPath);
  assert.throws(context.open);
  assert.equal(fs.existsSync(context.config.receiptKeyPath), false, 'startup never mints a replacement key');
  fs.writeFileSync(context.config.receiptKeyPath, prior, {mode:0o600});
});

test('native listener startup failure releases opened listeners, SQLite and the authority lock', async (t) => {
  const context = fixture(t, {enrolled:false});
  let actual;
  let address;
  await assert.rejects(startControlPlane({env:{WALLET_KERNEL_MODE:'deterministic'}, dependencies:{
    ...dependenciesFor(context),
    listenOperatorConsole:async({app,host})=>{
      actual = await listenLoopback({app, host, port:0});
      address = actual.address;
      return actual;
    },
    listenAgent:async()=>{throw Error('synthetic listener failure');},
  }}), /synthetic listener failure/u);
  await assert.rejects(fetch(`http://${address.host}:${address.port}/`));
  await actual.close();
  const lock = acquireAuthorityLock({databasePath:context.config.databasePath, role:'kernel', pathTrust:context.pathTrust});
  try {const reopened=context.open(); await reopened.authority.close();}
  finally {await lock.close();}
  assert.deepEqual(context.counts, {wallet:0, signing:0, seller:0, rpc:0});
});

test('fatal native listener error closes admission synchronously and releases the whole authority', async (t) => {
  const context = fixture(t);
  const servers = [];
  const originalListen = http.Server.prototype.listen;
  t.mock.method(http.Server.prototype, 'listen', function (...args) {
    servers.push(this);
    return Reflect.apply(originalListen, this, args);
  });
  const plane = await startControlPlane({env:{WALLET_KERNEL_MODE:'deterministic'}, dependencies:{
    ...dependenciesFor(context),
    listenOperatorConsole:input=>listenLoopback({...input, port:0}),
    listenAgent:input=>listenLoopback({...input, port:0}),
  }});
  t.after(()=>plane.close());
  assert.equal(servers.length, 2);
  servers[0].emit('error', Error('synthetic-secret-bearing-native-message'));
  assert.equal(plane.health().admission, 'closed');
  assert.equal(plane.health().reasonCode, 'RUNTIME_LISTENER');
  assert.equal(JSON.stringify(plane.health()).includes('synthetic-secret'), false);
  await plane.close();
  assert.equal(servers.every(server=>server.listening === false), true);
  const lock = acquireAuthorityLock({databasePath:context.config.databasePath, role:'kernel', pathTrust:context.pathTrust});
  try {const reopened=context.open(); await reopened.authority.close();}
  finally {await lock.close();}
  assert.equal(context.counts.signing, 0);
});

test('fatal event before the listener promise resolves releases late resources and refuses readiness', async (t) => {
  const context = fixture(t, {enrolled:false});
  const servers = [];
  const originalListen = http.Server.prototype.listen;
  t.mock.method(http.Server.prototype, 'listen', function (...args) {
    servers.push(this);
    const listening = args.at(-1);
    args[args.length - 1] = () => {
      listening();
      this.emit('error', Error('synthetic-secret-before-startup-resolves'));
    };
    return Reflect.apply(originalListen, this, args);
  });
  let published = false;
  await assert.rejects(startControlPlane({env:{WALLET_KERNEL_MODE:'deterministic'}, dependencies:{
    ...dependenciesFor(context),
    listenOperatorConsole:input=>listenLoopback({...input, port:0}),
    listenAgent:input=>listenLoopback({...input, port:0}),
    publishReady:()=>{published=true;},
  }}), error=>error.code === 'RUNTIME_LISTENER' && !String(error).includes('synthetic-secret'));
  assert.equal(published, false);
  assert.equal(servers.length, 1);
  assert.equal(servers[0].listening, false);
  const lock = acquireAuthorityLock({databasePath:context.config.databasePath, role:'kernel', pathTrust:context.pathTrust});
  try {const reopened=context.open(); await reopened.authority.close();}
  finally {await lock.close();}
});
