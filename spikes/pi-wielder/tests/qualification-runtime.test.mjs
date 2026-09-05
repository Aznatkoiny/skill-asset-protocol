import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { createControlPlane } from '../src/control-plane.mjs';
import { createAgentEnrollmentRepository } from '../src/kernel/agent-enrollment.mjs';
import { acquireAuthorityLock } from '../src/kernel/authority-lock.mjs';
import { canonicalJson, sha256 } from '../src/kernel/canonical.mjs';
import { createPolicyRepository } from '../src/kernel/policy-repository.mjs';
import { loadOrCreateReceiptSigner, verifySignedReceipt } from '../src/kernel/receipt-signing.mjs';
import { recoverKernelAuthority } from '../src/kernel/recovery.mjs';
import { openKernelStore } from '../src/kernel/sqlite-store.mjs';
import { loadOrCreateOperatorToken } from '../src/operator/auth.mjs';
import { openRuntimeAuthority } from '../src/runtime/authority.mjs';
import { createOfflineQualificationClients, OFFLINE_QUALIFICATION as Q, readOfflineQualificationJournal } from '../src/runtime/qualification-clients.mjs';

const BASE_POLICY = JSON.parse(fs.readFileSync(new URL('../policies/base-sepolia.example.json', import.meta.url)));
const CREDENTIAL = Buffer.alloc(32, 0x42);
const ROUTES = {schemaVersion:1, routes:Q.routes.map(({scenario, amountAtomic, ...route})=>route)};

// This proves the closed providers through the real authority locally. It does
// not substitute for installed systemd, UID separation, or fault qualification.
function fixture(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'wallet-kernel-qualification-runtime-'));
  fs.chmodSync(directory, 0o700);
  const pathTrust = Object.freeze({mode:'deterministic', trustedAncestor:directory,
    kernelUid:process.getuid(), agentUid:process.getuid()});
  const now = () => new Date().toISOString();
  const config = Object.freeze({mode:'deterministic',
    agentHost:'127.0.0.1', agentPort:8402, operatorHost:'127.0.0.1', operatorPort:8405,
    operatorAdminTransport:'loopback-demo', operatorSocketPath:null,
    operatorConsoleTransport:'loopback-demo', operatorConsoleActivationName:null,
    databasePath:path.join(directory,'kernel.sqlite'), receiptKeyPath:path.join(directory,'receipt.pem'),
    operatorTokenPath:path.join(directory,'operator.token'), policyPath:path.join(directory,'policy.json'),
    routePath:path.join(directory,'routes.json'), trustedAncestor:directory,
    expectedAgentUid:process.getuid(), expectedAgentGid:process.getgid(),
    cdpWalletName:Q.environment.CDP_WALLET_NAME, network:Q.network, observer:'deterministic'});
  const store = openKernelStore({filePath:config.databasePath, pathTrust, now});
  createPolicyRepository(store).apply({...BASE_POLICY, wallet:Q.walletAddress,
    sellers:BASE_POLICY.sellers.map(seller=>({...seller,origin:Q.sellerOrigin}))}, now());
  loadOrCreateReceiptSigner(config.receiptKeyPath, {pathTrust});
  const operatorToken = loadOrCreateOperatorToken({filePath:config.operatorTokenPath,pathTrust});
  const descriptor = {schemaVersion:1,agentInstanceId:Buffer.alloc(16,0x42).toString('base64url'),
    credentialDigest:sha256(CREDENTIAL),agentUid:String(process.getuid()),agentGid:String(process.getgid())};
  createAgentEnrollmentRepository({store,now}).enroll({descriptor,
    expectedDescriptorHash:sha256(canonicalJson(descriptor)),operatorIdHash:sha256('qualification operator'),
    mode:'deterministic',kernelUid:process.getuid(),kernelGid:process.getgid(),
    expectedAgentUid:process.getuid(),expectedAgentGid:process.getgid()});
  store.close();
  let plane;
  let composition;
  const close = async()=>{if (plane) {await plane.close(); plane=null;}};
  t.after(async()=>{await close(); fs.rmSync(directory,{recursive:true,force:true});});
  return {
    close,
    async open() {
      let lock;
      let provider;
      plane = await createControlPlane({env:{WALLET_KERNEL_MODE:'deterministic'},dependencies:{
        loadConfig:()=>({publicConfig:config,assertCredentialPresence(){}}),
        readRouteDocument:()=>ROUTES,
        acquireAuthorityLock({role}) {
          lock=acquireAuthorityLock({databasePath:config.databasePath,role,pathTrust});
          return lock;
        },
        openAuthority({routes}) {
          provider=createOfflineQualificationClients({environment:{...Q.environment},
            config:{...config,mode:'cdp-testnet'},routes,pathTrust,authorityLock:lock});
          try {composition=openRuntimeAuthority({config,routes,pathTrust,clients:provider.clients,now});}
          catch (error) {provider.close(); throw error;}
          return Object.freeze({...composition.authority,async close() {
            try {await composition.authority.close();} finally {provider.close();}
          }});
        },
        recoverAuthority:recoverKernelAuthority,
      }});
      await composition.assertObservation();
    },
    async invoke(scenario, callByte) {
      const response = await plane.apps.agent.request(`http://127.0.0.1:8402/agent/v1/invoke/qualification-${scenario}`,{
        method:'POST',headers:{authorization:`WalletKernelAgent ${CREDENTIAL.toString('base64url')}`,
          'content-type':'application/json','x-agent-call-id':Buffer.alloc(32,callByte).toString('base64url')},
        body:'{"qualification":true}',
      });
      return {status:response.status,body:await response.json()};
    },
    async approve(approval) {
      const response=await plane.apps.operatorConsole.request(`http://127.0.0.1:8405/operator/v1/approvals/${approval.approvalId}/approve`,{
        method:'POST',headers:{authorization:`Bearer ${operatorToken}`,'content-type':'application/json'},
        body:canonicalJson({expectedIntentHash:approval.intentHash}),
      });
      return {status:response.status,body:await response.json()};
    },
    overview:()=>composition.authority.operatorReads.overview(),
    publicKey:()=>composition.authority.operatorReads.receiptPublicKey(),
    journal:()=>readOfflineQualificationJournal({databasePath:config.databasePath,pathTrust}),
  };
}

test('qualification providers produce persisted charged and unresolved receipts without another sign after reopening', async(t)=>{
  for (const [scenario,callByte,status,terminal,charge] of [
    ['allow',0x51,200,'completed','50000'],
    ['charged-failure',0x52,500,'execution_failed','60000'],
    ['payment-unresolved',0x53,503,'payment_unresolved',null],
  ]) {
    await t.test(scenario,async(t)=>{
      const context=fixture(t);
      await context.open();
      const result=await context.invoke(scenario,callByte);
      assert.equal(result.status,status,JSON.stringify(result));
      assert.equal(result.body.status,terminal,JSON.stringify(result));
      assert.equal(result.body.receipt.chargedAtomic,charge);
      const before=context.journal();
      assert.deepEqual(before.counters,{providerOpens:1,unpaidRequests:1,signerCalls:1,signaturesProduced:1,paidRequests:1});
      const overview=await context.overview();
      assert.equal(overview.receipts.length,1);
      assert.equal(verifySignedReceipt(overview.receipts[0],await context.publicKey()),true);
      assert.equal(overview.reconciliations.length,scenario==='allow'?0:1);
      await context.close();
      await context.open();
      const replay=await context.invoke(scenario,callByte);
      assert.equal(replay.body.receipt.hash,result.body.receipt.hash,JSON.stringify(replay));
      const after=context.journal();
      assert.deepEqual(after.events.slice(0,before.events.length),before.events);
      assert.deepEqual(after.counters,{...before.counters,providerOpens:2});
    });
  }
});

test('qualification approval requires the real Operator decision then signs exactly once on Agent retry',async(t)=>{
  const context=fixture(t);
  await context.open();
  const waiting=await context.invoke('approval',0x61);
  assert.equal(waiting.status,409,JSON.stringify(waiting));
  assert.equal(waiting.body.status,'payment_approval_required');
  assert.equal(context.journal().counters.signerCalls,0);
  const overview=await context.overview();
  assert.equal(overview.approvals.length,1);
  const decision=await context.approve(overview.approvals[0]);
  assert.equal(decision.status,200,JSON.stringify(decision));
  assert.equal(context.journal().counters.signerCalls,0,'Operator decision cannot execute the request');
  const completed=await context.invoke('approval',0x61);
  assert.equal(completed.status,200,JSON.stringify(completed));
  assert.equal(completed.body.receipt.chargedAtomic,'250000');
  const counters=context.journal().counters;
  assert.equal(counters.signerCalls,1);
  assert.equal(counters.paidRequests,1);
  const replay=await context.invoke('approval',0x61);
  assert.equal(replay.body.receipt.hash,completed.body.receipt.hash);
  assert.deepEqual(context.journal().counters,counters);
});
