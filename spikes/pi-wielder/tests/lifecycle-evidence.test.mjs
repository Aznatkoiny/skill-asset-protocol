import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { execFileSync } from 'node:child_process';
import { canonicalJson, sha256 } from '../src/kernel/canonical.mjs';
import { createReceiptSigner } from '../src/kernel/receipt-signing.mjs';
import { OFFLINE_QUALIFICATION as Q } from '../src/runtime/qualification-clients.mjs';
import { SERVICE_PROPERTIES, SOCKET_PROPERTIES } from '../scripts/inspect-systemd-effective.mjs';
import { LIFECYCLE_EXPECTATIONS, summarizeLifecycleEvents, verifyLifecycleEvidence } from '../scripts/verify-lifecycle-evidence.mjs';

const NOW='2026-09-05T12:00:00.000Z';
function journalSteps(steps, previous) {
  const events=structuredClone(previous?.events??[]);
  for (const [kind,scenario] of steps) {
    const routeId=scenario?`qualification-${scenario}`:null;
    const requestHash=scenario?sha256(`${kind.startsWith('signer_')?'sign':'request'}:${scenario}`):null;
    const body={sequence:events.length+1,kind,routeId,requestHash,recordedAt:NOW,previousHash:events.at(-1)?.eventHash??null};
    events.push({...body,eventHash:sha256(canonicalJson(body))});
  }
  const counts={providerOpens:'provider_opened',unpaidRequests:'unpaid_requested',signerCalls:'signer_started',
    signaturesProduced:'signer_completed',paidRequests:'paid_requested'};
  return {schemaVersion:1,profile:Q.profile,events,lastEvent:events.at(-1),
    counters:Object.fromEntries(Object.entries(counts).map(([field,kind])=>[field,events.filter(event=>event.kind===kind).length]))};
}
function paidJournal(scenario) {
  return journalSteps([['provider_opened'],...['unpaid_requested','signer_started','signer_completed','paid_requested'].map(kind=>[kind,scenario])]);
}
function signedReceipt(signer,scenario) {
  const route=Q.routes.find(value=>value.scenario===scenario);
  const failure=scenario==='charged-failure';
  const approved=scenario==='approval';
  const receipt={schemaVersion:1,receiptId:`receipt:${scenario}`,revision:1,issuedAt:NOW,
    intent:{id:`intent:${scenario}`,requestId:`request:${scenario}`,intentHash:sha256(`intent:${scenario}`),sessionId:'session:1',
      sellerOrigin:Q.sellerOrigin,resourcePath:`/paid/${scenario}`,purposeLabel:'qualification.invoke'},
    outcome:{status:failure?'execution_failed':'completed',reasonCode:failure?'UPSTREAM_HTTP_FAILURE':'PAYMENT_SETTLED'},
    policy:{versionId:'policy:1',decision:approved?'approval_required':'allow',reasonCode:approved?'HUMAN_APPROVAL_REQUIRED':'WITHIN_AUTO_LIMIT'},
    approval:{state:approved?'consumed':'not_required',operatorIdHash:approved?sha256('operator'):null},
    payment:{state:'settled',amountAtomic:route.amountAtomic,network:Q.network,asset:Q.asset,payTo:Q.payTo,transactionId:`0x${'ab'.repeat(32)}`},
    execution:{state:failure?'failed':'succeeded',httpStatus:failure?500:200,responseHash:failure?null:sha256('synthetic result')},
    budget:{disposition:'committed',amountAtomic:route.amountAtomic},reconciliation:null,
    refund:failure?{state:'pending',amountAtomic:route.amountAtomic,transactionId:null}:null,supersedesReceiptHash:null};
  const receiptHash=sha256(canonicalJson(receipt)).slice(7);
  return {id:receipt.receiptId,intentId:receipt.intent.id,revision:1,receipt,receiptHash,signature:signer.signHash(receiptHash),
    algorithm:signer.algorithm,keyId:signer.keyId,supersedesReceiptHash:null,createdAt:NOW,verified:true};
}
function holdDetails(scenario) {
  const amount=Q.routes.find(route=>route.scenario===scenario).amountAtomic;
  const intent={id:`intent:${scenario}`,requestId:`request:${scenario}`,sessionId:'session:1',routeId:`qualification-${scenario}`,
    intentHash:sha256('intent'),challengeHash:sha256('challenge'),state:'unresolved'};
  const signing=scenario==='signing-interruption';
  const payment={id:'payment:1',intentId:intent.id,state:'unresolved',paymentHash:signing?null:sha256('header'),
    signingClaimedAt:NOW,signedAt:signing?null:NOW,retryStartedAt:signing?null:NOW,reasonCode:'RECOVERY_PAYMENT_AMBIGUOUS',
    payloadHash:signing?null:sha256('payload'),headerHash:signing?null:sha256('header'),signatureHash:signing?null:sha256('signature')};
  const budget=(unresolved)=>({totals:{reservedAtomic:unresolved?'0':amount,committedAtomic:'0',releasedAtomic:'0',
    unresolvedAtomic:unresolved?amount:'0',heldAtomic:amount},reservations:[{intentId:intent.id,sessionId:intent.sessionId,
      state:unresolved?'unresolved':'reserved',reservedAtomic:unresolved?'0':amount,committedAtomic:'0',releasedAtomic:'0',
      unresolvedAtomic:unresolved?amount:'0'}]});
  return {routeId:intent.routeId,intents:[intent],payments:[payment],before:budget(scenario==='payment-unresolved'),after:budget(true)};
}
function validDetails() {
  const signer=createReceiptSigner();
  const receiptPublicKey={algorithm:signer.algorithm,keyId:signer.keyId,publicKeyPem:signer.publicKeyPem};
  const automatic=signedReceipt(signer,'allow');
  const approvedReceipt=signedReceipt(signer,'approval');
  const failed=signedReceipt(signer,'charged-failure');
  const autoJournal=paidJournal('allow');
  const approvedJournal=journalSteps([['unpaid_requested','approval']],autoJournal);
  const restartJournal=journalSteps([['provider_opened']],approvedJournal);
  const completedJournal=journalSteps(['unpaid_requested','signer_started','signer_completed','paid_requested'].map(kind=>[kind,'approval']),restartJournal);
  const hardJournal=journalSteps([['provider_opened']],completedJournal);
  const approval={id:'approval:1',approvalId:'approval:1',intentId:'intent:approval',decision:'pending',
    intentHash:sha256('intent:approval'),challengeHash:sha256('challenge'),amountCeilingAtomic:'250000',
    expiresAt:'2026-09-05T12:01:00.000Z',decidedAt:NOW,consumedAt:null};
  const accepted={...approval,decision:'approved'};
  const response=(status,body)=>({httpStatus:status,status,responseHash:sha256(canonicalJson(body)),response:body});
  const service=Object.fromEntries(SERVICE_PROPERTIES.map(key=>[key,'']));
  Object.assign(service,{User:'501',Group:'502',NoNewPrivileges:'yes',IPAddressAllow:['127.0.0.0/8','::1/128'],IPAddressDeny:['0.0.0.0/0','::/0']});
  const socket=Object.fromEntries(SOCKET_PROPERTIES.map(key=>[key,'']));
  Object.assign(socket,{Listen:'127.0.0.1:8405 (Stream)',FileDescriptorName:'wallet-kernel-console'});
  const projection={service,socket};
  const release=Object.fromEntries(['releaseManifestHash','releaseTreeHash','nodeExecutableHash','serviceArtifactsHash',
    'systemdEffectiveConfigHash','environmentMetadataHash'].map(field=>[field,sha256(`fixture ${field}`)]));
  release.systemdEffectiveConfigHash=sha256(`wallet-kernel/systemd-effective/v1\0${canonicalJson(projection)}`);
  const stoppedService={ActiveState:'failed',SubState:'failed',MainPID:'0',NRestarts:'0',Job:'',UnitFileState:'static',Result:'exit-code'};
  const stoppedSocket={ActiveState:'inactive',SubState:'dead',Job:'',UnitFileState:'disabled'};
  const probes=expected=>({passed:true,probes:Object.fromEntries(Object.entries(expected).map(([name,allowed])=>[
    name,{result:allowed[0],expected:allowed,passed:true}]))});
  const details={
    'install.pid1Bound':{release,systemd:{platform:'linux',managerVersion:'255',systemctlVersion:'systemd 255',
      systemctlExecutablePathHash:sha256('systemctl path'),systemctlExecutableSha256:sha256('systemctl'),
      effectiveConfigHash:release.systemdEffectiveConfigHash,projection}},
    'startup.confinement':{uid:'501',gid:'502',status:['Uid:\t501\t501\t501\t501','Gid:\t502\t502\t502\t502','Groups:\t502',
      ...['CapInh','CapPrm','CapEff','CapBnd','CapAmb'].map(name=>`${name}:\t0000000000000000`),'NoNewPrivs:\t1']},
    'startup.inheritedSocket':{descriptor:'socket:[123]',rows:[['0:','0100007F:20D5','00000000:0000','0A','0','0','0','501','0','123']]},
    'isolation.agent':probes({authorityDirectoryRead:['EACCES'],databaseRead:['EACCES'],receiptKeyRead:['EACCES'],operatorTokenRead:['EACCES'],
      environmentSourceRead:['EACCES'],evidenceDirectoryRead:['EACCES'],authorityDirectoryWrite:['EACCES','EROFS'],releaseDirectoryWrite:['EACCES','EROFS'],
      evidenceDirectoryWrite:['EACCES','EROFS'],outboxWrite:['EACCES','EROFS'],outboxRead:['READABLE'],inboxWrite:['WRITABLE'],deliveredCredentialRead:['EACCES']}),
    'isolation.kernel':probes({agentCredentialRead:['EACCES'],enrollmentRead:['READABLE'],inboxWrite:['EACCES','EROFS'],environmentSourceRead:['EACCES']}),
    'automatic.status':response(200,{status:'completed',requestId:automatic.receipt.intent.requestId}),
    'automatic.signerCalls':autoJournal.counters,
    'automatic.receiptVerified':{receiptPublicKey,receipts:[automatic]},
    'approval.pending':{response:response(409,{status:'payment_approval_required'}),approvals:[approval],counters:approvedJournal.counters},
    'approval.approved':{response:response(200,{ok:true}),approvals:[accepted],counters:approvedJournal.counters},
    'restart.changedPid':{before:'1000',after:'1001'},
    'restart.approvalPreserved':{before:[accepted],after:[accepted]},
    'restart.noSignature':{before:approvedJournal,after:restartJournal},
    'approval.retryStatus':response(200,{status:'completed',requestId:approvedReceipt.receipt.intent.requestId}),
    'approval.receiptVerified':{receiptPublicKey,receipts:[automatic,approvedReceipt]},
    'replay.noDoubleSigning':{before:completedJournal,after:completedJournal},
    'hardRestart.receiptsPreserved':{receiptPublicKey,before:[automatic,approvedReceipt],after:[automatic,approvedReceipt]},
    'hardRestart.noDoubleSigning':{before:completedJournal,after:hardJournal},
    'retryInterruption.signaturePreserved':{before:[sha256('signature')],after:[sha256('signature')]},
    'chargedFailure.receiptPreserved':{receiptPublicKey,before:[failed],after:[failed]},
    'cleanup.serviceStopped':stoppedService,'cleanup.socketDisabled':stoppedSocket,
  };
  for (const name of ['reject.staleAttestation','reject.releaseChange','reject.pid1Change','reject.cdpProfile']) {
    details[name]={state:{service:stoppedService,socket:stoppedSocket},before:hardJournal,after:hardJournal};
  }
  details['reject.staleAttestation'].attestation={reportHash:sha256('report'),probedAt:'2026-09-05T11:59:50.000Z',
    importedAt:'2026-09-05T11:59:51.000Z',expiresAt:'2026-09-05T11:59:58.000Z',rejectedAt:NOW};
  for (const [prefix,scenario] of [['signingInterruption','signing-interruption'],['retryInterruption','retry-interruption'],
    ['unresolved','payment-unresolved'],['chargedFailure','charged-failure']]) {
    let before=scenario==='signing-interruption'?journalSteps([['provider_opened'],['unpaid_requested',scenario],['signer_started',scenario],['signer_blocked',scenario]]):paidJournal(scenario);
    if (scenario==='retry-interruption') before=journalSteps([['retry_blocked',scenario]],before);
    details[`${prefix}.noDoubleSigning`]={before,after:journalSteps([['provider_opened']],before)};
    if (prefix!=='chargedFailure') details[`${prefix}.holdPreserved`]=holdDetails(scenario);
  }
  return {details,release};
}

function fixture(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'lifecycle-evidence-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const events = [];
  const {details,release}=validDetails();
  for (const [name, actual] of Object.entries(LIFECYCLE_EXPECTATIONS)) {
    const body = { sequence: events.length + 1, name, actual, details: structuredClone(details[name]??null),
      observedAt: '2026-09-05T12:00:00.000Z', previousHash: events.at(-1)?.eventHash ?? null };
    events.push({ ...body, eventHash: sha256(canonicalJson(body)) });
  }
  const commit = 'a'.repeat(40);
  const write = (name, value) => fs.writeFileSync(path.join(directory, name), `${canonicalJson(value)}\n`);
  const seal = () => {
    const eventBytes = Buffer.from(events.map((event) => `${canonicalJson(event)}\n`).join(''));
    fs.writeFileSync(path.join(directory, 'events.jsonl'), eventBytes);
    write('summary.json', summarizeLifecycleEvents(events));
    write('manifest.json', { schemaVersion: 1, commit, scope: 'installed-offline-qualification',
      executionProfile: 'offline-qualification', nodeVersion: 'v24.18.1', nodeExecutableHash: release.nodeExecutableHash,
      hostKernel:'6.8.0-synthetic-fixture',hostArchitecture:'x64',release,failure:null,publicRelease:'not-qualified',
      liveCdp: 'not-run', testnetTransaction: 'not-run', eventsHash: sha256(eventBytes),
      summaryHash: sha256(fs.readFileSync(path.join(directory, 'summary.json'))) });
  };
  const rehash=()=>{
    for (let index=0;index<events.length;index++) {
      const {eventHash,...body}=events[index];
      body.sequence=index+1; body.previousHash=events[index-1]?.eventHash??null;
      events[index]={...body,eventHash:sha256(canonicalJson(body))};
    }
  };
  return { directory, events, commit, seal, write, rehash };
}

test('complete canonical lifecycle artifact recomputes without promoting its scope to live evidence', (t) => {
  const f = fixture(t); f.seal();
  assert.deepEqual(summarizeLifecycleEvents(f.events).failed,[]);
  const result = verifyLifecycleEvidence(f.directory, f.commit);
  assert.equal(result.valid, true); assert.equal(result.checks, Object.keys(LIFECYCLE_EXPECTATIONS).length);
  assert.equal(result.liveCdp, 'not-run'); assert.equal(result.publicRelease, 'not-qualified');
  assert.throws(() => verifyLifecycleEvidence(f.directory, 'b'.repeat(40)));
});

test('missing or failed host checks cannot be relabeled as a successful qualification', (t) => {
  const f = fixture(t); f.events.pop(); f.seal();
  assert.throws(() => verifyLifecycleEvidence(f.directory, f.commit));
  const summary = JSON.parse(fs.readFileSync(path.join(f.directory, 'summary.json')));
  assert.equal(summary.valid, false); assert.deepEqual(summary.missing, ['cleanup.listenersClosed']);
  const g = fixture(t);
  const first = { ...g.events[0], actual: 'darwin' }; delete first.eventHash;
  g.events[0] = { ...first, eventHash: sha256(canonicalJson(first)) };
  for (let index = 1; index < g.events.length; index++) {
    const { eventHash, ...body } = g.events[index]; body.previousHash = g.events[index - 1].eventHash;
    g.events[index] = { ...body, eventHash: sha256(canonicalJson(body)) };
  }
  g.seal(); assert.throws(() => verifyLifecycleEvidence(g.directory, g.commit));
});

test('event tampering, duplicate coverage, manifest drift, and summary edits are rejected', (t) => {
  for (const mutate of [
    (f) => fs.appendFileSync(path.join(f.directory, 'events.jsonl'), `${canonicalJson(f.events[0])}\n`),
    (f) => f.write('summary.json', { valid: true }),
    (f) => { const manifest = JSON.parse(fs.readFileSync(path.join(f.directory, 'manifest.json'))); manifest.liveCdp = 'verified'; f.write('manifest.json', manifest); },
    (f) => { const value = fs.readFileSync(path.join(f.directory, 'events.jsonl'), 'utf8'); fs.writeFileSync(path.join(f.directory, 'events.jsonl'), value.replace('systemd', 'fake-pid1')); },
  ]) { const f = fixture(t); f.seal(); mutate(f); assert.throws(() => verifyLifecycleEvidence(f.directory, f.commit)); }
});

test('a complete success manifest must retain its exact release binding and an explicit absence of failure', (t)=>{
  for (const mutate of [
    manifest=>{delete manifest.failure;},manifest=>{manifest.failure={stage:'cleanup',code:'QUALIFICATION_FAILED'};},
    manifest=>{delete manifest.release;},manifest=>{manifest.release=null;},
    manifest=>{delete manifest.release.environmentMetadataHash;},
    manifest=>{manifest.release.releaseManifestHash='not-a-hash';},
    manifest=>{manifest.release.releaseTreeHash=sha256('different release');},
    manifest=>{manifest.nodeExecutableHash=sha256('different runtime');},
    manifest=>{delete manifest.publicRelease;},manifest=>{manifest.publicRelease='qualified';},
    manifest=>{delete manifest.hostKernel;},manifest=>{manifest.hostArchitecture='unknown';},
    manifest=>{manifest.unrecognizedApproval=true;},
  ]) {
    const f=fixture(t); f.seal();
    const manifest=JSON.parse(fs.readFileSync(path.join(f.directory,'manifest.json')));
    mutate(manifest); f.write('manifest.json',manifest);
    assert.throws(()=>verifyLifecycleEvidence(f.directory,f.commit));
  }
});

test('recomputed hashes and true flags cannot conceal missing or contradictory case evidence', (t)=>{
  for (const [name,mutate] of [
    ['automatic.receiptVerified',event=>{event.details=null;}],
    ['automatic.status',event=>{event.details.httpStatus=500;}],
    ['startup.confinement',event=>{event.details.status=event.details.status.map(line=>line.replace('CapEff:\t0000000000000000','CapEff:\t0000000000000001'));}],
    ['startup.inheritedSocket',event=>{event.details.rows[0][9]='124';}],
    ['isolation.agent',event=>{event.details.probes.deliveredCredentialRead={result:'READABLE',expected:['READABLE'],passed:true};}],
    ['isolation.kernel',event=>{delete event.details.probes.agentCredentialRead;}],
    ['approval.approved',event=>{event.details.approvals[0].decision='pending';}],
    ['restart.changedPid',event=>{event.details.after=event.details.before;}],
    ['restart.approvalPreserved',event=>{event.details.after=[];}],
    ['reject.staleAttestation',event=>{event.details.attestation.importedAt=event.details.attestation.expiresAt;}],
    ['reject.pid1Change',event=>{event.details.state.service.MainPID='4123';}],
    ['unresolved.holdPreserved',event=>{event.details.after.totals.unresolvedAtomic='0';}],
    ['retryInterruption.holdPreserved',event=>{event.details.payments[0].intentId='intent:unrelated';}],
    ['signingInterruption.holdPreserved',event=>{event.details.payments[0].signatureHash=sha256('unretained signature');}],
    ['cleanup.socketDisabled',event=>{event.details.UnitFileState='enabled';}],
  ]) {
    const f=fixture(t); mutate(f.events.find(event=>event.name===name)); f.rehash(); f.seal();
    assert.ok(summarizeLifecycleEvents(f.events).failed.includes(name),name);
    assert.throws(()=>verifyLifecycleEvidence(f.directory,f.commit),name);
  }
  const f=fixture(t); for (const event of f.events) event.details=null; f.rehash(); f.seal();
  assert.throws(()=>verifyLifecycleEvidence(f.directory,f.commit),'the old detail-free success fixture is incomplete');
});

test('retained receipts require valid Ed25519 signatures and the exact charged-failure meaning', (t)=>{
  for (const mutate of [
    details=>{for (const field of ['before','after']) details[field][0].signature=Buffer.alloc(64).toString('base64');},
    details=>{for (const field of ['before','after']) details[field][0].receipt.payment.amountAtomic='1';},
    details=>{delete details.receiptPublicKey;},
    details=>{details.receiptPublicKey.keyId=sha256('wrong key');},
    details=>{
      const signer=createReceiptSigner();
      details.receiptPublicKey={algorithm:signer.algorithm,keyId:signer.keyId,publicKeyPem:signer.publicKeyPem};
      details.before=[signedReceipt(signer,'allow')];details.after=structuredClone(details.before);
    },
  ]) {
    const f=fixture(t); const event=f.events.find(event=>event.name==='chargedFailure.receiptPreserved');
    mutate(event.details); f.rehash(); f.seal();
    assert.ok(summarizeLifecycleEvents(f.events).failed.includes(event.name));
    assert.throws(()=>verifyLifecycleEvidence(f.directory,f.commit));
  }
});

test('journal counters are recomputed and restart evidence must preserve the complete existing prefix', (t)=>{
  for (const mutate of [
    details=>{details.after.counters.signerCalls=1;},
    details=>{details.after.events[0].eventHash=sha256('forged head');},
    details=>{details.after=journalSteps([['provider_opened']],paidJournal('allow'));},
    details=>{details.after=structuredClone(details.before);},
  ]) {
    const f=fixture(t); const event=f.events.find(event=>event.name==='hardRestart.noDoubleSigning');
    mutate(event.details); f.rehash(); f.seal();
    assert.ok(summarizeLifecycleEvents(f.events).failed.includes(event.name));
    assert.throws(()=>verifyLifecycleEvidence(f.directory,f.commit));
  }
});

test('events must be one bounded canonical regular file, with no symlinks, hard links, or trailing records', (t)=>{
  for (const mutate of [
    (file,f)=>{fs.unlinkSync(file);fs.symlinkSync(path.join(f.directory,'summary.json'),file);},
    (file,f)=>{fs.linkSync(file,path.join(f.directory,'linked-events'));},
    file=>fs.appendFileSync(file,'\n'),
    file=>fs.truncateSync(file,4*1024*1024+1),
    file=>{fs.unlinkSync(file);fs.mkdirSync(file);},
  ]) {
    const f=fixture(t); f.seal(); mutate(path.join(f.directory,'events.jsonl'),f);
    assert.throws(()=>verifyLifecycleEvidence(f.directory,f.commit));
  }
});

test('FIFO artifacts and a regular-file-to-FIFO replacement fail without waiting for a writer',
  {skip:process.platform!=='linux'},(t)=>{
    const f=fixture(t); f.seal(); const target=path.join(f.directory,'events.jsonl');
    const originalOpen=fs.openSync;
    let replaced=false;
    t.mock.method(fs,'openSync',function(file,...args){
      if (file===target && !replaced) {
        replaced=true;fs.unlinkSync(target);execFileSync('/usr/bin/mkfifo',[target]);
      }
      return Reflect.apply(originalOpen,fs,[file,...args]);
    });
    assert.throws(()=>verifyLifecycleEvidence(f.directory,f.commit));
    assert.equal(replaced,true);
    assert.throws(()=>verifyLifecycleEvidence(f.directory,f.commit));
  });
