#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalJson, exactRecord, sha256 } from '../src/kernel/canonical.mjs';
import { createSignedReceiptRepository } from '../src/kernel/signed-receipts.mjs';
import { assertServiceConfinement } from '../src/runtime/installed-service.mjs';
import { OFFLINE_QUALIFICATION as Q } from '../src/runtime/qualification-clients.mjs';
import { SERVICE_PROPERTIES, SOCKET_PROPERTIES } from './inspect-systemd-effective.mjs';

export const LIFECYCLE_EXPECTATIONS = Object.freeze({
  'host.platform': 'linux', 'host.pid1': 'systemd', 'host.node': 'v24.18.1',
  'install.execution': 'installed', 'install.status': 'sealed_not_started',
  'install.serviceStopped': true, 'install.pid1Bound': true,
  'startup.active': 'active', 'startup.confinement': true, 'startup.inheritedSocket': true,
  'isolation.agent': true, 'isolation.kernel': true,
  'automatic.status': 200, 'automatic.signerCalls': 1, 'automatic.receiptVerified': true,
  'approval.pending': true, 'approval.approved': true,
  'restart.changedPid': true, 'restart.approvalPreserved': true, 'restart.noSignature': true,
  'approval.retryStatus': 200, 'approval.receiptVerified': true,
  'replay.noDoubleSigning': true,
  'hardRestart.staleSocketPresent': true, 'hardRestart.socketRecovered': true,
  'hardRestart.receiptsPreserved': true, 'hardRestart.noDoubleSigning': true,
  'reject.staleAttestation': true, 'reject.releaseChange': true,
  'reject.pid1Change': true, 'reject.cdpProfile': true,
  'signingInterruption.holdPreserved': true, 'signingInterruption.noDoubleSigning': true,
  'retryInterruption.holdPreserved': true, 'retryInterruption.signaturePreserved': true,
  'retryInterruption.noDoubleSigning': true,
  'unresolved.holdPreserved': true, 'unresolved.noDoubleSigning': true,
  'chargedFailure.receiptPreserved': true, 'chargedFailure.noDoubleSigning': true,
  'cleanup.serviceStopped': true, 'cleanup.socketDisabled': true, 'cleanup.listenersClosed': true,
});

function fail() { throw new Error('LIFECYCLE_EVIDENCE_INVALID'); }
const HASH = /^sha256:[0-9a-f]{64}$/u;
const TOKEN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$/u;
const RELEASE_FIELDS = ['releaseManifestHash', 'releaseTreeHash', 'nodeExecutableHash',
  'serviceArtifactsHash', 'systemdEffectiveConfigHash', 'environmentMetadataHash'];
const COUNTER_FIELDS = ['providerOpens', 'unpaidRequests', 'signerCalls', 'signaturesProduced', 'paidRequests'];
const EVENT_COUNTERS = {provider_opened:'providerOpens', unpaid_requested:'unpaidRequests',
  signer_started:'signerCalls', signer_completed:'signaturesProduced', paid_requested:'paidRequests',
  signer_blocked:null, retry_blocked:null};
const record = (value, fields, optional = []) => exactRecord(value, fields, optional,
  'LIFECYCLE_EVIDENCE_INVALID', 'lifecycle evidence');
const same = (left, right) => canonicalJson(left) === canonicalJson(right);
const timestamp = (value) => typeof value === 'string' && new Date(value).toISOString() === value;
const atomic = (value) => typeof value === 'string' && /^(0|[1-9][0-9]{0,77})$/u.test(value);
const list = (value, maximum = 512) => Array.isArray(value) && value.length <= maximum;

function boundedFile(filePath, maximumBytes) {
  const named = fs.lstatSync(filePath, {bigint:true});
  if (!named.isFile() || named.nlink !== 1n || named.size < 1n || named.size > BigInt(maximumBytes)) fail();
  // O_NONBLOCK prevents a regular-file-to-FIFO race from hanging the verifier;
  // O_NOFOLLOW and descriptor/path parity refuse symlinks and replacements.
  const descriptor = fs.openSync(filePath, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
  try {
    const parity = () => {
      const held = fs.fstatSync(descriptor, {bigint:true});
      const current = fs.lstatSync(filePath, {bigint:true});
      if (!held.isFile() || !current.isFile()
          || ['dev','ino','mode','uid','gid','nlink','size','mtimeNs','ctimeNs']
            .some(field=>held[field] !== named[field] || current[field] !== named[field])) fail();
    };
    parity();
    const bytes = Buffer.alloc(Number(named.size));
    let offset = 0;
    while (offset < bytes.length) {
      const read = fs.readSync(descriptor, bytes, offset, bytes.length-offset);
      if (read === 0) fail();
      offset += read;
    }
    if (fs.readSync(descriptor, Buffer.alloc(1), 0, 1) !== 0) fail();
    parity();
    if (!Buffer.from(bytes.toString('utf8')).equals(bytes)) fail();
    return bytes;
  } finally {fs.closeSync(descriptor);}
}

function canonicalFile(filePath, maximumBytes) {
  const bytes = boundedFile(filePath, maximumBytes);
  const value = JSON.parse(bytes.toString('utf8'));
  if (!bytes.equals(Buffer.from(`${canonicalJson(value)}\n`))) fail();
  return { bytes, value };
}

function releaseBinding(value) {
  const release = record(value, RELEASE_FIELDS);
  if (RELEASE_FIELDS.some(field=>typeof release[field] !== 'string' || !HASH.test(release[field]))) fail();
  return release;
}

function counters(value) {
  const result = record(value, COUNTER_FIELDS);
  if (COUNTER_FIELDS.some(field=>!Number.isSafeInteger(result[field]) || result[field] < 0 || result[field] > 512)
      || result.signaturesProduced > result.signerCalls) fail();
  return result;
}

function journal(value) {
  const result = record(value, ['schemaVersion','profile','counters','lastEvent','events']);
  if (result.schemaVersion !== 1 || result.profile !== Q.profile || !list(result.events)
      || result.events.length === 0) fail();
  const counted = Object.fromEntries(COUNTER_FIELDS.map(field=>[field,0]));
  let previousHash = null;
  const signerClaims = new Set();
  const completed = new Set();
  for (const [index, input] of result.events.entries()) {
    const event = record(input, ['sequence','kind','routeId','requestHash','recordedAt','previousHash','eventHash']);
    const {eventHash,...body} = event;
    if (event.sequence !== index+1 || event.previousHash !== previousHash
        || !Object.hasOwn(EVENT_COUNTERS,event.kind) || !timestamp(event.recordedAt)
        || eventHash !== sha256(canonicalJson(body)) || (index === 0 && event.kind !== 'provider_opened')) fail();
    if (event.kind === 'provider_opened') {
      if (event.routeId !== null || event.requestHash !== null) fail();
    } else if (!Q.routes.some(route=>route.id === event.routeId) || !HASH.test(event.requestHash)) fail();
    const claim = `${event.routeId}:${event.requestHash}`;
    if (event.kind === 'signer_started') {
      if (signerClaims.has(claim)) fail();
      signerClaims.add(claim);
    }
    if (event.kind === 'signer_completed') {
      if (!signerClaims.has(claim) || completed.has(claim)) fail();
      completed.add(claim);
    }
    if (event.kind === 'signer_blocked' && (!signerClaims.has(claim)
        || event.routeId !== 'qualification-signing-interruption')) fail();
    if (event.kind === 'retry_blocked' && (event.routeId !== 'qualification-retry-interruption'
        || result.events[index-1]?.kind !== 'paid_requested'
        || result.events[index-1]?.requestHash !== event.requestHash)) fail();
    if (EVENT_COUNTERS[event.kind]) counted[EVENT_COUNTERS[event.kind]]++;
    previousHash = eventHash;
  }
  if (!same(counters(result.counters),counted) || !same(result.lastEvent,result.events.at(-1))) fail();
  return result;
}

function journalPair(details, opens) {
  const input = record(details,['before','after']);
  const before = journal(input.before);
  const after = journal(input.after);
  if (before.events.length > after.events.length || !same(before.events,after.events.slice(0,before.events.length))
      || COUNTER_FIELDS.some(field=>after.counters[field] !== before.counters[field] + (field === 'providerOpens' ? opens : 0))) fail();
  return {before,after};
}

function receiptSet(publicKey, values) {
  const key = record(publicKey,['algorithm','keyId','publicKeyPem']);
  if (key.algorithm !== 'Ed25519' || !HASH.test(key.keyId) || typeof key.publicKeyPem !== 'string'
      || Buffer.byteLength(key.publicKeyPem) > 4096 || !list(values,20) || values.length === 0) fail();
  const readonly = () => fail();
  const verifier = createSignedReceiptRepository({store:{transaction:readonly,within:readonly},
    signer:{...key,signHash:readonly},idFactory:readonly,now:readonly});
  const ids = new Set();
  for (const value of values) {
    const {verified,...bundle} = record(value,['id','intentId','revision','receipt','receiptHash','signature',
      'algorithm','keyId','supersedesReceiptHash','createdAt','verified']);
    if (verified !== true || !verifier.verify(bundle) || ids.has(bundle.id)) fail();
    ids.add(bundle.id);
    const receipt = bundle.receipt;
    const route = Q.routes.find(candidate=>new URL(candidate.upstreamUrl).pathname === receipt.intent.resourcePath);
    if (!route || receipt.intent.sellerOrigin !== Q.sellerOrigin || receipt.intent.purposeLabel !== 'qualification.invoke'
        || receipt.payment.state !== 'settled' || receipt.payment.amountAtomic !== route.amountAtomic
        || receipt.payment.asset !== Q.asset || receipt.payment.network !== Q.network || receipt.payment.payTo !== Q.payTo
        || receipt.budget?.disposition !== 'committed' || receipt.budget.amountAtomic !== route.amountAtomic) fail();
  }
  return values;
}

function paidReceiptDetails(details, scenarios, preserved = false) {
  const value = record(details,preserved ? ['receiptPublicKey','before','after'] : ['receiptPublicKey','receipts']);
  const receipts = receiptSet(value.receiptPublicKey,preserved ? value.after : value.receipts);
  if (preserved) {
    receiptSet(value.receiptPublicKey,value.before);
    if (!same(value.before,value.after)) fail();
  }
  if (receipts.length !== scenarios.length) fail();
  for (const scenario of scenarios) {
    const matches = receipts.filter(bundle=>bundle.receipt.intent.resourcePath === `/paid/${scenario}`);
    if (matches.length !== 1) fail();
    const receipt = matches[0].receipt;
    const failed = scenario === 'charged-failure';
    if (receipt.outcome.status !== (failed ? 'execution_failed' : 'completed')
        || receipt.execution.state !== (failed ? 'failed' : 'succeeded')
        || receipt.execution.httpStatus !== (failed ? 500 : 200)
        || (scenario === 'approval' && receipt.approval.state !== 'consumed')) fail();
  }
  return true;
}

function approvals(value) {
  if (!list(value,20) || value.length === 0) fail();
  const seen = new Set();
  for (const input of value) {
    const entry = record(input,['id','intentId','decision','intentHash','challengeHash','amountCeilingAtomic',
      'expiresAt','decidedAt','consumedAt','approvalId']);
    if (!TOKEN.test(entry.id) || entry.approvalId !== entry.id || !TOKEN.test(entry.intentId)
        || seen.has(entry.id) || !HASH.test(entry.intentHash) || !HASH.test(entry.challengeHash)
        || !atomic(entry.amountCeilingAtomic) || !timestamp(entry.expiresAt)
        || (entry.decidedAt !== null && !timestamp(entry.decidedAt))
        || (entry.consumedAt !== null && !timestamp(entry.consumedAt))
        || !['pending','approved','consumed'].includes(entry.decision)) fail();
    seen.add(entry.id);
  }
  return value;
}

function response(value, status, outcome) {
  const input = record(value,['httpStatus','responseHash','response','status']);
  return input.httpStatus === status && input.status === status && HASH.test(input.responseHash)
    && input.response && typeof input.response === 'object'
    && (outcome === null ? input.response.ok === true : input.response.status === outcome);
}

const SERVICE_STATE = ['ActiveState','SubState','MainPID','NRestarts','Job','UnitFileState','Result'];
const SOCKET_STATE = ['ActiveState','SubState','Job','UnitFileState'];
function stopped(details) {
  const value = record(details,['service','socket']);
  const service = record(value.service,SERVICE_STATE);
  const socket = record(value.socket,SOCKET_STATE);
  return ['inactive','failed'].includes(service.ActiveState) && service.MainPID === '0' && service.Job === ''
    && socket.ActiveState === 'inactive' && socket.Job === '' && socket.UnitFileState === 'disabled';
}

function budget(value) {
  const input = record(value,['totals','reservations']);
  const fields = ['reservedAtomic','committedAtomic','releasedAtomic','unresolvedAtomic'];
  const totals = record(input.totals,[...fields,'heldAtomic']);
  if (!list(input.reservations,20) || input.reservations.length !== 1) fail();
  const row = record(input.reservations[0],['intentId','sessionId','state',...fields]);
  if (!TOKEN.test(row.intentId) || !TOKEN.test(row.sessionId)
      || fields.some(field=>!atomic(row[field]) || totals[field] !== row[field])
      || totals.heldAtomic !== (BigInt(row.reservedAtomic)+BigInt(row.unresolvedAtomic)).toString()) fail();
  return input;
}

function retainedHold(details, scenario) {
  const input = record(details,['routeId','intents','payments','before','after']);
  const route = Q.routes.find(value=>value.scenario === scenario);
  if (input.routeId !== route.id || !list(input.intents,1) || input.intents.length !== 1
      || !list(input.payments,1) || input.payments.length !== 1) fail();
  const intent = record(input.intents[0],['id','requestId','sessionId','routeId','intentHash','challengeHash','state']);
  const payment = record(input.payments[0],['id','intentId','state','paymentHash','signingClaimedAt','signedAt',
    'retryStartedAt','reasonCode','payloadHash','headerHash','signatureHash']);
  const before = budget(input.before);
  const after = budget(input.after);
  if (intent.routeId !== route.id || intent.state !== 'unresolved' || !HASH.test(intent.intentHash)
      || !HASH.test(intent.challengeHash) || !TOKEN.test(intent.id) || !TOKEN.test(intent.requestId)
      || payment.intentId !== intent.id || payment.state !== 'unresolved' || !TOKEN.test(payment.id)
      || !timestamp(payment.signingClaimedAt)
      || before.reservations[0].intentId !== intent.id || after.reservations[0].intentId !== intent.id
      || before.reservations[0].sessionId !== intent.sessionId || after.reservations[0].sessionId !== intent.sessionId
      || before.totals.heldAtomic !== route.amountAtomic || after.totals.heldAtomic !== route.amountAtomic
      || after.totals.unresolvedAtomic !== route.amountAtomic || after.totals.reservedAtomic !== '0'
      || after.totals.committedAtomic !== '0' || after.totals.releasedAtomic !== '0'
      || after.reservations[0].state !== 'unresolved') fail();
  if (scenario === 'signing-interruption') {
    if (['signedAt','retryStartedAt','paymentHash','payloadHash','headerHash','signatureHash'].some(field=>payment[field] !== null)) fail();
  } else if (!timestamp(payment.signedAt) || !timestamp(payment.retryStartedAt)
      || ['paymentHash','payloadHash','headerHash','signatureHash'].some(field=>!HASH.test(payment[field]))
      || payment.paymentHash !== payment.headerHash) fail();
  return true;
}

function semanticEvidence(name, details, all) {
  if (['host.platform','host.pid1','host.node','install.execution','install.status','install.serviceStopped',
    'startup.active','hardRestart.staleSocketPresent','hardRestart.socketRecovered','cleanup.listenersClosed'].includes(name)) {
    return details === null;
  }
  if (name === 'install.pid1Bound') {
    const value=record(details,['systemd','release']);
    const release=releaseBinding(value.release);
    const systemd=record(value.systemd,['platform','managerVersion','systemctlVersion',
      'systemctlExecutablePathHash','systemctlExecutableSha256','effectiveConfigHash','projection']);
    const projection=record(systemd.projection,['service','socket']);
    const service=record(projection.service,SERVICE_PROPERTIES);
    const socket=record(projection.socket,SOCKET_PROPERTIES);
    return systemd.platform === 'linux' && [systemd.managerVersion,systemd.systemctlVersion]
      .every(value=>typeof value === 'string' && value.length>0 && value.length<=256 && !/[\r\n\0]/u.test(value))
      && HASH.test(systemd.systemctlExecutablePathHash) && HASH.test(systemd.systemctlExecutableSha256)
      && systemd.effectiveConfigHash === sha256(`wallet-kernel/systemd-effective/v1\0${canonicalJson(projection)}`)
      && release.systemdEffectiveConfigHash === systemd.effectiveConfigHash
      && same(service.IPAddressAllow,['127.0.0.0/8','::1/128']) && same(service.IPAddressDeny,['0.0.0.0/0','::/0'])
      && service.NoNewPrivileges === 'yes' && service.CapabilityBoundingSet === '' && service.AmbientCapabilities === ''
      && service.User === all.get('startup.confinement')?.details?.uid
      && service.Group === all.get('startup.confinement')?.details?.gid
      && socket.Listen === '127.0.0.1:8405 (Stream)' && socket.FileDescriptorName === 'wallet-kernel-console';
  }
  if (name === 'startup.confinement') {
    const value=record(details,['uid','gid','status']);
    if (!/^[1-9][0-9]{0,9}$/u.test(value.uid) || !/^[1-9][0-9]{0,9}$/u.test(value.gid)
        || !list(value.status,12) || value.status.some(line=>typeof line !== 'string' || /[\r\n\0]/u.test(line))) fail();
    const status=value.status.join('\n');
    assertServiceConfinement(status);
    for (const [field,expected] of [['Uid',value.uid],['Gid',value.gid]]) {
      const lines=value.status.filter(line=>line.startsWith(`${field}:`));
      if (lines.length !== 1 || !same(lines[0].split(':')[1].trim().split(/\s+/u),[expected,expected,expected,expected])) fail();
    }
    const groups=value.status.filter(line=>line.startsWith('Groups:'));
    return groups.length === 1 && groups[0].slice(7).trim().split(/\s+/u).filter(Boolean).every(group=>group===value.gid);
  }
  if (name === 'startup.inheritedSocket') {
    const value=record(details,['descriptor','rows']);
    const inode=typeof value.descriptor === 'string' ? value.descriptor.match(/^socket:\[([1-9][0-9]*)\]$/u)?.[1] : null;
    return inode !== null && inode !== undefined && list(value.rows,1) && value.rows.length === 1
      && list(value.rows[0],30) && value.rows[0].length>=10 && value.rows[0][9] === inode
      && value.rows[0][1] === '0100007F:20D5' && value.rows[0][3] === '0A';
  }
  if (name.startsWith('isolation.')) {
    const value=record(details,['passed','probes']);
    const expected=name === 'isolation.agent' ? {
      authorityDirectoryRead:['EACCES'],databaseRead:['EACCES'],receiptKeyRead:['EACCES'],operatorTokenRead:['EACCES'],
      environmentSourceRead:['EACCES'],evidenceDirectoryRead:['EACCES'],authorityDirectoryWrite:['EACCES','EROFS'],
      releaseDirectoryWrite:['EACCES','EROFS'],evidenceDirectoryWrite:['EACCES','EROFS'],outboxWrite:['EACCES','EROFS'],
      outboxRead:['READABLE'],inboxWrite:['WRITABLE'],deliveredCredentialRead:['EACCES'],
    } : {agentCredentialRead:['EACCES'],enrollmentRead:['READABLE'],inboxWrite:['EACCES','EROFS'],environmentSourceRead:['EACCES']};
    const probes=record(value.probes,Object.keys(expected));
    return value.passed === true && Object.entries(expected).every(([name,allowed])=>{
      const probe=record(probes[name],['result','expected','passed']);
      return same(probe.expected,allowed) && allowed.includes(probe.result) && probe.passed === true;
    });
  }
  if (name === 'automatic.status' || name === 'approval.retryStatus') return response(details,200,'completed');
  if (name === 'automatic.signerCalls') return same(counters(details),{
    providerOpens:1,unpaidRequests:1,signerCalls:1,signaturesProduced:1,paidRequests:1});
  if (name === 'automatic.receiptVerified') return paidReceiptDetails(details,['allow']);
  if (name === 'approval.receiptVerified') {
    const automatic=all.get('automatic.receiptVerified')?.details;
    return paidReceiptDetails(details,['allow','approval']) && same(details.receiptPublicKey,automatic?.receiptPublicKey)
      && automatic.receipts.every(receipt=>details.receipts.some(value=>same(receipt,value)));
  }
  if (name === 'approval.pending' || name === 'approval.approved') {
    const value=record(details,['response','approvals','counters']);
    const entries=approvals(value.approvals);
    const counts=counters(value.counters);
    const pending=name === 'approval.pending';
    return response(value.response,pending?409:200,pending?'payment_approval_required':null)
      && counts.signerCalls === 1 && counts.signaturesProduced === 1 && counts.paidRequests === 1
      && entries.filter(entry=>entry.decision === (pending?'pending':'approved') && entry.amountCeilingAtomic === '250000').length === 1;
  }
  if (name === 'restart.changedPid') {
    const value=record(details,['before','after']);
    return /^[1-9][0-9]{0,9}$/u.test(value.before) && /^[1-9][0-9]{0,9}$/u.test(value.after) && value.before !== value.after;
  }
  if (name === 'restart.approvalPreserved') {
    const value=record(details,['before','after']);
    return same(approvals(value.before),approvals(value.after))
      && same(value.before,all.get('approval.approved')?.details?.approvals)
      && value.after.some(entry=>entry.decision === 'approved');
  }
  if (name === 'hardRestart.receiptsPreserved') {
    const approved=all.get('approval.receiptVerified')?.details;
    return paidReceiptDetails(details,['allow','approval'],true)
      && same(details.receiptPublicKey,approved?.receiptPublicKey) && same(details.before,approved.receipts);
  }
  if (name === 'chargedFailure.receiptPreserved') return paidReceiptDetails(details,['charged-failure'],true);
  if (name.endsWith('.noDoubleSigning') || name === 'restart.noSignature') {
    const pair=journalPair(details,name === 'replay.noDoubleSigning'?0:1);
    const counts=pair.after.counters;
    const initial=name === 'restart.noSignature';
    const repeated=['replay.noDoubleSigning','hardRestart.noDoubleSigning'].includes(name);
    const blocked=name === 'signingInterruption.noDoubleSigning';
    if (counts.signerCalls !== (repeated?2:1) || counts.paidRequests !== (repeated?2:blocked?0:1)
        || counts.signaturesProduced !== (repeated?2:blocked?0:1)) return false;
    if (blocked && pair.before.lastEvent.kind !== 'signer_blocked') return false;
    if (name === 'retryInterruption.noDoubleSigning' && pair.before.lastEvent.kind !== 'retry_blocked') return false;
    return !initial || same(pair.before.counters,all.get('approval.approved')?.details?.counters);
  }
  if (name.endsWith('.holdPreserved')) {
    const scenario={'signingInterruption.holdPreserved':'signing-interruption',
      'retryInterruption.holdPreserved':'retry-interruption','unresolved.holdPreserved':'payment-unresolved'}[name];
    return retainedHold(details,scenario);
  }
  if (name === 'retryInterruption.signaturePreserved') {
    const value=record(details,['before','after']);
    return list(value.before,1) && value.before.length === 1 && HASH.test(value.before[0]) && same(value.before,value.after);
  }
  if (name.startsWith('reject.')) {
    const value=record(details,name==='reject.staleAttestation'?['state','before','after','attestation']:['state','before','after']);
    journalPair({before:value.before,after:value.after},0);
    if (!stopped(value.state) || value.state.service.NRestarts !== '0' || !same(value.before,value.after)) return false;
    if (name === 'reject.staleAttestation') {
      const attestation=record(value.attestation,['reportHash','probedAt','expiresAt','importedAt','rejectedAt']);
      return HASH.test(attestation.reportHash) && ['probedAt','expiresAt','importedAt','rejectedAt'].every(field=>timestamp(attestation[field]))
        && attestation.probedAt <= attestation.importedAt && attestation.importedAt < attestation.expiresAt
        && attestation.expiresAt <= attestation.rejectedAt;
    }
    return true;
  }
  if (name === 'cleanup.serviceStopped') {
    const value=record(details,SERVICE_STATE);
    return value.MainPID === '0' && value.Job === '' && ['inactive','failed'].includes(value.ActiveState);
  }
  if (name === 'cleanup.socketDisabled') {
    const value=record(details,SOCKET_STATE);
    return value.UnitFileState === 'disabled' && value.ActiveState === 'inactive' && value.Job === '';
  }
  return false;
}

export function summarizeLifecycleEvents(events) {
  if (!list(events,Object.keys(LIFECYCLE_EXPECTATIONS).length)) fail();
  const all=new Map(events.map(event=>[event?.name,event]));
  let previousHash = null;
  const observed = new Set();
  const failed = [];
  for (const [index, value] of events.entries()) {
    const event = exactRecord(value,
      ['sequence', 'name', 'actual', 'details', 'observedAt', 'previousHash', 'eventHash'], [],
      'LIFECYCLE_EVIDENCE_INVALID', 'lifecycle event');
    const { eventHash, ...body } = event;
    if (event.sequence !== index + 1 || event.previousHash !== previousHash
        || eventHash !== sha256(canonicalJson(body)) || observed.has(event.name)
        || !Object.hasOwn(LIFECYCLE_EXPECTATIONS, event.name)
        || new Date(event.observedAt).toISOString() !== event.observedAt) fail();
    observed.add(event.name);
    let semantic=false;
    try {semantic=semanticEvidence(event.name,event.details,all);} catch {}
    if (!same(event.actual,LIFECYCLE_EXPECTATIONS[event.name]) || !semantic) failed.push(event.name);
    previousHash = eventHash;
  }
  const missing = Object.keys(LIFECYCLE_EXPECTATIONS).filter((name) => !observed.has(name));
  return { schemaVersion: 1, scope: 'installed-offline-qualification',
    valid: failed.length === 0 && missing.length === 0,
    checks: events.length, failed, missing, lastEventHash: previousHash,
    liveCdp: 'not-run', testnetTransaction: 'not-run', publicRelease: 'not-qualified' };
}

export function verifyLifecycleEvidence(directory, expectedCommit) {
  if (!/^[0-9a-f]{40}$/.test(expectedCommit)) fail();
  if (fs.realpathSync(directory) !== path.resolve(directory) || !fs.lstatSync(directory).isDirectory()) fail();
  const { value: manifest } = canonicalFile(path.join(directory, 'manifest.json'), 64 * 1024);
  const { value: summary, bytes: summaryBytes } = canonicalFile(path.join(directory, 'summary.json'), 64 * 1024);
  const eventBytes = boundedFile(path.join(directory, 'events.jsonl'),4 * 1024 * 1024);
  if (eventBytes.at(-1) !== 10) fail();
  const events = eventBytes.toString('utf8').slice(0,-1).split('\n').map((line) => {
    const value = JSON.parse(line); if (canonicalJson(value) !== line) fail(); return value;
  });
  record(manifest,['schemaVersion','commit','scope','executionProfile','nodeVersion','nodeExecutableHash',
    'hostKernel','hostArchitecture','release','failure','eventsHash','summaryHash','liveCdp','testnetTransaction','publicRelease']);
  const release=releaseBinding(manifest.release);
  if (manifest.schemaVersion !== 1 || manifest.commit !== expectedCommit
      || manifest.scope !== 'installed-offline-qualification'
      || manifest.eventsHash !== sha256(eventBytes) || manifest.summaryHash !== sha256(summaryBytes)
      || manifest.executionProfile !== 'offline-qualification'
      || manifest.liveCdp !== 'not-run' || manifest.testnetTransaction !== 'not-run'
      || manifest.publicRelease !== 'not-qualified' || manifest.failure !== null
      || typeof manifest.hostKernel !== 'string' || manifest.hostKernel.length < 1 || manifest.hostKernel.length > 256
      || /[\r\n\0]/u.test(manifest.hostKernel) || !['x64','arm64'].includes(manifest.hostArchitecture)
      || manifest.nodeVersion !== 'v24.18.1'
      || manifest.nodeExecutableHash !== release.nodeExecutableHash
      || !same(events.find(event=>event.name==='install.pid1Bound')?.details?.release,release)) fail();
  const recomputed = summarizeLifecycleEvents(events);
  if (canonicalJson(summary) !== canonicalJson(recomputed) || !recomputed.valid) fail();
  return { valid: true, commit: expectedCommit, ...recomputed };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv.length !== 5 || process.argv[3] !== '--commit') fail();
    process.stdout.write(`${canonicalJson(verifyLifecycleEvidence(path.resolve(process.argv[2]), process.argv[4]))}\n`);
  } catch {
    process.stderr.write('LIFECYCLE_EVIDENCE_INVALID\n'); process.exitCode = 1;
  }
}
