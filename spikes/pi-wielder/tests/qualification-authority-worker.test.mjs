import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import test from 'node:test';

import {
  parseQualificationArguments, projectQualificationHttpResponse,
  projectQualificationSnapshot, validateQualificationIdentity, validateQualificationPayload,
} from '../scripts/qualification-authority-worker.mjs';
import { canonicalJson, sha256 } from '../src/kernel/canonical.mjs';
import { createReceiptSigner, verifySignedReceipt } from '../src/kernel/receipt-signing.mjs';
import { SCHEMA_V1_SQL } from '../src/kernel/sqlite-schema.mjs';
import { OFFLINE_QUALIFICATION } from '../src/runtime/qualification-clients.mjs';

const HASH = sha256('public qualification test');
const NOW = '2026-09-05T18:00:00.000Z';

function identity(action = 'snapshot', role = 'kernel') {
  const uid = role === 'kernel' ? 501 : 601;
  const gid = role === 'kernel' ? 502 : 602;
  return {config:{executionProfile:'offline-qualification', kernelUid:'501', kernelGid:'502',
    agentUid:'601', agentGid:'602'}, action, platform:'linux', version:'v24.18.1',
  uid, euid:uid, gid, egid:gid, groups:[gid], status:[
    `Uid:\t${uid}\t${uid}\t${uid}\t${uid}`, `Gid:\t${gid}\t${gid}\t${gid}\t${gid}`,
    ...['CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb'].map(name => `${name}:\t0000000000000000`),
    'NoNewPrivs:\t1', '',
  ].join('\n')};
}

test('worker arguments and action inputs cannot select arbitrary paths, providers, or authority transitions', () => {
  assert.deepEqual(parseQualificationArguments(['--deployment', '/opt/release/deployment.json', '--action', 'snapshot']),
    {deploymentPath:'/opt/release/deployment.json', action:'snapshot'});
  for (const args of [[], ['--deployment', './deployment.json', '--action', 'snapshot'],
    ['--deployment', '/opt/release/deployment.json', '--action', 'sql'],
    ['--deployment', '/opt/release/deployment.json', '--action', 'snapshot', '--live']]) {
    assert.throws(() => parseQualificationArguments(args));
  }
  for (const route of OFFLINE_QUALIFICATION.routes) {
    assert.doesNotThrow(() => validateQualificationPayload('agent-request',
      {routeId:route.id, callId:Buffer.alloc(32, 0x32).toString('base64url'), body:{qualification:true}}));
  }
  for (const value of [
    {routeId:'arbitrary', callId:Buffer.alloc(32).toString('base64url'), body:{qualification:true}},
    {routeId:'qualification-allow', callId:'noncanonical', body:{qualification:true}},
    {routeId:'qualification-allow', callId:Buffer.alloc(32).toString('base64url'), body:{qualification:true, prompt:'secret'}},
  ]) assert.throws(() => validateQualificationPayload('agent-request', value));
  assert.throws(() => validateQualificationPayload('bootstrap', {policyPath:'/tmp/policy.json'}));
  assert.throws(() => validateQualificationPayload('import-isolation', {confirm:'yes'}));
  assert.doesNotThrow(() => validateQualificationPayload('enroll', {confirm:HASH}));
});

test('operator helper accepts exact approvals and reconciliation routes but no token-minting or URL override', () => {
  for (const input of [
    {method:'GET', path:'/operator/v1/overview'},
    {method:'POST', path:'/operator/v1/approvals/approval-1/approve', body:{expectedIntentHash:HASH}},
    {method:'POST', path:'/operator/v1/approvals/approval-1/deny', body:{expectedIntentHash:HASH, reasonCode:'OPERATOR_DENIED'}},
    {method:'POST', path:'/operator/v1/reconciliations/intent-1/payment', body:{expectedIntentHash:HASH, expectedCaseHash:HASH}},
  ]) assert.doesNotThrow(() => validateQualificationPayload('operator-request', input));
  for (const input of [
    {method:'POST', path:'/operator/v1/browser-launch', body:{}},
    {method:'GET', path:'https://outside.invalid/operator/v1/overview'},
    {method:'GET', path:'/operator/v1/overview', body:{}},
    {method:'POST', path:'/operator/v1/approvals/approval-1/approve', body:{expectedIntentHash:HASH, signature:'secret'}},
    {method:'POST', path:'/operator/v1/approvals/approval-1/deny', body:{expectedIntentHash:HASH, reasonCode:'OTHER'}},
  ]) assert.throws(() => validateQualificationPayload('operator-request', input));
});

test('worker requires exact offline identity, no capabilities, no extra groups, and no privilege elevation', () => {
  assert.equal(validateQualificationIdentity(identity()), 'kernel');
  assert.equal(validateQualificationIdentity(identity('agent-init', 'agent')), 'agent');
  assert.equal(validateQualificationIdentity(identity('boundary-probes', 'agent')), 'agent');
  assert.equal(validateQualificationIdentity(identity('delivered-credential-probe', 'agent')), 'agent');
  assert.throws(() => validateQualificationIdentity(identity('delivered-credential-probe')),
    {code:'QUALIFICATION_WORKER_IDENTITY'});
  for (const mutate of [
    input => { input.config.executionProfile = 'cdp-testnet'; },
    input => { delete input.config.executionProfile; },
    input => { input.uid = 0; }, input => { input.euid++; }, input => { input.egid++; },
    input => { input.groups.push(999); }, input => { input.platform = 'darwin'; },
    input => { input.version = 'v24.18.0'; }, input => { input.action = 'agent-init'; },
    input => { input.status = input.status.replace('NoNewPrivs:\t1', 'NoNewPrivs:\t0'); },
    input => { input.status += 'NoNewPrivs:\t1\n'; },
    ...['CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb'].map(name => input => {
      input.status = input.status.replace(`${name}:\t0000000000000000`, `${name}:\t0000000000000001`);
    }),
    input => { input.status = input.status.replace('Uid:\t501\t501\t501\t501', 'Uid:\t501\t501\t501\t0'); },
  ]) {
    const input = identity(); mutate(input);
    assert.throws(() => validateQualificationIdentity(input), {code:'QUALIFICATION_WORKER_IDENTITY'});
  }
});

function fixture(t) {
  const database = new DatabaseSync(':memory:', {readBigInts:true});
  database.exec(SCHEMA_V1_SQL);
  t.after(() => database.close());
  const insert = (table, values) => database.prepare(`INSERT INTO ${table}
    (${Object.keys(values).join(',')}) VALUES (${Object.keys(values).map(() => '?').join(',')})`).run(...Object.values(values));
  insert('policy_versions', {id:'policy-1', schema_version:1, canonical_json:'{}', policy_hash:HASH, applied_at:NOW});
  insert('agent_enrollments', {agent_instance_id:'agent-1', credential_digest:HASH, enrollment_hash:HASH,
    agent_uid:'601', agent_gid:'602', state:'active', enrolled_by_operator_hash:HASH, enrolled_at:NOW});
  insert('spend_sessions', {id:'session-1', adapter_id:'fixture', wallet_address:OFFLINE_QUALIFICATION.walletAddress,
    policy_version_id:'policy-1', state:'open', created_at:NOW});
  insert('spend_intents', {id:'intent-1', request_id:'request-1', session_id:'session-1', enrollment_hash:HASH,
    route_id:'qualification-allow', method:'POST', request_url_hash:HASH, seller_origin:OFFLINE_QUALIFICATION.sellerOrigin,
    resource_path:'/paid/allow', body_hash:HASH, header_allowlist_hash:HASH, ordinary_fingerprint:HASH,
    purpose_label:'PRIVATE_PROMPT_MARKER', correlation_id:'correlation-1', idempotency_key:'idempotency-1',
    wallet_address:OFFLINE_QUALIFICATION.walletAddress, intent_hash:HASH, state:'terminal', created_at:NOW, updated_at:NOW});
  insert('approvals', {id:'approval-1', intent_id:'intent-1', decision:'consumed', intent_hash:HASH,
    challenge_hash:HASH, quote_id:'quote-1', accepted_index:0, amount_ceiling_atomic:'50000',
    wallet_address:OFFLINE_QUALIFICATION.walletAddress, policy_version_id:'policy-1', expires_at:NOW,
    decided_at:NOW, consumed_at:NOW});
  insert('budget_reservations', {intent_id:'intent-1', session_id:'session-1', seller_origin:OFFLINE_QUALIFICATION.sellerOrigin,
    reserved_atomic:'9007199254740993', committed_atomic:'0', released_atomic:'0', unresolved_atomic:'0', state:'reserved', updated_at:NOW});
  const paymentSignature = `0x${'23'.repeat(65)}`;
  insert('payment_attempts', {id:'payment-1', intent_id:'intent-1', state:'signed',
    payment_required_projection_json:'PRIVATE_CHALLENGE_MARKER', accepted_index:0,
    payment_payload_json:JSON.stringify({payload:{signature:paymentSignature}, private:'PRIVATE_PAYLOAD_MARKER'}),
    payment_header:'PRIVATE_HEADER_MARKER', payment_hash:HASH, quote_id:'quote-1',
    signing_claimed_at:NOW, signed_at:NOW, created_at:NOW, updated_at:NOW});
  const signer = createReceiptSigner();
  const receipt = {schemaVersion:1, receiptId:'receipt-1', revision:1, issuedAt:NOW,
    intent:{id:'intent-1', requestId:'request-1', intentHash:HASH, sessionId:'session-1',
      sellerOrigin:OFFLINE_QUALIFICATION.sellerOrigin, resourcePath:'/paid/allow', purposeLabel:'qualification.invoke'},
    outcome:{status:'completed', reasonCode:'PAYMENT_SETTLED'},
    policy:{versionId:'policy-1', decision:'allow', reasonCode:'WITHIN_AUTO_LIMIT'},
    approval:{state:'not_required', operatorIdHash:null},
    payment:{state:'settled', amountAtomic:'50000', network:OFFLINE_QUALIFICATION.network,
      asset:OFFLINE_QUALIFICATION.asset, payTo:OFFLINE_QUALIFICATION.payTo, transactionId:`0x${'ab'.repeat(32)}`},
    execution:{state:'succeeded', httpStatus:200, responseHash:HASH},
    budget:{disposition:'committed', amountAtomic:'50000'}, reconciliation:null, refund:null, supersedesReceiptHash:null};
  const receiptHash = crypto.createHash('sha256').update(canonicalJson(receipt)).digest('hex');
  insert('signed_receipts', {id:'receipt-1', intent_id:'intent-1', revision:1, receipt_json:canonicalJson(receipt),
    receipt_hash:receiptHash, signature:signer.signHash(receiptHash), algorithm:signer.algorithm,
    key_id:signer.keyId, created_at:NOW});
  const receiptPublicKey = {algorithm:signer.algorithm, keyId:signer.keyId, publicKeyPem:signer.publicKeyPem};
  return {database, receiptPublicKey, paymentSignature};
}

test('read-only snapshot uses exact atomic sums and hashes persisted payment secrets while verifying public receipts', async t => {
  const {database, receiptPublicKey, paymentSignature} = fixture(t);
  database.exec('PRAGMA query_only = ON; BEGIN;');
  const changes = database.prepare('SELECT total_changes() AS changes').get().changes;
  const result = await projectQualificationSnapshot(database, receiptPublicKey);
  assert.equal(result.budgets.totals.heldAtomic, '9007199254740993');
  assert.equal(result.approvals[0].decision, 'consumed');
  assert.equal(result.approvals[0].intentHash, HASH);
  assert.equal(result.payments[0].signatureHash, sha256(paymentSignature));
  assert.equal(result.receipts[0].verified, true);
  assert.equal(verifySignedReceipt(result.receipts[0], result.receiptPublicKey), true);
  assert.equal(database.prepare('SELECT total_changes() AS changes').get().changes, changes);
  assert.equal((await projectQualificationSnapshot(database, receiptPublicKey)).stateHash, result.stateHash);
  assert.equal(/PRIVATE_/.test(JSON.stringify(result)), false);
  assert.equal(JSON.stringify(result).includes(paymentSignature), false);
  database.exec('COMMIT');
});

test('snapshot refuses non-qualification authority and malformed public receipt projections', async t => {
  const {database, receiptPublicKey} = fixture(t);
  database.exec("UPDATE spend_intents SET route_id = 'arbitrary'");
  await assert.rejects(projectQualificationSnapshot(database, receiptPublicKey), {code:'QUALIFICATION_SNAPSHOT_ROUTE'});
  database.exec("UPDATE spend_intents SET route_id = 'qualification-allow'");
  const row = database.prepare('SELECT receipt_json FROM signed_receipts').get();
  const receipt = JSON.parse(row.receipt_json);
  receipt.rawSecret = 'PRIVATE_SECRET_MARKER';
  database.prepare('UPDATE signed_receipts SET receipt_json = ?').run(JSON.stringify(receipt));
  await assert.rejects(projectQualificationSnapshot(database, receiptPublicKey), {code:'QUALIFICATION_SNAPSHOT_RECEIPT'});
});

test('HTTP projection discards raw upstream bodies and rejects token-bearing operator output', async () => {
  const result = await projectQualificationHttpResponse('agent-request', 200, Buffer.from(JSON.stringify({
    status:'completed', requestId:'request-1', resource:{httpStatus:200, contentType:'application/json', body:'PRIVATE_PROMPT_MARKER'},
  })));
  assert.deepEqual(result.response, {status:'completed', requestId:'request-1'});
  assert.equal(JSON.stringify(result).includes('PRIVATE_PROMPT_MARKER'), false);
  assert.match(result.responseHash, /^sha256:[0-9a-f]{64}$/u);
  const replay = await projectQualificationHttpResponse('agent-request', 409, Buffer.from(JSON.stringify({
    status:'completed_replay', terminalStatus:'completed', requestId:'request-1', reasonCode:'PAYMENT_SETTLED',
    projections:{request:'/agent/v1/intents/request-1', receipt:'/agent/v1/receipts/receipt-1'},
  })));
  assert.deepEqual(replay.response, {status:'completed_replay', terminalStatus:'completed',
    requestId:'request-1', reasonCode:'PAYMENT_SETTLED'});
  await assert.rejects(projectQualificationHttpResponse('operator-request', 200,
    Buffer.from('{"ok":true,"data":{"token":"PRIVATE_TOKEN_MARKER"}}')));
  assert.deepEqual((await projectQualificationHttpResponse('operator-request', 403,
    Buffer.from('{"ok":false,"error":{"code":"OPERATOR_UNAUTHORIZED","message":"PRIVATE_TOKEN_MARKER"}}'))).response,
  {ok:false, error:{code:'OPERATOR_UNAUTHORIZED'}});
});

test('worker keeps authority imports behind process identity validation and does not offer a live switch', () => {
  const source = fs.readFileSync(new URL('../scripts/qualification-authority-worker.mjs', import.meta.url), 'utf8');
  const imports = [...source.matchAll(/^import\s.+?from\s+'([^']+)'/gmu)].map(match => match[1]);
  assert.ok(imports.length > 0 && imports.every(specifier => specifier.startsWith('node:')));
  assert.match(source, /const role = validateQualificationIdentity/);
  assert.equal(source.includes('process.setuid('), false, 'identity drop happens outside Node');
  assert.equal(source.includes('LIVE_LAUNCH_GATE'), false, 'worker cannot clear the live eligibility gate');
});
