#!/usr/bin/env node
// The root lifecycle harness invokes setpriv BEFORE Node. Static imports are
// built-ins only; authority and credential modules load after identity checks.
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import { types as utilTypes } from 'node:util';

const PROFILE = 'offline-qualification';
const MAXIMUM_INPUT_BYTES = 16_384;
const MAXIMUM_OUTPUT_BYTES = 1_048_576;
const MAXIMUM_ROWS = 128;
const HASH = /^sha256:[0-9a-f]{64}$/u;
const IDENTIFIER = '[A-Za-z0-9][A-Za-z0-9._:-]{0,199}';
const ACTIONS = new Set(['bootstrap', 'agent-init', 'enroll', 'import-isolation',
  'snapshot', 'agent-request', 'operator-request', 'boundary-probes', 'delivered-credential-probe']);
const AGENT_ACTIONS = new Set(['agent-init', 'agent-request', 'delivered-credential-probe']);
const ROUTES = new Set(['allow', 'approval', 'charged-failure', 'payment-unresolved',
  'signing-interruption', 'retry-interruption'].map(name => `qualification-${name}`));
const DELIVERED_CREDENTIAL = '/run/credentials/wallet-kernel.service/wallet-kernel-environment';

function fail(code = 'QUALIFICATION_WORKER_INPUT') {
  const error = new Error('Qualification authority worker refused');
  error.code = code;
  throw error;
}

function record(value, required, optional = []) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || utilTypes.isProxy(value)
      || Object.getPrototypeOf(value) !== Object.prototype
      || required.some(field => !Object.hasOwn(value, field))
      || Reflect.ownKeys(value).some(field => typeof field !== 'string'
        || ![...required, ...optional].includes(field)
        || !Object.getOwnPropertyDescriptor(value, field)?.enumerable
        || !Object.hasOwn(Object.getOwnPropertyDescriptor(value, field), 'value'))) fail();
  return value;
}

function canonical(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number' && Number.isSafeInteger(value) && !Object.is(value, -0)) return String(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (!value || typeof value !== 'object' || utilTypes.isProxy(value)
      || Object.getPrototypeOf(value) !== Object.prototype) fail('QUALIFICATION_WORKER_OUTPUT');
  return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
}

const digest = value => `sha256:${crypto.createHash('sha256').update(value).digest('hex')}`;

export function parseQualificationArguments(argv) {
  if (!Array.isArray(argv) || argv.length !== 4 || argv[0] !== '--deployment'
      || argv[2] !== '--action' || typeof argv[1] !== 'string'
      || !path.isAbsolute(argv[1]) || path.resolve(argv[1]) !== argv[1]
      || path.basename(argv[1]) !== 'deployment.json' || !ACTIONS.has(argv[3])) fail();
  return {deploymentPath:argv[1], action:argv[3]};
}

export function validateQualificationPayload(action, payload) {
  if (!ACTIONS.has(action)) fail();
  if (['bootstrap', 'agent-init', 'snapshot', 'boundary-probes', 'delivered-credential-probe'].includes(action)) return record(payload, []);
  if (['enroll', 'import-isolation'].includes(action)) {
    record(payload, ['confirm']);
    if (typeof payload.confirm !== 'string' || !HASH.test(payload.confirm)) fail();
    return payload;
  }
  if (action === 'agent-request') {
    record(payload, ['routeId', 'callId', 'body']);
    record(payload.body, ['qualification']);
    if (!ROUTES.has(payload.routeId) || payload.body.qualification !== true
        || typeof payload.callId !== 'string' || !/^[A-Za-z0-9_-]{43}$/u.test(payload.callId)
        || Buffer.from(payload.callId, 'base64url').length !== 32
        || Buffer.from(payload.callId, 'base64url').toString('base64url') !== payload.callId) fail();
    return payload;
  }
  record(payload, ['method', 'path'], ['body']);
  if (payload.method === 'GET') {
    if (Object.hasOwn(payload, 'body') || ![
      '/operator/v1/overview', '/operator/v1/policies', '/operator/v1/approvals',
      '/operator/v1/receipts', '/operator/v1/receipt-public-key',
    ].includes(payload.path)) fail();
    return payload;
  }
  if (payload.method !== 'POST' || typeof payload.path !== 'string') fail();
  const approval = new RegExp(`^/operator/v1/approvals/(${IDENTIFIER})/(approve|deny)$`, 'u').exec(payload.path);
  const reconciliation = new RegExp(`^/operator/v1/reconciliations/(${IDENTIFIER})/(payment|execution)$`, 'u').exec(payload.path);
  if (approval) {
    record(payload.body, approval[2] === 'approve' ? ['expectedIntentHash'] : ['expectedIntentHash', 'reasonCode']);
    if (approval[2] === 'deny' && payload.body.reasonCode !== 'OPERATOR_DENIED') fail();
  } else if (reconciliation) {
    record(payload.body, ['expectedIntentHash', 'expectedCaseHash'],
      reconciliation[2] === 'payment' ? ['paymentTransactionId'] : []);
    if (!HASH.test(payload.body.expectedCaseHash)
        || (Object.hasOwn(payload.body, 'paymentTransactionId')
          && !/^0x[0-9a-f]{64}$/u.test(payload.body.paymentTransactionId))) fail();
  } else fail();
  if (typeof payload.body.expectedIntentHash !== 'string' || !HASH.test(payload.body.expectedIntentHash)) fail();
  return payload;
}

// This accepts captured kernel-reported facts for focused tests. The CLI always
// captures them itself; no request or environment variable supplies these facts.
export function validateQualificationIdentity({config, action, platform, version,
  uid, euid, gid, egid, groups, status}) {
  if (config.executionProfile !== PROFILE || platform !== 'linux' || version !== 'v24.18.1'
      || typeof status !== 'string' || status.length > 65_536 || !Array.isArray(groups)) fail('QUALIFICATION_WORKER_IDENTITY');
  const role = uid === Number(config.kernelUid) ? 'kernel'
    : uid === Number(config.agentUid) ? 'agent' : null;
  const expectedUid = Number(role === 'kernel' ? config.kernelUid : config.agentUid);
  const expectedGid = Number(role === 'kernel' ? config.kernelGid : config.agentGid);
  if (!ACTIONS.has(action) || role === null || expectedUid <= 0 || expectedGid <= 0
      || uid !== expectedUid || euid !== expectedUid || gid !== expectedGid || egid !== expectedGid
      || groups.some(group => group !== expectedGid)
      || (action !== 'boundary-probes' && (AGENT_ACTIONS.has(action) ? role !== 'agent' : role !== 'kernel'))) {
    fail('QUALIFICATION_WORKER_IDENTITY');
  }
  const field = name => {
    const matches = [...status.matchAll(new RegExp(`^${name}:\\s*([^\\r\\n]+)$`, 'gmu'))];
    if (matches.length !== 1) fail('QUALIFICATION_WORKER_IDENTITY');
    return matches[0][1].trim();
  };
  for (const name of ['CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb']) {
    if (!/^0{16}$/u.test(field(name))) fail('QUALIFICATION_WORKER_IDENTITY');
  }
  for (const [name, expected] of [['Uid', expectedUid], ['Gid', expectedGid]]) {
    const values = field(name).split(/\s+/u);
    if (values.length !== 4 || values.some(value => value !== String(expected))) fail('QUALIFICATION_WORKER_IDENTITY');
  }
  if (field('NoNewPrivs') !== '1') fail('QUALIFICATION_WORKER_IDENTITY');
  return role;
}

export async function readQualificationInput() {
  const bytes = Buffer.alloc(MAXIMUM_INPUT_BYTES + 1);
  let length = 0;
  try {
    // setpriv can preserve a nonblocking stdin pipe. Wait for the stream's EOF
    // rather than treating an interim EAGAIN after a complete chunk as bad JSON.
    for await (const chunk of process.stdin) {
      try {
        if (!Buffer.isBuffer(chunk) || length + chunk.length > MAXIMUM_INPUT_BYTES) fail();
        chunk.copy(bytes, length);
        length += chunk.length;
      } finally { if (Buffer.isBuffer(chunk)) chunk.fill(0); }
    }
    if (length === 0 || length > MAXIMUM_INPUT_BYTES) fail();
    return JSON.parse(new TextDecoder('utf-8', {fatal:true}).decode(bytes.subarray(0, length)));
  } catch { fail(); } finally { bytes.fill(0); }
}

function assertImmutablePath(filePath, maximumBytes) {
  let current = '/';
  const components = filePath.slice(1).split('/');
  for (let index = 0; index < components.length; index += 1) {
    current = path.join(current, components[index]);
    const stat = fs.lstatSync(current, {bigint:true});
    if (stat.uid !== 0n || stat.isSymbolicLink() || (stat.mode & 0o022n) !== 0n
        || (index === components.length - 1 ? !stat.isFile() || stat.nlink !== 1n
          || stat.size <= 0n || stat.size > BigInt(maximumBytes) : !stat.isDirectory())) {
      fail('QUALIFICATION_WORKER_RELEASE');
    }
  }
}

function kernelPathTrust(config) {
  return Object.freeze({mode:'cdp-testnet', trustedAncestor:config.trustedAncestor,
    kernelUid:Number(config.kernelUid), agentUid:Number(config.agentUid)});
}

function bootstrapConfig(config) {
  return {mode:'cdp-testnet', databasePath:config.databasePath, receiptKeyPath:config.receiptKeyPath,
    operatorTokenPath:config.operatorTokenPath, operatorSocketPath:config.operatorSocketPath,
    origin:'http://127.0.0.1:8405', trustedAncestor:config.trustedAncestor,
    enrollmentInboxPath:config.enrollmentInboxPath, expectedAgentUid:Number(config.agentUid),
    expectedAgentGid:Number(config.agentGid), kernelUid:Number(config.kernelUid), kernelGid:Number(config.kernelGid)};
}

async function readOperatorToken(config) {
  const {readPrivateInputFile} = await import('../src/kernel/secure-storage.mjs');
  const bytes = readPrivateInputFile(config.operatorTokenPath, 'Operator token',
    {pathTrust:kernelPathTrust(config), maximumBytes:43});
  try {
    const token = bytes.toString('ascii');
    if (bytes.length !== 43 || bytes.some(value => value > 0x7f) || !/^[A-Za-z0-9_-]{43}$/u.test(token)
        || Buffer.from(token, 'base64url').length !== 32
        || Buffer.from(token, 'base64url').toString('base64url') !== token) fail('QUALIFICATION_WORKER_CREDENTIAL');
    return token;
  } finally { bytes.fill(0); }
}

async function bootstrap(config) {
  const [lockModule, storage, signing, auth, policies, policyValidation] = await Promise.all([
    import('../src/kernel/authority-lock.mjs'), import('../src/kernel/sqlite-store.mjs'),
    import('../src/kernel/receipt-signing.mjs'), import('../src/operator/auth.mjs'),
    import('../src/kernel/policy-repository.mjs'), import('../src/kernel/policy-engine.mjs'),
  ]);
  const pathTrust = kernelPathTrust(config);
  assertImmutablePath(config.policyPath, 65_536);
  const policy = policyValidation.validatePolicyDocument(JSON.parse(fs.readFileSync(config.policyPath, 'utf8')));
  const lock = lockModule.acquireAuthorityLock({databasePath:config.databasePath, role:'bootstrap', pathTrust});
  let store;
  try {
    for (const filePath of [config.databasePath, config.receiptKeyPath, config.operatorTokenPath]) {
      try { fs.lstatSync(filePath); fail('QUALIFICATION_BOOTSTRAP_EXISTS'); }
      catch (error) { if (error.code !== 'ENOENT') throw error; }
    }
    store = storage.openKernelStore({filePath:config.databasePath, pathTrust});
    const signer = signing.loadOrCreateReceiptSigner(config.receiptKeyPath, {pathTrust});
    auth.loadOrCreateOperatorToken({filePath:config.operatorTokenPath, pathTrust});
    const applied = policies.createPolicyRepository(store).apply(policy, new Date().toISOString());
    return {policyHash:applied.policyVersion.hash,
      receiptPublicKey:{algorithm:signer.algorithm, keyId:signer.keyId, publicKeyPem:signer.publicKeyPem}};
  } finally { try { store?.close(); } finally { lock.close(); } }
}

async function agentInit(config) {
  const {runAgentCredentialCli} = await import('../src/agent/credential-cli.mjs');
  let descriptorHash;
  runAgentCredentialCli({argv:['init', '--credential', config.agentCredentialPath,
    '--enrollment', path.join(config.enrollmentInboxPath, 'enrollment.json')],
  writeStdout:bytes => { descriptorHash = bytes.trim(); },
  dependencies:{pathTrust:Object.freeze({mode:'cdp-testnet', trustedAncestor:config.trustedAncestor,
    agentUid:Number(config.agentUid)})}});
  if (!HASH.test(descriptorHash)) fail('QUALIFICATION_WORKER_OUTPUT');
  return {descriptorHash};
}

async function offlineMutation(config, action, payload) {
  const {runOfflineBootstrap} = await import('../src/offline-bootstrap.mjs');
  const command = action === 'enroll'
    ? {name:'agent-enroll', descriptorPath:path.join(config.enrollmentInboxPath, 'enrollment.json'),
      expectedDescriptorHash:payload.confirm}
    : {name:'isolation-attest', reportPath:config.isolationReportPath, expectedReportHash:payload.confirm};
  return runOfflineBootstrap({config:bootstrapConfig(config), command, operatorToken:await readOperatorToken(config)});
}

function camelRow(row) {
  return Object.fromEntries(Object.entries(row).map(([key, value]) => {
    if (typeof value === 'bigint') {
      if (value > BigInt(Number.MAX_SAFE_INTEGER) || value < 0n) fail('QUALIFICATION_SNAPSHOT_BOUNDS');
      value = Number(value);
    }
    if (typeof value === 'string' && Buffer.byteLength(value) > 4096) fail('QUALIFICATION_SNAPSHOT_BOUNDS');
    return [key.replace(/_([a-z])/gu, (_match, letter) => letter.toUpperCase()), value];
  }));
}

/** Select public columns from a caller-held read transaction; never write/recover. */
export async function projectQualificationSnapshot(database, receiptPublicKey) {
  const {createSignedReceiptRepository} = await import('../src/kernel/signed-receipts.mjs');
  const readonly = () => fail('QUALIFICATION_SNAPSHOT_WRITE');
  const verifier = createSignedReceiptRepository({store:{transaction:readonly, within:readonly},
    signer:{...receiptPublicKey, signHash:readonly}, idFactory:readonly, now:readonly});
  const rows = (table, columns, order = 'rowid') => {
    const result = database.prepare(`SELECT ${columns} FROM ${table} ORDER BY ${order} LIMIT ${MAXIMUM_ROWS + 1}`).all();
    if (result.length > MAXIMUM_ROWS) fail('QUALIFICATION_SNAPSHOT_BOUNDS');
    return result;
  };
  const intents = rows('spend_intents', 'id, request_id, session_id, route_id, intent_hash, challenge_hash, state').map(camelRow);
  if (intents.some(intent => !ROUTES.has(intent.routeId))) fail('QUALIFICATION_SNAPSHOT_ROUTE');
  const approvals = rows('approvals', 'id, intent_id, decision, intent_hash, challenge_hash, amount_ceiling_atomic, expires_at, decided_at, consumed_at').map(camelRow);
  const reservations = rows('budget_reservations', 'intent_id, session_id, state, reserved_atomic, committed_atomic, released_atomic, unresolved_atomic').map(camelRow);
  const totals = {};
  for (const field of ['reservedAtomic', 'committedAtomic', 'releasedAtomic', 'unresolvedAtomic']) {
    if (reservations.some(row => !/^(?:0|[1-9][0-9]*)$/u.test(row[field]) || row[field].length > 78)) fail('QUALIFICATION_SNAPSHOT_BOUNDS');
    totals[field] = reservations.reduce((sum, row) => sum + BigInt(row[field]), 0n).toString();
  }
  totals.heldAtomic = (BigInt(totals.reservedAtomic) + BigInt(totals.unresolvedAtomic)).toString();
  const payments = rows('payment_attempts', 'id, intent_id, state, payment_hash, payment_payload_json, payment_header, signing_claimed_at, signed_at, retry_started_at, reason_code').map(row => {
    const {payment_payload_json:payload, payment_header:header, ...publicRow} = row;
    if ([payload, header].some(value => value !== null
      && (typeof value !== 'string' || Buffer.byteLength(value) > 262_144))) fail('QUALIFICATION_SNAPSHOT_BOUNDS');
    const signature = payload === null ? null : JSON.parse(payload)?.payload?.signature;
    if (payload !== null && (typeof signature !== 'string' || !/^0x[0-9a-fA-F]{130}$/u.test(signature))) fail('QUALIFICATION_SNAPSHOT_PAYMENT');
    return {...camelRow(publicRow), payloadHash:payload === null ? null : digest(payload),
      headerHash:header === null ? null : digest(header), signatureHash:signature === null ? null : digest(signature)};
  });
  const receipts = rows('signed_receipts', 'id, intent_id, revision, receipt_json, receipt_hash, signature, algorithm, key_id, supersedes_receipt_hash, created_at').map(row => {
    if (Buffer.byteLength(row.receipt_json) > 65_536) fail('QUALIFICATION_SNAPSHOT_BOUNDS');
    const {receipt_json:receiptJson, ...publicRow} = row;
    const receipt = {...camelRow(publicRow), receipt:JSON.parse(receiptJson)};
    if (!verifier.verify(receipt)) fail('QUALIFICATION_SNAPSHOT_RECEIPT');
    return {...receipt, verified:true};
  });
  const enrollment = rows('agent_enrollments', 'agent_instance_id, enrollment_hash, state, agent_uid, agent_gid').map(camelRow);
  const sessions = rows('spend_sessions', 'id, state, policy_version_id, created_at, closed_at').map(camelRow);
  const attestations = rows('isolation_attestations', 'id, report_hash, enrollment_hash, state, probed_at, expires_at').map(camelRow);
  const outcomes = rows('buyer_outcomes', 'intent_id, status, reason_code, revision, recorded_at').map(camelRow);
  const executionResolutions = rows('execution_resolutions', 'intent_id, state, reason_code, blocks_wallet, opened_at, resolved_at').map(camelRow);
  const eventHeadRow = database.prepare('SELECT sequence, event_hash FROM events ORDER BY sequence DESC LIMIT 1').get();
  const counts = Object.fromEntries(Object.entries({intents, approvals, reservations, payments, receipts,
    enrollment, sessions, attestations, outcomes, executionResolutions}).map(([name, value]) => [name, value.length]));
  const projection = {counts, enrollment, sessions, attestations, intents, approvals,
    budgets:{totals, reservations}, payments, outcomes, executionResolutions, receiptPublicKey, receipts,
    eventHead:eventHeadRow ? camelRow(eventHeadRow) : null};
  return {...projection, stateHash:digest(canonical(projection))};
}

async function snapshot(config) {
  const [{DatabaseSync}, storage, signing] = await Promise.all([import('node:sqlite'),
    import('../src/kernel/secure-storage.mjs'), import('../src/kernel/receipt-signing.mjs')]);
  const pathTrust = kernelPathTrust(config);
  storage.preflightSqliteFiles(config.databasePath, {pathTrust});
  const keyBytes = storage.readPrivateInputFile(config.receiptKeyPath, 'receipt key', {pathTrust, maximumBytes:4096});
  let receiptPublicKey;
  try {
    const publicKey = crypto.createPublicKey(crypto.createPrivateKey(keyBytes));
    if (publicKey.asymmetricKeyType !== 'ed25519') fail('QUALIFICATION_SNAPSHOT_RECEIPT');
    receiptPublicKey = {algorithm:'Ed25519', keyId:signing.receiptKeyId(publicKey),
      publicKeyPem:publicKey.export({type:'spki', format:'pem'}).toString()};
  } finally { keyBytes.fill(0); }
  const database = new DatabaseSync(config.databasePath, {readOnly:true, readBigInts:true, timeout:5000});
  let projection;
  try {
    database.exec('PRAGMA query_only = ON; PRAGMA trusted_schema = OFF; BEGIN;');
    projection = await projectQualificationSnapshot(database, receiptPublicKey);
    database.exec('COMMIT');
  } finally { database.close(); }
  const qualification = await import('../src/runtime/qualification-clients.mjs');
  let journal = null;
  try {
    fs.lstatSync(path.join(path.dirname(config.databasePath), qualification.OFFLINE_QUALIFICATION.journalName));
    journal = qualification.readOfflineQualificationJournal({databasePath:config.databasePath, pathTrust});
  } catch (error) { if (error.code !== 'ENOENT') throw error; }
  // The journal is a separate durable observation, not an atomic SQLite member.
  return {...projection, capturedAt:new Date().toISOString(), journal, journalAtomicWithDatabase:false};
}

export async function projectQualificationHttpResponse(action, httpStatus, bytes) {
  if (!['agent-request', 'operator-request'].includes(action) || !Number.isSafeInteger(httpStatus)
      || httpStatus < 100 || httpStatus > 599 || !Buffer.isBuffer(bytes)
      || bytes.length === 0 || bytes.length > MAXIMUM_OUTPUT_BYTES) fail('QUALIFICATION_HTTP_RESPONSE');
  let response;
  try { response = JSON.parse(new TextDecoder('utf-8', {fatal:true}).decode(bytes)); }
  catch { fail('QUALIFICATION_HTTP_RESPONSE'); }
  const {projectOperatorPublicResult} = await import('../src/operator/api.mjs');
  if (action === 'operator-request') {
    if (response?.ok === true) {
      record(response, ['ok', 'data']);
      response = {ok:true, data:projectOperatorPublicResult(response.data)};
    } else {
      record(response, ['ok', 'error']);
      if (response.ok !== false || typeof response.error?.code !== 'string'
          || !/^[A-Z][A-Z0-9_]{0,127}$/u.test(response.error.code)) fail('QUALIFICATION_HTTP_RESPONSE');
      response = {ok:false, error:{code:response.error.code}};
    }
  } else {
    record(response, [], ['status', 'requestId', 'reasonCode', 'terminalStatus',
      'approval', 'receipt', 'resource', 'projections', 'error']);
    const selected = {};
    for (const field of ['status', 'requestId', 'reasonCode', 'approval', 'receipt']) {
      if (Object.hasOwn(response, field)) selected[field] = response[field];
    }
    if (Object.hasOwn(response, 'terminalStatus') && response.terminalStatus !== 'completed') fail('QUALIFICATION_HTTP_RESPONSE');
    const terminal = Object.hasOwn(response, 'terminalStatus') ? {terminalStatus:response.terminalStatus} : {};
    const code = response.error?.code;
    if (code !== undefined && (typeof code !== 'string' || !/^[A-Z][A-Z0-9_]{0,127}$/u.test(code))) fail('QUALIFICATION_HTTP_RESPONSE');
    response = {...projectOperatorPublicResult(selected), ...terminal, ...(code === undefined ? {} : {code})};
  }
  return {httpStatus, responseHash:digest(bytes), response};
}

function requestHttp(options, body) {
  return new Promise((resolve, reject) => {
    const request = http.request({...options, agent:false}, response => {
      const chunks = [];
      let length = 0;
      response.on('data', chunk => {
        length += chunk.length;
        if (length > MAXIMUM_OUTPUT_BYTES) response.destroy(Object.assign(new Error(), {code:'QUALIFICATION_HTTP_BOUNDS'}));
        else chunks.push(chunk);
      });
      response.on('end', () => resolve({httpStatus:response.statusCode, bytes:Buffer.concat(chunks)}));
      response.on('error', reject);
    });
    const timer = setTimeout(() => request.destroy(Object.assign(new Error(), {code:'QUALIFICATION_HTTP_TIMEOUT'})), 25_000);
    request.on('close', () => clearTimeout(timer));
    request.on('error', reject);
    request.end(body);
  });
}

async function agentRequest(config, payload) {
  // A request never initializes or recovers credential files. Hold the trusted
  // parent and read one existing private leaf under the actual Agent identity.
  const [{openAgentTrustedParent}, {createAgentEnrollmentDescriptor}] = await Promise.all([
    import('../src/kernel/trusted-path.mjs'), import('../src/agent/credential.mjs'),
  ]);
  const guard = openAgentTrustedParent({mode:'cdp-testnet', trustedAncestor:config.trustedAncestor,
    agentUid:Number(config.agentUid), targetFile:config.agentCredentialPath,
    terminalOwnerUid:Number(config.agentUid), terminalMode:0o700, role:'agent-private'});
  let descriptor;
  let credentialBytes;
  let credential;
  try {
    descriptor = guard.openLeaf(fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
    const before = fs.fstatSync(descriptor, {bigint:true});
    if (!before.isFile() || before.uid !== BigInt(config.agentUid) || before.gid !== BigInt(config.agentGid)
        || (before.mode & 0o7777n) !== 0o600n || before.nlink !== 1n
        || before.size <= 0n || before.size > 1024n) fail('QUALIFICATION_WORKER_CREDENTIAL');
    credentialBytes = Buffer.alloc(Number(before.size) + 1);
    let offset = 0;
    while (offset < credentialBytes.length) {
      const count = fs.readSync(descriptor, credentialBytes, offset, credentialBytes.length - offset, offset);
      if (count === 0) break;
      offset += count;
    }
    credential = JSON.parse(new TextDecoder('utf-8', {fatal:true}).decode(credentialBytes.subarray(0, offset)));
    createAgentEnrollmentDescriptor({credential}); // Existing closed credential grammar.
    if (offset !== Number(before.size)
        || !credentialBytes.subarray(0, offset).equals(Buffer.from(`${canonical(credential)}\n`))) fail('QUALIFICATION_WORKER_CREDENTIAL');
    const after = fs.fstatSync(descriptor, {bigint:true});
    if (['dev', 'ino', 'mode', 'uid', 'gid', 'nlink', 'size', 'mtimeNs', 'ctimeNs']
      .some(field => before[field] !== after[field])) fail('QUALIFICATION_WORKER_CREDENTIAL');
    guard.revalidate();
  } finally {
    credentialBytes?.fill(0);
    try { if (descriptor !== undefined) fs.closeSync(descriptor); } finally { guard.close(); }
  }
  const body = Buffer.from(canonical(payload.body));
  const response = await requestHttp({host:'127.0.0.1', port:8402, method:'POST',
    path:`/agent/v1/invoke/${payload.routeId}`, headers:{'Content-Type':'application/json',
      'Content-Length':body.length, 'X-Agent-Call-Id':payload.callId,
      Authorization:`WalletKernelAgent ${credential.token}`}}, body);
  try { return await projectQualificationHttpResponse('agent-request', response.httpStatus, response.bytes); }
  finally { response.bytes.fill(0); }
}

async function operatorRequest(config, payload) {
  const token = await readOperatorToken(config);
  const body = payload.method === 'POST' ? Buffer.from(canonical(payload.body)) : undefined;
  const response = await requestHttp({socketPath:config.operatorSocketPath, method:payload.method, path:payload.path,
    headers:{Host:'127.0.0.1:8405', Authorization:`Bearer ${token}`,
      ...(body ? {'Content-Type':'application/json', 'Content-Length':body.length} : {})}}, body);
  try { return await projectQualificationHttpResponse('operator-request', response.httpStatus, response.bytes); }
  finally { response.bytes.fill(0); }
}

function probeRead(target, directory = false) {
  let descriptor;
  let bytes;
  try {
    descriptor = fs.openSync(target, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW
      | fs.constants.O_NONBLOCK | (directory ? fs.constants.O_DIRECTORY : 0));
    if (directory) fs.readdirSync(target);
    else { bytes = Buffer.alloc(1); fs.readSync(descriptor, bytes, 0, 1, 0); }
    return 'READABLE';
  } catch (error) { return /^[A-Z][A-Z0-9_]{0,63}$/u.test(error?.code) ? error.code : 'PROBE_ERROR'; }
  finally { bytes?.fill(0); if (descriptor !== undefined) fs.closeSync(descriptor); }
}

function probeWrite(directory) {
  const target = path.join(directory, `.qualification-probe-${process.pid}`);
  let descriptor;
  try {
    descriptor = fs.openSync(target, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
    fs.writeSync(descriptor, Buffer.from('qualification\n'));
    return 'WRITABLE';
  } catch (error) { return /^[A-Z][A-Z0-9_]{0,63}$/u.test(error?.code) ? error.code : 'PROBE_ERROR'; }
  finally { if (descriptor !== undefined) { fs.closeSync(descriptor); fs.unlinkSync(target); } }
}

function boundaryProbes(config, role) {
  const probes = {};
  const add = (name, result, expected) => { probes[name] = {result, expected, passed:expected.includes(result)}; };
  if (role === 'agent') {
    for (const [name, target, directory] of [
      ['authorityDirectoryRead', config.authorityRoot, true], ['databaseRead', config.databasePath, false],
      ['receiptKeyRead', config.receiptKeyPath, false], ['operatorTokenRead', config.operatorTokenPath, false],
      ['environmentSourceRead', config.environmentPath, false], ['evidenceDirectoryRead', config.evidenceRoot, true],
    ]) add(name, probeRead(target, directory), ['EACCES']);
    for (const [name, target] of [['authorityDirectoryWrite', config.authorityRoot],
      ['releaseDirectoryWrite', config.releaseRoot], ['evidenceDirectoryWrite', config.evidenceRoot],
      ['outboxWrite', config.agentRunOutboxPath]]) add(name, probeWrite(target), ['EACCES', 'EROFS']);
    add('outboxRead', probeRead(path.join(config.agentRunOutboxPath, 'qualification-public.json')), ['READABLE']);
    add('inboxWrite', probeWrite(config.enrollmentInboxPath), ['WRITABLE']);
  } else {
    add('agentCredentialRead', probeRead(config.agentCredentialPath), ['EACCES']);
    add('enrollmentRead', probeRead(path.join(config.enrollmentInboxPath, 'enrollment.json')), ['READABLE']);
    add('inboxWrite', probeWrite(config.enrollmentInboxPath), ['EACCES', 'EROFS']);
    add('environmentSourceRead', probeRead(config.environmentPath), ['EACCES']);
  }
  return {passed:Object.values(probes).every(probe => probe.passed), probes};
}

async function run() {
  const input = parseQualificationArguments(process.argv.slice(2));
  const payload = validateQualificationPayload(input.action, await readQualificationInput());
  // Public metadata is the only project import before the exact identity check.
  const {readDeploymentConfig} = await import('../src/kernel/deployment.mjs');
  const config = readDeploymentConfig(input.deploymentPath);
  const role = validateQualificationIdentity({config, action:input.action, platform:process.platform,
    version:process.version, uid:process.getuid?.(), euid:process.geteuid?.(), gid:process.getgid?.(),
    egid:process.getegid?.(), groups:process.getgroups?.(), status:fs.readFileSync('/proc/self/status', 'utf8')});
  if (fileURLToPath(import.meta.url) !== path.join(config.releaseRoot, 'scripts/qualification-authority-worker.mjs')
      || process.execPath !== config.nodePath || fs.realpathSync(process.execPath) !== config.nodePath) fail('QUALIFICATION_WORKER_RELEASE');
  assertImmutablePath(input.deploymentPath, 32_768);
  assertImmutablePath(fileURLToPath(import.meta.url), 65_536);
  assertImmutablePath(config.nodePath, 256_000_000);
  let result;
  if (input.action === 'bootstrap') result = await bootstrap(config);
  else if (input.action === 'agent-init') result = await agentInit(config);
  else if (input.action === 'enroll' || input.action === 'import-isolation') result = await offlineMutation(config, input.action, payload);
  else if (input.action === 'snapshot') result = await snapshot(config);
  else if (input.action === 'agent-request') result = await agentRequest(config, payload);
  else if (input.action === 'operator-request') result = await operatorRequest(config, payload);
  else if (input.action === 'delivered-credential-probe') {
    const observed = probeRead(DELIVERED_CREDENTIAL);
    result = {passed:observed === 'EACCES', probes:{deliveredEnvironmentRead:
      {result:observed, expected:['EACCES'], passed:observed === 'EACCES'}}};
  }
  else result = boundaryProbes(config, role);
  const output = canonical({schemaVersion:1, profile:PROFILE, action:input.action, role, result});
  if (Buffer.byteLength(output) > MAXIMUM_OUTPUT_BYTES) fail('QUALIFICATION_WORKER_OUTPUT');
  process.stdout.write(`${output}\n`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  run().catch(error => {
    const code = /^[A-Z][A-Z0-9_]{0,127}$/u.test(error?.code) ? error.code : 'QUALIFICATION_WORKER_FAILED';
    process.stdout.write(`${canonical({schemaVersion:1, profile:PROFILE, code})}\n`);
    process.exitCode = 1;
  });
}
