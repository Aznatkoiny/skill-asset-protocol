import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath } from 'node:url';

import { createControlPlane } from '../../src/control-plane.mjs';
import { createAgentEnrollmentRepository } from '../../src/kernel/agent-enrollment.mjs';
import { acquireAuthorityLock } from '../../src/kernel/authority-lock.mjs';
import { canonicalJson, sha256 } from '../../src/kernel/canonical.mjs';
import { createPolicyRepository } from '../../src/kernel/policy-repository.mjs';
import { loadOrCreateReceiptSigner } from '../../src/kernel/receipt-signing.mjs';
import { recoverKernelAuthority } from '../../src/kernel/recovery.mjs';
import { openKernelStore } from '../../src/kernel/sqlite-store.mjs';
import { loadOrCreateOperatorToken } from '../../src/operator/auth.mjs';
import { openRuntimeAuthority } from '../../src/runtime/authority.mjs';
import { createOfflineQualificationClients, OFFLINE_QUALIFICATION as Q,
  readOfflineQualificationJournal } from '../../src/runtime/qualification-clients.mjs';

const CREDENTIAL = Buffer.alloc(32, 0x42);
const ROUTES = {schemaVersion:1, routes:Q.routes.map(({scenario, amountAtomic, ...route}) => route)};
const BASE_POLICY = JSON.parse(fs.readFileSync(new URL('../../policies/base-sepolia.example.json', import.meta.url)));

// Local, same-UID crash coverage only. This fixture never installs a service,
// constructs real provider clients, or represents PID1/OS-isolation evidence.
export function qualificationCrashContext(directory) {
  const pathTrust = Object.freeze({mode:'deterministic', trustedAncestor:directory,
    kernelUid:process.getuid(), agentUid:process.getuid()});
  const config = Object.freeze({mode:'deterministic',
    agentHost:'127.0.0.1', agentPort:8402, operatorHost:'127.0.0.1', operatorPort:8405,
    operatorAdminTransport:'loopback-demo', operatorSocketPath:null,
    operatorConsoleTransport:'loopback-demo', operatorConsoleActivationName:null,
    databasePath:path.join(directory, 'kernel.sqlite'), receiptKeyPath:path.join(directory, 'receipt.pem'),
    operatorTokenPath:path.join(directory, 'operator.token'), policyPath:path.join(directory, 'policy.json'),
    routePath:path.join(directory, 'routes.json'), trustedAncestor:directory,
    expectedAgentUid:process.getuid(), expectedAgentGid:process.getgid(),
    cdpWalletName:Q.environment.CDP_WALLET_NAME, network:Q.network, observer:'deterministic'});
  return {config, pathTrust};
}

export function readQualificationCrashSnapshot(databasePath) {
  const db = new DatabaseSync(databasePath, {readOnly:true, timeout:1000});
  try {
    db.exec('PRAGMA query_only = ON; PRAGMA trusted_schema = OFF; BEGIN;');
    const intents = db.prepare('SELECT id, route_id, session_id, state FROM spend_intents ORDER BY id').all()
      .map(row => ({...row}));
    const reservations = db.prepare(`SELECT intent_id, state, reserved_atomic, committed_atomic,
      released_atomic, unresolved_atomic FROM budget_reservations ORDER BY intent_id`).all().map(row => ({...row}));
    const payments = db.prepare(`SELECT id, intent_id, state, payment_hash, payment_payload_json,
      payment_header, signing_claimed_at, signed_at, retry_started_at FROM payment_attempts ORDER BY id`).all()
      .map(({payment_payload_json:payload, payment_header:header, ...row}) => ({...row,
        payloadHash:payload === null ? null : sha256(payload),
        headerHash:header === null ? null : sha256(header),
        signatureHash:payload === null ? null : sha256(JSON.parse(payload).payload.signature)}));
    const outcomes = db.prepare('SELECT intent_id, status, reason_code FROM buyer_outcomes ORDER BY intent_id').all()
      .map(row => ({...row}));
    db.exec('COMMIT');
    return {intents, reservations, payments, outcomes};
  } finally {db.close();}
}

function bootstrap({config, pathTrust}, now) {
  const store = openKernelStore({filePath:config.databasePath, pathTrust, now});
  try {
    createPolicyRepository(store).apply({...BASE_POLICY, wallet:Q.walletAddress,
      sellers:BASE_POLICY.sellers.map(seller => ({...seller, origin:Q.sellerOrigin}))}, now());
    loadOrCreateReceiptSigner(config.receiptKeyPath, {pathTrust});
    loadOrCreateOperatorToken({filePath:config.operatorTokenPath, pathTrust});
    const descriptor = {schemaVersion:1, agentInstanceId:Buffer.alloc(16, 0x42).toString('base64url'),
      credentialDigest:sha256(CREDENTIAL), agentUid:String(process.getuid()), agentGid:String(process.getgid())};
    createAgentEnrollmentRepository({store, now}).enroll({descriptor,
      expectedDescriptorHash:sha256(canonicalJson(descriptor)), operatorIdHash:sha256('crash qualification operator'),
      mode:'deterministic', kernelUid:process.getuid(), kernelGid:process.getgid(),
      expectedAgentUid:process.getuid(), expectedAgentGid:process.getgid()});
  } finally {store.close();}
}

async function run() {
  const [directory, scenario, phase] = process.argv.slice(2);
  if (!path.isAbsolute(directory) || !['signing-interruption', 'retry-interruption'].includes(scenario)
      || !['crash', 'recover'].includes(phase) || process.argv.length !== 5 || !process.send) {
    throw new Error('QUALIFICATION_CRASH_ARGUMENTS');
  }
  const context = qualificationCrashContext(directory);
  const {config, pathTrust} = context;
  const now = () => new Date().toISOString();
  if (phase === 'crash') bootstrap(context, now);
  let lock;
  let provider;
  let composition;
  const plane = await createControlPlane({env:{WALLET_KERNEL_MODE:'deterministic'}, dependencies:{
    loadConfig:() => ({publicConfig:config, assertCredentialPresence(){}}),
    readRouteDocument:() => ROUTES,
    acquireAuthorityLock({role}) {
      lock = acquireAuthorityLock({databasePath:config.databasePath, role, pathTrust});
      return lock;
    },
    openAuthority({routes}) {
      provider = createOfflineQualificationClients({environment:{...Q.environment},
        config:{...config, mode:'cdp-testnet'}, routes, pathTrust, authorityLock:lock});
      try {composition = openRuntimeAuthority({config, routes, pathTrust, clients:provider.clients, now});}
      catch (error) {provider.close(); throw error;}
      return Object.freeze({...composition.authority, async close() {
        try {await composition.authority.close();} finally {provider.close();}
      }});
    },
    recoverAuthority(input) {
      try {return recoverKernelAuthority(input);}
      catch (error) {
        // This fixture contains public synthetic inputs only. Keep the error
        // diagnostic bounded and local to the child-process test.
        const causes = [];
        for (let cause = error; cause && causes.length < 4; cause = cause.cause) {
          causes.push({code:cause.code ?? null, message:String(cause.message).slice(0, 500)});
        }
        process.send({type:'recovery-diagnostic', causes});
        throw error;
      }
    },
  }});
  let reportedBarrier = false;
  const keepAlive = setInterval(() => {
    if (phase !== 'crash' || reportedBarrier) return;
    // Running this callback in the same child event loop proves the provider's
    // synchronous journal fsync returned before the parent sends SIGKILL.
    const journal = readOfflineQualificationJournal({databasePath:config.databasePath, pathTrust});
    const expected = scenario === 'signing-interruption' ? 'signer_blocked' : 'retry_blocked';
    if (journal.lastEvent?.kind === expected) {
      reportedBarrier = true;
      process.send({type:'durable-barrier', kind:expected, eventHash:journal.lastEvent.eventHash});
    }
  }, 10);
  try {
    await composition.assertObservation();
    const request = {route:`qualification-${scenario}`, callId:Buffer.alloc(32, 0x62).toString('base64url'),
      method:'POST', body:'{"qualification":true}'};
    process.send({type:'ready', phase, pid:process.pid, scope:'local-process-offline',
      requestHash:sha256(canonicalJson(request))});
    const response = await plane.apps.agent.request(`http://127.0.0.1:8402/agent/v1/invoke/${request.route}`, {
      method:request.method, headers:{authorization:`WalletKernelAgent ${CREDENTIAL.toString('base64url')}`,
        'content-type':'application/json', 'x-agent-call-id':request.callId}, body:request.body,
    });
    process.send({type:'response', phase, status:response.status, body:await response.json(),
      snapshot:readQualificationCrashSnapshot(config.databasePath)});
  } finally {
    clearInterval(keepAlive);
    await plane.close();
    process.disconnect();
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  run().catch(error => {
    process.send?.({type:'failure', code:error.code ?? 'QUALIFICATION_CRASH_WORKER_FAILED'});
    process.exitCode = 1;
    if (process.connected) process.disconnect();
  });
}
