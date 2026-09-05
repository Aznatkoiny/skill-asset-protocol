import crypto from 'node:crypto';
import fs from 'node:fs';

import { createCdpWalletAdapter } from '../adapters/cdp-wallet-adapter.mjs';
import { createBaseSepoliaObserver } from '../adapters/base-sepolia-observer.mjs';
import { createSellerEvidenceResolver } from '../adapters/seller-evidence-resolver.mjs';
import { createX402V2Transport } from '../adapters/x402-v2-transport.mjs';
import { createIsolationAttestationRepository, validateIsolationReportBytes } from '../agent/isolation-preflight.mjs';
import { createAgentEnrollmentRepository } from '../kernel/agent-enrollment.mjs';
import { createApprovalQueue } from '../kernel/approval-queue.mjs';
import { createPermitAuthority } from '../kernel/authorized-permit.mjs';
import { createBudgetLedger } from '../kernel/budget-ledger.mjs';
import { canonicalJson, KernelError } from '../kernel/canonical.mjs';
import { createIntentRepository } from '../kernel/intent-builder.mjs';
import { createPolicyRepository } from '../kernel/policy-repository.mjs';
import { createProjectionExporter } from '../kernel/projection-exporter.mjs';
import { loadOrCreateReceiptSigner } from '../kernel/receipt-signing.mjs';
import { createSignedReceiptRepository } from '../kernel/signed-receipts.mjs';
import { openKernelStore } from '../kernel/sqlite-store.mjs';
import { createOperatorAuth, loadOrCreateOperatorToken } from '../operator/auth.mjs';
import { bindingRows, createRuntimeOperatorReads } from './operator-reads.mjs';

function fault(code = 'RUNTIME_AUTHORITY') {
  throw new KernelError(code, 'Installed Wallet Kernel authority refused');
}

/** Compose the durable authority; dependencies replace only external wallet/chain services. */
export function openRuntimeAuthority({ config, routes, pathTrust, clients, now = () => new Date().toISOString() }) {
  // Bootstrap is a separate Operator operation. Startup cannot silently mint
  // a new receipt key, Operator credential, or empty monetary authority.
  for (const filePath of [config.databasePath, config.receiptKeyPath, config.operatorTokenPath]) {
    const stat = fs.lstatSync(filePath, { bigint: true });
    if (!stat.isFile() || stat.uid !== BigInt(pathTrust.kernelUid)
        || stat.nlink !== 1n || (stat.mode & 0o7777n) !== 0o600n || stat.size === 0n) fault();
  }
  const store = openKernelStore({ filePath: config.databasePath, pathTrust, now });
  try {
    const idFactory = (kind) => `${kind}:${crypto.randomUUID()}`;
    const policies = createPolicyRepository(store);
    const activePolicy = policies.active();
    if (!activePolicy) fault('POLICY_CORRUPTION');
    const walletIdentity = Object.freeze({
      address: activePolicy.policy.wallet,
      network: config.network,
    });
    const enrollments = createAgentEnrollmentRepository({ store, now });
    const isolation = createIsolationAttestationRepository({store, now,
      idFactory: () => idFactory('isolation')});
    const intents = createIntentRepository({ store, idFactory, now,
      routeMetadata: Object.freeze(Object.fromEntries(routes.routes.map(route => [route.id,
        Object.freeze({description: route.resourceDescription, mimeType: route.resourceMimeType})]))),
      allowLoopbackHttp: config.mode === 'deterministic',
    });
    const budgets = createBudgetLedger({store, now});
    const approvals = createApprovalQueue({store, idFactory, now});
    const signer = loadOrCreateReceiptSigner(config.receiptKeyPath, {pathTrust});
    const receipts = createSignedReceiptRepository({store, signer, idFactory, now});
    const exporter = createProjectionExporter({store, receipts, signer, now});
    const token = loadOrCreateOperatorToken({filePath: config.operatorTokenPath, pathTrust});
    const operatorAuth = createOperatorAuth({mode: config.mode,
      origin: `http://127.0.0.1:${config.operatorPort}`, token});
    const permitAuthority = createPermitAuthority();
    const walletAdapter = createCdpWalletAdapter({cdpClient: clients.cdpClient,
      walletName: config.cdpWalletName, verifyAndConsume: permitAuthority.verifyAndConsume});
    const observer = createBaseSepoliaObserver({publicClient: clients.publicClient, now});
    const fetchImpl = clients.fetchImpl ?? fetch;
    const transport = createX402V2Transport({fetchImpl, mode: config.mode,
      limits: {requestTimeoutMs: 15_000, maximumResponseBytes: 1_048_576, maximumPaymentHeaderBytes: 16_384}});
    const sellerEvidence = createSellerEvidenceResolver({fetchImpl, mode: config.mode, now,
      limits: {requestTimeoutMs: 5_000, maximumResponseBytes: 16_384}});
    const resolver = Object.freeze({
      observePayment: (binding) => observer.observePayment(binding),
      observeExecution: (binding) => sellerEvidence.observeExecution(binding),
      async observeRefund(binding) {
        const confirmed = await observer.observeRefund(binding);
        if (confirmed.kind !== 'refund_transfer_confirmed') return confirmed;
        const attested = await sellerEvidence.observeRefund(binding);
        if (attested.kind !== 'refund_attested') return attested;
        return Object.freeze({kind: 'refund_attested_and_confirmed',
          attestation: attested.attestation, attestationHash: attested.attestationHash,
          rpcTransferProof: confirmed.rpcTransferProof});
      },
    });
    let closed = false;
    const authority = Object.freeze({
      activePolicy: () => policies.active(),
      activeEnrollment: () => enrollments.active(),
      bindingsForEnrollment: (input) => bindingRows(store, intents, input),
      walletIdentity: () => walletIdentity,
      operatorAuth,
      operatorReads: createRuntimeOperatorReads({store, intents, policies, approvals,
        receipts, exporter, signer, walletIdentity, mode: config.mode}),
      agentAuthDependencies: Object.freeze({store, intents}),
      async createKernelDependencies() {
        return Object.freeze({store, policies, enrollments, intents, budgets, approvals,
          receipts, permitAuthority, walletAdapter, transport, now, idFactory,
          randomBytes: crypto.randomBytes, faultInjector() {}});
      },
      reconcilerDependencies: Object.freeze({store, budgets, receipts, resolver, now, idFactory}),
      recoveryDependencies: Object.freeze({store, intents, budgets, approvals, receipts, now}),
      recoverySessionCloser: (input) => store.transaction(tokenValue =>
        intents.closeBoundSessionInTransaction(tokenValue, input)),
      async close() { if (!closed) {closed = true; store.close();} },
    });
    return Object.freeze({
      authority,
      assertIsolation(admission, {enrollment, release}) {
        const {report, reportHash} = validateIsolationReportBytes(
          Buffer.from(`${canonicalJson(admission.report)}\n`), {
            expectedReportHash: admission.reportHash,
            expectedEnrollmentHash: enrollment.enrollmentHash,
            expectedKernelUid: String(process.getuid()),
            expectedKernelGid: String(process.getgid()),
            expectedReleaseManifestHash: release.releaseManifestHash,
            expectedAuthorityMetadataHash: admission.authorityMetadataHash,
            now,
          });
        const current = isolation.currentFor({enrollmentHash: enrollment.enrollmentHash,
          authorityMetadataHash: admission.authorityMetadataHash,
          releaseManifestHash: release.releaseManifestHash,
          expectedReportHash: reportHash});
        if (!current || store.readOne('SELECT report_json FROM isolation_attestations WHERE id = ?',
          [current.id])?.report_json !== canonicalJson(report)) fault('ISOLATION_BINDING_MISMATCH');
        return Object.freeze({isolation:'verified'});
      },
      async assertObservation() {
        // Identity and chain/USDC facts are checked after local recovery and
        // before any listener or paid request; this never funds a wallet.
        const actual = await walletAdapter.walletIdentity();
        if (actual.network !== walletIdentity.network || actual.address !== walletIdentity.address) {
          fault('CDP_WALLET_IDENTITY_MISMATCH');
        }
        await observer.preflight();
        return Object.freeze({observer: 'verified'});
      },
    });
  } catch (error) {
    store.close();
    if (error instanceof KernelError) throw error;
    fault();
  }
}
