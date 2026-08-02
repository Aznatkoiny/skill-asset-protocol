import { types as utilTypes } from 'node:util';

import {
  canonicalJson,
  canonicalToken,
  canonicalTimestamp,
  exactRecord,
  KernelError,
  sha256,
} from './canonical.mjs';
import { deriveAuthorizationWindow } from './authorized-permit.mjs';
import { WalletSigningError } from '../adapters/wallet-adapter-contract.mjs';
import {
  evaluateSpendPolicy,
  projectPaymentRequired,
} from './policy-engine.mjs';

const DEPENDENCY_NAMES = Object.freeze([
  'store',
  'policies',
  'enrollments',
  'intents',
  'budgets',
  'approvals',
  'receipts',
  'permitAuthority',
  'walletAdapter',
  'transport',
  'authorityMutationCoordinator',
  'markAuthorityUnhealthy',
  'now',
  'idFactory',
  'randomBytes',
  'faultInjector',
]);

const FUNCTION_DEPENDENCIES = new Set([
  'markAuthorityUnhealthy',
  'now',
  'idFactory',
  'randomBytes',
  'faultInjector',
]);

export const KERNEL_FAULT_POINTS = Object.freeze([
  'after_intent_commit',
  'after_challenge_commit',
  'after_reservation_commit',
  'after_signing_claim_commit',
  'after_signer_return',
  'after_signed_payment_commit',
  'after_retry_claim_commit',
  'after_paid_response',
  'after_settlement_commit',
  'before_terminal_receipt_commit',
]);

function readDependencies(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || utilTypes.isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new TypeError('Wallet Kernel dependencies must be one plain object');
  }
  const keys = Reflect.ownKeys(value);
  if (keys.length !== DEPENDENCY_NAMES.length
      || keys.some((key) => typeof key !== 'string' || !DEPENDENCY_NAMES.includes(key))) {
    throw new TypeError('Wallet Kernel dependencies have an invalid shape');
  }
  const dependencies = {};
  for (const name of DEPENDENCY_NAMES) {
    const descriptor = Object.getOwnPropertyDescriptor(value, name);
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) {
      throw new TypeError(`Wallet Kernel dependency ${name} must be an enumerable data property`);
    }
    const dependency = descriptor.value;
    if (FUNCTION_DEPENDENCIES.has(name)) {
      if (typeof dependency !== 'function' || utilTypes.isProxy(dependency)) {
        throw new TypeError(`Wallet Kernel dependency ${name} must be a non-proxy function`);
      }
    } else if (!dependency || typeof dependency !== 'object' || utilTypes.isProxy(dependency)) {
      throw new TypeError(`Wallet Kernel dependency ${name} must be a non-proxy object`);
    }
    dependencies[name] = dependency;
  }
  return Object.freeze(dependencies);
}

function canonicalHash(value, code, label) {
  if (typeof value !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(value)) {
    throw new KernelError(code, `${label} must be one canonical SHA-256 hash`);
  }
  return value;
}

function shallowRecord(value, required, optional, code, label) {
  if (!value || typeof value !== 'object' || utilTypes.isProxy(value)
      || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new KernelError(code, `${label} must be one plain object`);
  }
  const allowed = new Set([...required, ...optional]);
  const keys = Reflect.ownKeys(value);
  if (required.some((key) => !Object.hasOwn(value, key))
      || keys.some((key) => typeof key !== 'string' || !allowed.has(key))) {
    throw new KernelError(code, `${label} fields do not match the closed schema`);
  }
  const result = {};
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) {
      throw new KernelError(code, `${label} fields must be enumerable data properties`);
    }
    result[key] = descriptor.value;
  }
  return Object.freeze(result);
}

function isNonceCollision(error) {
  return error?.code === 'ERR_SQLITE_ERROR'
    && error?.errcode === 2067
    && error?.message === 'UNIQUE constraint failed: payment_attempts.nonce';
}

function challengeDenialReason(error) {
  if (error?.code === 'PAYMENT_REQUIRED_TOO_LARGE') {
    return 'PAYMENT_CHALLENGE_OVERSIZED';
  }
  if (error?.code === 'CHALLENGE_SCHEMA'
      || (typeof error?.code === 'string' && error.code.startsWith('PAYMENT_REQUIRED_'))) {
    return 'PAYMENT_CHALLENGE_MALFORMED';
  }
  return null;
}

export function createWalletKernel(value) {
  const dependencies = readDependencies(value);
  const {
    policies,
    enrollments,
    intents,
    budgets,
    approvals,
    receipts,
    store,
    transport,
    walletAdapter,
    permitAuthority,
    authorityMutationCoordinator,
    markAuthorityUnhealthy,
    now,
    idFactory,
    randomBytes,
    faultInjector,
  } = dependencies;
  const inFlightByIntent = new Map();
  let agentSessionUnavailable = false;

  const runMutation = (operation) => authorityMutationCoordinator.runExclusive(operation);

  const assertAgentSessionAvailable = () => {
    if (agentSessionUnavailable) {
      throw new KernelError(
        'AGENT_SESSION_UNAVAILABLE',
        'this Kernel instance closed its agent session and cannot hot-rotate or reopen it',
      );
    }
  };

  const openOrResumeSession = async (input) => {
    const request = exactRecord(input, [
      'agentInstanceId',
      'walletAddress',
      'policyVersionId',
    ], [], 'SESSION_SCHEMA', 'open session request');
    return await runMutation(() => {
      assertAgentSessionAvailable();
      return intents.openOrResumeSession(request);
    });
  };

  const applyPolicy = async (input) => {
    const request = exactRecord(input, [
      'document',
      'expectedPolicyHash',
    ], [], 'POLICY_APPLY_SCHEMA', 'policy apply request');
    const expectedPolicyHash = canonicalHash(
      request.expectedPolicyHash,
      'POLICY_APPLY_SCHEMA',
      'expected policy hash',
    );
    let actualPolicyHash;
    try {
      actualPolicyHash = sha256(canonicalJson(request.document));
    } catch (cause) {
      throw new KernelError(
        'POLICY_APPLY_SCHEMA',
        'policy document must be inert canonical data',
        { cause },
      );
    }
    if (actualPolicyHash !== expectedPolicyHash) {
      throw new KernelError(
        'POLICY_CONFIRMATION_STALE',
        'displayed policy hash differs from the submitted document',
      );
    }
    assertAgentSessionAvailable();
    const configuredWallet = await walletAdapter.walletIdentity();
    return await runMutation(() => {
      assertAgentSessionAvailable();
      if (configuredWallet?.address !== request.document.wallet) {
        throw new KernelError(
          'WALLET_ROTATION_REQUIRES_OFFLINE_RESTART',
          'policy wallet differs from the wallet configured for this Kernel instance',
        );
      }
      return policies.apply(request.document, now());
    });
  };

  const revokeAgent = async (input) => {
    const request = exactRecord(input, [
      'agentInstanceId',
      'expectedEnrollmentHash',
      'operatorIdHash',
    ], [], 'AGENT_REVOCATION_SCHEMA', 'agent revocation');
    canonicalHash(
      request.expectedEnrollmentHash,
      'AGENT_REVOCATION_SCHEMA',
      'expected enrollment hash',
    );
    canonicalHash(request.operatorIdHash, 'AGENT_REVOCATION_SCHEMA', 'operator ID hash');
    return await runMutation(() => enrollments.revoke(request));
  };

  const approvePending = async (input) => {
    const request = exactRecord(input, [
      'approvalId',
      'expectedIntentHash',
      'operatorIdHash',
    ], [], 'APPROVAL_DECISION_SCHEMA', 'approval decision');
    canonicalHash(
      request.expectedIntentHash,
      'APPROVAL_DECISION_SCHEMA',
      'expected intent hash',
    );
    canonicalHash(request.operatorIdHash, 'APPROVAL_DECISION_SCHEMA', 'operator ID hash');
    const expired = await expireDueApprovals({ limit: 1_000 });
    if (expired.some((entry) => entry.approvalId === request.approvalId)) {
      throw new KernelError(
        'APPROVAL_STATE_CONFLICT',
        'approval expired before the operator decision',
      );
    }
    return await runMutation(() => approvals.approve(request));
  };

  const denyPending = async (input) => {
    const request = exactRecord(input, [
      'approvalId',
      'expectedIntentHash',
      'operatorIdHash',
      'reasonCode',
    ], [], 'APPROVAL_DECISION_SCHEMA', 'approval denial');
    canonicalHash(
      request.expectedIntentHash,
      'APPROVAL_DECISION_SCHEMA',
      'expected intent hash',
    );
    canonicalHash(request.operatorIdHash, 'APPROVAL_DECISION_SCHEMA', 'operator ID hash');
    if (request.reasonCode !== 'OPERATOR_DENIED') {
      throw new KernelError(
        'APPROVAL_DENIAL_REASON',
        'operator denial reason must be OPERATOR_DENIED',
      );
    }
    const expired = await expireDueApprovals({ limit: 1_000 });
    if (expired.some((entry) => entry.approvalId === request.approvalId)) {
      throw new KernelError(
        'APPROVAL_STATE_CONFLICT',
        'approval expired before the operator decision',
      );
    }
    const approval = approvals.get(request.approvalId);
    if (!approval || approval.intentHash !== request.expectedIntentHash) {
      throw new KernelError('APPROVAL_BINDING_MISMATCH', 'displayed approval binding is stale');
    }
    const intent = intents.getIntent(approval.intentId);
    if (intent === null) {
      throw new KernelError('INTENT_UNKNOWN', 'approval Spend Intent does not exist');
    }
    return await runMutation(() => {
      const recordedAt = canonicalTimestamp(now(), 'approval denial outcome recordedAt');
      store.transaction((token) => {
        receipts.assertParityInTransaction(token);
        approvals.denyForIntentInTransaction(token, {
          approvalId: approval.approvalId,
          intentId: approval.intentId,
          expectedIntentHash: request.expectedIntentHash,
          operatorIdHash: request.operatorIdHash,
          reasonCode: request.reasonCode,
        });
        intents.transitionInTransaction(token, {
          intentId: approval.intentId,
          expectedState: 'approval_pending',
          nextState: 'terminal',
          reasonCode: request.reasonCode,
        });
        store.within(token, ({ db, appendEvent }) => {
          db.prepare(`INSERT INTO buyer_outcomes
            (intent_id, status, reason_code, revision, recorded_at)
            VALUES (?, 'payment_denied', ?, 1, ?)`).run(
            approval.intentId,
            request.reasonCode,
            recordedAt,
          );
          appendEvent({
            entityType: 'buyer_outcome',
            entityId: approval.intentId,
            eventType: 'buyer_outcome.recorded',
            data: {
              status: 'payment_denied',
              reasonCode: request.reasonCode,
              revision: 1,
              recordedAt,
            },
          });
        });
      });
      const receipt = issueTerminalReceipt(approval.intentId);
      return Object.freeze({
        requestId: intent.requestId,
        approvalId: approval.approvalId,
        intentId: approval.intentId,
        status: 'payment_denied',
        reasonCode: request.reasonCode,
        receipt,
      });
    });
  };

  const issueTerminalReceipt = (intentId) => {
    faultInjector('before_terminal_receipt_commit', Object.freeze({ intentId }));
    try {
      return receipts.issueForTerminal({ intentId });
    } catch (error) {
      try {
        markAuthorityUnhealthy('RECEIPT_PARITY_REQUIRED');
      } catch (markError) {
        throw new KernelError(
          'RECEIPT_PARITY_REQUIRED',
          'terminal receipt failed and the authority fail-stop hook also failed',
          { cause: markError },
        );
      }
      throw error;
    }
  };

  const failStopAfterSignerReturn = (error) => {
    try {
      markAuthorityUnhealthy('AUTHORITY_UNHEALTHY');
    } catch (cause) {
      throw new KernelError(
        'AUTHORITY_UNHEALTHY',
        'post-signer authority failed and the authority fail-stop hook also failed',
        { cause },
      );
    }
    throw error;
  };

  const expireApprovalCandidate = async (candidate, sweepAt) => await runMutation(() => {
    const recordedAt = canonicalTimestamp(now(), 'approval expiry outcome recordedAt');
    let expired;
    store.transaction((token) => {
      receipts.assertParityInTransaction(token);
      expired = approvals.expireForIntentInTransaction(token, {
        approvalId: candidate.approvalId,
        intentId: candidate.intentId,
        expectedIntentHash: candidate.intentHash,
        at: sweepAt,
      });
      if (expired === null) return;
      intents.transitionInTransaction(token, {
        intentId: candidate.intentId,
        expectedState: 'approval_pending',
        nextState: 'terminal',
        reasonCode: 'APPROVAL_EXPIRED',
      });
      store.within(token, ({ db, appendEvent }) => {
        db.prepare(`INSERT INTO buyer_outcomes
          (intent_id, status, reason_code, revision, recorded_at)
          VALUES (?, 'payment_denied', 'APPROVAL_EXPIRED', 1, ?)`).run(
          candidate.intentId,
          recordedAt,
        );
        appendEvent({
          entityType: 'buyer_outcome',
          entityId: candidate.intentId,
          eventType: 'buyer_outcome.recorded',
          data: {
            status: 'payment_denied',
            reasonCode: 'APPROVAL_EXPIRED',
            revision: 1,
            recordedAt,
          },
        });
      });
    });
    if (expired === null) return null;
    const intent = intents.getIntent(candidate.intentId);
    const receipt = issueTerminalReceipt(candidate.intentId);
    return Object.freeze({
      requestId: intent.requestId,
      approvalId: candidate.approvalId,
      intentId: candidate.intentId,
      status: 'payment_denied',
      reasonCode: 'APPROVAL_EXPIRED',
      receipt,
    });
  });

  const expireDueApprovals = async (input) => {
    const request = exactRecord(
      input,
      ['limit'],
      [],
      'APPROVAL_EXPIRY_SCHEMA',
      'approval expiry sweep',
    );
    if (!Number.isSafeInteger(request.limit) || request.limit < 1 || request.limit > 1_000) {
      throw new KernelError(
        'APPROVAL_EXPIRY_SCHEMA',
        'approval expiry sweep limit must be between 1 and 1000',
      );
    }
    const sweepAt = canonicalTimestamp(now(), 'approval expiry sweep time');
    const due = approvals.listDue({ at: sweepAt, limit: request.limit });
    const results = [];
    for (const candidate of due) {
      const result = await expireApprovalCandidate(candidate, sweepAt);
      if (result !== null) results.push(result);
    }
    return Object.freeze(results);
  };

  const terminalizeOrdinary = async (intent, result) => await runMutation(() => {
    const recordedAt = canonicalTimestamp(now(), 'ordinary outcome recordedAt');
    store.transaction((token) => {
      receipts.assertParityInTransaction(token);
      intents.transitionInTransaction(token, {
        intentId: intent.id,
        expectedState: result.expectedState ?? 'captured',
        nextState: 'terminal',
        reasonCode: result.reasonCode,
      });
      return store.within(token, ({ db, appendEvent }) => {
        const responseHash = result.body === null ? null : sha256(result.body);
        const metadataJson = canonicalJson({ reasonCode: result.reasonCode });
        db.prepare(`INSERT INTO execution_outcomes
          (intent_id, state, http_status, response_hash, metadata_json, recorded_at)
          VALUES (?, ?, ?, ?, ?, ?)`).run(
          intent.id,
          result.executionState,
          result.upstreamStatus,
          responseHash,
          metadataJson,
          recordedAt,
        );
        db.prepare(`INSERT INTO buyer_outcomes
          (intent_id, status, reason_code, revision, recorded_at)
          VALUES (?, ?, ?, 1, ?)`).run(
          intent.id,
          result.status,
          result.reasonCode,
          recordedAt,
        );
        appendEvent({
          entityType: 'execution_outcome',
          entityId: intent.id,
          eventType: 'execution.recorded',
          data: {
            state: result.executionState,
            httpStatus: result.upstreamStatus,
            responseHash,
            metadataHash: sha256(metadataJson),
            reasonCode: result.reasonCode,
            recordedAt,
          },
        });
        appendEvent({
          entityType: 'buyer_outcome',
          entityId: intent.id,
          eventType: 'buyer_outcome.recorded',
          data: {
            status: result.status,
            reasonCode: result.reasonCode,
            revision: 1,
            recordedAt,
          },
        });
      });
    });
    const receipt = issueTerminalReceipt(intent.id);
    return Object.freeze({
      requestId: intent.requestId,
      status: result.status,
      reasonCode: result.reasonCode,
      upstreamStatus: result.upstreamStatus,
      body: result.body === null ? null : Buffer.from(result.body),
      receipt,
    });
  });

  const terminalizeWithoutExecution = async (intent, {
    expectedState,
    status,
    reasonCode,
  }) => await runMutation(() => {
    const recordedAt = canonicalTimestamp(now(), 'terminal outcome recordedAt');
    store.transaction((token) => {
      receipts.assertParityInTransaction(token);
      intents.transitionInTransaction(token, {
        intentId: intent.id,
        expectedState,
        nextState: 'terminal',
        reasonCode,
      });
      return store.within(token, ({ db, appendEvent }) => {
        db.prepare(`INSERT INTO buyer_outcomes
          (intent_id, status, reason_code, revision, recorded_at)
          VALUES (?, ?, ?, 1, ?)`).run(intent.id, status, reasonCode, recordedAt);
        appendEvent({
          entityType: 'buyer_outcome',
          entityId: intent.id,
          eventType: 'buyer_outcome.recorded',
          data: { status, reasonCode, revision: 1, recordedAt },
        });
      });
    });
    const receipt = issueTerminalReceipt(intent.id);
    return Object.freeze({
      requestId: intent.requestId,
      status,
      reasonCode,
      receipt,
    });
  });

  const evaluateChallenge = async ({ intent, request, paymentRequired, persist = true }) => {
    const challengeReceivedAt = canonicalTimestamp(now(), 'challenge receivedAt');
    const session = intents.getSession(intent.sessionId);
    const policyVersion = policies.get(session.policyVersionId);
    if (!policyVersion) {
      throw new KernelError('POLICY_VERSION_MISSING', 'Spend Session PolicyVersion is missing');
    }
    const wallet = await walletAdapter.walletIdentity();
    const budget = budgets.snapshot({
      sessionId: intent.sessionId,
      sellerOrigin: intent.sellerOrigin,
      at: challengeReceivedAt,
    });
    const pendingApprovalCount = approvals.list({ limit: 1_000, state: 'pending' }).length;
    const evaluation = evaluateSpendPolicy({
      policy: policyVersion.policy,
      policyVersion: { id: policyVersion.id, hash: policyVersion.hash },
      intent: {
        id: intent.id,
        method: intent.method,
        requestUrl: request.requestUrl,
        sellerOrigin: intent.sellerOrigin,
        resourcePath: intent.resourcePath,
        walletAddress: intent.walletAddress,
      },
      wallet,
      paymentRequired,
      challengeReceivedAtMs: Date.parse(challengeReceivedAt),
      nowMs: Date.parse(challengeReceivedAt),
      budgetSnapshot: {
        sellerSessionExposureAtomic: budget.sellerSessionExposureAtomic,
        sessionExposureAtomic: budget.sessionExposureAtomic,
        rolling24hExposureAtomic: budget.rolling24hExposureAtomic,
        pendingApprovalCount,
      },
    });
    if (persist) {
      await runMutation(() => store.transaction((token) => {
        receipts.assertParityInTransaction(token);
        const challenged = intents.attachChallengeInTransaction(token, {
          intentId: intent.id,
          paymentRequired,
          challengeReceivedAt,
        });
        policies.recordDecisionInTransaction(token, {
          intentId: intent.id,
          policyVersionId: policyVersion.id,
          evaluation,
          decidedAt: challenged.updatedAt,
        });
      }));
      faultInjector('after_challenge_commit', Object.freeze({ intentId: intent.id }));
    }
    return Object.freeze({ challengeReceivedAt, evaluation, policyVersion, wallet });
  };

  const approvalRequiredResult = (intent, approval) => Object.freeze({
    requestId: intent.requestId,
    status: 'payment_approval_required',
    reasonCode: 'HUMAN_APPROVAL_REQUIRED',
    expiresAt: approval.expiresAt,
    receipt: null,
  });

  const requestApproval = async (intent, evaluation, policyVersionId) => {
    await expireDueApprovals({ limit: 1_000 });
    const approval = await runMutation(() => store.transaction((token) => {
      receipts.assertParityInTransaction(token);
      const created = approvals.requestInTransaction(token, {
        intentId: intent.id,
        intentHash: intent.intentHash,
        challengeHash: evaluation.challengeHash,
        quoteId: evaluation.quoteId,
        amountCeilingAtomic: evaluation.amountCeilingAtomic,
        walletAddress: intent.walletAddress,
        policyVersionId,
        acceptedIndex: evaluation.acceptedIndex,
      });
      intents.transitionInTransaction(token, {
        intentId: intent.id,
        expectedState: 'challenged',
        nextState: 'approval_pending',
        reasonCode: 'HUMAN_APPROVAL_REQUIRED',
      });
      return created;
    }));
    return approvalRequiredResult(intent, approval);
  };

  const reserveAutomatic = async ({ intent, evaluation, policyVersion }) => {
    const challenged = intents.getIntent(intent.id);
    await runMutation(() => store.transaction((token) => {
      receipts.assertParityInTransaction(token);
      intents.transitionInTransaction(token, {
        intentId: intent.id,
        expectedState: 'challenged',
        nextState: 'authorized',
        reasonCode: 'POLICY_ALLOWED',
      });
      budgets.reserveInTransaction(token, {
        intentId: intent.id,
        amountAtomic: evaluation.amountCeilingAtomic,
      });
      store.within(token, ({ db, appendEvent }) => {
        const createdAt = canonicalTimestamp(now(), 'PaymentAttempt createdAt');
        const attemptId = idFactory('payment');
        db.prepare(`INSERT INTO payment_attempts
          (id, intent_id, state, payment_required_projection_json, accepted_index,
           quote_id, created_at, updated_at)
          VALUES (?, ?, 'reserved', ?, ?, ?, ?, ?)`).run(
          attemptId,
          intent.id,
          challenged.challengeProjectionJson,
          evaluation.acceptedIndex,
          evaluation.quoteId,
          createdAt,
          createdAt,
        );
        appendEvent({
          entityType: 'payment_attempt',
          entityId: attemptId,
          eventType: 'payment.reserved',
          data: {
            intentId: intent.id,
            policyVersionId: policyVersion.id,
            quoteId: evaluation.quoteId,
            createdAt,
          },
        });
      });
      // Reload active session and wallet authority in the same transaction. Any
      // failure here rolls back the payment-attempt claim above before signing.
      intents.transitionInTransaction(token, {
        intentId: intent.id,
        expectedState: 'authorized',
        nextState: 'reserved',
        reasonCode: 'BUDGET_RESERVED',
      });
    }));
    faultInjector('after_reservation_commit', Object.freeze({ intentId: intent.id }));
  };

  const reserveApproved = async ({ intent, evaluation, policyVersion, approval }) => {
    await runMutation(() => store.transaction((token) => {
      receipts.assertParityInTransaction(token);
      const consumed = approvals.consumeForInTransaction(token, {
        intentId: intent.id,
        intentHash: intent.intentHash,
        challengeHash: evaluation.challengeHash,
        quoteId: evaluation.quoteId,
        amountCeilingAtomic: evaluation.amountCeilingAtomic,
        walletAddress: intent.walletAddress,
        policyVersionId: policyVersion.id,
        acceptedIndex: evaluation.acceptedIndex,
        expiresAt: approval.expiresAt,
      });
      if (!consumed) {
        throw new KernelError('APPROVAL_EXPIRED', 'approved spend authority is no longer usable');
      }
      intents.transitionInTransaction(token, {
        intentId: intent.id,
        expectedState: 'approval_pending',
        nextState: 'authorized',
        reasonCode: 'APPROVAL_CONSUMED',
      });
      budgets.reserveInTransaction(token, {
        intentId: intent.id,
        amountAtomic: evaluation.amountCeilingAtomic,
      });
      store.within(token, ({ db, appendEvent }) => {
        const createdAt = canonicalTimestamp(now(), 'PaymentAttempt createdAt');
        const attemptId = idFactory('payment');
        db.prepare(`INSERT INTO payment_attempts
          (id, intent_id, state, payment_required_projection_json, accepted_index,
           quote_id, created_at, updated_at)
          VALUES (?, ?, 'reserved', ?, ?, ?, ?, ?)`).run(
          attemptId,
          intent.id,
          intent.challengeProjectionJson,
          evaluation.acceptedIndex,
          evaluation.quoteId,
          createdAt,
          createdAt,
        );
        appendEvent({
          entityType: 'payment_attempt',
          entityId: attemptId,
          eventType: 'payment.reserved',
          data: {
            intentId: intent.id,
            policyVersionId: policyVersion.id,
            quoteId: evaluation.quoteId,
            createdAt,
          },
        });
      });
      intents.transitionInTransaction(token, {
        intentId: intent.id,
        expectedState: 'authorized',
        nextState: 'reserved',
        reasonCode: 'BUDGET_RESERVED',
      });
    }));
    faultInjector('after_reservation_commit', Object.freeze({ intentId: intent.id }));
  };

  const signingClaim = async ({
    intent,
    request,
    paymentRequired,
    evaluation,
    policyVersion,
    approvalExpiresAt = null,
  }) => {
    const claimed = await runMutation(() => store.transaction((token) => {
      receipts.assertParityInTransaction(token);
      const at = canonicalTimestamp(now(), 'signing claimedAt');
      const snapshot = budgets.snapshotInTransaction(token, {
        sessionId: intent.sessionId,
        sellerOrigin: intent.sellerOrigin,
        at,
      });
      if (snapshot.walletBlocked) {
        throw new KernelError(
          'WALLET_RECOVERY_REQUIRED',
          'wallet recovery must complete before a signing claim',
        );
      }
      const selected = paymentRequired.accepts[evaluation.acceptedIndex];
      const atMs = Date.parse(at);
      const challengeDeadlineMs = Date.parse(intent.challengeReceivedAt)
        + policyVersion.policy.challengeMaxAgeMs;
      const approvalDeadlineMs = approvalExpiresAt === null
        ? Number.POSITIVE_INFINITY
        : Date.parse(approvalExpiresAt);
      const authorizationDeadlineMs = Math.min(challengeDeadlineMs, approvalDeadlineMs);
      if (!Number.isSafeInteger(challengeDeadlineMs)
          || !Number.isFinite(atMs)
          || !Number.isFinite(authorizationDeadlineMs)
          || Math.floor(authorizationDeadlineMs / 1_000) <= Math.floor(atMs / 1_000)) {
        throw new KernelError(
          'CHALLENGE_EXPIRED',
          'challenge authorization window expired before the signing claim',
        );
      }
      const window = deriveAuthorizationWindow({
        nowMs: atMs,
        challengeReceivedAtMs: Date.parse(intent.challengeReceivedAt),
        challengeMaxAgeMs: policyVersion.policy.challengeMaxAgeMs,
        maxTimeoutSeconds: selected.maxTimeoutSeconds,
        approvalExpiresAt,
        randomBytes,
      });
      store.within(token, ({ db, appendEvent }) => {
        const changed = db.prepare(`UPDATE payment_attempts
          SET state = 'signing', nonce = ?, valid_after = ?, valid_before = ?,
              signing_claimed_at = ?, updated_at = ?
          WHERE intent_id = ? AND state = 'reserved'
            AND nonce IS NULL AND valid_after IS NULL AND valid_before IS NULL
            AND signing_claimed_at IS NULL`).run(
          window.nonce,
          window.validAfter,
          window.validBefore,
          at,
          at,
          intent.id,
        );
        if (changed.changes !== 1n) {
          throw new KernelError('PAYMENT_ATTEMPT_STATE', 'signing claim lost its race');
        }
        appendEvent({
          entityType: 'payment_attempt',
          entityId: intent.id,
          eventType: 'payment.signing_claimed',
          data: { ...window, signingClaimedAt: at },
        });
      });
      intents.transitionInTransaction(token, {
        intentId: intent.id,
        expectedState: 'reserved',
        nextState: 'signing',
        reasonCode: 'SIGNING_CLAIMED',
      });
      return Object.freeze({
        intentId: intent.id,
        intentHash: intent.intentHash,
        challengeHash: intent.challengeHash,
        quoteId: evaluation.quoteId,
        acceptedIndex: evaluation.acceptedIndex,
        requestUrl: request.requestUrl,
        resourceDescription: paymentRequired.resource.description,
        resourceMimeType: paymentRequired.resource.mimeType,
        scheme: selected.scheme,
        network: selected.network,
        asset: selected.asset,
        walletAddress: intent.walletAddress,
        payTo: selected.payTo,
        amountAtomic: evaluation.amountCeilingAtomic,
        validAfter: window.validAfter,
        validBefore: window.validBefore,
        nonce: window.nonce,
        policyVersionId: policyVersion.id,
      });
    }));
    faultInjector('after_signing_claim_commit', Object.freeze({ intentId: intent.id }));
    return claimed;
  };

  const assertSignedPayload = (paymentPayload, binding, paymentRequired) => {
    const payment = shallowRecord(paymentPayload, [
      'x402Version',
      'resource',
      'accepted',
      'payload',
    ], [], 'WALLET_PAYMENT_PAYLOAD', 'signed payment');
    const payload = shallowRecord(payment.payload, [
      'signature',
      'authorization',
    ], [], 'WALLET_PAYMENT_PAYLOAD', 'signed payment payload');
    const authorization = exactRecord(payload.authorization, [
      'from',
      'to',
      'value',
      'validAfter',
      'validBefore',
      'nonce',
    ], [], 'WALLET_PAYMENT_PAYLOAD', 'signed authorization');
    if (payment.x402Version !== 2
        || canonicalJson(payment.resource) !== canonicalJson(paymentRequired.resource)
        || canonicalJson(payment.accepted)
          !== canonicalJson(paymentRequired.accepts[binding.acceptedIndex])
        || typeof payload.signature !== 'string'
        || !/^0x[0-9a-fA-F]{130}$/.test(payload.signature)
        || authorization.from !== binding.walletAddress
        || authorization.to !== binding.payTo
        || authorization.value !== binding.amountAtomic
        || authorization.validAfter !== binding.validAfter
        || authorization.validBefore !== binding.validBefore
        || authorization.nonce !== binding.nonce) {
      throw new KernelError(
        'WALLET_PAYMENT_PAYLOAD',
        'signed payment differs from its durable authorization claim',
      );
    }
    canonicalJson(paymentPayload);
    return paymentPayload;
  };

  const persistSignedPayment = async ({ intentId, paymentPayload, paymentHeader }) => {
    if (typeof paymentHeader !== 'string' || paymentHeader.length === 0
        || Buffer.byteLength(paymentHeader, 'ascii') > 16_384
        || /[^\x20-\x7e]/.test(paymentHeader)) {
      throw new KernelError('PAYMENT_HEADER_SCHEMA', 'encoded payment header is invalid');
    }
    const paymentPayloadJson = canonicalJson(paymentPayload);
    const paymentHash = sha256(Buffer.from(paymentHeader, 'ascii'));
    await runMutation(() => store.transaction((token) => {
      receipts.assertParityInTransaction(token);
      const signedAt = canonicalTimestamp(now(), 'payment signedAt');
      store.within(token, ({ db, appendEvent }) => {
        const changed = db.prepare(`UPDATE payment_attempts
          SET state = 'signed', payment_payload_json = ?, payment_header = ?,
              payment_hash = ?, signed_at = ?, updated_at = ?
          WHERE intent_id = ? AND state = 'signing'
            AND nonce IS NOT NULL AND valid_after IS NOT NULL AND valid_before IS NOT NULL
            AND signing_claimed_at IS NOT NULL AND payment_payload_json IS NULL
            AND payment_header IS NULL AND payment_hash IS NULL AND signed_at IS NULL`).run(
          paymentPayloadJson,
          paymentHeader,
          paymentHash,
          signedAt,
          signedAt,
          intentId,
        );
        if (changed.changes !== 1n) {
          throw new KernelError('PAYMENT_ATTEMPT_STATE', 'signed payment persistence lost its race');
        }
        appendEvent({
          entityType: 'payment_attempt',
          entityId: intentId,
          eventType: 'payment.signed',
          data: { paymentHash, signedAt },
        });
      });
      intents.transitionInTransaction(token, {
        intentId,
        expectedState: 'signing',
        nextState: 'signed',
        reasonCode: 'PAYMENT_SIGNED',
      });
    }));
    faultInjector('after_signed_payment_commit', Object.freeze({ intentId }));
    return paymentHash;
  };

  const claimPaidRetry = async (intentId) => {
    await runMutation(() => store.transaction((token) => {
      receipts.assertParityInTransaction(token);
      const retryStartedAt = canonicalTimestamp(now(), 'paid retry startedAt');
      store.within(token, ({ db, appendEvent }) => {
        const changed = db.prepare(`UPDATE payment_attempts
          SET state = 'retrying', retry_started_at = ?, updated_at = ?
          WHERE intent_id = ? AND state = 'signed'
            AND payment_payload_json IS NOT NULL AND payment_header IS NOT NULL
            AND payment_hash IS NOT NULL AND signed_at IS NOT NULL
            AND retry_started_at IS NULL`).run(retryStartedAt, retryStartedAt, intentId);
        if (changed.changes !== 1n) {
          throw new KernelError('PAYMENT_ATTEMPT_STATE', 'paid retry claim lost its race');
        }
        appendEvent({
          entityType: 'payment_attempt',
          entityId: intentId,
          eventType: 'payment.retrying',
          data: { retryStartedAt },
        });
      });
      intents.transitionInTransaction(token, {
        intentId,
        expectedState: 'signed',
        nextState: 'retrying',
        reasonCode: 'PAID_RETRY_STARTED',
      });
    }));
    faultInjector('after_retry_claim_commit', Object.freeze({ intentId }));
  };

  const settleExecution = async ({ intent, paid }) => await runMutation(() => {
    let status;
    let reasonCode;
    if (paid.executionState === 'succeeded') {
      status = 'completed';
      reasonCode = 'PAYMENT_SETTLED';
    } else if (paid.executionState === 'failed') {
      status = 'execution_failed';
      reasonCode = 'UPSTREAM_HTTP_FAILURE';
    } else {
      status = 'execution_unknown';
      reasonCode = 'PAID_RESPONSE_AMBIGUOUS';
    }
    store.transaction((token) => {
      receipts.assertParityInTransaction(token);
      const committed = budgets.commitInTransaction(token, {
        intentId: intent.id,
        settlementEvidence: paid.settlement,
      });
      const recordedAt = canonicalTimestamp(
        committed.committedAt,
        'settled execution recordedAt',
      );
      store.within(token, ({ db, appendEvent }) => {
        const responseHash = paid.body === null ? null : sha256(paid.body);
        const metadataJson = canonicalJson({
          ...(Object.hasOwn(paid, 'deliveryReason')
            ? { deliveryReason: paid.deliveryReason }
            : {}),
          reasonCode,
        });
        db.prepare(`INSERT INTO execution_outcomes
          (intent_id, state, http_status, response_hash, metadata_json, recorded_at)
          VALUES (?, ?, ?, ?, ?, ?)`).run(
          intent.id,
          paid.executionState,
          paid.status,
          responseHash,
          metadataJson,
          recordedAt,
        );
        if (paid.executionState === 'failed') {
          const amountAtomic = db.prepare(`SELECT amount_ceiling_atomic
            FROM policy_decisions WHERE intent_id = ?`).get(intent.id)?.amount_ceiling_atomic;
          if (typeof amountAtomic !== 'string') {
            throw new KernelError(
              'POLICY_DECISION_MISSING',
              'failed execution lost its committed amount authority',
            );
          }
          db.prepare(`INSERT INTO execution_resolutions
            (intent_id, state, reason_code, blocks_wallet, opened_at, resolved_at)
            VALUES (?, 'refund_pending', ?, 1, ?, NULL)`).run(
            intent.id,
            reasonCode,
            recordedAt,
          );
          appendEvent({
            entityType: 'execution_resolution',
            entityId: intent.id,
            eventType: 'execution_resolution.opened',
            data: {
              intentId: intent.id,
              state: 'refund_pending',
              reasonCode,
              blocksWallet: true,
              openedAt: recordedAt,
            },
          });
          const refundId = idFactory('refund');
          db.prepare(`INSERT INTO refunds
            (id, intent_id, original_transaction_id, amount_atomic, state,
             evidence_json, refund_transaction_id, created_at, updated_at)
            VALUES (?, ?, ?, ?, 'pending', NULL, NULL, ?, ?)`).run(
            refundId,
            intent.id,
            paid.settlement.transaction,
            amountAtomic,
            recordedAt,
            recordedAt,
          );
          appendEvent({
            entityType: 'refund',
            entityId: refundId,
            eventType: 'refund.opened',
            data: {
              refundId,
              intentId: intent.id,
              originalTransactionId: paid.settlement.transaction,
              amountAtomic,
              state: 'pending',
              createdAt: recordedAt,
            },
          });
        } else if (paid.executionState === 'unknown') {
          db.prepare(`INSERT INTO execution_resolutions
            (intent_id, state, reason_code, blocks_wallet, opened_at, resolved_at)
            VALUES (?, 'reconciliation_required', ?, 1, ?, NULL)`).run(
            intent.id,
            reasonCode,
            recordedAt,
          );
          appendEvent({
            entityType: 'execution_resolution',
            entityId: intent.id,
            eventType: 'execution_resolution.opened',
            data: {
              intentId: intent.id,
              state: 'reconciliation_required',
              reasonCode,
              blocksWallet: true,
              openedAt: recordedAt,
            },
          });
        }
        db.prepare(`INSERT INTO buyer_outcomes
          (intent_id, status, reason_code, revision, recorded_at)
          VALUES (?, ?, ?, 1, ?)`).run(intent.id, status, reasonCode, recordedAt);
        appendEvent({
          entityType: 'execution_outcome',
          entityId: intent.id,
          eventType: 'execution.recorded',
          data: {
            state: paid.executionState,
            httpStatus: paid.status,
            responseHash,
            metadataHash: sha256(metadataJson),
            reasonCode,
            recordedAt,
          },
        });
        appendEvent({
          entityType: 'buyer_outcome',
          entityId: intent.id,
          eventType: 'buyer_outcome.recorded',
          data: { status, reasonCode, revision: 1, recordedAt },
        });
      });
      intents.transitionInTransaction(token, {
        intentId: intent.id,
        expectedState: 'retrying',
        nextState: 'terminal',
        reasonCode,
      });
    });
    faultInjector('after_settlement_commit', Object.freeze({ intentId: intent.id }));
    const receipt = issueTerminalReceipt(intent.id);
    return Object.freeze({
      requestId: intent.requestId,
      status,
      reasonCode,
      upstreamStatus: paid.status,
      body: paid.body === null ? null : Buffer.from(paid.body),
      receipt,
    });
  });

  const holdPaidAmbiguity = async ({ intent, paid }) => await runMutation(() => {
    const reasonCode = paid.reasonCode === 'SECOND_PAYMENT_REQUIRED'
      ? 'SECOND_PAYMENT_REQUIRED'
      : (typeof paid.reasonCode === 'string' && paid.reasonCode.startsWith('SETTLEMENT_')
        ? 'SETTLEMENT_EVIDENCE_INVALID'
        : 'PAID_RESPONSE_AMBIGUOUS');
    const recordedAt = canonicalTimestamp(now(), 'payment unresolved recordedAt');
    store.transaction((token) => {
      receipts.assertParityInTransaction(token);
      budgets.holdUnresolvedInTransaction(token, { intentId: intent.id, reasonCode });
      const heldAt = store.within(token, ({ db }) => db.prepare(
        'SELECT updated_at FROM budget_reservations WHERE intent_id = ?',
      ).get(intent.id)?.updated_at);
      if (typeof heldAt !== 'string') {
        throw new KernelError('BUDGET_CORRUPTION', 'unresolved budget hold lost its timestamp');
      }
      store.within(token, ({ db, appendEvent }) => {
        const changed = db.prepare(`UPDATE payment_attempts
          SET state = 'unresolved', reason_code = ?, updated_at = ?
          WHERE intent_id = ? AND state = 'retrying'
            AND retry_started_at IS NOT NULL
            AND settlement_json IS NULL AND transaction_id IS NULL AND settled_at IS NULL`).run(
          reasonCode,
          heldAt,
          intent.id,
        );
        if (changed.changes !== 1n) {
          throw new KernelError('PAYMENT_ATTEMPT_STATE', 'payment hold lost its retrying attempt');
        }
        appendEvent({
          entityType: 'payment_attempt',
          entityId: intent.id,
          eventType: 'payment.unresolved',
          data: { reasonCode, recordedAt: heldAt },
        });
      });
      intents.transitionInTransaction(token, {
        intentId: intent.id,
        expectedState: 'retrying',
        nextState: 'unresolved',
        reasonCode,
      });
      store.within(token, ({ db, appendEvent }) => {
        db.prepare(`INSERT INTO buyer_outcomes
          (intent_id, status, reason_code, revision, recorded_at)
          VALUES (?, 'payment_unresolved', ?, 1, ?)`).run(
          intent.id,
          reasonCode,
          recordedAt,
        );
        appendEvent({
          entityType: 'buyer_outcome',
          entityId: intent.id,
          eventType: 'buyer_outcome.recorded',
          data: {
            status: 'payment_unresolved',
            reasonCode,
            revision: 1,
            recordedAt,
          },
        });
      });
    });
    const receipt = issueTerminalReceipt(intent.id);
    return Object.freeze({
      requestId: intent.requestId,
      status: 'payment_unresolved',
      reasonCode,
      receipt,
    });
  });

  const persistedResult = (intent) => {
    const outcome = store.readOne(
      'SELECT status, reason_code FROM buyer_outcomes WHERE intent_id = ?',
      [intent.id],
    );
    if (!outcome) return null;
    const receipt = receipts.latest(intent.id);
    if (!receipt) {
      throw new KernelError(
        'RECEIPT_PARITY_REQUIRED',
        'persisted BuyerOutcome is missing its signed receipt',
      );
    }
    return Object.freeze({
      requestId: intent.requestId,
      status: outcome.status,
      reasonCode: outcome.reason_code,
      receipt,
    });
  };

  const persistedTerminalWinnerAfterConflict = ({ error, originalIntent, correlationId }) => {
    if (!new Set([
      'INTENT_STATE_CONFLICT',
      'APPROVAL_STATE_CONFLICT',
      'APPROVAL_EXPIRED',
    ]).has(error?.code)) return null;
    if (correlationId !== originalIntent.correlationId) return null;
    const winner = intents.getIntent(originalIntent.id);
    if (winner.state !== 'terminal' || winner.retryMatchable) return null;
    const exactBindingFields = [
      'id',
      'requestId',
      'sessionId',
      'enrollmentHash',
      'routeId',
      'method',
      'requestUrlHash',
      'sellerOrigin',
      'resourcePath',
      'bodyHash',
      'headerAllowlistHash',
      'ordinaryFingerprint',
      'purposeLabel',
      'correlationId',
      'idempotencyKey',
      'walletAddress',
      'intentHash',
      'challengeProjectionJson',
      'challengeHash',
      'challengeReceivedAt',
      'createdAt',
    ];
    if (exactBindingFields.some((field) => winner[field] !== originalIntent[field])) return null;
    const result = persistedResult(winner);
    if (result === null) return null;
    const receiptIntent = result.receipt?.receipt?.intent;
    if (result.requestId !== winner.requestId
        || result.receipt?.intentId !== winner.id
        || receiptIntent?.id !== winner.id
        || receiptIntent.requestId !== winner.requestId
        || receiptIntent.sessionId !== winner.sessionId
        || receiptIntent.intentHash !== winner.intentHash) {
      throw new KernelError(
        'RECEIPT_PARITY_REQUIRED',
        'terminal race winner receipt disagrees with its Spend Intent binding',
      );
    }
    return result;
  };

  const releaseUnsignedReservation = async ({ intent, status, reasonCode }) => await runMutation(() => {
    const recordedAt = canonicalTimestamp(now(), 'unsigned reservation outcome recordedAt');
    store.transaction((token) => {
      receipts.assertParityInTransaction(token);
      budgets.releaseInTransaction(token, { intentId: intent.id, reasonCode });
      intents.transitionInTransaction(token, {
        intentId: intent.id,
        expectedState: 'reserved',
        nextState: 'terminal',
        reasonCode,
      });
      store.within(token, ({ db, appendEvent }) => {
        db.prepare(`INSERT INTO buyer_outcomes
          (intent_id, status, reason_code, revision, recorded_at)
          VALUES (?, ?, ?, 1, ?)`).run(intent.id, status, reasonCode, recordedAt);
        appendEvent({
          entityType: 'buyer_outcome',
          entityId: intent.id,
          eventType: 'buyer_outcome.recorded',
          data: { status, reasonCode, revision: 1, recordedAt },
        });
      });
    });
    const receipt = issueTerminalReceipt(intent.id);
    return Object.freeze({
      requestId: intent.requestId,
      status,
      reasonCode,
      receipt,
    });
  });

  const releasePreSignerRejection = async ({ intent, error }) => await runMutation(() => {
    const reasonCode = 'WALLET_PRE_SIGN_REJECTED';
    const recordedAt = canonicalTimestamp(now(), 'pre-signer rejection recordedAt');
    store.transaction((token) => {
      receipts.assertParityInTransaction(token);
      budgets.releaseInTransaction(token, {
        intentId: intent.id,
        reasonCode,
        preSignRejection: error,
      });
      intents.transitionInTransaction(token, {
        intentId: intent.id,
        expectedState: 'signing',
        nextState: 'unresolved',
        reasonCode,
      });
      intents.transitionInTransaction(token, {
        intentId: intent.id,
        expectedState: 'unresolved',
        nextState: 'terminal',
        reasonCode,
      });
      store.within(token, ({ db, appendEvent }) => {
        db.prepare(`INSERT INTO buyer_outcomes
          (intent_id, status, reason_code, revision, recorded_at)
          VALUES (?, 'payment_failed', ?, 1, ?)`).run(intent.id, reasonCode, recordedAt);
        appendEvent({
          entityType: 'buyer_outcome',
          entityId: intent.id,
          eventType: 'buyer_outcome.recorded',
          data: {
            status: 'payment_failed',
            reasonCode,
            revision: 1,
            recordedAt,
          },
        });
      });
    });
    const receipt = issueTerminalReceipt(intent.id);
    return Object.freeze({
      requestId: intent.requestId,
      status: 'payment_failed',
      reasonCode,
      receipt,
    });
  });

  const holdSigningAmbiguity = async (intent) => await runMutation(() => {
    const reasonCode = 'WALLET_SIGNATURE_AMBIGUOUS';
    const recordedAt = canonicalTimestamp(now(), 'wallet signing ambiguity recordedAt');
    store.transaction((token) => {
      receipts.assertParityInTransaction(token);
      budgets.holdUnresolvedInTransaction(token, { intentId: intent.id, reasonCode });
      const heldAt = store.within(token, ({ db }) => db.prepare(
        'SELECT updated_at FROM budget_reservations WHERE intent_id = ?',
      ).get(intent.id)?.updated_at);
      if (typeof heldAt !== 'string') {
        throw new KernelError('BUDGET_CORRUPTION', 'unresolved budget hold lost its timestamp');
      }
      store.within(token, ({ db, appendEvent }) => {
        const changed = db.prepare(`UPDATE payment_attempts
          SET state = 'unresolved', reason_code = ?, updated_at = ?
          WHERE intent_id = ? AND state = 'signing'
            AND signing_claimed_at IS NOT NULL
            AND settlement_json IS NULL AND transaction_id IS NULL AND settled_at IS NULL`).run(
          reasonCode,
          heldAt,
          intent.id,
        );
        if (changed.changes !== 1n) {
          throw new KernelError('PAYMENT_ATTEMPT_STATE', 'signing ambiguity lost its attempt');
        }
        appendEvent({
          entityType: 'payment_attempt',
          entityId: intent.id,
          eventType: 'payment.unresolved',
          data: { reasonCode, recordedAt: heldAt },
        });
      });
      intents.transitionInTransaction(token, {
        intentId: intent.id,
        expectedState: 'signing',
        nextState: 'unresolved',
        reasonCode,
      });
      store.within(token, ({ db, appendEvent }) => {
        db.prepare(`INSERT INTO buyer_outcomes
          (intent_id, status, reason_code, revision, recorded_at)
          VALUES (?, 'payment_unresolved', ?, 1, ?)`).run(
          intent.id,
          reasonCode,
          recordedAt,
        );
        appendEvent({
          entityType: 'buyer_outcome',
          entityId: intent.id,
          eventType: 'buyer_outcome.recorded',
          data: {
            status: 'payment_unresolved',
            reasonCode,
            revision: 1,
            recordedAt,
          },
        });
      });
    });
    const receipt = issueTerminalReceipt(intent.id);
    return Object.freeze({
      requestId: intent.requestId,
      status: 'payment_unresolved',
      reasonCode,
      receipt,
    });
  });

  const executeReserved = async ({
    intent,
    request,
    transportRequest,
    paymentRequired,
    evaluation,
    policyVersion,
    approvalExpiresAt = null,
  }) => {
    let binding;
    try {
      binding = await signingClaim({
        intent,
        request,
        paymentRequired,
        evaluation,
        policyVersion,
        approvalExpiresAt,
      });
    } catch (error) {
      if (isNonceCollision(error)) {
        return await releaseUnsignedReservation({
          intent,
          status: 'payment_failed',
          reasonCode: 'NONCE_COLLISION',
        });
      }
      if (error?.code === 'AGENT_REVOKED') {
        return await releaseUnsignedReservation({
          intent,
          status: 'payment_denied',
          reasonCode: 'AGENT_REVOKED',
        });
      }
      if (error?.code === 'WALLET_RECOVERY_REQUIRED') {
        return await releaseUnsignedReservation({
          intent,
          status: 'payment_denied',
          reasonCode: 'WALLET_RECOVERY_REQUIRED',
        });
      }
      if (error?.code === 'CHALLENGE_EXPIRED') {
        return await releaseUnsignedReservation({
          intent,
          status: 'payment_denied',
          reasonCode: 'CHALLENGE_EXPIRED',
        });
      }
      throw error;
    }
    const permit = permitAuthority.issue(binding);
    let signed;
    try {
      signed = await walletAdapter.signX402Exact(permit, paymentRequired);
    } catch (error) {
      if (WalletSigningError.isExact(error, 'WALLET_PRE_SIGN_REJECTED', false)) {
        return await releasePreSignerRejection({ intent, error });
      }
      return await holdSigningAmbiguity(intent);
    }
    try {
      faultInjector('after_signer_return', Object.freeze({ intentId: intent.id }));
      let paymentPayload;
      let paymentHeader;
      try {
        const signedResult = shallowRecord(
          signed,
          ['paymentPayload'],
          [],
          'WALLET_PAYMENT_PAYLOAD',
          'wallet signing result',
        );
        paymentPayload = assertSignedPayload(
          signedResult.paymentPayload,
          binding,
          paymentRequired,
        );
        paymentHeader = transport.encodePayment(paymentPayload);
      } catch {
        return await holdSigningAmbiguity(intent);
      }
      const paymentHash = await persistSignedPayment({
        intentId: intent.id,
        paymentPayload,
        paymentHeader,
      });
      await claimPaidRetry(intent.id);
      let paid;
      try {
        paid = await transport.retryPaid({
          request: transportRequest,
          paymentHeader,
          binding: {
            network: binding.network,
            walletAddress: binding.walletAddress,
            amountAtomic: binding.amountAtomic,
            paymentHash,
          },
        });
      } catch {
        return await holdPaidAmbiguity({
          intent,
          paid: Object.freeze({ reasonCode: 'PAID_RESPONSE_AMBIGUOUS' }),
        });
      }
      faultInjector('after_paid_response', Object.freeze({ intentId: intent.id }));
      if (paid.kind === 'settled_response') {
        return await settleExecution({ intent, paid });
      }
      return await holdPaidAmbiguity({ intent, paid });
    } catch (error) {
      return failStopAfterSignerReturn(error);
    }
  };

  const replaceChangedApproval = async ({
    intent,
    intentRequest,
    paymentRequired,
    challengeReceivedAt,
    evaluation,
    policyVersion,
  }) => await runMutation(() => {
    const recordedAt = canonicalTimestamp(now(), 'changed approval outcome recordedAt');
    let replacement = null;
    store.transaction((token) => {
      receipts.assertParityInTransaction(token);
      const cancelled = approvals.cancelForIntentInTransaction(token, {
        intentId: intent.id,
        reasonCode: 'APPROVAL_CHALLENGE_CHANGED',
      });
      if (cancelled === null) {
        throw new KernelError(
          'APPROVAL_STATE_CONFLICT',
          'changed challenge lost its open approval authority',
        );
      }
      intents.transitionInTransaction(token, {
        intentId: intent.id,
        expectedState: 'approval_pending',
        nextState: 'terminal',
        reasonCode: 'APPROVAL_CHALLENGE_CHANGED',
      });
      store.within(token, ({ db, appendEvent }) => {
        db.prepare(`INSERT INTO buyer_outcomes
          (intent_id, status, reason_code, revision, recorded_at)
          VALUES (?, 'payment_denied', 'APPROVAL_CHALLENGE_CHANGED', 1, ?)`).run(
          intent.id,
          recordedAt,
        );
        appendEvent({
          entityType: 'buyer_outcome',
          entityId: intent.id,
          eventType: 'buyer_outcome.recorded',
          data: {
            status: 'payment_denied',
            reasonCode: 'APPROVAL_CHALLENGE_CHANGED',
            revision: 1,
            recordedAt,
          },
        });
      });
      if (evaluation?.decision !== 'approval_required') return;
      const { correlationId: ignoredCorrelationId, ...replacementRequest } = intentRequest;
      void ignoredCorrelationId;
      const replacementIntent = intents.captureIntentInTransaction(token, {
        sessionId: intent.sessionId,
        ...replacementRequest,
      });
      const replacementChallenged = intents.attachChallengeInTransaction(token, {
        intentId: replacementIntent.id,
        paymentRequired,
        challengeReceivedAt: replacementIntent.updatedAt,
      });
      policies.recordDecisionInTransaction(token, {
        intentId: replacementIntent.id,
        policyVersionId: policyVersion.id,
        evaluation,
        decidedAt: replacementChallenged.updatedAt,
      });
      const replacementApproval = approvals.requestInTransaction(token, {
        intentId: replacementIntent.id,
        intentHash: replacementIntent.intentHash,
        challengeHash: evaluation.challengeHash,
        quoteId: evaluation.quoteId,
        amountCeilingAtomic: evaluation.amountCeilingAtomic,
        walletAddress: replacementIntent.walletAddress,
        policyVersionId: policyVersion.id,
        acceptedIndex: evaluation.acceptedIndex,
      });
      intents.transitionInTransaction(token, {
        intentId: replacementIntent.id,
        expectedState: 'challenged',
        nextState: 'approval_pending',
        reasonCode: 'HUMAN_APPROVAL_REQUIRED',
      });
      replacement = Object.freeze({
        intent: replacementIntent,
        approval: replacementApproval,
      });
    });
    const receipt = issueTerminalReceipt(intent.id);
    return Object.freeze({
      requestId: intent.requestId,
      status: 'payment_denied',
      reasonCode: 'APPROVAL_CHALLENGE_CHANGED',
      receipt,
      ...(replacement === null ? {} : {
        replacementRequestId: replacement.intent.requestId,
        replacementExpiresAt: replacement.approval.expiresAt,
      }),
    });
  });

  const terminateSessionIntentsInTransaction = (token, {
    sessionId,
    reasonCode,
    blockedCode,
    recordedAt,
  }) => {
    const rows = store.within(token, ({ db }) => db.prepare(`SELECT
        spend_intents.id,
        spend_intents.state,
        approvals.decision AS approval_decision,
        policy_decisions.decision AS policy_decision,
        policy_decisions.reason_code AS policy_reason_code,
        budget_reservations.state AS budget_state,
        payment_attempts.state AS payment_state
      FROM spend_intents
      LEFT JOIN approvals ON approvals.intent_id = spend_intents.id
      LEFT JOIN policy_decisions ON policy_decisions.intent_id = spend_intents.id
      LEFT JOIN budget_reservations ON budget_reservations.intent_id = spend_intents.id
      LEFT JOIN payment_attempts ON payment_attempts.intent_id = spend_intents.id
      WHERE spend_intents.session_id = ?
      ORDER BY spend_intents.id`).all(sessionId));
    const unsafeIntentStates = new Set(['signing', 'signed', 'retrying', 'unresolved']);
    const unsafePaymentStates = new Set(['signing', 'signed', 'retrying', 'unresolved', 'settled']);
    for (const row of rows) {
      if (row.state === 'terminal') continue;
      if (unsafeIntentStates.has(row.state)
          || unsafePaymentStates.has(row.payment_state)
          || (row.budget_state !== null && row.budget_state !== 'reserved')
          || (row.payment_state !== null && row.payment_state !== 'reserved')
          || (row.state === 'reserved'
            && (row.budget_state !== 'reserved' || row.payment_state !== 'reserved'))
          || (row.state === 'approval_pending'
            && !new Set(['pending', 'approved']).has(row.approval_decision))
          || (row.state === 'challenged'
            && !new Set(['allow', 'approval_required', 'deny']).has(row.policy_decision))) {
        throw new KernelError(blockedCode, 'Spend Session retains money-sensitive authority');
      }
    }
    const terminalIntentIds = [];
    for (const row of rows) {
      if (row.state === 'terminal') continue;
      if (row.approval_decision === 'pending' || row.approval_decision === 'approved') {
        const cancelled = approvals.cancelForIntentInTransaction(token, {
          intentId: row.id,
          reasonCode,
        });
        if (cancelled === null) {
          throw new KernelError(blockedCode, 'session approval changed during cancellation');
        }
      }
      if (row.budget_state === 'reserved') {
        budgets.releaseInTransaction(token, { intentId: row.id, reasonCode });
      }
      const terminalReasonCode = row.state === 'challenged' && row.policy_decision === 'deny'
        ? row.policy_reason_code
        : reasonCode;
      intents.transitionInTransaction(token, {
        intentId: row.id,
        expectedState: row.state,
        nextState: 'terminal',
        reasonCode: terminalReasonCode,
      });
      store.within(token, ({ db, appendEvent }) => {
        db.prepare(`INSERT INTO buyer_outcomes
          (intent_id, status, reason_code, revision, recorded_at)
          VALUES (?, 'payment_denied', ?, 1, ?)`).run(
          row.id,
          terminalReasonCode,
          recordedAt,
        );
        appendEvent({
          entityType: 'buyer_outcome',
          entityId: row.id,
          eventType: 'buyer_outcome.recorded',
          data: {
            status: 'payment_denied',
            reasonCode: terminalReasonCode,
            revision: 1,
            recordedAt,
          },
        });
      });
      terminalIntentIds.push(row.id);
    }
    return Object.freeze(terminalIntentIds);
  };

  const runSessionAggregate = async ({
    request,
    reasonCode,
    blockedCode,
    command,
    latchAgentSessionUnavailable = false,
  }) => {
    try {
      return await runMutation(() => {
        const recordedAt = canonicalTimestamp(now(), 'session aggregate outcome recordedAt');
        let terminalIntentIds;
        let sessionResult;
        store.transaction((token) => {
          receipts.assertParityInTransaction(token);
          terminalIntentIds = terminateSessionIntentsInTransaction(token, {
            sessionId: request.sessionId,
            reasonCode,
            blockedCode,
            recordedAt,
          });
          sessionResult = command(token);
        });
        const terminalReceipts = Object.freeze(terminalIntentIds.map((intentId) => Object.freeze({
          intentId,
          receipt: issueTerminalReceipt(intentId),
        })));
        if (latchAgentSessionUnavailable) agentSessionUnavailable = true;
        return Object.freeze({ ...sessionResult, terminalReceipts });
      });
    } catch (error) {
      if (error?.code === 'SESSION_MONETARY_AMBIGUITY') {
        throw new KernelError(blockedCode, 'Spend Session retains monetary ambiguity', {
          cause: error,
        });
      }
      throw error;
    }
  };

  const transitionSessionPolicy = async (input) => {
    const request = exactRecord(input, [
      'sessionId',
      'targetPolicyVersionId',
      'expectedSessionHash',
    ], [], 'SESSION_TRANSITION_SCHEMA', 'session policy transition');
    canonicalToken(request.sessionId, 'session ID');
    canonicalToken(request.targetPolicyVersionId, 'target policy version ID');
    canonicalHash(
      request.expectedSessionHash,
      'SESSION_TRANSITION_SCHEMA',
      'expected session hash',
    );
    return await runSessionAggregate({
      request,
      reasonCode: 'POLICY_SUPERSEDED',
      blockedCode: 'SESSION_TRANSITION_BLOCKED',
      command: (token) => intents.transitionBlockedSessionInTransaction(token, request),
    });
  };

  const closeSession = async (input) => {
    const request = exactRecord(input, [
      'sessionId',
      'expectedSessionHash',
    ], [], 'SESSION_CLOSE_SCHEMA', 'session close');
    canonicalToken(request.sessionId, 'session ID');
    canonicalHash(
      request.expectedSessionHash,
      'SESSION_CLOSE_SCHEMA',
      'expected session hash',
    );
    return await runSessionAggregate({
      request,
      reasonCode: 'SESSION_CLOSED',
      blockedCode: 'SESSION_CLOSE_BLOCKED',
      command: (token) => intents.closeBoundSessionInTransaction(token, request),
      latchAgentSessionUnavailable: true,
    });
  };

  const status = (input) => {
    const request = exactRecord(input, [
      'sessionId',
      'intentId',
    ], [], 'STATUS_SCHEMA', 'Kernel status request');
    const sessionId = canonicalToken(request.sessionId, 'session ID');
    const intentId = canonicalToken(request.intentId, 'intent ID');
    const session = intents.getSession(sessionId);
    if (session === null) {
      throw new KernelError('SESSION_UNKNOWN', 'Spend Session does not exist');
    }
    const intent = intents.getIntent(intentId);
    if (intent === null) {
      throw new KernelError('INTENT_UNKNOWN', 'Spend Intent does not exist');
    }
    if (intent.sessionId !== session.id) {
      throw new KernelError(
        'INTENT_SESSION_MISMATCH',
        'Spend Intent does not belong to the requested Spend Session',
      );
    }
    const approval = store.readOne(
      'SELECT decision FROM approvals WHERE intent_id = ?',
      [intent.id],
    );
    const budget = store.readOne(
      'SELECT state FROM budget_reservations WHERE intent_id = ?',
      [intent.id],
    );
    const payment = store.readOne(
      'SELECT state FROM payment_attempts WHERE intent_id = ?',
      [intent.id],
    );
    const persistedOutcome = store.readOne(
      'SELECT status, reason_code, revision FROM buyer_outcomes WHERE intent_id = ?',
      [intent.id],
    );
    const receipt = receipts.latest(intent.id);
    if ((persistedOutcome == null) !== (receipt === null)) {
      throw new KernelError(
        'RECEIPT_PARITY_REQUIRED',
        'BuyerOutcome and signed receipt must exist together',
      );
    }
    const outcome = persistedOutcome == null ? null : Object.freeze({
      status: persistedOutcome.status,
      reasonCode: persistedOutcome.reason_code,
      revision: Number(persistedOutcome.revision),
    });
    return Object.freeze({
      sessionId: session.id,
      intentId: intent.id,
      sessionState: session.state,
      intentState: intent.state,
      approvalState: approval?.decision ?? null,
      budgetState: budget?.state ?? null,
      paymentState: payment?.state ?? null,
      outcome,
      receipt,
    });
  };

  const agentStatusView = (sessionId, intentId) => {
    const internal = status({ sessionId, intentId });
    const intent = intents.getIntent(intentId);
    if (intent === null || intent.requestId === undefined
        || typeof intent.sellerOrigin !== 'string'
        || typeof intent.purposeLabel !== 'string') {
      throw new KernelError('INTENT_CORRUPTION', 'Spend Intent public identity is invalid');
    }
    const approvalRow = store.readOne(
      `SELECT decision, expires_at, amount_ceiling_atomic
       FROM approvals WHERE intent_id = ?`,
      [intent.id],
    );
    let approval = null;
    if (approvalRow && (approvalRow.decision === 'pending' || approvalRow.decision === 'approved')) {
      if (typeof approvalRow.expires_at !== 'string'
          || typeof approvalRow.amount_ceiling_atomic !== 'string'
          || !/^(0|[1-9][0-9]*)$/.test(approvalRow.amount_ceiling_atomic)) {
        throw new KernelError('APPROVAL_CORRUPTION', 'approval public projection is invalid');
      }
      approval = Object.freeze({
        state: approvalRow.decision,
        expiresAt: approvalRow.expires_at,
        amountAtomic: approvalRow.amount_ceiling_atomic,
      });
    }
    const snapshot = budgets.snapshot({
      sessionId,
      sellerOrigin: intent.sellerOrigin,
      at: now(),
    });
    const session = intents.getSession(sessionId);
    const policyVersion = session === null ? null : policies.get(session.policyVersionId);
    if (!policyVersion?.policy
        || typeof policyVersion.policy.sessionMaxAtomic !== 'string'
        || !/^(0|[1-9][0-9]*)$/.test(policyVersion.policy.sessionMaxAtomic)
        || typeof snapshot?.sessionExposureAtomic !== 'string'
        || !/^(0|[1-9][0-9]*)$/.test(snapshot.sessionExposureAtomic)) {
      throw new KernelError('BUDGET_CORRUPTION', 'session remaining projection is invalid');
    }
    const maximum = BigInt(policyVersion.policy.sessionMaxAtomic);
    const exposure = BigInt(snapshot.sessionExposureAtomic);
    if (exposure > maximum) {
      throw new KernelError('BUDGET_CORRUPTION', 'session exposure exceeds its policy maximum');
    }
    return Object.freeze({
      requestId: intent.requestId,
      sellerOrigin: intent.sellerOrigin,
      purposeLabel: intent.purposeLabel,
      intentState: internal.intentState,
      approval,
      outcome: internal.outcome,
      receipt: internal.receipt,
      remainingSessionAtomic: (maximum - exposure).toString(),
    });
  };

  const statusByRequestId = (input) => {
    const request = exactRecord(input, [
      'sessionId',
      'requestId',
    ], [], 'STATUS_SCHEMA', 'Kernel public request status');
    const sessionId = canonicalToken(request.sessionId, 'session ID');
    const requestId = canonicalToken(request.requestId, 'request ID');
    const row = store.readOne(
      'SELECT id FROM spend_intents WHERE session_id = ? AND request_id = ?',
      [sessionId, requestId],
    );
    if (row == null) return null;
    if (typeof row.id !== 'string') {
      throw new KernelError('INTENT_CORRUPTION', 'Spend Intent lookup is invalid');
    }
    return agentStatusView(sessionId, row.id);
  };

  const receiptById = (input) => {
    const request = exactRecord(input, [
      'sessionId',
      'receiptId',
    ], [], 'STATUS_SCHEMA', 'Kernel public receipt status');
    const sessionId = canonicalToken(request.sessionId, 'session ID');
    const receiptId = canonicalToken(request.receiptId, 'receipt ID');
    const row = store.readOne(
      `SELECT signed_receipts.intent_id
       FROM signed_receipts
       JOIN spend_intents ON spend_intents.id = signed_receipts.intent_id
       WHERE signed_receipts.id = ? AND spend_intents.session_id = ?`,
      [receiptId, sessionId],
    );
    if (row == null) return null;
    if (typeof row.intent_id !== 'string') {
      throw new KernelError('RECEIPT_CORRUPTION', 'signed receipt lookup is invalid');
    }
    return agentStatusView(sessionId, row.intent_id);
  };

  const execute = async (input) => {
    const invocation = shallowRecord(input, [
      'sessionId',
      'routeId',
      'request',
      'purposeLabel',
      'correlationId',
    ], [], 'EXECUTE_SCHEMA', 'Kernel execution');
    const request = shallowRecord(invocation.request, [
      'requestUrl',
      'method',
      'headers',
      'bodyBytes',
    ], [], 'EXECUTE_SCHEMA', 'Kernel ordinary request');
    const intentRequest = {
      routeId: invocation.routeId,
      method: request.method,
      requestUrl: request.requestUrl,
      headers: request.headers,
      bodyBytes: request.bodyBytes,
      purposeLabel: invocation.purposeLabel,
      correlationId: invocation.correlationId,
    };
    const matchedIntentId = intents.matchRetry({
      sessionId: invocation.sessionId,
      request: intentRequest,
    });
    const intent = matchedIntentId === null
      ? await runMutation(() => intents.captureIntent({
        sessionId: invocation.sessionId,
        ...intentRequest,
      }))
      : intents.getIntent(matchedIntentId);
    if (intent.state === 'terminal') {
      const existing = persistedResult(intent);
      if (existing === null) {
        throw new KernelError(
          'BUYER_OUTCOME_CORRUPTION',
          'terminal Spend Intent is missing its persisted BuyerOutcome',
        );
      }
      return existing;
    }
    if (intent.state === 'unresolved') {
      const existing = persistedResult(intent);
      if (existing) return existing;
    }
    if (new Set(['signing', 'signed', 'retrying']).has(intent.state)) {
      return Object.freeze({
        requestId: intent.requestId,
        status: 'request_in_flight',
        reasonCode: 'REQUEST_IN_FLIGHT',
        receipt: null,
      });
    }
    let approvedRetry = null;
    if (intent.state === 'approval_pending') {
      const approval = approvals.findRetryable({
        sessionId: intent.sessionId,
        intentHash: intent.intentHash,
      });
      const decisionAt = canonicalTimestamp(now(), 'approval retry decision time');
      if (approval !== null && Date.parse(decisionAt) >= Date.parse(approval.expiresAt)) {
        const expired = await expireApprovalCandidate({
          approvalId: approval.approvalId,
          intentId: approval.intentId,
          intentHash: approval.intentHash,
        }, decisionAt);
        if (expired !== null) return expired;
        const existing = persistedResult(intents.getIntent(intent.id));
        if (existing !== null) return existing;
        throw new KernelError(
          'APPROVAL_STATE_CONFLICT',
          'expired approval changed before its terminal outcome was observed',
        );
      }
      if (approval?.decision === 'pending') return approvalRequiredResult(intent, approval);
      if (approval?.decision === 'approved') approvedRetry = approval;
    }
    const active = inFlightByIntent.get(intent.id);
    if (active) {
      return Object.freeze({
        requestId: intent.requestId,
        status: 'request_in_flight',
        reasonCode: 'REQUEST_IN_FLIGHT',
        receipt: null,
      });
    }
    faultInjector('after_intent_commit', Object.freeze({ intentId: intent.id }));

    let complete;
    const operation = (async () => {
      const transportRequest = Object.freeze({
        requestUrl: request.requestUrl,
        method: request.method,
        headers: Object.freeze({
          ...request.headers,
          'idempotency-key': intent.idempotencyKey,
        }),
        bodyBytes: Buffer.from(request.bodyBytes),
      });
      let probed;
      try {
        probed = await transport.probe(transportRequest);
      } catch (error) {
        const challengeReason = challengeDenialReason(error);
        if (challengeReason !== null) {
          if (approvedRetry !== null) {
            return await replaceChangedApproval({
              intent,
              intentRequest,
              paymentRequired: null,
              challengeReceivedAt: null,
              evaluation: null,
              policyVersion: null,
            });
          }
          return await terminalizeWithoutExecution(intent, {
            expectedState: 'captured',
            status: 'payment_denied',
            reasonCode: challengeReason,
          });
        }
        if (approvedRetry !== null) {
          return await terminalizeOrdinary(intent, {
            status: 'upstream_failed',
            reasonCode: 'UPSTREAM_TRANSPORT_FAILURE',
            executionState: 'unknown',
            upstreamStatus: null,
            body: null,
            expectedState: 'approval_pending',
          });
        }
        return await terminalizeOrdinary(intent, {
          status: 'upstream_failed',
          reasonCode: 'UPSTREAM_TRANSPORT_FAILURE',
          executionState: 'unknown',
          upstreamStatus: null,
          body: null,
        });
      }
      if (probed.kind === 'response') {
        if (approvedRetry !== null) {
          return await replaceChangedApproval({
            intent,
            intentRequest,
            paymentRequired: null,
            challengeReceivedAt: null,
            evaluation: null,
            policyVersion: null,
          });
        }
        const successful = probed.status >= 200 && probed.status <= 299;
        return await terminalizeOrdinary(intent, {
          status: successful ? 'completed' : 'upstream_failed',
          reasonCode: successful ? 'ORDINARY_SUCCESS' : 'ORDINARY_HTTP_FAILURE',
          executionState: successful ? 'succeeded' : 'failed',
          upstreamStatus: probed.status,
          body: Buffer.from(probed.body),
        });
      }
      if (probed.kind === 'payment_required') {
        let challengeResult;
        try {
          challengeResult = await evaluateChallenge({
            intent,
            request,
            paymentRequired: probed.paymentRequired,
            persist: approvedRetry === null,
          });
        } catch (error) {
          const challengeReason = challengeDenialReason(error);
          if (challengeReason === null) throw error;
          if (approvedRetry !== null) {
            return await replaceChangedApproval({
              intent,
              intentRequest,
              paymentRequired: null,
              challengeReceivedAt: null,
              evaluation: null,
              policyVersion: null,
            });
          }
          return await terminalizeWithoutExecution(intent, {
            expectedState: 'captured',
            status: 'payment_denied',
            reasonCode: challengeReason,
          });
        }
        const { challengeReceivedAt, evaluation, policyVersion } = challengeResult;
        if (approvedRetry !== null) {
          const freshChallengeHash = sha256(canonicalJson(
            projectPaymentRequired(probed.paymentRequired),
          ));
          if (freshChallengeHash !== intent.challengeHash
              || evaluation.challengeHash !== intent.challengeHash) {
            return await replaceChangedApproval({
              intent,
              intentRequest,
              paymentRequired: probed.paymentRequired,
              challengeReceivedAt,
              evaluation,
              policyVersion,
            });
          }
          if (evaluation.decision !== 'approval_required') {
            return await replaceChangedApproval({
              intent,
              intentRequest,
              paymentRequired: probed.paymentRequired,
              challengeReceivedAt,
              evaluation,
              policyVersion,
            });
          }
          await reserveApproved({
            intent,
            evaluation,
            policyVersion,
            approval: approvedRetry,
          });
          return await executeReserved({
            intent: intents.getIntent(intent.id),
            request,
            transportRequest,
            paymentRequired: probed.paymentRequired,
            evaluation,
            policyVersion,
            approvalExpiresAt: approvedRetry.expiresAt,
          });
        }
        if (evaluation.decision === 'deny') {
          return await terminalizeWithoutExecution(intents.getIntent(intent.id), {
            expectedState: 'challenged',
            status: 'payment_denied',
            reasonCode: evaluation.reasonCode,
          });
        }
        if (evaluation.decision === 'approval_required') {
          return await requestApproval(
            intents.getIntent(intent.id),
            evaluation,
            policyVersion.id,
          );
        }
        await reserveAutomatic({ intent, evaluation, policyVersion });
        return await executeReserved({
          intent: intents.getIntent(intent.id),
          request,
          transportRequest,
          paymentRequired: probed.paymentRequired,
          evaluation,
          policyVersion,
        });
      }
      throw new KernelError(
        'TRANSPORT_RESULT_SCHEMA',
        'unpaid transport returned an unsupported result kind',
      );
    })();
    complete = operation;
    inFlightByIntent.set(intent.id, operation);
    try {
      return await operation;
    } catch (error) {
      const winner = persistedTerminalWinnerAfterConflict({
        error,
        originalIntent: intent,
        correlationId: invocation.correlationId,
      });
      if (winner !== null) return winner;
      throw error;
    } finally {
      if (inFlightByIntent.get(intent.id) === complete) inFlightByIntent.delete(intent.id);
    }
  };

  return Object.freeze({
    openOrResumeSession,
    applyPolicy,
    revokeAgent,
    transitionSessionPolicy,
    closeSession,
    approvePending,
    denyPending,
    expireDueApprovals,
    execute,
    status,
    statusByRequestId,
    receiptById,
  });
}
