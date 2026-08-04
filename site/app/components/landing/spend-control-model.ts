export const demoWallet = {
  provider: 'Customer-owned CDP wallet',
  address: '0x71d371d371d371d371d371d371d371d371d371d3',
  network: 'eip155:84532',
  networkLabel: 'Base Sepolia',
  asset: 'test USDC',
  simulated: true,
} as const;

export const demoOperator = {
  identity: 'operator:northstar-local-admin',
  label: 'Northstar local operator',
  evidence: 'simulated_fixture',
} as const;

export const spendPolicy = {
  name: 'Pilot spend policy v1',
  network: 'eip155:84532',
  asset: 'test USDC',
  allowedSellerOrigin: 'https://api.northstar.example',
  sessionBudgetAtomic: 5_000_000,
  sessionBudgetLabel: '5.00 test USDC',
  automaticAllowAtomic: 250_000,
  automaticAllowLabel: '0.25 test USDC',
  humanApprovalAtomic: 1_000_000,
  humanApprovalLabel: '1.00 test USDC',
  defaultAction: 'deny',
  versionHash:
    'sha256:74db8f3e74db8f3e74db8f3e74db8f3e74db8f3e74db8f3e74db8f3e74db8f3e',
} as const;

export interface DemoSpendIntent {
  id: string;
  callId: string;
  challengeId: string;
  sellerOrigin: string;
  resource: string;
  purpose: string;
  amountAtomic: number;
  amountLabel: string;
  decision: 'allow' | 'approval_required' | 'deny';
  requestHash: string;
  wallet: string;
  policyVersionHash: string;
  approvalExpiry: string | null;
  approvalExpiresAtMs: number | null;
  policyMismatch: string;
}

export const demoSpendIntents: readonly DemoSpendIntent[] = [
  {
    id: 'intent_model_context',
    callId: '0x8c0d2f4c…b811',
    challengeId: 'quote_model_context_0001',
    sellerOrigin: spendPolicy.allowedSellerOrigin,
    resource: '/v1/model-context',
    purpose: 'Fetch bounded model context',
    amountAtomic: 80_000,
    amountLabel: '0.08 test USDC',
    decision: 'allow',
    requestHash:
      'sha256:10a210a210a210a210a210a210a210a210a210a210a210a210a210a210a210a2',
    wallet: demoWallet.address,
    policyVersionHash: spendPolicy.versionHash,
    approvalExpiry: null,
    approvalExpiresAtMs: null,
    policyMismatch: 'None — every policy field matches',
  },
  {
    id: 'intent_unknown_seller',
    callId: '0x10f7b018…d920',
    challengeId: 'quote_unknown_seller_0002',
    sellerOrigin: 'https://unknown-seller.example',
    resource: '/v1/cheap-context',
    purpose: 'Try an unapproved seller',
    amountAtomic: 10_000,
    amountLabel: '0.01 test USDC',
    decision: 'deny',
    requestHash:
      'sha256:20b320b320b320b320b320b320b320b320b320b320b320b320b320b320b320b3',
    wallet: demoWallet.address,
    policyVersionHash: spendPolicy.versionHash,
    approvalExpiry: null,
    approvalExpiresAtMs: null,
    policyMismatch: 'Seller origin is not allow-listed',
  },
  {
    id: 'intent_repo_audit',
    callId: '0x9a61ed72…1c40',
    challengeId: 'quote_repo_audit_0003',
    sellerOrigin: spendPolicy.allowedSellerOrigin,
    resource: '/v1/repository-audit',
    purpose: 'Run repository risk audit',
    amountAtomic: 600_000,
    amountLabel: '0.60 test USDC',
    decision: 'approval_required',
    requestHash:
      'sha256:4ce14ce14ce14ce14ce14ce14ce14ce14ce14ce14ce14ce14ce14ce14ce14ce1',
    wallet: demoWallet.address,
    policyVersionHash: spendPolicy.versionHash,
    approvalExpiry: '2026-08-02T18:15:00Z · fictional fixture',
    approvalExpiresAtMs: Date.parse('2026-08-02T18:15:00Z'),
    policyMismatch: 'Amount is 0.35 test USDC above the automatic ceiling',
  },
] as const;

export const demoSessionProjection = {
  projectionId: 'session_projection_demo_0001',
  policyVersionHash: spendPolicy.versionHash,
  network: spendPolicy.network,
  chargedAtomic: 680_000,
  outcomeStates: ['simulated_allowed', 'denied', 'simulated_finalized'],
  settlementStatus: 'not_broadcast',
  projectedIntentIds: demoSpendIntents.map((intent) => intent.id),
  unsigned: true,
  simulated: true,
} as const;

export const SPEND_SANDBOX_STAGES = [
  'ready',
  'policy_loaded',
  'auto_allowed',
  'denied',
  'approval_pending',
  'approved_waiting_retry',
  'approval_invalidated',
  'finalized',
] as const;

export type SpendSandboxStage = (typeof SPEND_SANDBOX_STAGES)[number];

export interface SpendApprovalBinding {
  requestHash: string;
  challengeId: string;
  sellerOrigin: string;
  resource: string;
  amountAtomic: number;
  wallet: string;
  policyVersionHash: string;
  expiresAtMs: number;
}

export interface SpendApprovalPermit extends SpendApprovalBinding {
  approvedAtMs: number;
  operator: typeof demoOperator;
}

export type RetryInvalidationReason =
  | 'binding_mismatch'
  | 'approval_expired'
  | 'retry_before_approval'
  | 'invalid_retry_time';

export interface SpendRetryOutcome {
  reason: RetryInvalidationReason;
  attemptedAtMs: number;
}

export type SpendSandboxState =
  | {
      stage: Exclude<
        SpendSandboxStage,
        | 'approval_pending'
        | 'approved_waiting_retry'
        | 'approval_invalidated'
        | 'finalized'
      >;
    }
  | {
      stage: 'approval_pending';
      approvalIntent: DemoSpendIntent;
      pendingApproval: SpendApprovalBinding;
    }
  | {
      stage: 'approved_waiting_retry';
      approvalIntent: DemoSpendIntent;
      approvalPermit: SpendApprovalPermit;
    }
  | {
      stage: 'approval_invalidated';
      approvalIntent: DemoSpendIntent;
      approvalRecord: SpendApprovalPermit;
      retryOutcome: SpendRetryOutcome;
    }
  | {
      stage: 'finalized';
      approvalIntent: DemoSpendIntent;
      approvalPermit: SpendApprovalPermit;
    };

export type SpendSandboxAction =
  | { type: 'LOAD_POLICY' }
  | { type: 'RUN_ALLOWED_REQUEST' }
  | { type: 'RUN_DENIED_REQUEST' }
  | { type: 'QUEUE_APPROVAL'; intent: DemoSpendIntent }
  | { type: 'APPROVE'; nowMs: number }
  | {
      type: 'RETRY_APPROVED_REQUEST';
      repeatedIntent: DemoSpendIntent;
      nowMs: number;
    }
  | { type: 'RESET' };

export interface DemoSpendAttempt extends DemoSpendIntent {
  hasProjectedSigningBoundary: boolean;
  status:
    | 'Simulated allowed'
    | 'Denied'
    | 'Approval required'
    | 'Approved — waiting for retry'
    | 'Approval invalidated — changed request'
    | 'Approval expired — start again'
    | 'Approval invalidated — retry predates approval'
    | 'Approval invalidated — invalid retry time'
    | 'Simulated finalized';
}

export const INITIAL_SPEND_SANDBOX_STATE: SpendSandboxState = {
  stage: 'ready',
};

export const spendStageIndex = (stage: SpendSandboxStage): number =>
  SPEND_SANDBOX_STAGES.indexOf(stage);

function approvalBindingFor(
  intent: DemoSpendIntent,
): SpendApprovalBinding | null {
  if (
    intent.decision !== 'approval_required' ||
    intent.approvalExpiresAtMs === null
  ) {
    return null;
  }

  return {
    requestHash: intent.requestHash,
    challengeId: intent.challengeId,
    sellerOrigin: intent.sellerOrigin,
    resource: intent.resource,
    amountAtomic: intent.amountAtomic,
    wallet: intent.wallet,
    policyVersionHash: intent.policyVersionHash,
    expiresAtMs: intent.approvalExpiresAtMs,
  };
}

function permitMatchesRepeatedIntent(
  permit: SpendApprovalBinding,
  intent: DemoSpendIntent,
): boolean {
  return (
    permit.requestHash === intent.requestHash &&
    permit.challengeId === intent.challengeId &&
    permit.sellerOrigin === intent.sellerOrigin &&
    permit.resource === intent.resource &&
    permit.amountAtomic === intent.amountAtomic &&
    permit.wallet === intent.wallet &&
    permit.policyVersionHash === intent.policyVersionHash &&
    permit.expiresAtMs === intent.approvalExpiresAtMs
  );
}

function retryInvalidationReason(
  permit: SpendApprovalPermit,
  repeatedIntent: DemoSpendIntent,
  nowMs: number,
): RetryInvalidationReason | null {
  if (!Number.isFinite(nowMs)) return 'invalid_retry_time';
  if (nowMs < permit.approvedAtMs) return 'retry_before_approval';
  if (nowMs >= permit.expiresAtMs) return 'approval_expired';
  if (!permitMatchesRepeatedIntent(permit, repeatedIntent)) {
    return 'binding_mismatch';
  }
  return null;
}

function invalidatedAttemptStatus(
  reason: RetryInvalidationReason,
): DemoSpendAttempt['status'] {
  switch (reason) {
    case 'binding_mismatch':
      return 'Approval invalidated — changed request';
    case 'approval_expired':
      return 'Approval expired — start again';
    case 'retry_before_approval':
      return 'Approval invalidated — retry predates approval';
    case 'invalid_retry_time':
      return 'Approval invalidated — invalid retry time';
  }
}

function invalidatedAttemptDetail(reason: RetryInvalidationReason): string {
  switch (reason) {
    case 'binding_mismatch':
      return 'Repeated request did not match the exact approval. Start a new request.';
    case 'approval_expired':
      return 'Approval expired before retry. Start a new request.';
    case 'retry_before_approval':
      return 'Retry timestamp predates the approval. Start a new request.';
    case 'invalid_retry_time':
      return 'Retry timestamp was invalid. Start a new request.';
  }
}

export function spendSandboxReducer(
  state: SpendSandboxState,
  action: SpendSandboxAction,
): SpendSandboxState {
  switch (action.type) {
    case 'LOAD_POLICY':
      return state.stage === 'ready' ? { stage: 'policy_loaded' } : state;
    case 'RUN_ALLOWED_REQUEST':
      return state.stage === 'policy_loaded' ? { stage: 'auto_allowed' } : state;
    case 'RUN_DENIED_REQUEST':
      return state.stage === 'auto_allowed' ? { stage: 'denied' } : state;
    case 'QUEUE_APPROVAL': {
      if (state.stage !== 'denied') return state;
      const pendingApproval = approvalBindingFor(action.intent);
      return pendingApproval
        ? {
            stage: 'approval_pending',
            approvalIntent: { ...action.intent },
            pendingApproval,
          }
        : state;
    }
    case 'APPROVE': {
      if (state.stage !== 'approval_pending') return state;
      if (
        !Number.isFinite(action.nowMs) ||
        !(action.nowMs < state.pendingApproval.expiresAtMs)
      ) {
        return state;
      }
      return {
        stage: 'approved_waiting_retry',
        approvalIntent: state.approvalIntent,
        approvalPermit: {
          ...state.pendingApproval,
          approvedAtMs: action.nowMs,
          operator: demoOperator,
        },
      };
    }
    case 'RETRY_APPROVED_REQUEST': {
      if (state.stage !== 'approved_waiting_retry') return state;
      const permit = state.approvalPermit;
      const invalidationReason = retryInvalidationReason(
        permit,
        action.repeatedIntent,
        action.nowMs,
      );
      if (invalidationReason !== null) {
        return {
          stage: 'approval_invalidated',
          approvalIntent: state.approvalIntent,
          approvalRecord: permit,
          retryOutcome: {
            reason: invalidationReason,
            attemptedAtMs: action.nowMs,
          },
        };
      }
      return {
        stage: 'finalized',
        approvalIntent: state.approvalIntent,
        approvalPermit: permit,
      };
    }
    case 'RESET':
      return INITIAL_SPEND_SANDBOX_STATE;
    default:
      return state;
  }
}

export function spendSandboxView(state: SpendSandboxState) {
  const index = spendStageIndex(state.stage);
  const hasAutoAllowed = index >= spendStageIndex('auto_allowed');
  const hasDenied = index >= spendStageIndex('denied');
  const approvalIntent =
    state.stage === 'approval_pending' ||
    state.stage === 'approved_waiting_retry' ||
    state.stage === 'approval_invalidated' ||
    state.stage === 'finalized'
      ? state.approvalIntent
      : null;
  const hasApprovalAttempt = approvalIntent !== null;
  const isApprovedWaitingRetry = state.stage === 'approved_waiting_retry';
  const hasApprovedPermit = isApprovedWaitingRetry;
  const approvalRecord =
    state.stage === 'approved_waiting_retry' || state.stage === 'finalized'
      ? state.approvalPermit
      : state.stage === 'approval_invalidated'
        ? state.approvalRecord
        : null;
  const retryOutcome =
    state.stage === 'approval_invalidated' ? state.retryOutcome : null;
  const hasSessionProjection = state.stage === 'finalized';
  const approvalPanelState =
    state.stage === 'approval_pending'
      ? 'approval_required'
      : state.stage === 'approved_waiting_retry'
        ? 'approved_waiting_retry'
        : state.stage === 'approval_invalidated'
          ? 'approval_invalidated'
          : null;
  const attempts: DemoSpendAttempt[] = [];

  if (hasAutoAllowed) {
    attempts.push({
      ...demoSpendIntents[0],
      hasProjectedSigningBoundary: true,
      status: 'Simulated allowed',
    });
  }

  if (hasDenied) {
    attempts.push({
      ...demoSpendIntents[1],
      hasProjectedSigningBoundary: false,
      status: 'Denied',
    });
  }

  if (hasApprovalAttempt) {
    let status: DemoSpendAttempt['status'] = 'Approval required';
    if (isApprovedWaitingRetry) status = 'Approved — waiting for retry';
    if (retryOutcome !== null) {
      status = invalidatedAttemptStatus(retryOutcome.reason);
    }
    if (hasSessionProjection) status = 'Simulated finalized';
    attempts.push({
      ...approvalIntent,
      hasProjectedSigningBoundary: hasSessionProjection,
      status,
    });
  }

  const chargedAtomic = hasAutoAllowed
    ? demoSpendIntents[0].amountAtomic +
      (state.stage === 'finalized' ? state.approvalIntent.amountAtomic : 0)
    : 0;

  return {
    hasPolicy: index >= spendStageIndex('policy_loaded'),
    attempts,
    hasPendingApproval: state.stage === 'approval_pending',
    hasApprovedPermit,
    hasSessionProjection,
    approvalPanelState,
    approvalOperator: approvalRecord?.operator ?? null,
    retryOutcome,
    approvalInvalidationDetail:
      retryOutcome === null
        ? null
        : invalidatedAttemptDetail(retryOutcome.reason),
    chargedAtomic,
    remainingAtomic: spendPolicy.sessionBudgetAtomic - chargedAtomic,
  };
}

export function nextSpendSandboxAction(stage: SpendSandboxStage): {
  action: SpendSandboxAction;
  label: string;
  note: string;
} | null {
  switch (stage) {
    case 'ready':
      return {
        action: { type: 'LOAD_POLICY' },
        label: 'Load the sample policy',
        note: 'Creates a local default-deny policy. No wallet is contacted.',
      };
    case 'policy_loaded':
      return {
        action: { type: 'RUN_ALLOWED_REQUEST' },
        label: 'Run an in-policy request',
        note: 'Simulates one exact x402 payment below the automatic ceiling.',
      };
    case 'auto_allowed':
      return {
        action: { type: 'RUN_DENIED_REQUEST' },
        label: 'Try an unknown seller',
        note: 'Shows default deny before any wallet or signing path is reached.',
      };
    case 'denied':
      return {
        action: { type: 'QUEUE_APPROVAL', intent: demoSpendIntents[2] },
        label: 'Try a larger request',
        note: 'Creates an approval request without creating a payment signature.',
      };
    case 'approval_pending':
      return {
        action: {
          type: 'APPROVE',
          nowMs: Date.parse('2026-08-02T18:13:00Z'),
        },
        label: 'Approve this exact intent',
        note: 'Records one bounded approval, then stops. No signature or retry occurs.',
      };
    case 'approved_waiting_retry':
      return {
        action: {
          type: 'RETRY_APPROVED_REQUEST',
          repeatedIntent: demoSpendIntents[2],
          nowMs: Date.parse('2026-08-02T18:14:00Z'),
        },
        label: 'Repeat the exact Agent request',
        note: 'Simulates deliberate Wielder retry, exact revalidation, and an unsigned outcome projection.',
      };
    case 'approval_invalidated':
    case 'finalized':
      return null;
  }
}
