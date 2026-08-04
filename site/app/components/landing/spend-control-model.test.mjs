import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import * as model from './spend-control-model.ts';

const APPROVAL_NOW_MS = Date.parse('2026-08-02T18:13:00Z');
const queueApproval = (intent = model.demoSpendIntents[2]) =>
  model.spendSandboxReducer(
    { stage: 'denied' },
    { type: 'QUEUE_APPROVAL', intent },
  );

const approvePending = (pending = queueApproval()) =>
  model.spendSandboxReducer(pending, {
    type: 'APPROVE',
    nowMs: APPROVAL_NOW_MS,
  });

const finalizeApproved = (approved = approvePending()) =>
  model.spendSandboxReducer(
    approved,
    model.nextSpendSandboxAction('approved_waiting_retry').action,
  );

test('preview atomic money stays exact within Number safe-integer range', () => {
  const atomicEntries = (scope, record) =>
    Object.entries(record)
      .filter(([key]) => key.endsWith('Atomic'))
      .map(([key, value]) => [`${scope}.${key}`, value]);
  const atomicAmounts = [
    ...atomicEntries('policy', model.spendPolicy),
    ...model.demoSpendIntents.flatMap((intent) =>
      atomicEntries(`intent.${intent.id}`, intent),
    ),
    ...atomicEntries('projection', model.demoSessionProjection),
  ];
  const derivedTotals = [];
  let state = model.INITIAL_SPEND_SANDBOX_STATE;

  while (true) {
    const view = model.spendSandboxView(state);
    derivedTotals.push({
      stage: state.stage,
      chargedAtomic: view.chargedAtomic,
      remainingAtomic: view.remainingAtomic,
    });
    atomicAmounts.push(
      ...atomicEntries(`view.${state.stage}`, view),
    );

    const next = model.nextSpendSandboxAction(state.stage);
    if (next === null) break;
    state = model.spendSandboxReducer(state, next.action);
  }

  for (const [label, amount] of atomicAmounts) {
    assert.ok(
      Number.isSafeInteger(amount) && amount >= 0,
      `${label} must be a nonnegative Number safe integer`,
    );
  }

  for (const { stage, chargedAtomic, remainingAtomic } of derivedTotals) {
    assert.equal(
      chargedAtomic + remainingAtomic,
      model.spendPolicy.sessionBudgetAtomic,
      `${stage} totals must conserve the session budget exactly`,
    );
  }
});

test('the sample policy is default-deny and bound to Base Sepolia test USDC', () => {
  assert.ok(model.spendPolicy, 'spendPolicy must be exported');
  assert.equal(model.spendPolicy.defaultAction, 'deny');
  assert.equal(model.spendPolicy.network, 'eip155:84532');
  assert.equal(model.demoWallet.network, model.spendPolicy.network);
  assert.equal(model.demoWallet.asset, 'test USDC');
  assert.equal(model.demoWallet.simulated, true);
});

test('sample Spend Intents cover allow, deny, and exact approval decisions', () => {
  assert.ok(model.demoSpendIntents, 'demoSpendIntents must be exported');
  assert.equal(model.demoSpendIntents.length, 3);
  assert.equal(
    new Set(model.demoSpendIntents.map((intent) => intent.callId)).size,
    model.demoSpendIntents.length,
  );
  assert.deepEqual(
    model.demoSpendIntents.map((intent) => intent.decision),
    ['allow', 'deny', 'approval_required'],
  );
  assert.equal(
    model.demoSpendIntents[1].sellerOrigin ===
      model.spendPolicy.allowedSellerOrigin,
    false,
  );
});

test('the spend-control sandbox advances only through authorized transitions', () => {
  assert.equal(typeof model.spendSandboxReducer, 'function');
  let state = model.INITIAL_SPEND_SANDBOX_STATE;

  state = model.spendSandboxReducer(state, { type: 'RUN_ALLOWED_REQUEST' });
  assert.equal(state.stage, 'ready');

  state = model.spendSandboxReducer(state, { type: 'LOAD_POLICY' });
  assert.equal(state.stage, 'policy_loaded');

  state = model.spendSandboxReducer(state, { type: 'RUN_ALLOWED_REQUEST' });
  assert.equal(state.stage, 'auto_allowed');
  assert.equal(model.spendSandboxView(state).attempts.length, 1);

  state = model.spendSandboxReducer(state, { type: 'RUN_DENIED_REQUEST' });
  assert.equal(state.stage, 'denied');
  assert.equal(model.spendSandboxView(state).attempts.at(-1)?.status, 'Denied');

  state = model.spendSandboxReducer(
    state,
    model.nextSpendSandboxAction('denied').action,
  );
  assert.equal(state.stage, 'approval_pending');
  assert.equal(model.spendSandboxView(state).hasPendingApproval, true);

  state = model.spendSandboxReducer(
    state,
    model.nextSpendSandboxAction('approval_pending').action,
  );
  assert.equal(state.stage, 'approved_waiting_retry');
  assert.equal(model.spendSandboxView(state).hasApprovedPermit, true);
  assert.equal(
    model.spendSandboxView(state).attempts.at(-1)
      ?.hasProjectedSigningBoundary,
    false,
  );

  state = model.spendSandboxReducer(
    state,
    model.nextSpendSandboxAction('approved_waiting_retry').action,
  );
  assert.equal(state.stage, 'finalized');
  assert.equal(model.spendSandboxView(state).hasSessionProjection, true);
  assert.deepEqual(model.SPEND_SANDBOX_STAGES, [
    'ready',
    'policy_loaded',
    'auto_allowed',
    'denied',
    'approval_pending',
    'approved_waiting_retry',
    'approval_invalidated',
    'finalized',
  ]);
});

test('each changed approval binding invalidates the approval and preserves its audit outcome', () => {
  const intent = model.demoSpendIntents[2];
  const mutations = [
    ['requestHash', { ...intent, requestHash: `sha256:${'f'.repeat(64)}` }],
    ['challengeId', { ...intent, challengeId: 'quote_changed_fixture' }],
    [
      'sellerOrigin',
      { ...intent, sellerOrigin: 'https://changed-seller.example' },
    ],
    ['resource', { ...intent, resource: '/v1/changed-audit' }],
    ['amountAtomic', { ...intent, amountAtomic: intent.amountAtomic + 1 }],
    [
      'wallet',
      { ...intent, wallet: '0x82e482e482e482e482e482e482e482e482e482e4' },
    ],
    [
      'policyVersionHash',
      { ...intent, policyVersionHash: `sha256:${'e'.repeat(64)}` },
    ],
    [
      'approvalExpiryMs',
      {
        ...intent,
        approvalExpiresAtMs: intent.approvalExpiresAtMs + 1,
      },
    ],
  ];

  for (const [field, repeatedIntent] of mutations) {
    const approved = approvePending(queueApproval(intent));
    const retried = model.spendSandboxReducer(approved, {
      type: 'RETRY_APPROVED_REQUEST',
      repeatedIntent,
      nowMs: Date.parse('2026-08-02T18:14:00Z'),
    });

    assert.notEqual(retried.stage, 'finalized', `${field} must not finalize`);
    assert.equal(
      retried.stage,
      'approval_invalidated',
      `${field} must start again`,
    );
    assert.equal(retried.retryOutcome.reason, 'binding_mismatch', field);
    assert.deepEqual(retried.approvalIntent, intent, field);
    assert.equal(
      retried.approvalRecord.operator.evidence,
      'simulated_fixture',
      field,
    );
    assert.equal(
      'approvalPermit' in retried,
      false,
      `${field} must clear permit`,
    );
    assert.equal(
      'pendingApproval' in retried,
      false,
      `${field} must not reuse the old approval`,
    );
    assert.equal(
      model.spendSandboxView(retried).attempts.at(-1)?.status,
      'Approval invalidated — changed request',
      field,
    );
  }
});

test('approval records a simulated operator identity without claiming authentication', () => {
  const approved = approvePending();
  const approvalAction = model.nextSpendSandboxAction('approval_pending').action;

  assert.equal(approved.stage, 'approved_waiting_retry');
  assert.deepEqual(approved.approvalPermit.operator, {
    identity: 'operator:northstar-local-admin',
    label: 'Northstar local operator',
    evidence: 'simulated_fixture',
  });
  assert.deepEqual(
    model.spendSandboxView(approved).approvalOperator,
    approved.approvalPermit.operator,
  );
  assert.equal('operatorIdentity' in approvalAction, false);
});

test('the exact-authority preview exposes the approval operator identity', () => {
  const source = readFileSync(
    new URL('./SpendControlSandbox.tsx', import.meta.url),
    'utf8',
  );

  assert.match(source, /<dt>Simulated operator<\/dt>/);
  assert.match(source, /view\.approvalOperator/);
  assert.match(source, /Simulated operator/);
  assert.match(source, /no authentication performed/);
  assert.doesNotMatch(source, /authenticated operator/i);
});

test('approval promotes only the intent binding stored when it was queued', () => {
  const approvalIntent = model.demoSpendIntents[2];
  const substitutedIntent = {
    ...model.demoSpendIntents[0],
    approvalExpiry: approvalIntent.approvalExpiry,
    approvalExpiresAtMs: approvalIntent.approvalExpiresAtMs,
  };
  const pending = model.spendSandboxReducer(
    { stage: 'denied' },
    { type: 'QUEUE_APPROVAL', intent: approvalIntent },
  );
  const approved = model.spendSandboxReducer(pending, {
    type: 'APPROVE',
    nowMs: Date.parse('2026-08-02T18:14:00Z'),
    // Malicious surplus data must not replace the queued binding.
    intent: substitutedIntent,
  });
  const retried = model.spendSandboxReducer(approved, {
    type: 'RETRY_APPROVED_REQUEST',
    repeatedIntent: substitutedIntent,
    nowMs: Date.parse('2026-08-02T18:14:30Z'),
  });
  const rejectedQueue = model.spendSandboxReducer(
    { stage: 'denied' },
    { type: 'QUEUE_APPROVAL', intent: substitutedIntent },
  );

  assert.notEqual(retried.stage, 'finalized');
  assert.equal(retried.stage, 'approval_invalidated');
  assert.equal(retried.retryOutcome.reason, 'binding_mismatch');
  assert.deepEqual(retried.approvalIntent, approvalIntent);
  assert.equal('pendingApproval' in retried, false);
  assert.equal('approvalPermit' in retried, false);
  assert.deepEqual(rejectedQueue, { stage: 'denied' });
});

test('the exact permit expiry millisecond cannot finalize', () => {
  const intent = model.demoSpendIntents[2];
  const pending = model.spendSandboxReducer(
    { stage: 'denied' },
    { type: 'QUEUE_APPROVAL', intent },
  );
  const approved = model.spendSandboxReducer(pending, {
    type: 'APPROVE',
    nowMs: Date.parse('2026-08-02T18:14:00Z'),
  });
  const retried = model.spendSandboxReducer(approved, {
    type: 'RETRY_APPROVED_REQUEST',
    repeatedIntent: intent,
    nowMs: intent.approvalExpiresAtMs,
  });

  assert.equal(retried.stage, 'approval_invalidated');
  assert.equal(retried.retryOutcome.reason, 'approval_expired');
  assert.equal(retried.retryOutcome.attemptedAtMs, intent.approvalExpiresAtMs);
  assert.deepEqual(retried.approvalIntent, intent);
  assert.equal('pendingApproval' in retried, false);
  assert.equal('approvalPermit' in retried, false);
});

test('queued intent details remain the display source through finalization', () => {
  const alternateIntent = {
    ...model.demoSpendIntents[2],
    id: 'intent_dependency_review',
    callId: '0x6b70aa42…4f21',
    challengeId: 'quote_dependency_review_0004',
    resource: '/v1/dependency-review',
    purpose: 'Review dependency risk',
    amountAtomic: 700_000,
    amountLabel: '0.70 test USDC',
    requestHash: `sha256:${'d'.repeat(64)}`,
    approvalExpiry: '2026-08-02T18:20:00Z · fictional fixture',
    approvalExpiresAtMs: Date.parse('2026-08-02T18:20:00Z'),
    policyMismatch: 'Amount is 0.45 test USDC above the automatic ceiling',
  };
  const pending = queueApproval(alternateIntent);
  const approved = approvePending(pending);
  const finalized = model.spendSandboxReducer(approved, {
    type: 'RETRY_APPROVED_REQUEST',
    repeatedIntent: alternateIntent,
    nowMs: Date.parse('2026-08-02T18:14:00Z'),
  });
  const renderedIntent = (state) => {
    const attempt = model.spendSandboxView(state).attempts.at(-1);
    return Object.fromEntries(
      Object.keys(alternateIntent).map((key) => [key, attempt?.[key]]),
    );
  };

  for (const state of [pending, approved, finalized]) {
    assert.deepEqual(renderedIntent(state), alternateIntent);
    assert.deepEqual(state.approvalIntent, alternateIntent);
  }
});

test('the projection preview renders the finalized intent charge', () => {
  const alternateIntent = {
    ...model.demoSpendIntents[2],
    id: 'intent_charge_preview',
    callId: '0x7c81bb53…5a32',
    challengeId: 'quote_charge_preview_0005',
    amountAtomic: 700_000,
    amountLabel: '0.70 test USDC',
    requestHash: `sha256:${'c'.repeat(64)}`,
  };
  const finalized = model.spendSandboxReducer(
    approvePending(queueApproval(alternateIntent)),
    {
      type: 'RETRY_APPROVED_REQUEST',
      repeatedIntent: alternateIntent,
      nowMs: Date.parse('2026-08-02T18:14:00Z'),
    },
  );
  const view = model.spendSandboxView(finalized);
  const source = readFileSync(
    new URL('./SpendControlSandbox.tsx', import.meta.url),
    'utf8',
  );

  assert.equal(view.chargedAtomic, 780_000);
  assert.match(source, /chargedAtomic=\{view\.chargedAtomic\}/);
  assert.match(source, /formatAtomic\(chargedAtomic\)/);
  assert.doesNotMatch(
    source,
    /formatAtomic\(demoSessionProjection\.chargedAtomic\)/,
  );
});

test('invalid retry time invalidates the approval with an honest audit reason', () => {
  const intent = model.demoSpendIntents[2];
  const pending = queueApproval(intent);
  const invalidRetryTimes = [
    ['negative infinity', Number.NEGATIVE_INFINITY, 'invalid_retry_time'],
    ['before approval', APPROVAL_NOW_MS - 1, 'retry_before_approval'],
    ['positive infinity', Number.POSITIVE_INFINITY, 'invalid_retry_time'],
    ['NaN', Number.NaN, 'invalid_retry_time'],
  ];

  for (const [label, nowMs, expectedReason] of invalidRetryTimes) {
    const retried = model.spendSandboxReducer(approvePending(pending), {
      type: 'RETRY_APPROVED_REQUEST',
      repeatedIntent: intent,
      nowMs,
    });

    assert.equal(retried.stage, 'approval_invalidated', label);
    assert.equal(retried.retryOutcome.reason, expectedReason, label);
    assert.deepEqual(retried.approvalIntent, intent, label);
    assert.equal('approvalPermit' in retried, false, label);
    assert.equal('pendingApproval' in retried, false, label);
  }
});

test('a retry after the fixture expiry clears approval without finalizing', () => {
  const intent = model.demoSpendIntents[2];
  const approved = approvePending(queueApproval(intent));
  const retried = model.spendSandboxReducer(approved, {
    type: 'RETRY_APPROVED_REQUEST',
    repeatedIntent: intent,
    nowMs: Date.parse('2026-08-02T18:15:00Z') + 1,
  });

  assert.equal(retried.stage, 'approval_invalidated');
  assert.equal(retried.retryOutcome.reason, 'approval_expired');
  assert.deepEqual(retried.approvalIntent, intent);
  assert.equal('pendingApproval' in retried, false);
  assert.equal('approvalPermit' in retried, false);
  assert.equal(
    model.spendSandboxView(retried).attempts.at(-1)?.status,
    'Approval expired — start again',
  );
});

test('an invalidated retry is distinct from the earlier unknown-seller denial', () => {
  const intent = model.demoSpendIntents[2];
  const retried = model.spendSandboxReducer(approvePending(queueApproval(intent)), {
    type: 'RETRY_APPROVED_REQUEST',
    repeatedIntent: { ...intent, resource: '/v1/substituted-resource' },
    nowMs: Date.parse('2026-08-02T18:14:00Z'),
  });
  const view = model.spendSandboxView(retried);

  assert.equal(retried.stage, 'approval_invalidated');
  assert.equal(view.hasApprovedPermit, false);
  assert.equal(view.hasSessionProjection, false);
  assert.equal(view.approvalPanelState, 'approval_invalidated');
  assert.equal(view.retryOutcome.reason, 'binding_mismatch');
  assert.equal(view.attempts.length, 3);
  assert.equal(view.attempts[1]?.status, 'Denied');
  assert.equal(
    view.attempts[2]?.status,
    'Approval invalidated — changed request',
  );
});

test('operator approval ends without signing until the Wielder repeats the exact request', () => {
  const pendingState = queueApproval();
  const pending = model.spendSandboxView(pendingState);
  const escalated = pending.attempts.at(-1);
  assert.equal(escalated?.decision, 'approval_required');
  assert.equal(escalated?.hasProjectedSigningBoundary, false);
  assert.equal(escalated?.status, 'Approval required');
  assert.match(escalated?.requestHash ?? '', /^sha256:[a-f0-9]{64}$/);
  assert.equal(escalated?.wallet, model.demoWallet.address);
  assert.equal(escalated?.policyVersionHash, model.spendPolicy.versionHash);
  assert.ok(escalated?.approvalExpiry);
  assert.ok(escalated?.policyMismatch);

  const approved = model
    .spendSandboxView(approvePending(pendingState))
    .attempts.at(-1);
  assert.equal(approved?.hasProjectedSigningBoundary, false);
  assert.equal(approved?.status, 'Approved — waiting for retry');

  const finalized = model.spendSandboxView(finalizeApproved());
  const retried = finalized.attempts.at(-1);
  assert.equal(retried?.hasProjectedSigningBoundary, true);
  assert.equal('signatureCreated' in retried, false);
  assert.equal(retried?.status, 'Simulated finalized');
  assert.equal(finalized.attempts[0]?.status, 'Simulated allowed');
});

test('the finalized flow no longer exposes an approval panel waiting for retry', () => {
  assert.equal(
    model.spendSandboxView(approvePending()).approvalPanelState,
    'approved_waiting_retry',
  );
  assert.equal(
    model.spendSandboxView(finalizeApproved()).approvalPanelState,
    null,
  );
});

test('the final artifact is an unsigned session projection, not a signed receipt', () => {
  assert.ok(
    model.demoSessionProjection,
    'demoSessionProjection must be exported',
  );
  assert.equal('demoReceipt' in model, false);
  const view = model.spendSandboxView(finalizeApproved());
  assert.equal(view.chargedAtomic, 680_000);
  assert.equal(view.remainingAtomic, 4_320_000);
  assert.equal(
    view.remainingAtomic,
    model.spendPolicy.sessionBudgetAtomic - view.chargedAtomic,
  );
  assert.equal(model.demoSessionProjection.chargedAtomic, view.chargedAtomic);
  assert.equal(model.demoSessionProjection.simulated, true);
  assert.equal(model.demoSessionProjection.unsigned, true);
  assert.equal(model.demoSessionProjection.settlementStatus, 'not_broadcast');
  assert.equal('signatureAlgorithm' in model.demoSessionProjection, false);
  assert.deepEqual(model.demoSessionProjection.projectedIntentIds, [
    'intent_model_context',
    'intent_unknown_seller',
    'intent_repo_audit',
  ]);
});

test('each active stage exposes one explicit next operator action', () => {
  assert.equal(typeof model.nextSpendSandboxAction, 'function');
  assert.equal(
    model.nextSpendSandboxAction('ready')?.action.type,
    'LOAD_POLICY',
  );
  assert.equal(
    model.nextSpendSandboxAction('policy_loaded')?.action.type,
    'RUN_ALLOWED_REQUEST',
  );
  assert.equal(
    model.nextSpendSandboxAction('auto_allowed')?.action.type,
    'RUN_DENIED_REQUEST',
  );
  assert.equal(
    model.nextSpendSandboxAction('denied')?.action.type,
    'QUEUE_APPROVAL',
  );
  assert.equal(
    model.nextSpendSandboxAction('approval_pending')?.action.type,
    'APPROVE',
  );
  assert.equal(
    model.nextSpendSandboxAction('approved_waiting_retry')?.action.type,
    'RETRY_APPROVED_REQUEST',
  );
  assert.equal(model.nextSpendSandboxAction('approval_invalidated'), null);
  assert.equal(model.nextSpendSandboxAction('finalized'), null);
});

test('Hero and metadata independently lead with the Wallet Kernel', () => {
  const hero = readFileSync(new URL('./Hero.tsx', import.meta.url), 'utf8');
  const layout = readFileSync(
    new URL('../../layout.tsx', import.meta.url),
    'utf8',
  );

  assert.match(hero, /customer-hosted Wallet Kernel/i);
  assert.match(layout, /customer-hosted Wallet Kernel/i);
  assert.doesNotMatch(hero, /reward close|reward program/i);
});

test('metadata describes a pre-release preview with planned receipts', () => {
  const source = readFileSync(
    new URL('../../layout.tsx', import.meta.url),
    'utf8',
  );
  const descriptions = [
    ...source.matchAll(/description:\s*(?:\n\s*)?["']([^"']+)["']/g),
  ].map((match) => match[1]);

  assert.equal(descriptions.length, 2);
  for (const description of descriptions) {
    assert.match(description, /pre-release offline preview/i);
    assert.match(description, /planned signed receipts/i);
  }
});

test('landing content release-gates receipt and settlement capabilities', () => {
  const source = readFileSync(
    new URL('../../landing-content.ts', import.meta.url),
    'utf8',
  ).replace(/\s+/g, ' ');

  assert.match(source, /eyebrow: 'Planned receipt'/);
  assert.match(
    source,
    /A release-gated flow can anchor settlement on-chain .* in a signed local receipt\./,
  );
  assert.match(source, /Release-gated signed receipts will let teams inspect/);
  assert.match(source, /label: 'release-gated payment rail'/);
  assert.match(
    source,
    /value: 'UNSIGNED'.*label: 'browser artifact'.*not broadcast and not live evidence/,
  );
  assert.doesNotMatch(
    source,
    /value: 'SIGNED'.*label: 'terminal receipts'/,
  );
  assert.doesNotMatch(source, /48 settled x402 calls/i);
});

test('Hero presents signed receipts as planned and release-gated', () => {
  const source = readFileSync(
    new URL('./Hero.tsx', import.meta.url),
    'utf8',
  ).replace(/\s+/g, ' ');

  assert.match(source, /planned signed receipts behind the release gate/i);
});

test('ProofLoop keeps planned on-chain settlement behind the release gate', () => {
  const source = readFileSync(
    new URL('./ProofLoop.tsx', import.meta.url),
    'utf8',
  ).replace(/\s+/g, ' ');

  assert.match(
    source,
    /Planned on-chain settlement stays behind the release gate\./,
  );
  assert.doesNotMatch(source, /chain is optional plumbing/i);
});

test('pilot copy plans receipt export and allow-lists testnet sellers', () => {
  const source = readFileSync(
    new URL('./PilotCta.tsx', import.meta.url),
    'utf8',
  ).replace(/\s+/g, ' ');

  assert.match(source, /planned signed receipt export/i);
  assert.match(source, /Allow-listed Base Sepolia x402 sellers/);
  assert.doesNotMatch(source, /Approved Base Sepolia x402 resource servers/);
});

test('page evidence is unsigned and says live settlement evidence is not run', () => {
  const source = readFileSync(
    new URL('../../page.tsx', import.meta.url),
    'utf8',
  ).replace(/\s+/g, ' ');

  assert.match(source, /unsigned projection that is not broadcast/i);
  assert.match(
    source,
    /live CDP payment and live testnet settlement evidence remain not run/i,
  );
  assert.match(source, /customer-owned wallet/i);
  assert.match(source, /publication gate not cleared/i);
});

test('sandbox artifact is not a signed receipt or transaction broadcast', () => {
  const source = readFileSync(
    new URL('./SpendControlSandbox.tsx', import.meta.url),
    'utf8',
  ).replace(/\s+/g, ' ');

  assert.match(source, /unsigned session projection/i);
  assert.match(source, /not a SignedReceipt/i);
  assert.match(source, /no transaction broadcast/i);
});

test('the historical proof advertises neither a live endpoint nor unpublished latency', () => {
  const files = [
    '../../../../README.md',
    '../../../README.md',
    '../../proof/page.tsx',
    '../../content.ts',
    '../../manifesto.tsx',
  ];
  const copy = files
    .map((file) => readFileSync(new URL(file, import.meta.url), 'utf8'))
    .join('\n');

  assert.match(copy, /static archive/i);
  assert.match(copy, /no live (?:payment )?endpoint/i);
  assert.doesNotMatch(copy, /live x402 endpoint/i);
  assert.doesNotMatch(copy, /nothing real is at risk/i);
  assert.doesNotMatch(copy, /payment overhead/i);
  assert.doesNotMatch(copy, /every cent reconciled/i);
  assert.doesNotMatch(copy, /receipts are real/i);
  assert.doesNotMatch(copy, /the skill stayed home/i);
  assert.doesNotMatch(copy, /never the skill/i);
  assert.doesNotMatch(copy, /anything that can pay can invoke/i);
});
