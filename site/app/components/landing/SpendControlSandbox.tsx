'use client';

import { useEffect, useReducer, useRef } from 'react';

import styles from '../../landing.module.css';
import {
  demoSessionProjection,
  demoWallet,
  INITIAL_SPEND_SANDBOX_STATE,
  nextSpendSandboxAction,
  spendPolicy,
  spendSandboxReducer,
  spendSandboxView,
  spendStageIndex,
  type DemoSpendAttempt,
  type SpendSandboxStage,
} from './spend-control-model';

const steps: readonly {
  label: string;
  detail: string;
  stage: SpendSandboxStage;
}[] = [
  { label: 'Policy', detail: 'Default deny', stage: 'ready' },
  { label: 'Auto-pay', detail: 'Below ceiling', stage: 'policy_loaded' },
  { label: 'Deny', detail: 'Unknown seller', stage: 'auto_allowed' },
  { label: 'Escalate', detail: 'Exact mismatch', stage: 'denied' },
  { label: 'Approve', detail: 'Still no signature', stage: 'approval_pending' },
  { label: 'Retry', detail: 'Wielder repeats', stage: 'approved_waiting_retry' },
];

const announcements: Record<SpendSandboxStage, string> = {
  ready: 'Sandbox ready. Load the fictional customer policy to begin.',
  policy_loaded:
    'Default-deny policy loaded for one customer-owned Base Sepolia wallet.',
  auto_allowed:
    'The 0.08 test-USDC request matched policy and advanced in simulation.',
  denied:
    'The unknown seller was denied before the fictional wallet or signer path.',
  approval_pending:
    'The 0.60 request is queued for exact approval. No signature exists.',
  approved_waiting_retry:
    'Approval is recorded and the flow has stopped. The Wielder must repeat the exact request.',
  finalized:
    'The exact request was deliberately repeated and an unsigned session projection is ready.',
};

const isStepComplete = (
  stepStage: SpendSandboxStage,
  currentStage: SpendSandboxStage,
): boolean => spendStageIndex(currentStage) > spendStageIndex(stepStage);

const formatAtomic = (atomic: number): string =>
  `${(atomic / 1_000_000).toFixed(2)} test USDC`;

const decisionLabel = (attempt: DemoSpendAttempt): string => {
  if (attempt.decision === 'allow') return '✓ Policy matched';
  if (attempt.decision === 'deny') return '× Default denied';
  return '◇ Exact approval path';
};

const signatureLabel = (attempt: DemoSpendAttempt): string => {
  if (attempt.hasProjectedSigningBoundary) {
    return 'Unsigned flow projection · no key used';
  }
  if (attempt.decision === 'deny') return 'Signer never reached';
  return 'No signature created';
};

function SpendProjectionPreview({
  pilotUrl,
  chargedAtomic,
  remainingAtomic,
}: {
  pilotUrl: string;
  chargedAtomic: number;
  remainingAtomic: number;
}) {
  return (
    <>
      <div className={styles.closeGrid}>
        <article className={styles.policyCard} aria-labelledby="policy-title">
          <div>
            <p className={styles.eyebrow}>Exact authority</p>
            <h3 id="policy-title">The approval cannot become a blank check.</h3>
            <p>
              It is bound to one Spend Intent, seller, resource, wallet, exact
              approved amount, policy version, and expiry. A changed request
              must start again.
            </p>
          </div>
          <dl className={styles.policyFactors}>
            <div>
              <dt>Default action</dt>
              <dd>
                <span>Unknown seller or shape</span>
                <strong>Deny</strong>
              </dd>
            </div>
            <div>
              <dt>Automatic ceiling</dt>
              <dd>
                <span>Every policy field matches</span>
                <strong>{spendPolicy.automaticAllowLabel}</strong>
              </dd>
            </div>
            <div>
              <dt>Human ceiling</dt>
              <dd>
                <span>Exact one-time approval</span>
                <strong>{spendPolicy.humanApprovalLabel}</strong>
              </dd>
            </div>
            <div className={styles.policyTotal}>
              <dt>Session budget</dt>
              <dd>
                <span>{formatAtomic(remainingAtomic)} remaining</span>
                <strong>{spendPolicy.sessionBudgetLabel}</strong>
              </dd>
            </div>
          </dl>
          <p className={styles.policyFootnote}>
            Offline fixture · immutable policy hash · no credential loaded
          </p>
        </article>

        <article className={styles.rewardReceipt} aria-labelledby="projection-title">
          <div className={styles.receiptTear} aria-hidden="true">
            ✂ · · · · · · · · · · · · · · · · · · · ·
          </div>
          <p className={styles.receiptBrand}>Skill Asset Protocol</p>
          <h3 id="projection-title">Unsigned session projection</h3>
          <p className={styles.receiptDim}>
            Illustrative only · not a SignedReceipt · no transaction broadcast
          </p>
          <div className={styles.receiptRule} />
          <dl className={styles.receiptRows}>
            <div>
              <dt>Projection</dt>
              <dd>{demoSessionProjection.projectionId}</dd>
            </div>
            <div>
              <dt>Agent</dt>
              <dd>pi-coding-agent</dd>
            </div>
            <div>
              <dt>Wallet</dt>
              <dd>{demoWallet.address}</dd>
            </div>
            <div>
              <dt>Network</dt>
              <dd>{demoWallet.network}</dd>
            </div>
            <div>
              <dt>Policy</dt>
              <dd>{demoSessionProjection.policyVersionHash}</dd>
            </div>
            <div>
              <dt>Projected outcomes</dt>
              <dd>{demoSessionProjection.outcomeStates.join(' · ')}</dd>
            </div>
            <div>
              <dt>Settlement</dt>
              <dd>{demoSessionProjection.settlementStatus}</dd>
            </div>
          </dl>
          <div className={styles.receiptRule} />
          <div className={styles.awardTotal}>
            <span>Simulated charged total</span>
            <strong>{formatAtomic(chargedAtomic)}</strong>
          </div>
          <p className={styles.receiptDim}>
            Unsigned fixture · no key used · not live evidence
          </p>
          <div className={styles.receiptBarcode} aria-hidden="true" />
        </article>
      </div>

      <div className={styles.sandboxComplete}>
        <div>
          <p className={styles.eyebrow}>Sandbox complete</p>
          <p>
            One request auto-cleared, one was denied, and one approval stopped
            until a deliberate exact retry—with no key, payment, or network call.
          </p>
        </div>
        <a className={styles.primaryButton} href={pilotUrl}>
          Scope a customer-hosted pilot
          <span aria-hidden="true">↗</span>
        </a>
      </div>
    </>
  );
}

export function SpendControlSandbox({ pilotUrl }: { pilotUrl: string }) {
  const [state, dispatch] = useReducer(
    spendSandboxReducer,
    INITIAL_SPEND_SANDBOX_STATE,
  );
  const view = spendSandboxView(state);
  const next = nextSpendSandboxAction(state.stage);
  const approvalAttempt = view.attempts.find(
    (attempt) => attempt.decision === 'approval_required',
  );
  const focusRef = useRef<HTMLHeadingElement>(null);
  const didMountRef = useRef(false);

  useEffect(() => {
    if (didMountRef.current) focusRef.current?.focus();
    else didMountRef.current = true;
  }, [state.stage]);

  return (
    <section
      id="sandbox"
      className={styles.sandboxSection}
      aria-labelledby="sandbox-title"
    >
      <div className={styles.sandboxIntro}>
        <div>
          <p className={styles.eyebrow}>Offline spend-control sandbox</p>
          <h2 id="sandbox-title">
            Walk a Spend Intent through the Wallet Kernel.
          </h2>
        </div>
        <div className={styles.sandboxNotice}>
          <strong>Illustrative sample</strong>
          <span>No account, wallet key, network call, payment, or saved data.</span>
        </div>
      </div>

      <ol className={styles.stepper} aria-label="Sandbox progress">
        {steps.map((step, index) => {
          const complete = isStepComplete(step.stage, state.stage);
          const current =
            state.stage === 'finalized'
              ? index === steps.length - 1
              : spendStageIndex(step.stage) === spendStageIndex(state.stage);
          return (
            <li
              key={step.label}
              className={`${styles.step} ${
                complete ? styles.stepComplete : ''
              } ${current ? styles.stepCurrent : ''}`}
              aria-current={current ? 'step' : undefined}
            >
              <span className={styles.stepNumber}>
                {complete ? '✓' : String(index + 1).padStart(2, '0')}
              </span>
              <span>
                <strong>{step.label}</strong>
                <small>{step.detail}</small>
              </span>
            </li>
          );
        })}
      </ol>

      <div className={styles.sandboxStatus} aria-live="polite">
        <span className={styles.statusPulse} aria-hidden="true" />
        <h3 ref={focusRef} tabIndex={-1}>
          {announcements[state.stage]}
        </h3>
        {state.stage !== 'ready' && (
          <button
            className={styles.resetButton}
            type="button"
            onClick={() => dispatch({ type: 'RESET' })}
          >
            Restart sandbox
          </button>
        )}
      </div>

      <div className={styles.sandboxWorkspace}>
        <article
          className={`${styles.registryCard} ${
            view.hasPolicy ? styles.registryCardActive : ''
          }`}
          aria-labelledby="sample-kernel-name"
        >
          <div className={styles.cardBar}>
            <span>Wallet + policy · sample</span>
            <span>{view.hasPolicy ? 'Policy active' : 'Ready to load'}</span>
          </div>
          <div className={styles.registryBody}>
            <div className={styles.skillIdentity}>
              <span className={styles.skillMonogram} aria-hidden="true">
                WK
              </span>
              <div>
                <p className={styles.microLabel}>Customer-hosted Wallet Kernel</p>
                <h3 id="sample-kernel-name">Northstar Pi spend session</h3>
                <p>
                  Ordinary Agent requests in; policy-bound x402 authority out.
                </p>
              </div>
            </div>

            <dl className={styles.skillFacts}>
              <div>
                <dt>Agent</dt>
                <dd>
                  <span className={styles.avatar} aria-hidden="true">
                    PI
                  </span>
                  <span>
                    pi-coding-agent
                    <small>Local adapter · fictional session</small>
                  </span>
                </dd>
              </div>
              <div>
                <dt>Customer-owned wallet</dt>
                <dd>
                  <span>{demoWallet.address}</span>
                  <small>{demoWallet.provider}</small>
                </dd>
              </div>
              <div>
                <dt>Network</dt>
                <dd>
                  {demoWallet.networkLabel}
                  <small>{demoWallet.network} · {demoWallet.asset}</small>
                </dd>
              </div>
              <div>
                <dt>Default</dt>
                <dd>
                  Deny
                  <small>{spendPolicy.versionHash}</small>
                </dd>
              </div>
            </dl>

            <div className={styles.integrityNote}>
              <span aria-hidden="true">◇</span>
              <span>
                Allowed seller: {spendPolicy.allowedSellerOrigin}. The Agent
                cannot access credentials, change policy, approve, or sign.
              </span>
            </div>
          </div>
        </article>

        <article className={styles.activityCard} aria-labelledby="activity-title">
          <div className={styles.cardBar}>
            <span id="activity-title">Spend journal · local preview</span>
            <span>{view.attempts.length}/3 intents</span>
          </div>

          {view.attempts.length === 0 ? (
            <div className={styles.emptyLedger}>
              <div className={styles.emptyLedgerMark} aria-hidden="true">
                +
              </div>
              <h3>No Spend Intents yet.</h3>
              <p>
                Load policy, then run three deterministic Spend Intents. Nothing
                leaves this browser tab.
              </p>
            </div>
          ) : (
            <ol className={styles.invocationList}>
              {view.attempts.map((attempt, index) => (
                <li key={attempt.id} className={styles.invocation}>
                  <span className={styles.avatar} aria-hidden="true">
                    {String(index + 1).padStart(2, '0')}
                  </span>
                  <div className={styles.invocationMain}>
                    <div>
                      <strong>{attempt.purpose}</strong>
                      <span>{attempt.amountLabel}</span>
                    </div>
                    <p>{attempt.resource}</p>
                    <small>
                      {attempt.sellerOrigin} · call {attempt.callId}
                    </small>
                    <div className={styles.outcomeTag}>
                      <span>
                        {decisionLabel(attempt)}
                      </span>
                      <span>{signatureLabel(attempt)}</span>
                    </div>
                  </div>
                  <span className={styles.successBadge}>{attempt.status}</span>
                </li>
              ))}
            </ol>
          )}

          {approvalAttempt && view.approvalPanelState && (
              <section
                className={styles.approvalPanel}
                aria-labelledby="approval-details-title"
              >
                <p className={styles.microLabel}>Exact authority preview</p>
                <h3 id="approval-details-title">
                  {view.approvalPanelState === 'approved_waiting_retry'
                    ? 'Approved once — waiting for Wielder retry'
                    : 'Operator decision required'}
                </h3>
                <dl className={styles.approvalGrid}>
                  <div>
                    <dt>Request hash</dt>
                    <dd>{approvalAttempt.requestHash}</dd>
                  </div>
                  <div>
                    <dt>Challenge / quote</dt>
                    <dd>{approvalAttempt.challengeId}</dd>
                  </div>
                  <div>
                    <dt>Approved amount</dt>
                    <dd>{approvalAttempt.amountLabel}</dd>
                  </div>
                  <div>
                    <dt>Wallet</dt>
                    <dd>{approvalAttempt.wallet}</dd>
                  </div>
                  <div>
                    <dt>Policy version</dt>
                    <dd>{approvalAttempt.policyVersionHash}</dd>
                  </div>
                  <div>
                    <dt>Policy mismatch</dt>
                    <dd>{approvalAttempt.policyMismatch}</dd>
                  </div>
                  <div>
                    <dt>Expiry</dt>
                    <dd>{approvalAttempt.approvalExpiry}</dd>
                  </div>
                </dl>
                <p className={styles.approvalWarning}>
                  Any changed challenge, seller, resource, request hash, amount,
                  wallet, policy version, or expiry must start a new approval.
                </p>
              </section>
            )}

          {next && (
            <div className={styles.nextAction}>
              <div>
                <p className={styles.microLabel}>Next action</p>
                <p>{next.note}</p>
              </div>
              <button
                type="button"
                className={styles.actionButton}
                onClick={() => dispatch(next.action)}
              >
                {next.label}
                <span aria-hidden="true">→</span>
              </button>
            </div>
          )}
        </article>
      </div>

      {view.hasSessionProjection && (
        <SpendProjectionPreview
          pilotUrl={pilotUrl}
          chargedAtomic={view.chargedAtomic}
          remainingAtomic={view.remainingAtomic}
        />
      )}
    </section>
  );
}
