'use client';

import { useEffect, useReducer, useRef } from 'react';

import styles from '../../landing.module.css';
import {
  demoInvocations,
  demoOrganization,
  demoOutcome,
  demoSkill,
  INITIAL_SANDBOX_STATE,
  nextSandboxAction,
  rewardPolicy,
  sandboxReducer,
  sandboxView,
  stageIndex,
  type SandboxStage,
} from './sandbox-model';

const steps: readonly { label: string; detail: string; stage: SandboxStage }[] = [
  { label: 'Register', detail: 'Creator + version', stage: 'ready' },
  { label: 'Record use', detail: '3 teammates', stage: 'registered' },
  { label: 'Add outcome', detail: 'Accepted + linked', stage: 'used' },
  { label: 'Preview close', detail: 'Fixed pool', stage: 'evidenced' },
];

const announcements: Record<SandboxStage, string> = {
  ready: 'Sandbox ready. Import the fictional sample Skill to begin.',
  registered:
    'Sample Skill registered with Maya Chen as Creator and version 1.4.0.',
  used: 'Three successful simulated teammate uses were added.',
  evidenced:
    'One result was accepted and linked to a fictional pull request.',
  closed:
    'The July reward-close preview is ready. The proposed award is provisional and unpaid.',
};

const isStepComplete = (
  stepStage: SandboxStage,
  currentStage: SandboxStage,
): boolean => stageIndex(currentStage) > stageIndex(stepStage);

function SandboxClosePreview({ pilotUrl }: { pilotUrl: string }) {
  return (
    <>
      <div className={styles.closeGrid}>
        <article
          className={styles.policyCard}
          aria-labelledby="policy-title"
        >
          <div>
            <p className={styles.eyebrow}>Transparent policy</p>
            <h3 id="policy-title">Portfolio share, not pay-per-call.</h3>
            <p>
              The employer fixes the budget first. Outcome evidence earns
              points; the selected Skill receives its reviewed share of the
              portfolio pool.
            </p>
          </div>
          <dl className={styles.policyFactors}>
            {rewardPolicy.factors.map((factor) => (
              <div key={factor.label}>
                <dt>{factor.label}</dt>
                <dd>
                  <span>{factor.calculation}</span>
                  <strong>+{factor.points}</strong>
                </dd>
              </div>
            ))}
            <div className={styles.policyTotal}>
              <dt>Selected Skill score</dt>
              <dd>
                <span>
                  {rewardPolicy.selectedSkillPoints}/
                  {rewardPolicy.portfolioPoints} portfolio points
                </span>
                <strong>{rewardPolicy.selectedSkillPoints}</strong>
              </dd>
            </div>
          </dl>
          <p className={styles.policyFootnote}>
            Sample policy · 40% per-Skill cap · admin review required
          </p>
        </article>

        <article
          className={styles.rewardReceipt}
          aria-labelledby="reward-statement-title"
        >
          <div className={styles.receiptTear} aria-hidden="true">
            ✂ · · · · · · · · · · · · · · · · · · · ·
          </div>
          <p className={styles.receiptBrand}>Skill Asset Protocol</p>
          <h3 id="reward-statement-title">Creator award preview</h3>
          <p className={styles.receiptDim}>
            Illustrative statement · not approved or paid
          </p>
          <div className={styles.receiptRule} />
          <dl className={styles.receiptRows}>
            <div>
              <dt>Organization</dt>
              <dd>{demoOrganization.name}</dd>
            </div>
            <div>
              <dt>Period</dt>
              <dd>{demoOrganization.rewardPeriod}</dd>
            </div>
            <div>
              <dt>Creator</dt>
              <dd>{demoSkill.creator.name}</dd>
            </div>
            <div>
              <dt>Skill</dt>
              <dd>
                {demoSkill.displayName} v{demoSkill.version}
              </dd>
            </div>
            <div>
              <dt>Successful uses</dt>
              <dd>3</dd>
            </div>
            <div>
              <dt>Outcome-backed uses</dt>
              <dd>1</dd>
            </div>
            <div>
              <dt>Employer pool</dt>
              <dd>{rewardPolicy.poolLabel}</dd>
            </div>
          </dl>
          <div className={styles.receiptRule} />
          <div className={styles.awardTotal}>
            <span>Provisional award</span>
            <strong>{rewardPolicy.proposedAwardLabel}</strong>
          </div>
          <p className={styles.receiptDim}>
            Status: review required · no transfer initiated
          </p>
          <div className={styles.receiptBarcode} aria-hidden="true" />
        </article>
      </div>

      <div className={styles.sandboxComplete}>
        <div>
          <p className={styles.eyebrow}>Sandbox complete</p>
          <p>
            The sample went from versioned authored work to a reviewable reward
            statement—with no wallet or payment rail in the employee workflow.
          </p>
        </div>
        <a className={styles.primaryButton} href={pilotUrl}>
          Try this with a real portfolio
          <span aria-hidden="true">↗</span>
        </a>
      </div>
    </>
  );
}

export function AttributionSandbox({ pilotUrl }: { pilotUrl: string }) {
  const [state, dispatch] = useReducer(
    sandboxReducer,
    INITIAL_SANDBOX_STATE,
  );
  const view = sandboxView(state);
  const next = nextSandboxAction(state.stage);
  const focusRef = useRef<HTMLHeadingElement>(null);

  useEffect(() => {
    if (state.stage !== 'ready') {
      focusRef.current?.focus();
    }
  }, [state.stage]);

  return (
    <section
      id="sandbox"
      className={styles.sandboxSection}
      aria-labelledby="sandbox-title"
    >
      <div className={styles.sandboxIntro}>
        <div>
          <p className={styles.eyebrow}>No-wallet product sandbox</p>
          <h2 id="sandbox-title">
            See the entire attribution loop before connecting anything.
          </h2>
        </div>
        <div className={styles.sandboxNotice}>
          <strong>Illustrative sample</strong>
          <span>No account, network call, payment, or saved data.</span>
        </div>
      </div>

      <ol className={styles.stepper} aria-label="Sandbox progress">
        {steps.map((step, index) => {
          const complete = isStepComplete(step.stage, state.stage);
          const current =
            state.stage === 'closed'
              ? index === steps.length - 1
              : stageIndex(step.stage) === stageIndex(state.stage);
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
            view.isRegistered ? styles.registryCardActive : ''
          }`}
          aria-labelledby="sample-skill-name"
        >
          <div className={styles.cardBar}>
            <span>Skill record · sample</span>
            <span>{view.isRegistered ? 'Registered' : 'Ready to import'}</span>
          </div>
          <div className={styles.registryBody}>
            <div className={styles.skillIdentity}>
              <span className={styles.skillMonogram} aria-hidden="true">
                PR
              </span>
              <div>
                <p className={styles.microLabel}>Approved internal Skill</p>
                <h3 id="sample-skill-name">{demoSkill.displayName}</h3>
                <p>{demoSkill.description}</p>
              </div>
            </div>

            <dl className={styles.skillFacts}>
              <div>
                <dt>Creator</dt>
                <dd>
                  <span className={styles.avatar} aria-hidden="true">
                    {demoSkill.creator.initials}
                  </span>
                  <span>
                    {demoSkill.creator.name}
                    <small>{demoSkill.creator.team}</small>
                  </span>
                </dd>
              </div>
              <div>
                <dt>Version</dt>
                <dd>
                  <span>v{demoSkill.version}</span>
                  <small>{demoSkill.shortHash}</small>
                </dd>
              </div>
              <div>
                <dt>Source</dt>
                <dd className={styles.breakable}>{demoSkill.source}</dd>
              </div>
              <div>
                <dt>Beneficiary</dt>
                <dd>
                  {demoOrganization.name}
                  <small>Fictional organization</small>
                </dd>
              </div>
            </dl>

            <div className={styles.integrityNote}>
              <span aria-hidden="true">◇</span>
              <span>
                Version evidence stays attached to this artifact hash. The
                sandbox does not contact the sample repository.
              </span>
            </div>
          </div>
        </article>

        <article className={styles.activityCard} aria-labelledby="activity-title">
          <div className={styles.cardBar}>
            <span id="activity-title">Evidence ledger · local preview</span>
            <span>{view.invocations.length}/3 uses</span>
          </div>

          {view.invocations.length === 0 ? (
            <div className={styles.emptyLedger}>
              <div className={styles.emptyLedgerMark} aria-hidden="true">
                +
              </div>
              <h3>No teammate evidence yet.</h3>
              <p>
                Register the Skill, then add three deterministic sample uses.
                Nothing leaves this browser tab.
              </p>
            </div>
          ) : (
            <ol className={styles.invocationList}>
              {demoInvocations.map((invocation) => {
                const hasOutcome =
                  view.hasOutcome &&
                  invocation.id === demoOutcome.invocationId;
                return (
                  <li key={invocation.id} className={styles.invocation}>
                    <span className={styles.avatar} aria-hidden="true">
                      {invocation.wielder.initials}
                    </span>
                    <div className={styles.invocationMain}>
                      <div>
                        <strong>{invocation.wielder.name}</strong>
                        <span>{invocation.occurredAt}</span>
                      </div>
                      <p>{invocation.summary}</p>
                      <small>
                        {invocation.wielder.team} · v{demoSkill.version} ·
                        Simulated
                      </small>
                      {hasOutcome && (
                        <div className={styles.outcomeTag}>
                          <span>✓ Accepted result</span>
                          <span>
                            ↗ {demoOutcome.artifact} ·{' '}
                            {demoOutcome.artifactTitle}
                          </span>
                        </div>
                      )}
                    </div>
                    <span className={styles.successBadge}>
                      {invocation.status}
                    </span>
                  </li>
                );
              })}
            </ol>
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

      {view.hasClosePreview && (
        <SandboxClosePreview pilotUrl={pilotUrl} />
      )}
    </section>
  );
}
