import Link from 'next/link';

import styles from '../../landing.module.css';

export function Hero({ pilotUrl }: { pilotUrl: string }) {
  return (
    <section className={styles.hero} aria-labelledby="product-title">
      <div className={styles.heroCopy}>
        <p className={styles.eyebrow}>
          Intra-org Skill attribution <span aria-hidden="true">/</span> Product preview
        </p>
        <h1 id="product-title" className={styles.heroTitle}>
          Make the people behind your AI leverage visible.
        </h1>
        <p className={styles.heroLead}>
          Register employee-authored AI Skills. Verify real reuse. Close a
          transparent reward program without changing how teams work.
        </p>
        <div className={styles.heroActions}>
          <a className={styles.primaryButton} href="#sandbox">
            Try the 3-minute sandbox
            <span aria-hidden="true">↓</span>
          </a>
          <a className={styles.secondaryButton} href={pilotUrl}>
            Run a design-partner pilot
            <span aria-hidden="true">↗</span>
          </a>
        </div>
        <ul className={styles.heroAssurances} aria-label="Sandbox assurances">
          <li>No wallet</li>
          <li>No raw prompts</li>
          <li>No data saved</li>
        </ul>
      </div>

      <div className={styles.snapshotWrap}>
        <span className={styles.cropMarkTopLeft} aria-hidden="true" />
        <span className={styles.cropMarkTopRight} aria-hidden="true" />
        <span className={styles.cropMarkBottomLeft} aria-hidden="true" />
        <span className={styles.cropMarkBottomRight} aria-hidden="true" />
        <div className={styles.snapshot}>
          <div className={styles.snapshotHeader}>
            <div>
              <p className={styles.microLabel}>Illustrative program</p>
              <p className={styles.snapshotOrg}>Northstar Systems</p>
            </div>
            <span className={styles.draftBadge}>Draft close</span>
          </div>

          <div className={styles.poolRow}>
            <div>
              <p className={styles.microLabel}>Employer-funded pool</p>
              <p className={styles.poolValue}>$5,000</p>
            </div>
            <div className={styles.poolMeta}>
              <span>July 2026</span>
              <span>Review required</span>
            </div>
          </div>

          <dl className={styles.snapshotStats}>
            <div>
              <dt>Registered Skills</dt>
              <dd>14</dd>
            </div>
            <div>
              <dt>Active Creators</dt>
              <dd>8</dd>
            </div>
            <div>
              <dt>Outcome-backed uses</dt>
              <dd>37</dd>
            </div>
          </dl>

          <div className={styles.ledgerPreview}>
            <div className={styles.ledgerHead}>
              <span>Recent evidence</span>
              <span>Simulated</span>
            </div>
            <div className={styles.ledgerLine}>
              <span className={styles.ledgerIndex}>0142</span>
              <span>
                <strong>Pull Request Risk Brief</strong>
                <small>Payments · accepted result</small>
              </span>
              <span className={styles.included}>Included</span>
            </div>
            <div className={styles.ledgerLine}>
              <span className={styles.ledgerIndex}>0141</span>
              <span>
                <strong>Incident Handoff</strong>
                <small>Support · linked incident</small>
              </span>
              <span className={styles.included}>Included</span>
            </div>
            <div className={styles.ledgerLine}>
              <span className={styles.ledgerIndex}>0140</span>
              <span>
                <strong>Support Escalation Triage</strong>
                <small>Success · outcome pending</small>
              </span>
              <span className={styles.pending}>Pending</span>
            </div>
          </div>

          <div className={styles.snapshotFooter}>
            <span>Evidence, not pay-per-call</span>
            <Link href="/proof">Inspect protocol proof →</Link>
          </div>
        </div>
      </div>
    </section>
  );
}
