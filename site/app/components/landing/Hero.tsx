import Link from 'next/link';

import styles from '../../landing.module.css';

export function Hero({ pilotUrl }: { pilotUrl: string }) {
  return (
    <section className={styles.hero} aria-labelledby="product-title">
      <div className={styles.heroCopy}>
        <p className={styles.eyebrow}>
          Wallet-native Agent spending <span aria-hidden="true">/</span>{' '}
          Product preview
        </p>
        <h1 id="product-title" className={styles.heroTitle}>
          Give AI Agents a wallet without giving them the keys.
        </h1>
        <p className={styles.heroLead}>
          A customer-hosted Wallet Kernel turns ordinary Agent requests into
          policy-bound x402 payment controls—with budgets, exact approvals, and
          planned signed receipts behind the release gate.
        </p>
        <div className={styles.heroActions}>
          <a className={styles.primaryButton} href="#sandbox">
            Try the offline sandbox
            <span aria-hidden="true">↓</span>
          </a>
          <a className={styles.secondaryButton} href={pilotUrl}>
            Discuss a design-partner pilot
            <span aria-hidden="true">↗</span>
          </a>
        </div>
        <ul className={styles.heroAssurances} aria-label="Sandbox assurances">
          <li>Customer-owned wallet</li>
          <li>Default deny</li>
          <li>No transaction broadcast</li>
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
              <p className={styles.microLabel}>Illustrative Wallet Kernel</p>
              <p className={styles.snapshotOrg}>Northstar · Pi session</p>
            </div>
            <span className={styles.draftBadge}>Simulation</span>
          </div>

          <div className={styles.poolRow}>
            <div>
              <p className={styles.microLabel}>Session budget</p>
              <p className={styles.poolValue}>5.00</p>
            </div>
            <div className={styles.poolMeta}>
              <span>test USDC</span>
              <span>Base Sepolia · 84532</span>
            </div>
          </div>

          <dl className={styles.snapshotStats}>
            <div>
              <dt>Auto-allow ceiling</dt>
              <dd>0.25</dd>
            </div>
            <div>
              <dt>Approval ceiling</dt>
              <dd>1.00</dd>
            </div>
            <div>
              <dt>Wallet custody</dt>
              <dd>Customer</dd>
            </div>
          </dl>

          <div className={styles.ledgerPreview}>
            <div className={styles.ledgerHead}>
              <span>Policy outcomes</span>
              <span>Offline fixture</span>
            </div>
            <div className={styles.ledgerLine}>
              <span className={styles.ledgerIndex}>0001</span>
              <span>
                <strong>Model context · 0.08</strong>
                <small>Approved seller · below auto ceiling</small>
              </span>
              <span className={styles.included}>Allow</span>
            </div>
            <div className={styles.ledgerLine}>
              <span className={styles.ledgerIndex}>0002</span>
              <span>
                <strong>Repository audit · 0.60</strong>
                <small>Exact operator decision required</small>
              </span>
              <span className={styles.pending}>Approve</span>
            </div>
            <div className={styles.ledgerLine}>
              <span className={styles.ledgerIndex}>0003</span>
              <span>
                <strong>Unknown seller · 0.01</strong>
                <small>Default-deny boundary</small>
              </span>
              <span className={styles.pending}>Deny</span>
            </div>
          </div>

          <div className={styles.snapshotFooter}>
            <span>Policy before signature</span>
            <Link href="/proof">Inspect the legacy protocol proof →</Link>
          </div>
        </div>
      </div>
    </section>
  );
}
