import styles from '../../landing.module.css';

export function PilotCta({ pilotUrl }: { pilotUrl: string }) {
  return (
    <section className={styles.pilotCta} aria-labelledby="pilot-title">
      <div>
        <p className={styles.eyebrow}>Customer-hosted design-partner pilot</p>
        <h2 id="pilot-title">
          Put one real Agent workflow behind an explicit spending boundary.
        </h2>
      </div>
      <div className={styles.pilotDetails}>
        <ul>
          <li>One Pi workflow and local Agent adapter</li>
          <li>One customer-owned CDP wallet</li>
          <li>Allow-listed Base Sepolia x402 sellers</li>
          <li>
            Policy, approvals, reconciliation, and planned signed receipt export
          </li>
        </ul>
        <a className={styles.primaryButtonDark} href={pilotUrl}>
          Discuss a spend-control pilot
          <span aria-hidden="true">↗</span>
        </a>
      </div>
    </section>
  );
}
