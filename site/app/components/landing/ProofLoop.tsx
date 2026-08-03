import { productProof } from '../../landing-content';
import styles from '../../landing.module.css';

export function ProofLoop() {
  return (
    <section className={styles.section} aria-labelledby="how-it-works">
      <div className={styles.sectionHeading}>
        <p className={styles.eyebrow}>The control loop</p>
        <h2 id="how-it-works">From Agent request to accountable spend.</h2>
        <p>
          The customer-hosted Wallet Kernel stays wallet-first: it decides what
          may be signed and records what happened. Planned on-chain settlement
          stays behind the release gate.
        </p>
      </div>

      <ol className={styles.proofGrid}>
        {productProof.map((item, index) => (
          <li key={item.number} className={styles.proofCard}>
            <div className={styles.proofCardTop}>
              <span className={styles.outlineNumber}>{item.number}</span>
              <span className={styles.microLabel}>{item.eyebrow}</span>
            </div>
            <h3>{item.title}</h3>
            <p>{item.body}</p>
            <div className={styles.proofSample}>
              <span className={styles.statusDot} aria-hidden="true" />
              {item.sample}
            </div>
            {index < productProof.length - 1 && (
              <span className={styles.proofArrow} aria-hidden="true">
                →
              </span>
            )}
          </li>
        ))}
      </ol>
    </section>
  );
}
