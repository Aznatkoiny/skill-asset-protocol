import { productProof } from '../../landing-content';
import styles from '../../landing.module.css';

export function ProofLoop() {
  return (
    <section className={styles.section} aria-labelledby="how-it-works">
      <div className={styles.sectionHeading}>
        <p className={styles.eyebrow}>The operating loop</p>
        <h2 id="how-it-works">From authored work to a defensible reward close.</h2>
        <p>
          The chain is optional plumbing. The product is the monthly system of
          record your organization can explain.
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
