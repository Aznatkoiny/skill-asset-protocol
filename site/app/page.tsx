import Link from 'next/link';

import { AttributionSandbox } from './components/landing/AttributionSandbox';
import { Hero } from './components/landing/Hero';
import { PilotCta } from './components/landing/PilotCta';
import { ProofLoop } from './components/landing/ProofLoop';
import {
  defaultPilotUrl,
  evidenceReceipts,
  repositoryUrl,
  rolePaths,
} from './landing-content';
import styles from './landing.module.css';

export default function Page() {
  const pilotUrl =
    process.env.NEXT_PUBLIC_PILOT_CONTACT_URL?.trim() || defaultPilotUrl;

  return (
    <main id="main-content" className={styles.page}>
      <a className={styles.skipLink} href="#product-title">
        Skip to main content
      </a>

      <header className={styles.topNav}>
        <nav className={styles.navInner} aria-label="Primary navigation">
          <Link className={styles.brand} href="/">
            <span className={styles.brandMark} aria-hidden="true">
              SA
            </span>
            <span className={styles.brandText}>
              Skill Asset Protocol
              <small>Intra-org preview</small>
            </span>
          </Link>
          <div className={styles.navLinks}>
            <a href="#how-it-works">How it works</a>
            <a href="#sandbox">Sandbox</a>
            <Link href="/proof">Protocol proof</Link>
          </div>
          <a className={styles.navCta} href={pilotUrl}>
            Design partner ↗
          </a>
        </nav>
      </header>

      <div className={styles.researchStrip}>
        <span>Research build</span>
        <span>
          Employer demand remains unvalidated · this preview tests the product
          direction
        </span>
      </div>

      <Hero pilotUrl={pilotUrl} />
      <div className={styles.hazardBand} aria-hidden="true" />
      <ProofLoop />

      <section className={styles.rolesSection} aria-labelledby="roles-title">
        <div className={styles.rolesHeading}>
          <div>
            <p className={styles.eyebrow}>One ledger · three jobs</p>
            <h2 id="roles-title">Useful to the whole buying group.</h2>
          </div>
          <p>
            The Creator is the center of the promise. The employer funds the
            program. The platform team makes the evidence trustworthy.
          </p>
        </div>
        <div className={styles.roleGrid}>
          {rolePaths.map((role) => (
            <article key={role.label} className={styles.roleCard}>
              <p className={styles.microLabel}>{role.label}</p>
              <h3>{role.title}</h3>
              <p>{role.body}</p>
            </article>
          ))}
        </div>
      </section>

      <AttributionSandbox pilotUrl={pilotUrl} />

      <div className={styles.evidenceSection}>
        <section aria-labelledby="evidence-title">
          <div className={styles.evidenceHeader}>
            <div>
              <p className={styles.eyebrow}>Proof stays attached</p>
              <h2 id="evidence-title">
                The product direction changed. The receipts did not.
              </h2>
            </div>
            <p>
              The repository keeps measured, modeled, and hypothetical claims
              separate. The employer workflow above is the next hypothesis to
              test.
            </p>
          </div>

          <div className={styles.evidenceGrid}>
            {evidenceReceipts.map((receipt) => (
              <article key={receipt.label} className={styles.evidenceReceipt}>
                <strong>{receipt.value}</strong>
                <span>{receipt.label}</span>
                <p>{receipt.detail}</p>
              </article>
            ))}
          </div>

          <div className={styles.evidenceActions}>
            <Link className={styles.evidenceLink} href="/proof">
              Open the manifesto + x402 proof <span aria-hidden="true">→</span>
            </Link>
            <a className={styles.evidenceLink} href={repositoryUrl}>
              Inspect the source <span aria-hidden="true">↗</span>
            </a>
            <p className={styles.evidenceCaveat}>
              Testnet evidence · not a traction claim
            </p>
          </div>
        </section>
      </div>

      <PilotCta pilotUrl={pilotUrl} />

      <footer className={styles.footer}>
        <div className={styles.footerBrand}>
          <strong>Skill Asset Protocol</strong>
          <p>
            Compensation, attribution, and metering for authored AI Skills.
            Research build · Apache-2.0.
          </p>
        </div>
        <div className={styles.footerColumn}>
          <strong>Explore</strong>
          <a href="#how-it-works">How it works</a>
          <a href="#sandbox">Product sandbox</a>
          <Link href="/proof">Manifesto + proof</Link>
        </div>
        <div className={styles.footerColumn}>
          <strong>Source</strong>
          <a href={repositoryUrl}>GitHub repository ↗</a>
          <a
            href={`${repositoryUrl}/blob/main/docs/product-onboarding-retention-and-monetization.md`}
          >
            Product recommendation ↗
          </a>
        </div>
      </footer>
    </main>
  );
}
