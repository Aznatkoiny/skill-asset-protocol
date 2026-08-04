import Link from 'next/link';

import { Hero } from './components/landing/Hero';
import { PilotCta } from './components/landing/PilotCta';
import { ProofLoop } from './components/landing/ProofLoop';
import { SpendControlSandbox } from './components/landing/SpendControlSandbox';
import {
  defaultPilotUrl,
  evidenceReceipts,
  repositoryUrl,
  rolePaths,
  spendControlDesignUrl,
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
              <small>Agent spend preview</small>
            </span>
          </Link>
          <div className={styles.navLinks}>
            <a href="#how-it-works">How it works</a>
            <a href="#sandbox">Sandbox</a>
            <Link href="/proof">Legacy protocol proof</Link>
          </div>
          <a className={styles.navCta} href={pilotUrl}>
            Design partner ↗
          </a>
        </nav>
      </header>

      <div className={styles.researchStrip}>
        <span>Pre-release candidate · publication gate not cleared</span>
        <span>
          Customer demand, funded-wallet deployment, and live Wallet Kernel
          settlement remain unvalidated
        </span>
      </div>

      <Hero pilotUrl={pilotUrl} />
      <div className={styles.hazardBand} aria-hidden="true" />
      <ProofLoop />

      <section className={styles.rolesSection} aria-labelledby="roles-title">
        <div className={styles.rolesHeading}>
          <div>
            <p className={styles.eyebrow}>One kernel · three control surfaces</p>
            <h2 id="roles-title">Bounded autonomy the buying group can inspect.</h2>
          </div>
          <p>
            The Agent requests. The operator governs. The customer-owned wallet
            signs only what the Wallet Kernel has already authorized.
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

      <SpendControlSandbox pilotUrl={pilotUrl} />

      <div className={styles.evidenceSection}>
        <section aria-labelledby="evidence-title">
          <div className={styles.evidenceHeader}>
            <div>
              <p className={styles.eyebrow}>Evidence stays bounded</p>
              <h2 id="evidence-title">
                Offline Wallet Kernel proof—not a production claim.
              </h2>
            </div>
            <p>
              The repository verifies policy, budget, approval, replay, refund,
              and recovery behavior offline. This browser produces only an
              unsigned projection that is not broadcast. Live CDP payment and
              live testnet settlement evidence remain not run. The pinned Linux
              deployment is also not run.
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
            <a className={styles.evidenceLink} href={spendControlDesignUrl}>
              Read the approved control-plane design{' '}
              <span aria-hidden="true">↗</span>
            </a>
            <a className={styles.evidenceLink} href={repositoryUrl}>
              Inspect the source <span aria-hidden="true">↗</span>
            </a>
            <p className={styles.evidenceCaveat}>
              Base Sepolia fixture · no mainnet · no real funds
            </p>
          </div>
        </section>
      </div>

      <PilotCta pilotUrl={pilotUrl} />

      <footer className={styles.footer}>
        <div className={styles.footerBrand}>
          <strong>Skill Asset Protocol</strong>
          <p>
            Wallet-native spending controls for AI Agents. Research build ·
            Apache-2.0.
          </p>
        </div>
        <div className={styles.footerColumn}>
          <strong>Explore</strong>
          <a href="#how-it-works">How it works</a>
          <a href="#sandbox">Spend-control sandbox</a>
          <Link href="/proof">Historical protocol proof</Link>
        </div>
        <div className={styles.footerColumn}>
          <strong>Source</strong>
          <a href={repositoryUrl}>GitHub repository ↗</a>
          <a href={spendControlDesignUrl}>Approved product design ↗</a>
        </div>
      </footer>
    </main>
  );
}
