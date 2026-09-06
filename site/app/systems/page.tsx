import type { Metadata } from 'next';
import { SiteFrame, TextLink } from '../components/human-choice/SiteFrame';
import { SpendControlSandbox } from '../components/landing/SpendControlSandbox';
import { defaultPilotUrl } from '../landing-content';
import { designUrl, evidenceUrl, repositoryUrl } from '../human-choice-content';
import styles from '../human-choice.module.css';

export const metadata: Metadata = {
  title: 'Wallet Kernel',
  description: 'Explore an offline Wallet Kernel simulation for bounded agent spending, exact approval, and deliberate retry. Inspect the separate engineering evidence.',
  alternates: { canonical: '/systems' },
  openGraph: { title: 'Wallet Kernel · Human Choice', description: 'An offline demonstration of spending authority for AI agents. Live CDP payment and live testnet settlement have not been run.', url: '/systems' },
};

export default function SystemsPage() {
  const pilotUrl = process.env.NEXT_PUBLIC_PILOT_CONTACT_URL?.trim() || defaultPilotUrl;
  return (
    <SiteFrame active="Systems">
      <section className={styles.systemIntro}>
        <p className={styles.eyebrow}>Systems / Agency</p>
        <h1>Wallet Kernel</h1>
        <p>Can people delegate useful work to AI without taking on unacceptable financial risk or constant supervision?</p>
        <p>This customer-hosted Wallet Kernel explores a specific part of that question: spending within explicit budgets, seller rules, and exact human approvals, through a customer-owned wallet.</p>
        <div className={styles.actions}><span className={styles.status}>Offline prototype</span><TextLink href="#sandbox">Try the demonstration</TextLink><TextLink href="#evidence">Inspect the evidence</TextLink></div>
      </section>
      <section className={styles.section}>
        <div className={styles.sectionHeading}><div><p className={styles.eyebrow}>From principle to behavior</p><h2>Authority you can inspect.</h2></div><p>The initial product is for AI platform and gateway teams. Its effects on human understanding and effort remain research questions.</p></div>
        <div className={styles.commitmentGrid}>
          <article className={styles.commitment}><p className={styles.label}>Set limits</p><h3>Decide what may proceed.</h3><p>Specify a budget, permitted sellers, and when a request needs a person&apos;s approval.</p></article>
          <article className={styles.commitment}><p className={styles.label}>Approve precisely</p><h3>Keep an agreement specific.</h3><p>An approval is bound to one request. A changed seller, amount, or resource needs a new decision.</p></article>
          <article className={styles.commitment}><p className={styles.label}>Inspect outcomes</p><h3>Keep the record honest.</h3><p>Distinguish permission, payment, useful work, and an unresolved result. Preserve what happened across recovery.</p></article>
        </div>
      </section>
      <div className={styles.sandboxSurface}><SpendControlSandbox pilotUrl={pilotUrl} /></div>
      <section className={styles.section} id="evidence" aria-labelledby="evidence-title">
        <div className={styles.sectionHeading}><div><p className={styles.eyebrow}>Evidence and limits</p><h2 id="evidence-title">What has been demonstrated.</h2></div><p>Different kinds of evidence answer different questions. These states should remain visible together.</p></div>
        <div className={styles.evidenceGrid}>
          <article className={styles.evidenceItem}><p className={styles.label}>This browser</p><h3>A simulation.</h3><p>The demonstration creates an unsigned projection that is not broadcast. Its sample people, wallet, requests, and outcomes are fictional.</p></article>
          <article className={styles.evidenceItem}><p className={styles.label}>Installed engineering checks</p><h3>43 of 43 checks passed.</h3><p>The archived run at <code>3ef2dbc</code> tested installed offline behavior on Ubuntu 24.04 with Node 24.18.1. Wallet, seller, and chain adapters were synthetic.</p><TextLink href={evidenceUrl}>Read the original evidence</TextLink></article>
          <article className={styles.evidenceItem}><p className={styles.label}>Live use and human outcomes</p><h3>Still to establish.</h3><p>Live CDP payment and live testnet settlement evidence remain not run. Effects on comprehension, supervision, demand, and people&apos;s lives need separate studies.</p></article>
        </div>
        <div className={styles.note}><p><strong>Wallet Kernel is not released for live use.</strong></p><p>The demonstration and archived engineering checks do not establish production readiness. Read the design for the remaining implementation and release requirements.</p><div className={styles.actions}><TextLink href={designUrl}>Read the approved design</TextLink><TextLink href={repositoryUrl}>Inspect the source</TextLink></div></div>
        <TextLink href="/research/meaningful-delegation">Explore the human research question</TextLink>
      </section>
    </SiteFrame>
  );
}
