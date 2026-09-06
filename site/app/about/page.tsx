import type { Metadata } from 'next';
import { SiteFrame, TextLink } from '../components/human-choice/SiteFrame';
import { discussionUrl, repositoryUrl } from '../human-choice-content';
import styles from '../human-choice.module.css';

export const metadata: Metadata = {
  title: 'About the project',
  description: 'Human Choice is an independent project building and studying systems for capability, agency, and participation in the age of AI.',
  alternates: { canonical: '/about' },
  openGraph: { title: 'About · Human Choice', url: '/about' },
};

export default function AboutPage() {
  return (
    <SiteFrame active="About">
      <div className={styles.pageIntro}><p className={styles.eyebrow}>About Human Choice</p><h1>A human purpose for more capable machines.</h1><p>Human Choice is an independent project that builds and studies systems for human flourishing in the age of AI and automation.</p></div>
      <div className={styles.reading}>
        <section className={styles.readingSection}><p className={styles.label}>Why we exist</p><div><h2>Follow the benefits all the way to people.</h2><p>We care about what people can do, the choices they control, and the benefits they receive. A faster task is a starting point. Time to learn, stronger security, meaningful work, and freedom to care for others belong in the account of progress too.</p><TextLink href="/principles">Read the founding principles</TextLink></div></section>
        <section className={styles.readingSection}><p className={styles.label}>Where we began</p><div><h2>From authored skills to human choice.</h2><p>The work began as Skill Asset Protocol, exploring reusable expertise, attribution, and compensation. Wallet Kernel followed with a concrete engineering question about authority over AI spending.</p><p>Human Choice gives those questions a shared purpose. The initial research focus is people whose expertise and everyday work are being reshaped by AI. The earlier work remains available with its historical context and evidence limits.</p><TextLink href="/proof">Visit the project archive</TextLink></div></section>
        <section className={styles.readingSection}><p className={styles.label}>How we work</p><div><h2>Build, inspect, learn, revise.</h2><p>We connect each system to a human question. We distinguish a principle from a hypothesis, an experiment from a finding, and a payment record from evidence of useful work.</p><p>We intend to publish methods and results, including negative findings and corrections. The first human-outcomes studies are proposed; current engineering evidence is described on the Systems page.</p><TextLink href="/systems">See the current system</TextLink></div></section>
        <section className={styles.readingSection}><p className={styles.label}>Take part</p><div><h2>Bring a real question.</h2><p>Researchers, builders, and people using AI in their work can help sharpen the questions. A useful starting point is a specific situation: what changed, who benefited, what became harder, and what would have helped.</p><p>Research discussion and implementation work currently take place in the public GitHub repository.</p><div className={styles.actions}><TextLink href={discussionUrl}>Explore the public discussion</TextLink><TextLink href={repositoryUrl}>Explore the source</TextLink></div></div></section>
      </div>
    </SiteFrame>
  );
}
