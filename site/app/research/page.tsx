import type { Metadata } from 'next';
import Link from 'next/link';
import { SiteFrame, TextLink } from '../components/human-choice/SiteFrame';
import { questions } from '../human-choice-content';
import styles from '../human-choice.module.css';

export const metadata: Metadata = {
  title: 'Research',
  description: 'Proposed studies on time recovered, meaningful delegation, lasting capability, and sharing the gains from AI.',
  alternates: { canonical: '/research' },
  openGraph: { title: 'Research · Human Choice', url: '/research' },
};

export default function ResearchPage() {
  return (
    <SiteFrame active="Research">
      <div className={styles.pageIntro}><p className={styles.eyebrow}>Research</p><h1>What changes for the person?</h1><p>Our first focus is people whose expertise and daily work are being reshaped by AI. We want to understand when automation expands their capabilities, time, and choices.</p></div>
      <div className={styles.researchIndex}>
        <p className={styles.researchIntroNote}>These four studies are proposed. Each page sets out a question, a method outline, and what would change our thinking. Results will be added after the work is carried out.</p>
        <div className={styles.researchList}>{questions.map((question) => <Link href={`/research/${question.slug}`} key={question.slug} className={styles.researchRow}><span className={styles.researchNumber}>{question.number}</span><div><p className={styles.label}>{question.lens}</p><h3>{question.title}</h3><p>{question.summary}</p></div><div className={styles.researchEnd}>Proposed<span aria-hidden="true">↗</span></div></Link>)}</div>
        <div className={styles.note}><p><strong>Engineering evidence is available for Wallet Kernel.</strong></p><p>Installed offline checks examine specific control and recovery behavior. They provide a starting point for comparative research; they do not establish effects on people&apos;s lives.</p><TextLink href="/systems#evidence">Inspect the system and its evidence</TextLink></div>
      </div>
    </SiteFrame>
  );
}
