import type { Metadata } from 'next';
import Link from 'next/link';
import { notFound } from 'next/navigation';
import { SiteFrame, TextLink } from '../../components/human-choice/SiteFrame';
import { questions } from '../../human-choice-content';
import styles from '../../human-choice.module.css';

type Props = { params: Promise<{ slug: string }> };
export const dynamicParams = false;
export function generateStaticParams() { return questions.map(({ slug }) => ({ slug })); }
export async function generateMetadata({ params }: Props): Promise<Metadata> {
  const { slug } = await params;
  const question = questions.find((item) => item.slug === slug);
  if (!question) return { title: 'Question not found' };
  return { title: question.title, description: `Proposed study: ${question.summary}`, alternates: { canonical: `/research/${slug}` }, openGraph: { title: `${question.title} · Human Choice`, description: `Proposed study: ${question.summary}`, url: `/research/${slug}` } };
}

export default async function QuestionPage({ params }: Props) {
  const { slug } = await params;
  const question = questions.find((item) => item.slug === slug);
  if (!question) notFound();
  const related = questions.find((item) => item.slug === question.related);
  return (
    <SiteFrame active="Research">
      <div className={styles.pageIntro}>
        <Link href="/research" className={styles.backLink}>← All research questions</Link>
        <p className={styles.eyebrow}>Question {question.number} / {question.lens}</p>
        <h1 style={{ maxWidth: '21ch' }}>{question.title}</h1>
        <p>{question.summary}</p>
        <div className={styles.questionMeta}><span className={styles.status}>Proposed study</span><span>Method outline · September 2026</span></div>
      </div>
      <div className={styles.reading}>
        <section className={styles.readingSection}><p className={styles.label}>Why it matters</p><div><h2>The human question.</h2><p>{question.why}</p></div></section>
        <section className={styles.readingSection}><p className={styles.label}>Working hypothesis</p><div><h2>What we expect—and need to test.</h2><p>{question.expectation}</p></div></section>
        <section className={styles.readingSection}><p className={styles.label}>Approach</p><div><h2>How we would investigate.</h2><p>{question.method}</p><p>{question.comparison}</p></div></section>
        <section className={styles.readingSection}><p className={styles.label}>Outcomes</p><div><h2>What we would look for.</h2><ul>{question.measures.map((measure) => <li key={measure}>{measure}</li>)}</ul></div></section>
        <section className={styles.readingSection}><p className={styles.label}>Reconsideration</p><div><h2>What would change our thinking.</h2><p>{question.reconsider}</p></div></section>
        <section className={styles.readingSection}><p className={styles.label}>Current status</p><div><h2>The study has not yet run.</h2><p>This is a proposed study, with no participant results or measured effects to report. The sampling plan, final measures, and analysis need to be specified before the study begins.</p><p><strong>Next step:</strong> {question.next}</p>{question.slug === 'meaningful-delegation' ? <TextLink href="/systems#evidence">See the related engineering evidence</TextLink> : null}</div></section>
        {related ? <section className={styles.readingSection}><p className={styles.label}>Connected question</p><div><h2>{related.title}</h2><TextLink href={`/research/${related.slug}`}>Read the proposed study</TextLink></div></section> : null}
      </div>
    </SiteFrame>
  );
}
