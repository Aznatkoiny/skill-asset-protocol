import type { Metadata } from 'next';
import { SiteFrame, TextLink } from '../components/human-choice/SiteFrame';
import { commitments } from '../human-choice-content';
import styles from '../human-choice.module.css';

export const metadata: Metadata = {
  title: 'Our principles',
  description: 'Capability, agency, and participation: the principles guiding Human Choice toward human flourishing.',
  alternates: { canonical: '/principles' },
  openGraph: { title: 'Our principles · Human Choice', url: '/principles' },
};

export default function PrinciplesPage() {
  return (
    <SiteFrame active="Principles">
      <div className={styles.pageIntro}>
        <p className={styles.eyebrow}>Our principles · September 2026</p>
        <h1>A life you have a say in.</h1>
        <p>AI and automation should expand people&apos;s freedom to live lives they value.</p>
        <p>We build and study systems that increase human capability, preserve meaningful choice, and give people a say in how the benefits are shared.</p>
      </div>
      <div className={styles.reading}>
        <section className={styles.readingSection}>
          <p className={styles.label}>The purpose</p>
          <div><h2>Flourishing is the measure of the ambition.</h2><p>Progress means better possibilities for people: more time, security, learning, creativity, and control over their lives. Productivity matters because of what it makes possible.</p><blockquote>A person accomplishing the same work with more time for a life they value is a success.</blockquote><p>People should have room to define a good life for themselves. We will ask how our systems affect that room, including effects that a task-completion score cannot capture.</p></div>
        </section>
        {commitments.map((item, index) => (
          <section className={styles.readingSection} key={item.name}>
            <p className={styles.label}>0{index + 1} / {item.name}</p>
            <div><h2>{item.title}</h2><p>{item.description}</p><blockquote>{item.question}</blockquote>
              {index === 0 ? <p>Useful assistance can help someone produce, learn, care, or recover time. We will examine immediate results alongside lasting skill and the effort of supervision and correction.</p> : index === 1 ? <p>Choice needs practical support: knowledge, time, resources, and security. It includes the freedom to delegate and the ability to change the terms. An approval button alone cannot establish meaningful control.</p> : <p>Contributors, users, and the people affected by a system may value different things. Explicit agreements should give those differences a place to be heard, including the ability to renegotiate or leave.</p>}
            </div>
          </section>
        ))}
        <section className={styles.readingSection}>
          <p className={styles.label}>The difficult parts</p>
          <div><h2>Keep the tradeoffs visible.</h2><p>Greater autonomy can involve more risk. Compensation can support contributors while adding costs to sharing. A tool can help one person while shifting work to another.</p><p>We will report who receives gains and who bears costs. Ownership, open sharing, payment systems, and protocols are arrangements to evaluate against the purpose. We should be willing to change them.</p></div>
        </section>
        <section className={styles.readingSection}>
          <p className={styles.label}>How we learn</p>
          <div><h2>Make room to be wrong.</h2><p>Each project should explain whose circumstances it aims to improve, what improvement would look like, and what evidence would make us reconsider. We will publish methods, limitations, negative findings, and corrections.</p><p>These principles express commitments. Whether a particular system lives up to them is a question for evidence.</p><TextLink href="/research">See the questions we are preparing to study</TextLink></div>
        </section>
      </div>
    </SiteFrame>
  );
}
