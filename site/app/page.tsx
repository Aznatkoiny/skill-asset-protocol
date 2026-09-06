import Link from 'next/link';
import { SiteFrame, TextLink } from './components/human-choice/SiteFrame';
import { RoomToChoose } from './components/human-choice/RoomToChoose';
import { commitments, questions } from './human-choice-content';
import styles from './human-choice.module.css';

export default function HomePage() {
  return (
    <SiteFrame>
      <section className={styles.hero} aria-labelledby="home-title">
        <div>
          <p className={styles.eyebrow}>Research + tools for human flourishing</p>
          <h1 id="home-title">Make room for a better human life.</h1>
          <p className={styles.heroIntro}>We build and study AI systems that help people accomplish meaningful work, gain time, and retain control over their choices.</p>
          <p className={styles.heroFootnote}>Our research asks how the benefits of automation reach the people whose lives it changes.</p>
          <div className={styles.actions}>
            <Link className={styles.button} href="/systems">Explore the work <span aria-hidden="true">↗</span></Link>
            <TextLink href="/principles">Read our principles</TextLink>
          </div>
        </div>
        <RoomToChoose />
      </section>
      <section className={styles.section} aria-labelledby="commitments-title">
        <div className={styles.sectionHeading}>
          <div><p className={styles.eyebrow}>What guides the work</p><h2 id="commitments-title">Progress people can feel in their lives.</h2></div>
          <p>More time, stronger choices, and greater security count as progress—even when output stays the same.</p>
        </div>
        <div className={styles.commitmentGrid}>
          {commitments.map((item) => <article className={styles.commitment} key={item.name}><p className={styles.label}>{item.name}</p><h3>{item.title}</h3><p>{item.description}</p></article>)}
        </div>
      </section>
      <section className={styles.section} aria-labelledby="system-title">
        <div className={styles.projectFeature}>
          <div>
            <p className={styles.eyebrow}>A concrete place to start</p>
            <h2 id="system-title">Delegate the task.<br />Keep a say in the terms.</h2>
            <p>Wallet Kernel explores one part of human agency: letting an AI agent buy a resource within limits its operator understands and sets.</p>
            <p><span className={styles.status}>Wallet Kernel · offline prototype</span></p>
            <TextLink href="/systems">Try the spending-control demo</TextLink>
          </div>
          <div className={styles.flow}>
            <p className={styles.label}>The idea in four steps</p>
            <ol className={styles.flowSteps}>
              <li><span>01</span><div><strong>You set the terms.</strong><p>Choose permitted sellers, budgets, and approval rules.</p></div></li>
              <li><span>02</span><div><strong>The agent requests a resource.</strong><p>It asks within the authority you have given it.</p></div></li>
              <li><span>03</span><div><strong>The kernel checks the request.</strong><p>Allow, decline, or ask for an exact approval.</p></div></li>
              <li><span>04</span><div><strong>The outcome stays inspectable.</strong><p>Keep authorization, payment, and useful results distinct.</p></div></li>
            </ol>
            <p className={styles.finePrint}>Explore a browser simulation and inspect the separate engineering evidence.</p>
          </div>
        </div>
      </section>
      <section className={styles.section} aria-labelledby="research-title">
        <div className={styles.sectionHeading}>
          <div><p className={styles.eyebrow}>The research agenda</p><h2 id="research-title">Questions worth staying with.</h2></div>
          <p>Our first focus: people whose expertise and daily work are being reshaped by AI.</p>
        </div>
        <div className={styles.researchList}>
          {questions.slice(0, 3).map((question) => <Link href={`/research/${question.slug}`} className={styles.researchRow} key={question.slug}><span className={styles.researchNumber}>{question.number}</span><div><h3>{question.title}</h3><p>{question.summary}</p></div><div className={styles.researchEnd}>Proposed<span aria-hidden="true">↗</span></div></Link>)}
        </div>
        <div style={{ marginTop: 23 }}><TextLink href="/research">Explore all research questions</TextLink></div>
      </section>
      <section className={styles.closing}>
        <p className={styles.eyebrow}>A purpose we can hold ourselves to</p>
        <h2>AI should expand the lives people can choose.</h2>
        <p>We will judge our work by what changes for people, publish what we learn, and change direction when the evidence calls for it.</p>
        <TextLink href="/about">Meet the project</TextLink>
      </section>
    </SiteFrame>
  );
}
