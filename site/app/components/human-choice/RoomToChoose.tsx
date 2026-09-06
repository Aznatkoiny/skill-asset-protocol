'use client';
import { useState } from 'react';
import styles from '../../human-choice.module.css';

const possibilities = [
  { label: 'Learn', title: 'Room to grow.', detail: 'Explore an idea. Practice a skill. Follow your curiosity.' },
  { label: 'Create', title: 'Room to make.', detail: 'Start something of your own. Give an unfinished idea your attention.' },
  { label: 'Connect', title: 'Room for others.', detail: 'Be present with someone. Make time for the people who matter.' },
  { label: 'Rest', title: 'Room to simply be.', detail: 'Take a walk. Recover your energy. Leave some time unplanned.' },
] as const;

export function RoomToChoose() {
  const [selected, setSelected] = useState(0);
  const possibility = possibilities[selected];
  return (
    <aside className={styles.possibility} aria-label="A thought experiment about time">
      <p className={styles.label}>A thought experiment</p>
      <div className={styles.timeIllustration} aria-hidden="true"><div className={styles.timeSun}><span>2h</span><small>back in your day</small></div><div className={styles.horizon} /></div>
      <p className={styles.possibilityPrompt}>Imagine AI gives you two hours back.<br />What would you make room for?</p>
      <div className={styles.choices} role="group" aria-label="Explore a possibility">
        {possibilities.map((item, index) => <button type="button" key={item.label} aria-pressed={index === selected} onClick={() => setSelected(index)}>{item.label}</button>)}
      </div>
      <div className={styles.possibilityResult} aria-live="polite" aria-atomic="true"><strong>{possibility.title}</strong><p>{possibility.detail}</p></div>
      <p className={styles.finePrint}>An illustration of the mission. Actual time savings are a research question.</p>
    </aside>
  );
}
