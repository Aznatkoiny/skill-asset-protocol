import styles from '../../landing.module.css';

export function PilotCta({ pilotUrl }: { pilotUrl: string }) {
  return (
    <section className={styles.pilotCta} aria-labelledby="pilot-title">
      <div>
        <p className={styles.eyebrow}>Founding design partners · 3 openings</p>
        <h2 id="pilot-title">
          Run one real Skill portfolio through one real reward close.
        </h2>
      </div>
      <div className={styles.pilotDetails}>
        <ul>
          <li>8–12 week paid pilot</li>
          <li>One Skill source and one runtime</li>
          <li>Creator + admin evidence views</li>
          <li>Policy preview and award-ready export</li>
        </ul>
        <a className={styles.primaryButtonDark} href={pilotUrl}>
          Discuss a pilot
          <span aria-hidden="true">↗</span>
        </a>
      </div>
    </section>
  );
}
