import Link from 'next/link';
import type { ReactNode } from 'react';
import { repositoryUrl } from '../../human-choice-content';
import styles from '../../human-choice.module.css';

const navigation = [['Principles', '/principles'], ['Research', '/research'], ['Systems', '/systems'], ['About', '/about']] as const;

export function SiteFrame({ children, active }: { children: ReactNode; active?: string }) {
  return (
    <div className={styles.site}>
      <a className={styles.skipLink} href="#main-content">Skip to content</a>
      <header className={styles.header}>
        <Link className={styles.brand} href="/" aria-label="Human Choice home">
          <svg viewBox="0 0 36 36" aria-hidden="true" width="36" height="36"><path d="M6 29V17a12 12 0 0 1 24 0v12M12 29V17a6 6 0 0 1 12 0v12" fill="none" stroke="currentColor" strokeWidth="1.8" /><path d="M18 29V17" stroke="currentColor" strokeWidth="1.8" /></svg>
          <span>Human Choice</span>
        </Link>
        <nav className={styles.navigation} aria-label="Main navigation">
          {navigation.map(([label, href]) => <Link key={href} href={href} aria-current={active === label ? 'page' : undefined}>{label}</Link>)}
        </nav>
      </header>
      <main id="main-content">{children}</main>
      <footer className={styles.footer}>
        <div><Link href="/" className={styles.footerBrand}>Human Choice</Link><p>More room for a life you value.</p></div>
        <div className={styles.footerLinks}><Link href="/principles">Our principles</Link><Link href="/proof">Project archive</Link><a href={repositoryUrl}>Source on GitHub ↗</a></div>
        <p className={styles.footerNote}>An independent project building and studying AI for human flourishing.</p>
      </footer>
    </div>
  );
}

export function TextLink({ href, children }: { href: string; children: ReactNode }) {
  return <Link className={styles.textLink} href={href}>{children}<span aria-hidden="true">↗</span></Link>;
}
