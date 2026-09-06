import { SiteFrame, TextLink } from './components/human-choice/SiteFrame';
import styles from './human-choice.module.css';

export default function NotFound() {
  return <SiteFrame><div className={styles.notFound}><p className={styles.eyebrow}>Page not found</p><h1>Another way forward.</h1><p>This page is not available. Explore the project from the homepage.</p><TextLink href="/">Return to Human Choice</TextLink></div></SiteFrame>;
}
