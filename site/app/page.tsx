import { manifesto } from './content';
import Manifesto from './manifesto';

// Design decision 2026-07-12: three prototype variants were built and flipped
// live ("THE TEN" / "RECEIPT" / "GALLERY PLACARD"); "THE TEN" won. The
// "RECEIPT" variant is preserved in ../design-archive — its thermal-printer
// ledger aesthetic is a candidate for future invocation-receipt views.

export default function Page() {
  return <Manifesto manifesto={manifesto} />;
}
