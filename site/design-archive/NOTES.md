# Design archive

Prototype question (2026-07-12): *what should the manifesto page look like?*
Three structurally different variants were built and flipped live via
`?variant=`; the decision:

- **Winner — "THE TEN"** (industrial wall text): promoted to `app/manifesto.tsx`.
- **Archived — "RECEIPT"** (`VariantB.module.css` here): the visual direction
  used a thermal-printer point-of-sale receipt — black, phosphor monospace,
  line-item texture, and a CSS barcode. The interactive `VariantB.tsx` prototype
  was retired with the browser-wallet payment path because it depended on the
  deleted invocation hook and preserved obsolete signing copy. The remaining CSS
  is a visual reference for **future receipt and session-ledger views**; it is not
  a runnable payment interface.
- **Scrapped — "GALLERY PLACARD"**: museum-placard editorial layout. Verdict:
  too quiet for the material.

This stylesheet is a design artifact, not live code, and `design-archive/`
remains excluded from the TypeScript build.
