# Design archive

Prototype question (2026-07-12): *what should the manifesto page look like?*
Three structurally different variants were built and flipped live via
`?variant=`; the decision:

- **Winner — "THE TEN"** (industrial wall text): promoted to `app/manifesto.tsx`.
- **Archived — "RECEIPT"** (`VariantB.tsx` + `VariantB.module.css` here):
  the whole manifesto as a thermal-printer point-of-sale receipt — black,
  phosphor monospace, principles as line items, txHashes as texture, terminal
  invoke prompt. Kept because the owner likes its elements; it is the natural
  design language for **future invocation-receipt and session-ledger views**.
- **Scrapped — "GALLERY PLACARD"**: museum-placard editorial layout. Verdict:
  too quiet for the material.

These files are design artifacts, not live code — excluded from the TypeScript
build; their imports reference `app/` paths that may drift.
