---
title: Skill Asset Protocol — Verified Accounting Demo
emoji: 🔏
colorFrom: gray
colorTo: blue
sdk: static
app_file: index.html
short_description: Testnet-only HTTP 402 and generated accounting evidence.
license: apache-2.0
---

# Skill Asset Protocol — verified accounting demo

This standalone static root renders the same deterministic accounting fixture
as the Gradio root. The fixture is generated from
`prototype/atomic-money.mjs`, copied byte-for-byte into this root, and checked
against a local SHA-256 integrity manifest before parsing.

The default mode is **Intra-org**, the terminal-product spike. **Education** is
deferred after free re-authoring dominated the tested model. **Marketplace** is
Phase-3 optionality. The browser does not calculate fees, COGS, ancestry,
percentages, rounding, account identifiers, Royalty-claim pools, or Invocation
awards. It displays the kernel-returned journal entries and only sums them to
verify conservation.

The live button makes one unpaid request to a fixed Collar endpoint. Redirects
are refused and the response is size-bounded. Only a valid x402 v1 `exact`
offer for Base Sepolia is marked live; JSON 200/500 and malformed responses are
non-live. No cached response is presented as current.

Evidence is deliberately narrow. The historical inference-route aggregate is
`historical_unreproducible` and not publication-eligible because normalized
samples were not retained. One successful historical Base Sepolia USDC
transfer has a rechecked receipt, and the 2026-07-12 repository log labels it
as the Skill leg; that does not establish current endpoint behavior, latency,
Royalty-claim split correctness, or Skill execution output.

Everything uses **Base Sepolia testnet play money**. This demo holds no key,
signs no payment, sends no transaction, deploys nothing, and is not an offer of
any financial product.
