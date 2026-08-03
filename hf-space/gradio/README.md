---
title: Skill Asset Protocol — Verified Accounting Demo
emoji: 🔏
colorFrom: gray
colorTo: blue
sdk: gradio
sdk_version: 6.20.0
app_file: app.py
python_version: "3.12"
short_description: Testnet-only HTTP 402 and generated accounting evidence.
license: apache-2.0
---

# Skill Asset Protocol — verified accounting demo

> **PROPOSED / NONCANONICAL:** The employer-funded internal Invocation-award model is pending explicit approval.

This standalone Gradio root is a research demo for the compensation,
attribution, and metering layer for authored AI Skills. It defaults to the
terminal-product **Intra-org** scenario. **Education** is deferred after free
re-authoring dominated the tested model; **Marketplace** remains Phase-3
optionality.

The allocation fixture is generated from `prototype/atomic-money.mjs` and
packaged into this Space root with a SHA-256 integrity manifest. The runtime
does not derive fees, Royalty-claim pools, Invocation awards, ancestry splits,
rounding, or account identifiers. It renders the kernel-returned journal rows.
The illustration is synthetic. A credited allocation is not a withdrawal or
on-chain settlement; neither is implemented in this demo.

The live check makes one unpaid request only to the fixed Collar endpoint,
refuses redirects, uses a bounded timeout, and marks a response live only when
it is a valid x402 v1 `exact` offer for Base Sepolia. A failed request or JSON
200/500 response is explicitly non-live. There is no cached-offer fallback.

Evidence shown here is deliberately narrow:

- the historical inference-route aggregate is `historical_unreproducible` and
  not publication-eligible because normalized samples were not retained;
- one successful historical Base Sepolia USDC transfer has a rechecked receipt,
  and the 2026-07-12 repository log labels it as the Skill leg;
- that receipt does not establish current endpoint behavior, latency,
  Royalty-claim split correctness, or Skill execution output.

Everything is **Base Sepolia testnet play money**. This demo holds no key,
signs no payment, sends no transaction, deploys nothing, and is not an offer of
any financial product.
