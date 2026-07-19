# RUNBOOK — offline verification and Collar trust

The supported automated workflow is offline and in-process. No funded wallet, API key,
listener, or live facilitator is needed.

## 1. Run the verified workflow

From `spikes/pi-wielder`:

```bash
npm install
npm test
npm run e2e
```

The unit/integration suite uses injected Hono apps. The e2e uses one unfunded throwaway
wallet, canned model output, an ephemeral receipt signer, and synthetic settlement.
Timing output is explicitly synthetic.

## 2. Run standalone processes in mock mode

The multi-process demo needs a stable Collar signing key because the proxy refuses Skill
routes without a separately pinned public key and expected key ID.

1. Copy `.env.example` to the already ignored `.env`.
2. Create a private directory **outside this checkout**. Put absolute paths in `.env`:

   ```dotenv
   ALLOW_LIVE_X402=0
   MOCK_LLM=1
   COLLAR_JOURNAL_FILE=/absolute/outside-checkout/pi-wielder/events.jsonl
   COLLAR_SIGNING_KEY_FILE=/absolute/outside-checkout/pi-wielder/receipt-private.pem
   COLLAR_PUBLIC_KEY_FILE=/absolute/outside-checkout/pi-wielder/receipt-public.pem
   COLLAR_KEY_ID=
   ```

   The directory must already exist. Never put the private key or journal in this repo.
   The Collar creates new journal/key files with mode `0600`, rejects symlinks, and
   refuses a path inside the checkout. Both private paths must be set together.

3. Load the environment and start the Collar. With `ALLOW_LIVE_X402=0`, it constructs an
   in-process mock transport; `FACILITATOR_URL` is ignored.

   ```bash
   set -a
   source .env
   set +a
   npm run collar
   ```

4. In another terminal, bootstrap the local demo's public trust file from the loopback
   health endpoint. This command refuses to overwrite an existing public key file and
   prints the key ID:

   ```bash
   set -a
   source .env
   set +a
   node --input-type=module -e 'import fs from "node:fs"; const h=await (await fetch("http://127.0.0.1:8404/healthz")).json(); fs.writeFileSync(process.env.COLLAR_PUBLIC_KEY_FILE,h.signingPublicKeyPem,{flag:"wx",mode:0o644}); console.log(h.signingKeyId)'
   ```

   Copy the printed `sha256:...` value into `COLLAR_KEY_ID` in `.env`. For anything
   beyond a loopback mock demo, provision the public key and its one-hash SPKI-DER ID by
   an authenticated out-of-band channel; do not bootstrap trust from an untrusted server
   response.

5. Start the mock gateway and pinned proxy in separate terminals, loading `.env` in
   each:

   ```bash
   npm run gateway
   npm run proxy
   ```

6. Exercise both routes through the proxy:

   ```bash
   curl -s http://127.0.0.1:8402/v1/chat/completions \
     -H 'content-type: application/json' \
     -H 'x-session-label: plan' \
     -d '{"model":"claude-sonnet-4-6","messages":[{"role":"user","content":"Plan a refactor."}]}'

   curl -s http://127.0.0.1:8402/invoke/optimizing-claude-code-prompts \
     -H 'content-type: application/json' \
     -d '{"input":"make the checkout page faster"}'

   curl -s http://127.0.0.1:8402/ledger
   ```

`/ledger` is a payer-side receipt view. It is not the Collar journal and is not a
cross-seller accounting authority.

### Runtime limits

The mock and standalone paths use the same bounded runtime contract as the tests.
Collar/Skill request bodies stop at exactly 4,096 bytes; model requests stop at 1 MiB.
x402 challenges and facilitator JSON stop at 64 KiB; gateway provider JSON and proxy
upstream responses stop at 1 MiB. Streaming and chunked bodies are counted as they
arrive, so omitting `Content-Length` does not bypass a limit.

The default deadlines are 15 seconds for an unpaid buyer fetch, 30 seconds for its
single paid retry, 5 seconds for request-body reads, 10 seconds each for facilitator
verify and settle, and 30 seconds for provider execution/upstream response reads. The
gateway's provider deadline covers both the fetch and the streamed response read,
cannot be configured above 30 seconds, composes the request abort signal, and refuses
redirects. Provider HTTP failures never consume or expose the raw response body; all
public failures are stable and sanitized. Unsuccessful facilitator and provider bodies,
plus paid output withheld for invalid settlement evidence, are cancelled without being
read or exposed.
An unpaid timeout remains unreserved. Any timeout after the signature keeps the payment
unresolved/held until trusted reconciliation. A provider timeout after settlement
returns no output and finalizes a signed failed receipt with unknown COGS and the full
gross held for reconciliation or refund.

The Collar keeps no durable state for an unpaid challenge. Its paywall admits at most
128 process-local pending offers, each with a 60-second TTL. New keys beyond the cap get
`503 PENDING_OFFER_CAPACITY` with `Retry-After: 1`; active keys still get their frozen
offer. `Idempotency-Key` is restricted to 1-128 canonical ASCII characters. Only expired
unpaid entries are reclaimed. After facilitator verification, the exact payment-header
digest and all signed, unresolved, settled, refunded, execution, and terminal state
remain in the append-only journal and are never capacity-pruned. A replay must match that
digest; legacy journal entries without one are sent back through facilitator verification.

The standalone gateway has no durable response authority. Before verification it claims
the fixed network, asset, payer, and nonce for exactly one Idempotency-Key and binds the
exact verified payment-header hash to that owner. Cross-key, concurrent, and alternate-
encoding reuse fails before a second verification, settlement, or provider execution;
a successful claim stays through its exact frozen-offer validity window in bounded
TTL-scoped admission state. Do not treat this as response replay. The authoritative Collar
journal remains the only terminal replay path. Facilitator verification accepts only the
exact boolean `true`.

A restart after `402` but before successful verification intentionally loses that
non-authoritative offer. A paid retry carrying the old key then gets `409` before any
facilitator or provider call. Keep the Wielder reservation unresolved, reconcile the
signed nonce through a trusted operator path, and issue a fresh key only after that
check. A retry whose verified state was journaled continues through the normal durable
reconciliation and replay paths.

## 3. Persistent authority contract

`COLLAR_JOURNAL_FILE` and `COLLAR_SIGNING_KEY_FILE` are one authority pair:

- both are explicit absolute paths outside the checkout;
- both are regular non-symlink files with exact mode `0600` once created;
- the journal is append-only JSONL, fsynced, hash-chained, and Ed25519-signed per event;
- same-host processes serialize writes with a private lease file and record-level
  compare-and-swap checks;
- stale lease removal is an explicit exact-lease-ID API operation, not an automatic
  timeout deletion;
- the private key never enters the proxy. The proxy receives only
  `COLLAR_PUBLIC_KEY_FILE` plus `COLLAR_KEY_ID` and independently recomputes the ID.

Changing the private signing key without starting a new journal is rejected. Rotating
the Collar key also requires updating the proxy's pinned public key and ID through a
trusted operator process.

## 4. Trusted reconciliation and refunds

The HTTP endpoints do not accept caller-supplied settlement or refund proofs:

- `GET /receipts/by-settlement/:reference` is read-only.
- `POST /reconcile/by-settlement/:reference` calls the injected
  `resolveSettlement` adapter and requires exact reference, payer, gross amount, and
  transaction evidence.
- `POST /refund/by-settlement/:reference` durably claims one refund attempt before it
  calls the injected `executeRefund` adapter.
- `POST /reconcile/refund/by-settlement/:reference` calls the separate injected
  `resolveRefund` adapter after an ambiguous/crashed refund outcome.

An integration must construct the Collar with trusted code, not with proof fields from
an HTTP request:

```js
createCollar({
  facilitatorTransport,
  journalFile,
  signingKeyFile,
  resolveSettlement,
  executeRefund,
  resolveRefund,
});
```

Every adapter result is checked against journal-bound payer, reference, transaction,
and canonical atomic amount. Exceptions are returned as stable public errors. A refund
resolver may confirm the already claimed attempt; it must not initiate a second refund.

There is currently no operator endpoint that resolves a Skill attempt left `executing`
after the provider returned but before the terminal journal append. Such an Invocation
remains explicit `503 execution outcome unresolved` until a future trusted execution
reconciliation design exists. Do not manually rewrite the journal.

## 5. Live Base Sepolia boundary — intentionally blocked in the CLI

Before a live provider run, verify the current provider price sheet and construct a new
immutable catalog version with `evidenceLabel: human_verified`, source, and as-of
timestamp. Compute its exact canonical `catalogDigest`; the spend cap must cover the
maximum worst-case provider cost across every allowed model in that catalog. Do not
embed approval or spend authorization in the catalog itself, and never relabel a
`synthetic_config` catalog as measured.

The Collar and gateway use separate operator approvals:

- Collar construction receives `LIVE_CATALOG_DIGEST` and `LIVE_SPEND_CAP_ATOMIC`.
- The standalone gateway reads `GATEWAY_LIVE_CATALOG_DIGEST` and
  `GATEWAY_LIVE_SPEND_CAP_ATOMIC`.
- Both require `ALLOW_LIVE_PROVIDER=1`, `MOCK_LLM=0`, and live x402 settlement through
  the pinned approved facilitator; the provider credential is supplied only through
  operator secret injection. A live provider can never run behind mock settlement.

The Collar approval checks the gross ceiling for one Invocation. The gateway approval
instead funds one cumulative in-memory process-run budget. After facilitator verification
and before settlement, the gateway synchronously reserves that request's catalog
worst-case input/output cost. A valid provider response commits actual catalog-rated
usage, while a timeout, HTTP failure, invalid usage, or other ambiguous outcome consumes
the full reservation. A new paid retry is refused before settlement when its worst case
no longer fits. The cap resets on process restart and is not durable or shared across
workers, so a production integration still needs an independent persistent aggregate
budget.

The committed gateway catalog is deliberately `synthetic_config`, so `npm run gateway`
remains blocked from live execution even if the flags, digest, cap, and provider key are
set. A reviewed integration must inject a `human_verified` catalog and its exact digest.
The gateway enforces its catalog's exact model allowlist, output bound, and conservative
input bound before offering payment. That input bound treats each raw request byte as at
most one provider token and reserves another 1,024 tokens for provider-side chat
framing. The pre-offer schema is closed: messages, text parts, function tools/calls/results,
and provider-specific options must match the documented Pi/OpenAI shapes. Unknown or
malformed fields fail with `400` before facilitator or provider activity. Anthropic
options are translated explicitly; unsupported `strict` tool semantics and requests that
would translate to no non-system provider message are rejected.
Provider requests refuse redirects, use one absolute fetch-plus-body deadline,
whose configurable value cannot exceed 30 seconds, and stream responses through a hard
1 MiB cap. Automated verification stays on the mock facilitator and mock model and uses
no real funds.

Provider approval is separate from the x402 settlement gate below. Both gates must be
satisfied by a future integration; enabling either one does not implicitly authorize
the other.

Live mode is opt-in only:

```dotenv
ALLOW_LIVE_X402=1
FACILITATOR_URL=https://x402.org/facilitator
```

The URL must match the single approved HTTPS base byte-for-byte. Redirects are disabled,
and only `/verify` and `/settle` are constructed. Mainnet is unsupported.

The standalone `npm run collar` command intentionally does **not** load settlement or
refund adapters from environment variables. Therefore it refuses live startup even when
the URL and persistent files are present. A future authorized Base Sepolia run must add
reviewed, injected implementations for all three trusted adapters above, preserve the
persistent authority pair, pin the proxy trust out of band, and use a human-funded
testnet-only wallet. No such live run was performed during this remediation.

This fail-closed boundary is expected behavior, not a setup bug.

## 6. Manual Pi adapter

The Pi extension is optional and not compiled in CI:

```bash
mkdir -p .pi/extensions
cp <this-repo>/spikes/pi-wielder/pi-extension/x402.ts .pi/extensions/
```

With the three standalone mock processes running, start the compatible Pi version and
reload extensions. The extension points model calls and `invoke_skill` at the local
proxy and renders the signed receipt bundle shape. `/ledger` shows the proxy's local
view. Verify the extension API against the installed Pi version before a demo.

## 7. Manual-only boundaries

- Provisioning and protecting persistent key material.
- Supplying reviewed trusted settlement/refund adapters.
- Funding any future Base Sepolia wallet; never automate faucets here.
- Installing and smoke-testing Pi.
- Authorizing and retaining evidence for any future live measurement.

Secure card, billing, private-key, and wallet-funding details do not belong in chat,
tracked files, receipts, or logs.
