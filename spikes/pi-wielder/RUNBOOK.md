# RUNBOOK - Pi Wielder Agent Spend Control Plane

The supported automated workflow is deterministic and offline. It covers both the
legacy Collar proof and the newer Wallet Kernel process-acceptance path. No funded
wallet, provider key, CDP credential, or live facilitator is needed. Pi is the Wielder;
Agent and Operator name local control-plane security roles.

Current release status is intentionally asymmetric:

- deterministic verification and evidence are **measured offline**; wallet settlement,
  deployment, and cross-UID isolation are simulated;
- live CDP and Base Sepolia payment are **not-run**;
- the installed preflight, runtime, secret delivery, and native listener composition
  have offline tests; a sealed `offline-qualification` profile and disposable Linux
  workflow are prepared, but no passing installed-host artifact is claimed here;
- the default or explicit `cdp-testnet` profile remains **blocked** by
  `LIVE_LAUNCH_NOT_READY` (exit 78); offline qualification does not enable live CDP;
- there is no mainnet mode, automated funding, custody service, or real-funds workflow.

Do not interpret a local macOS pass, a deterministic adapter, or a skipped systemd test
as evidence that the live host boundary works.

## 1. Run the verified workflow

Requirements:

- a POSIX host;
- Node 24.18.1 or newer for deterministic development;
- the package-lock-installed dependency tree (`npm ci`, not an unconstrained update).

The future attested live release is narrower: Linux with systemd and exactly Node
24.18.1. From `spikes/pi-wielder`:

```bash
npm ci
npm run verify:spend-control
```

The legacy unit/integration path uses injected Hono apps. The spend-control acceptance
path starts real loopback child processes when the host sandbox permits it. Both use an
unfunded deterministic wallet, canned model output, signed local receipts, and
synthetic settlement. Timing and isolation output are explicitly offline/simulated.

Create and independently verify a fresh offline evidence bundle:

```bash
evidence_parent="$(mktemp -d /tmp/pi-wielder-evidence.XXXXXX)"
evidence_parent="$(cd "$evidence_parent" && pwd -P)"
npm run evidence:offline -- \
  --output "$evidence_parent/bundle" \
  --anchor-output "$evidence_parent/manifest.sha256"
manifest_sha256="$(tr -d '\n' < "$evidence_parent/manifest.sha256")"
npm run evidence:verify -- "$evidence_parent/bundle" \
  --expect-manifest-sha256 "$manifest_sha256"
npm run verify:no-secrets
```

Keep `manifest.sha256` outside the bundle. The verifier requires that external value,
hashes the exact manifest bytes, replays the normalized evidence chain, and verifies
the canonical set of signed per-session authority projections and exact receipt
partition/revision history. It does not open SQLite, call a
network, or claim to reconstruct redacted private event data. The bundle and anchor
paths are exclusive-create; generate a new directory for every run.

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

## 6. Pi adapter

The extension is pinned to Pi `0.80.6`. Automated contract tests import the TypeScript
module with Node's type stripping and invoke Pi's real five-argument tool ABI. Copying
it into a Pi installation remains a manual host step:

```bash
mkdir -p .pi/extensions
cp <this-repo>/spikes/pi-wielder/pi-extension/x402.ts .pi/extensions/
```

With the Wallet Kernel's loopback Agent API running, start the exact compatible Pi
version and reload extensions. The extension points model calls and `invoke_skill` at
fixed local routes. A new logical model call gets a fresh call ID; its hook retains
that ID across an error until Pi reports a terminal outcome, then rotates it. The tool
uses its real `toolCallId` to derive a stable call ID and performs at most one automatic
same-key retry only when its local `fetch` throws or response-body reading fails. It
never automatically retries a received invalid content type, malformed JSON, or any
HTTP/application result, including `payment_approval_required`. A completed replay
returns a non-success JSON envelope: the charge and signed receipt remain available,
but provider output is not fabricated or retained. Later legitimate model and Skill
calls use fresh IDs even when their ordinary payloads are identical. For an identical
payload, a fresh ID creates a new intent only when no active retry-matchable intent or
prior alias exists; otherwise the Kernel resolves it to the active or previously bound
intent. `npm run e2e:spend-control` exercises this path fully offline without external
providers or chain access.

## 7. Manual-only boundaries

- Provisioning and protecting persistent key material.
- Supplying reviewed trusted settlement/refund adapters.
- Funding any future Base Sepolia wallet; never automate faucets here.
- Installing and smoke-testing Pi.
- Authorizing and retaining evidence for any future live measurement.

Secure card, billing, private-key, and wallet-funding details do not belong in chat,
tracked files, receipts, or logs.

## 8. Wallet Kernel operating model

The Wallet Kernel is the Wielder-side spending authority. Pi receives only a Pi-owned
Agent credential and the loopback Agent API. It cannot choose the wallet, target URL,
HTTP method, seller, payee, amount, policy, Spend Session, approval ID, payment
idempotency key, or payment header. Those values come from the active PolicyVersion,
fixed route map, durable intent, and wallet adapter. Pi must provide a separate
32-byte `x-agent-call-id`; it grants no spend authority, never reaches the seller, and
is bound by the Kernel to the authenticated Agent credential, exact Spend Session,
route, method, body, allowlisted headers, and purpose. It cannot convey an Approval,
wallet, payee, amount, policy, payment idempotency key, signature, or payment header.
Reusing it for the same completed call cannot pay again; reusing it for a different
request fails with `CORRELATION_CONFLICT`. A later legitimate call, including an
identical one, must use a fresh key. While an exact fingerprint remains active, a fresh
key is atomically recorded as its correlation alias before signing rather than creating
a second intent. Only a fresh unbound key with no active exact fingerprint can create a
later identical intent.

The policy decision is made before signing and enforces all of these independent
limits:

- the seller's per-request maximum;
- the seller's exposure maximum within the Spend Session;
- the Wielder's whole-session exposure maximum;
- the Wielder's rolling-24-hour exposure maximum.

Amounts at or below `autoApproveAtomic` may proceed automatically. Amounts above that
threshold and at or below `humanApproveAtomic` enter the bounded approval queue. All
other requests fail closed. A signature is never recreated for a retry: the exact
authorization and payment bytes are persisted before the one paid attempt. Ambiguous
payment or execution outcomes continue to consume budget until trusted reconciliation
resolves them.

There are two local principals:

- **Agent:** the Pi process acting as the Wielder. It authenticates only to the narrow
  Agent API with `WalletKernelAgent`; it cannot use Operator routes.
- **Operator:** the wallet owner. The Operator owns an independent bearer and uses the
  offline bootstrap CLI or the authenticated local admin plane. Operator responses are
  closed public projections and do not contain raw credentials, prompts, bodies,
  payment payloads, or private paths.

Zero active Agent enrollments starts only an operator recovery surface. It creates no
Spend Session or signer admission. A revoked enrollment cannot spend after restart;
the Operator may still inspect, reconcile, export, and guarded-close retained records.

## 9. Live host and filesystem prerequisites

These are mandatory for a future `cdp-testnet` host. They are documented now so an
operator can review the trust boundary; satisfying them does not remove the current
`LIVE_LAUNCH_NOT_READY` block.

1. Use Linux with systemd, a clean exact Git commit, `npm ci`, and exactly Node
   24.18.1. The pinned Node executable and the full installed dependency tree are part
   of release integrity.
2. Provision distinct, non-root numeric Kernel and Pi UIDs with pinned primary GIDs
   and no additional account-group memberships. Dropped probes clear supplementary
   groups, and service startup checks the actual process groups. An empty systemd
   `SupplementaryGroups=` does not remove the account database's memberships.
   Startup refuses root, a shared UID, identity drift, or enrollment/config drift.
3. Choose one root-owned trusted ancestor. Every configured private, writable,
   configuration, release, socket, evidence, and handoff path must be reached by a
   complete non-symlink descriptor walk beneath it. Any group/other-writable or sticky
   writable ancestor is rejected.
4. Keep the immutable release and all writable state separate. A reference ownership
   layout is:

   | Path role | Owner and mode | Direction or contents |
   |---|---|---|
   | Versioned release tree | root; no group/other write | Source, lockfile-installed dependencies, pinned Node binding, manifest, unit artifacts, policy seed, and fixed route map |
   | Authority root | Kernel `0700` | SQLite, receipt key, Operator token, and authority lock; private files are `0600` |
   | Runtime root | Kernel `0700` | Unix admin socket and runtime-only state |
   | Evidence root | Kernel `0700` | New immutable testnet run directories; never under the release tree |
   | Pi credential parent | Pi `0700` | Raw Agent credential `0600`; Kernel traversal must receive `EACCES` |
   | Enrollment inbox | Pi `0755` | Pi writes one non-secret descriptor `0644`; Kernel can read but must not write/rename/delete |
   | Agent-run outbox | Kernel `0755` | Kernel writes one public run descriptor `0644`; Pi can read but must not write/rename/delete |
   | Attested environment file | root-owned regular file, `0600`; traversable immutable root-owned ancestors | Closed Kernel inputs; root checks metadata only and PID1 supplies a separate credential copy |

The two handoff parents are deliberately separate. Before live admission, dropped-UID
probes must prove both wrong-direction write/rename/delete attempts fail with `EACCES`,
Pi can read only its own credential, and Pi cannot read or modify Kernel authority,
release, service, environment, or evidence state.

## 10. Clean install, bootstrap, and the intentional live block

`scripts/install-live-deployment.mjs` seals a **prepared** release; account provisioning,
offline authority bootstrap, and separately confirmed enrollment/policy inputs remain
explicit prerequisites. It verifies a clean standalone source checkout at the declared
commit, the prepared source bytes/modes, and installed package metadata against the
committed lock, then hashes every installed byte into the release manifest. It does not
run npm as root or claim to reproduce registry tarballs. Both installed CDP entrypoints
remain gated; there is no environment flag or CLI switch that enables a live release.
The separate manifest-bound `offline-qualification` profile below can exercise the
installed lifecycle only with its fixed synthetic external adapters.

Start from [deployment.example.json](deploy/deployment.example.json) and
[kernel.env.example](deploy/kernel.env.example). Replace the zero commit, choose actual
distinct non-root Kernel/Agent UIDs **and GIDs**, and commit the selected policy/route
files in the reviewed source. The public deployment file must be canonical JSON plus
one newline at `<releaseRoot>/deployment.json`; it contains paths and identities only.
The separate environment source contains customer CDP/RPC inputs as inert, bounded
`KEY=VALUE` data. Do not use the legacy mixed-purpose `.env.example` for this service.
The example uses trusted ancestor `/` to cover `/opt`, `/var`, `/run`, and `/etc`;
every traversed directory still must pass its ownership and non-symlink checks.
Commit the reviewed source first, then generate the deployment file inside the
prepared release addressed by that commit. Do not try to commit a deployment file
that contains its own resulting Git commit. The release manifest binds that generated
file, the selected policy/routes, and the committed executable graph.

Production unit artifacts have fixed paths:
`/etc/systemd/system/wallet-kernel.service` and
`/etc/systemd/system/wallet-kernel-console.socket`. Linked or custom search-path units
are unsupported. The host must provide immutable root-owned `/usr/bin/systemctl`
and `/usr/bin/busctl`. The inspector reads credential mappings and the environment-file
list as typed PID1 properties because systemd v255 does not faithfully print them
through `systemctl show`. Run the installer only from the verified source or prepared release,
using the exact pinned Node binary, after completing the offline prerequisites:

```text
<pinned-node> <reviewed-source>/spikes/pi-wielder/scripts/install-live-deployment.mjs \
  --deployment <immutable-release>/deployment.json \
  --source-checkout <clean-standalone-reviewed-source>
```

Successful sealing reports `sealed_not_started`, `started: false`, and
`qualification: not_performed`. It refuses existing artifacts and performs
render → daemon-reload → enable socket **without start** → inspect PID1 → build/write/
verify manifest. Failure after attempted enablement independently attempts service
stop, socket stop, and socket disable, retaining the original failure code and each
cleanup result. Review any failed cleanup before retrying; a successful command is
not itself lifecycle qualification.

The required clean-install order is exact:

1. From a clean commit, install the dependency-locked tree into a version-addressed,
   root-owned immutable release path such as `/opt/wallet-kernel/releases/<commit>`.
   Never run live from a developer checkout, symlink named `current`, or Pi-writable
   workspace.
2. Provision distinct Kernel-writable authority, runtime, and evidence roots plus the
   two directional handoff parents described above.
3. Render both systemd artifacts to their exact immutable paths. The renderer is a
   library boundary intended for a privileged installer and refuses an ad hoc direct
   invocation.
4. Run Kernel `preflight` offline, before opening a network listener.
5. Under the Pi UID, create the raw Agent credential and public enrollment descriptor.
6. Under the Kernel UID, import that descriptor with its separately confirmed hash.
7. Validate the candidate policy, then apply it only with its separately confirmed
   hash. Validate the route map before any start.
8. Run `systemctl daemon-reload`.
9. Run `systemctl enable wallet-kernel-console.socket` without starting it. The socket
   template has `[Install] WantedBy=sockets.target`; enable it independently from the
   static service.
10. Inspect PID1's complete effective service/socket configuration, then create and
    verify the release manifest against the immutable tree, exact Node 24.18.1 binary,
    both unit artifacts, and that effective-config hash.
11. Run the privileged dropped-identity isolation probe bound to the enrollment and
    release manifest. Import its fresh, Kernel-owned `0600` report with the separately
    confirmed report hash. The report expires after at most 15 minutes and must be
    regenerated before each live start.
12. Verify the same effective configuration, run
    `systemctl start wallet-kernel-console.socket`, and only then start the service.

The loaded service passes only `WALLET_KERNEL_ENV_FILE=<absolute path>` as its custom
environment input to the
root-prefixed preflight. It may not use `EnvironmentFile=`, `PassEnvironment=`, or
place CDP/RPC secret values in root's environment. Loader controls including
`NODE_OPTIONS`, `NODE_PATH`, `LD_*`, `DYLD_*`, `GCONV_PATH`, and `GLIBC_TUNABLES` are
forbidden. Root verifies public release, unit, PID1, and path facts, then uses an
empty-environment child that clears groups and drops to the exact Kernel GID/UID for
read-only enrollment inspection. A recovery-only authority requires no retained Agent
credential. An enrolled authority additionally requires fresh dropped-Agent probes,
unchanged before/after credential and authority metadata, and a second dropped-Kernel
audit that compares the confirmed report with stored authority. No report is silently
approved or imported by startup.

`LoadCredential=wallet-kernel-environment:<source>` lets PID1 deliver the credential
at `/run/credentials/wallet-kernel.service/wallet-kernel-environment`. The Kernel
checks its real/effective IDs and supplementary groups before opening that copy.
Root-owned ACL delivery is accepted only at that fixed path on the verified read-only
tmpfs/ramfs credential mount; the unmounted plain-directory fallback is unsupported.
The loader never sources shell text or mutates `process.env`. Native Hono adapters use
`overrideGlobalObjects: false`. The Operator Unix socket and inherited console listener
start before Agent admission; the runtime closes its authority and listeners on startup
failure. Actual PID1 delivery, dropped-Agent denial of the delivered copy, and installed
start/restart/cleanup must still be qualified on the target Linux host.

For the default or explicit `cdp-testnet` profile, step 12 does **not** produce a live
service. The preflight command emits a machine-readable gate with code
`LIVE_LAUNCH_NOT_READY` and exits 78. The remaining release blocker is:

- `LIVE_SYSTEMD_LIFECYCLE_EVIDENCE_REQUIRED`.

The listener requirement includes production `@hono/node-server` adapters configured
with `overrideGlobalObjects: false`. A local macOS test cannot supply the required
Linux root/systemd lifecycle evidence. A skipped Linux/systemd integration is recorded
as skipped, never passed. Any failure after socket enablement must leave the socket
disabled and the service stopped.

### Disposable installed qualification

The [`installed-lifecycle` job](../../.github/workflows/pi-wielder-systemd.yml)
is the prepared host procedure for `executionProfile: "offline-qualification"`.
It needs a disposable Ubuntu 24.04 VM with systemd as PID1, root for installation,
and exactly Node 24.18.1. It creates dedicated Kernel/Agent accounts and installs the
fixed unit names under `/etc/systemd/system`. Use a clean VM with none of the fixed
qualification directories or Wallet Kernel units already present. This procedure
creates and resets synthetic authority; it must not select a customer deployment.

The workflow checks out the exact qualification revision, creates a standalone
source clone, installs locked dependencies unprivileged with `npm ci --ignore-scripts`,
and copies the prepared source, release, and Node executable into root-owned paths
under `/opt/wallet-kernel-qualification`. The source checkout stays clean. Per-host
deployment, fixture policy, and route files are generated only in
`releases/<commit>` before the installer seals that release. The installer verifies
the source commit and bytes, package lock, ownership, unit paths, and PID1 configuration;
it enables the console socket without starting it.

The qualification harness then uses the installed commands and listeners. Its intended
coverage includes actual process IDs, capabilities and inherited socket identity;
Agent/Kernel filesystem boundaries and PID1 credential delivery; automatic payment and
exact approval with deliberate retry; clean restart and forced-process recovery;
rejected invalid starts; and durable holds, signatures and signed receipts across
interrupted signing, interrupted paid retry, unresolved payment, and charged failure.
Each monetary scenario uses fresh synthetic authority. The fixture key is public and
must never receive funds. No customer CDP/RPC values are supplied or live adapters loaded.

The profile renders `IPAddressDeny=any` and `IPAddressAllow=localhost`, and the inspector
checks the effective properties. Those properties alone are not a network-denial test.
The workflow does not establish reboot recovery or recreate `/run` state across a VM
reboot. No passing installed-host run is recorded by this documentation; a local pass
or skipped test cannot supply one.

Only `manifest.json`, `events.jsonl`, and `summary.json` in
`/opt/wallet-kernel-qualification/report` are uploaded. These public files contain
bounded lifecycle observations and public projections, not environment files,
credentials, private keys, payment headers, SQLite files, or raw service logs. The
workflow runs `scripts/verify-lifecycle-evidence.mjs` against the expected commit and
retains the artifacts for 30 days. Review the run conclusion and retained artifacts
together; an uploaded failure report is not successful qualification. The evidence
scope remains `installed-offline-qualification`, with live CDP and testnet transactions
`not-run` and public release `not-qualified`.

The final workflow step invokes `scripts/cleanup-systemd-qualification.mjs` with
`--deployment <release>/deployment.json` and the pinned Node executable. This helper accepts only
the exact disposable profile/paths and verifies installed unit bytes, PID1 fragment
paths and commands before acting. It attempts socket stop, service stop, and socket
disable independently, then waits for no jobs, no service process, a disabled inactive
socket, and closed TCP/admin listeners. It deletes only the verified unit files after
quiescence and reloads PID1. Failed ownership or quiescence checks retain the unit
files; any cleanup error fails the step. The helper never deletes unrelated units
or accounts. The VM, fixture state and dedicated accounts may then be discarded as
a whole.

This job prepares evidence for the installed-host prerequisite. It does not remove
`LIVE_LAUNCH_NOT_READY`, authorize a funded run, or satisfy the separately human-gated
Base Sepolia runner and evidence requirements in section 14.

## 11. Agent enrollment, policy, and credential handling

Never put a raw Agent credential in the Kernel `.env`, enrollment inbox, database,
logs, receipts, evidence, or Operator output. The Kernel must remain unable to open its
Pi-owned `0700` parent.

Under the Pi identity, create or reuse the owner-only credential and exclusive-create
the non-secret descriptor:

```bash
node src/agent/credential-cli.mjs init \
  --credential /absolute/pi-private/agent-credential.json \
  --enrollment /absolute/enrollment-inbox/agent-enrollment.json
```

The command prints only the descriptor's `sha256:...` digest. Confirm that digest by a
separate trusted channel. With the Kernel environment already installed and no daemon
holding the authority lock, use the Operator CLI:

```bash
npm run operator -- preflight --json
npm run operator -- agent enroll /absolute/enrollment-inbox/agent-enrollment.json \
  --confirm sha256:<descriptor-digest> --json
npm run operator -- policy validate /absolute/operator-input/policy.json --json
npm run operator -- policy apply /absolute/operator-input/policy.json \
  --confirm sha256:<policy-digest> --json
npm run operator -- isolation attest /absolute/kernel-staging/isolation-report.json \
  --confirm sha256:<report-digest> --json
```

Each mutating bootstrap command acquires the bootstrap authority lock, opens the
persistent receipt signer, performs full integrity/recovery/receipt-parity checks, and
only then applies its one mutation. Never edit SQLite directly.

Restarting with the same active credential and unchanged PolicyVersion reuses the
existing Agent binding, Spend Session, pending intent, and approval state. Startup does
not create a replacement session merely because the process restarted.

For ordinary planned replacement, first guarded-close the active Spend Session, then
revoke the current enrollment with its displayed hashes:

```bash
npm run operator -- sessions close <session-id> \
  --confirm sha256:<expected-session-hash> --json
npm run operator -- agent revoke <agent-instance-id> \
  --confirm sha256:<expected-enrollment-hash> --json
```

If unresolved money makes close unsafe, revoke first, remain in operator-only recovery,
reconcile and close, then stop and replace. In either case, quiesce the host exactly as
described in section 13 before creating a second credential. A replacement requires a
new descriptor confirmation, enrollment import, policy/config validation, and fresh
isolation report; it never silently rotates a token inside an existing binding.

CDP credentials are human-provisioned secrets. The required names are
`CDP_API_KEY_ID`, `CDP_API_KEY_SECRET`, `CDP_WALLET_SECRET`, and `CDP_WALLET_NAME`.
The installed composition obtains its inert environment input through PID1's fixed
credential copy, opened after the Kernel identity and release checks. The live profile
remains blocked and the qualification workflow uses only synthetic values. For a
future authorized CDP deployment, provision the external owner-only source described
in section 9; do not populate an improvised environment or paste values into shell
history, chat, unit files, release manifests, run
descriptors, evidence, or tracked files. `CDP_WALLET_NAME` must resolve to the same
customer-owned wallet address pinned by the active PolicyVersion. Funding that wallet
with Base Sepolia test USDC is a human action; the software never invokes a faucet or
transfers funds to satisfy a preflight.

## 12. Operator procedures

The Operator token is an independent 32-byte base64url bearer stored as a regular
`0600` file in the Kernel-owned `0700` authority parent. It is read locally and never
printed. In `cdp-testnet`, the admin CLI sends it only over the Kernel-owned `0600` Unix
socket. Deterministic development uses the fixed loopback operator endpoint and must
remain labeled simulated.

### Console startup and launch

For a future live release, the order before service start is exact:

```bash
systemctl daemon-reload
systemctl enable wallet-kernel-console.socket
# Run the privileged effective-config inspection and compare its hash.
systemctl start wallet-kernel-console.socket
```

Then `npm run operator -- console launch` asks the Unix admin API for a one-time URL.
The bearer travels only in the URL fragment, which browsers do not send in HTTP. The
root-owned socket-activated loopback listener supplies the Kernel's inherited console
descriptor. Clean restarts preserve socket activation; failed starts or runtime faults
disable and stop it as described in section 13. Do not replace it with a self-bound
listener. Deterministic mode has a direct
loopback fallback for offline testing only.

### Approval and denial

```bash
npm run operator -- approvals list --state pending --json
npm run operator -- approvals approve <approval-id> \
  --confirm sha256:<expected-intent-hash> --json
npm run operator -- approvals deny <approval-id> \
  --confirm sha256:<expected-intent-hash> --reason OPERATOR_DENIED --json
```

The Agent request that creates the approval returns
`payment_approval_required` immediately. Do not add `Prefer: wait`, keep that request
connected, poll the Operator API from Pi, or automatically replay the application
request. After Operator approval, the Wielder deliberately repeats the exact
ordinary request, preferably reusing its `x-agent-call-id`. If Pi supplies a fresh call
ID, the Kernel atomically binds it as a correlation alias to the active exact
fingerprint before signing, so a same-ID response-loss replay cannot spend twice. Pi
never sends the approval ID, wallet identity, or payment authority.

Use only IDs and confirmation hashes from a fresh authenticated projection. Approval is
compare-and-swap, scoped to the exact intent, and bounded by its expiry. An expired
approval is not renewed or widened; the Agent must submit a fresh ordinary request with
a fresh call ID.

### Receipt and session observation

```bash
npm run operator -- receipts list --json
npm run operator -- receipts verify <receipt-id> --json
npm run operator -- export <session-id> \
  --output /absolute/operator-private/session-export.json --json
```

Exports exclusive-create an owner-only file and refuse overwrite or symlinks. Signed
receipt revisions are authoritative public outcomes; never infer a final outcome from
a candidate row or raw provider response.

### Reconciliation and refunds

For a payment, execution, or refund case, first obtain the current intent hash and case
hash from the authenticated Operator view. Then use the one matching operation:

```bash
npm run operator -- reconcile payment <intent-id> \
  --confirm sha256:<intent-hash> --confirm-case sha256:<case-hash> \
  --payment-transaction 0x<confirmed-transaction-hash> --json

npm run operator -- reconcile execution <intent-id> \
  --confirm sha256:<intent-hash> --confirm-case sha256:<case-hash> --json

npm run operator -- reconcile refund-observation <intent-id> \
  --confirm sha256:<intent-hash> --confirm-case sha256:<case-hash> \
  --refund-transaction 0x<confirmed-refund-transaction-hash> --json
```

The Base Sepolia observer is read-only. It checks finalized transaction/receipt facts,
exact asset, wallet, payee/source, amount, nonce, and seller attestations; it cannot
fund, sign, send, or execute a refund. A full refund becomes final only after the
seller-attested and on-chain facts agree with the durable original payment and the
Kernel emits the superseding signed receipt revision. Never retry an ambiguous refund
execution, accept caller-supplied proof as final, or release exposure from a pending
candidate. A demonstrably invalid payment or refund candidate may be abandoned only
with the current intent/case hashes and the explicit `reconcile abandon-candidate`
operation.

## 13. Shutdown, replacement, backup, and incidents

### Normal shutdown and restart

The control plane closes admission first, waits for in-flight unsigned work, preserves
all signed or ambiguous holds, closes Agent, console, and admin listeners in order,
closes SQLite, and releases the process-lifetime authority lock last. A normal restart
must run full recovery, event-chain and receipt-parity validation before reopening
admission. Do not delete a lock, socket, intent, or pending row to make startup pass.

`ExecStopPost` invokes the pinned Node cleanup helper. Only exact
`SERVICE_RESULT=success` preserves the enabled console socket so an ordinary
`systemctl restart wallet-kernel.service` can pass preflight again. A failed preflight,
failed start, runtime failure or `SIGKILL` independently attempts socket disable and
`stop --no-block`. Missing or malformed stop-phase status fails into cleanup. The
helper requests cleanup; the caller must still await an inactive/failed service with
`MainPID=0`, no jobs, and a disabled inactive socket. There is no automatic restart
loop or retained console listener after a fault. Explicit fault recovery re-enables
the socket and imports a fresh isolation attestation before starting again.

For maintenance or Agent replacement, prevent socket activation before stopping the
service:

```bash
systemctl disable --now wallet-kernel-console.socket
systemctl stop wallet-kernel.service
```

Verify the service is `inactive` or `failed` with `MainPID=0`, the socket is `inactive`
and `disabled`, both `Job` values are empty, no listener remains on `127.0.0.1:8402`,
`127.0.0.1:8405` or the configured Unix admin socket, and a role-`bootstrap`
authority-lock probe succeeds. Keep a connection storm running during the check; after
socket disablement, dropped Pi traffic must not reactivate the service or acquire the
authority lock. If any check fails, leave the socket disabled and the service stopped.

Restore the service only after replacement/bootstrap succeeds: `daemon-reload`, enable
the socket without starting it, verify the full PID1 effective projection, import a
fresh isolation attestation, start the socket, then start the service. There is no
failure path that silently resumes an old enrollment or policy binding.

### Offline backup and restore

Treat backup/restore as an offline SQLite authority operation:

1. Complete the maintenance quiesce above and prove the authority lock is available.
2. Use a trusted SQLite backup operation, or an exact file copy only after all Kernel
   connections are closed and SQLite has checkpointed its WAL. Do not copy a live
   database or omit live `-wal`/`-shm` state by guesswork.
3. Store the backup as sensitive authority data outside the checkout. Protect receipt
   signing keys and Operator credentials separately under the same security policy;
   never put them in the evidence bundle.
4. Restore to a newly provisioned Kernel-owned `0700` parent with exact `0600` file
   modes. Run SQLite `PRAGMA integrity_check`, then Kernel `preflight`, full semantic
   recovery, event-chain verification, receipt signature/parity verification, policy
   validation, and fresh isolation attestation before enabling the socket.

Never repair an incident by hand-editing the database. If integrity, semantic recovery,
or receipt parity fails, preserve the files, keep admission closed, and escalate the
exact stable error code.

### Incident decision points

- **Signing/payment ambiguity:** stop new admission, retain the full reservation, and
  use read-only Base Sepolia observation plus `reconcile payment`. Never create a new
  signature for the old intent or resend merely because a response was lost.
- **Execution-evidence ambiguity:** preserve the committed payment and response hold.
  Use `reconcile execution`; never invent output or a Royalty claim from transport
  failure details.
- **Seller-attested refund or on-chain refund ambiguity:** preserve the pending full
  exposure. Use `reconcile refund-observation` only when the independent seller and
  chain bindings are available. Never execute a second refund from an uncertain first
  attempt.
- **Credential compromise:** revoke immediately if necessary, restart in recovery-only
  mode, reconcile and close retained sessions, then follow the full quiesce and
  replacement sequence. Do not retain the compromised credential for convenience.
- **Authority corruption or missing receipt:** do not start listeners. Recovery may
  repair only the exact designed missing-receipt gap; all other corruption remains a
  blocked incident for preserved forensic review.

## 14. Human-gated Base Sepolia evidence

A qualifying testnet run is a separate human authorization event, not an environment
toggle. In this implementation,
`run-evidence.mjs --mode base-sepolia-testnet` deliberately exits 2 with canonical
`EVIDENCE_TESTNET_NOT_RUN`; there is no privileged Kernel-side live orchestration API
and no real adapter is constructed. Do not treat the separately testable Pi-side
descriptor runner as a complete testnet workflow.

A future reviewed Kernel-side runner must stop before constructing a real adapter
unless all of these are true at the same time:

- the root-owned release manifest/tree, exact commit, Node binary, both unit artifacts,
  and fresh PID1 effective-config hash reverify;
- network and asset equal Base Sepolia `eip155:84532` and its pinned USDC contract;
- the active PolicyVersion wallet equals the customer-owned CDP wallet;
- Operator preflight and the unexpired imported Agent isolation attestation are green;
- the read-only observer reports sufficient funds at a recorded block for the run
  intent's full `maximumTotalAtomic` amount;
- the output is a new `YYYY-MM-DD-agent-spend-control-RUN_ID` directory under the
  external Kernel-owned `0700` evidence root;
- the human supplies `--confirm-sha256` equal to the canonical run-intent digest.

Confirmation may not come from an environment variable. Insufficient or unavailable
funding exits before signing; the runner never faucets, funds, transfers, selects
mainnet, lowers the declared ceiling, overwrites an evidence directory, or writes into
the release/source tree.

After a future reviewed Kernel-side runner publishes the bounded `0644` descriptor in
the Kernel-owned outbox, the human separately invokes the Pi-side runner under the
enrolled Pi UID/GID:

```bash
node scripts/run-testnet-agent.mjs \
  --run-intent /absolute/kernel-run-outbox/run-intent.json \
  --confirm-sha256 sha256:<run-intent-digest>
```

That Pi-side process validates the single-open descriptor, Kernel ownership/mode/hash,
its own identity, the `0600` credential, exact routes, amount ceiling, and expiry. It
has no Operator token or CDP environment and emits no credential. A timeout leaves the
run incomplete/`not-run`; it does not weaken policy or imply success.

Every completed evidence directory is immutable. Verify it against the out-of-band
manifest anchor before any optional human-reviewed copy into the repository. A public
website reframe remains gated on fresh qualifying testnet evidence; the quarantined
2026-07-15 n=48 aggregate cannot satisfy that gate because normalized per-call samples
were not retained.

The following remain unqualified: an actual passing installed Linux lifecycle run,
PID1 credential delivery on that host, and live CDP payment with retained Base Sepolia
evidence. Mainnet, real funds, custody, hosted policy authority, automated funding, and
public commercialization claims based only on offline evidence remain outside scope.
