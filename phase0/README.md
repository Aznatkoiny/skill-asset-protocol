# Phase 0 — wallet-attested Story registration

This testnet demo proves `wallet_asserted` registration and declared Derivative
ancestry. It does not prove authorship, originality, repository control, or
safety.

From a prepared Story Aeneid wallet, one command creates an SPG NFT collection,
registers a base **Skill**, and registers two declared Derivatives:

```bash
cd phase0
npm install
cp .env.example .env        # add a throwaway testnet key and Pinata JWT
npm run check
npm run demo
```

The committed `registrations.json` remains honestly `status: "not-run"` until a
human completes the real testnet prerequisites and runs the demo. Automated
tests use injected fakes and do not read a wallet key, contact Pinata or Story,
wrap IP, approve WIP, or submit a transaction.

## Registration evidence

The confirmed sequence is:

1. create an SPG NFT collection;
2. register the base Skill with commercial-remix PIL terms and a configured
   `0.001 WIP` minting-fee estimate;
3. register a declared Derivative of that Skill;
4. register a second-level Derivative whose parent is the first Derivative.

Every registration hashes the committed `SKILL.md` artifact bytes. The evidence
artifact records the Aeneid network, connected wallet, SPG collection, confirmed
transaction hashes, event-derived IP IDs and license fields, declared parent
edges, fee caps, and exact metadata URI/hash pairs. These are wallet and chain
facts, not proof that the wallet authored the artifacts.

## Offline attestation sidecar

Registration remains immutable. Optional evidence is recorded in the local,
ignored `attestations.jsonl` append-only sidecar and rendered at one of three
levels:

1. `wallet_asserted`: a wallet registered these bytes and declared this
   ancestry;
2. `repository_control_verified`: a wallet signature and matching bytes were
   verified against a trusted forge observation and verifier-provisioned Git
   snapshot;
3. `organization_approved`: a named, allow-listed organization signer approved
   the Skill and Creator relationship.

Safety review is a separate status. Duplicate artifact bytes registered by
different wallets produce a visible deterministic conflict; no arrival order
chooses an owner. Challenge openings must be signed by the existing challenger
registration wallet. Resolution and revocation bundles must be pre-signed by an
admin listed in `attestation-admins.json`. Revocation removes only the named
higher evidence level and does not delete registration, event, conflict, or
chain history. The `wallet_asserted` confirmed-proof floor cannot be created or
revoked through the sidecar.

Signed repository, organization, challenge, resolution, and revocation
statements use domain-separated `v2` canonical JSON with fixed key order and
real JSON arrays. Free-text fields and URI arrays are never newline- or
comma-joined, so delimiter redistribution cannot preserve a signature while
changing semantics. Event timestamps must be nondecreasing. Organization
approval must follow active repository evidence and precede its event envelope;
resolution must follow a signed challenge; revocation must follow the active
evidence it removes.

A repository statement hash, challenge nonce, wallet signature, and bound forge
observation are single-use credentials across the entire log. An organization
statement hash and signature are also single-use. Revocation does not make an
old credential reusable under a fresh event ID or sequence. Reactivation
requires genuinely fresh signed evidence, not merely a later event envelope.
After a repository-level revocation, both the wallet-signed challenge's
`issuedAt` and the forge observation's `observedAt` must be strictly later than
the latest repository revocation. After an organization-level revocation, or a
repository revocation that cascades to organization evidence, the new
organization approval's signed `approvedAt` must be strictly later than that
latest revocation cutoff.

Inspect evidence without a network or chain write:

```bash
npm run attestation-status -- --artifact-hash 0x<64-lowercase-hex> --json
npm run attestation-status -- --registration-id eip155:1315:0x<40-lowercase-hex>
npm run attestation-conflicts -- --json
```

Append only fully signed, offline-verifiable bundles:

```bash
npm run attestation-verify-repository -- --bundle /absolute/path/repository-bundle.json
npm run attestation-verify-organization -- --bundle /absolute/path/organization-event.json
npm run attestation-append-challenge -- --bundle /absolute/path/challenge-event.json
npm run attestation-resolve -- --bundle /absolute/path/resolution-event.json
npm run attestation-revoke -- --bundle /absolute/path/revocation-event.json
```

Repository bundles contain the wallet-signed challenge and the forge
observation. They do not accept a repository path, trusted ref, public key, or
trust-root override. `repository-trust.json` fixes the repository URL, checkout
key, trusted ref, and allowed forge signer IDs. Public forge keys live in
`forge-signers.json`; both trust-root files are empty by default.

The verifier resolves each checkout key through the machine-local file
`phase0/.attestation-checkouts.local.json`:

```json
{
  "schemaVersion": 1,
  "checkouts": {
    "example-checkout-key": "/canonical/absolute/path/to/verifier-checkout"
  }
}
```

The file must be a non-symlink regular file owned by the current user with mode
`0600` (`chmod 600 phase0/.attestation-checkouts.local.json`). Every checkout
must already be its canonical absolute real path, be owned by the current user,
and not be group- or world-writable. An optional absolute
`PHASE0_ATTESTATION_CHECKOUTS_FILE` may point outside the repository; an
in-repository override must equal the exact ignored default path. Missing
configuration fails with `repository snapshot mapping unavailable` before Git
runs. This machine-local mapping must never be staged, copied into a bundle, or
used as claimant evidence.

The verifier invokes the fixed absolute `/usr/bin/git` executable with a minimal
allow-listed environment. It does not inherit `PATH`, `GIT_DIR`,
`GIT_WORK_TREE`, object-directory, namespace, or config-injection variables.
Global and system config are disabled, replacement objects are ignored, all
protocol transports are disabled, and lazy fetching is disabled. Missing local
objects therefore fail offline rather than contacting a promisor remote.

At mapping load, the verifier pins the checkout directory's device and inode.
It reopens and compares that identity before, between, and after external Git
operations. This detects ordinary checkout-path replacement, but the spike
cannot portably keep one directory file descriptor bound across every external
Git process. Directory identity also does not freeze in-place changes to the
checkout's refs, object database, configuration, or worktree. A privileged
same-machine attacker capable of changing those contents, or of replacing and
restoring the path inside a single check-to-exec interval, remains a residual
local-verifier risk. Production hardening would require a platform-specific
descriptor-bound execution boundary or an isolated immutable snapshot.

`repository_control_verified` means a trusted forge observer and a
verifier-provisioned Git snapshot matched the wallet-signed bytes at an
observation time. It does not prove current remote account ownership or
continuing hosting.

An attestation records evidence about who made or approved a registration. It
does not prove originality, legal ownership, absence of prior art, or Skill
safety. Safety review is a separate status.

The local sidecar uses an owner-only lock and exact-token stale recovery. Inspect
the printed lock metadata and prove its PID is absent before running:

```bash
npm run attestation-recover-lock -- --lock-token <exact-token>
```

Before broadcast, the demo signs the transaction locally and atomically saves
its hash, serialized testnet transaction, and canonical operation intent to the
mode-0600, ignored `pending-transactions.json`. The whole demo holds an exclusive
same-host journal lease and updates it with compare-and-swap revisions. A rerun
validates the journal-bound intent and prerequisite proofs, reconciles or
rebroadcasts the exact persisted bytes and hash without a Pinata or funding read,
waits for that same hash, saves confirmed evidence from persisted metadata, and
only then clears the matching journal revision. Only after recovery does it
compare the current local run configuration and permit another prepare.

Never delete `pending-transactions.json`, its `.lock`, or a `.claim` file merely
to force progress. An intent/config mismatch or unresolved/replaced nonce
requires operator investigation. A stale lock may be recovered only on the same
host, for a PID proven absent, while the recorded lease remains byte-for-byte
unchanged. Copy the exact lease ID printed by the lock error:

```bash
npm run recover-stale-lock -- <expectedLeaseId>
```

There is no force flag, timeout deletion, or automatic lease-ID discovery.

## Durable metadata boundary

Metadata defaults to public IPFS pinning. Pinata credentials and any wallet key
remain local. The JWT-bearing upload URL is fixed to
`https://uploads.pinata.cloud/v3/files`, redirects are disabled, and public
gateway verification requests never carry the JWT or follow redirects.

Stage-specific URI overrides must be supplied in complete IP/NFT pairs. They
must use the exact configured, allow-listed Pinata gateway origin, contain the
exact `/ipfs/<cid>` path, and return byte-identical content. The only allowed
gateway hosts are `gateway.pinata.cloud` and HTTPS subdomains of
`mypinata.cloud`, with no port, credentials, query, or fragment. Every metadata
document is serialized once, hashed, fetched, and byte-compared before a new
transaction is prepared.

## Native gas and WIP are separate prerequisites

Run `npm run check` before each human testnet step. It reports pending recovery,
remaining new writes, native-IP gas readiness, and—only when the next missing
write is a Derivative—the WIP balance, allowance, and exact spender. It never
uploads metadata, wraps IP, approves WIP, signs, broadcasts, reconciles, or
clears a transaction.

The native-IP minimum is a conservative preflight estimate, not a guarantee of
final gas use. There is no validated per-stage gas allocation, so any positive
number of remaining writes retains the full four-write envelope; zero remaining
writes requires zero and performs no balance or gas-price read.

Derivative minting fees use WIP, not native IP. The displayed `0.001 WIP` is a
configured estimate, not a substitute for the per-parent on-chain prediction
performed immediately before each new Derivative prepare. Because the crash-safe
path requests `encodedTxDataOnly`, the Story SDK does not perform its normal
automatic IP-to-WIP wrapping or WIP approval. Before a real testnet demo, a
human must use supported Story testnet tooling to wrap sufficient IP to WIP and
approve the exact `DerivativeWorkflows` spender.

On a clean `not-run` manifest, collection is next, so `npm run check` correctly
performs no WIP read and prints that the WIP domain is not yet applicable. The
staged operator flow is:

1. verify native gas with `npm run check`;
2. run `npm run demo`; it may confirm and persist the collection and root, then
   fails closed before preparing the child when WIP is not ready;
3. run `npm run check` again, now with child next, to print the exact spender,
   WIP balance, and allowance;
4. complete the human testnet wrap and approval, rerun `npm run check`, and only
   then resume `npm run demo`.

The demo predicts the current fee and rechecks WIP balance and allowance before
each new Derivative prepare. A matching signed Derivative already in the journal
is recovered without those reads because it may already have consumed the funds.
The prerequisite wrap and approval transactions are not journaled by this demo.

Funding remains a human action. Obtain test IP only from the Story Aeneid faucet:
<https://aeneid.faucet.story.foundation/>.

## Network boundary

This code rejects any chain other than **Story Aeneid testnet, chain ID 1315**
and never targets mainnet or real funds. The PRD Phase-0 success criterion names
Story mainnet, chain ID 1514, and requires broader evidence. Aeneid registration
evidence does not satisfy that criterion.

## Local verification

```bash
npm test
npm run typecheck
```

The suite uses injected filesystem, HTTP, RPC, and SDK boundaries and requires
no network, wallet key, Pinata credential, WIP operation, or transaction.
