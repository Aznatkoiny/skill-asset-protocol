# Authorship Attestation and Registration Conflicts Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an offline-verifiable attestation sidecar that distinguishes wallet assertion, repository control, and organization approval; exposes duplicate-byte conflicts; and preserves challenge, resolution, and revocation history without claiming originality or safety.

**Architecture:** Keep Story registration immutable and unchanged, then add an append-only local JSONL attestation log keyed by registration IP ID and artifact SHA-256. A deterministic async reducer derives levels and conflicts only after verifying wallet, organization, challenger, resolver, and revoker signatures against verifier-provisioned trust roots. Repository evidence resolves a signed repository URL through verifier-controlled configuration to a pre-provisioned local checkout and trusted ref; claimant-supplied checkout paths or refs are never trust inputs. CLI output states this local-verifier trust assumption and uses `wallet_asserted` as the floor; no level is called remote-host ownership, originality, or safety proof.

**Tech Stack:** TypeScript 5.6, Node.js 22, built-in `node:test`, `viem` message signing/verification, Git CLI read operations, append-only JSONL.

---

## File map

- Create `phase0/src/attestations.ts` — event schemas, canonical statements, signature verification, reducer, duplicate/conflict derivation, revocation.
- Create `phase0/src/attestation-store.ts` — append-only JSONL store with fsync-safe writes and full-log validation.
- Create `phase0/src/attestation-git.ts` — injected Git reader and offline repository-control verifier.
- Create `phase0/src/attestation-config.ts` — strict loader for the ignored local checkout-path mapping used by production CLI verification.
- Create `phase0/src/attestation-cli.ts` — CLI command handlers with machine-readable JSON output.
- Create `phase0/tests/attestations.test.ts` — level, signature, conflict, dispute, and revocation tests.
- Create `phase0/tests/attestation-store.test.ts` — append-only persistence and malformed-log tests.
- Create `phase0/tests/attestation-git.test.ts` — local Git commit and exact-byte verification tests.
- Modify `phase0/src/index.ts` — add read-only/attestation commands without adding a chain write.
- Modify `phase0/package.json` — add command aliases.
- Modify `phase0/README.md` — replace authorship/provenance overclaims with evidence-level language and document offline workflow.
- Create `phase0/attestations.jsonl` — empty tracked sidecar with no fabricated events.
- Create `phase0/organization-signers.json` — committed public trust-root allow-list, initially empty.
- Create `phase0/attestation-admins.json` — committed resolver/revoker wallet trust roots, initially empty.
- Create `phase0/repository-trust.json` — committed normalized repository allow-list and trusted-ref identifiers, initially empty; checkout paths are verifier-provisioned separately.
- Create `phase0/forge-signers.json` — verifier-provisioned forge-observer public keys, initially empty.
- Modify `.gitignore` — unignore the intentionally tracked empty attestation log and ignore only the local checkout-path mapping; never ignore tracked trust-root files.

## Public schema and semantics

```ts
export type AttestationLevel =
  | "wallet_asserted"
  | "repository_control_verified"
  | "organization_approved";

export type AttestationStatus = "active" | "challenged";
export type SafetyReviewStatus = "not_reviewed" | "pending" | "approved" | "rejected";

export interface RegistrationSubject {
  registrationId: `eip155:1315:${string}`;
  ipId: `0x${string}`;
  wallet: `0x${string}`;
  artifactHash: `0x${string}`;
  declaredParentIpIds: `0x${string}`[];
}

export interface RepositoryControlChallengeV1 {
  schemaVersion: 1;
  subject: RegistrationSubject;
  repositoryUrl: string;
  artifactCommitSha: string;
  artifactPath: string;
  challengePath: string;
  nonce: `0x${string}`;
  issuedAt: string;
  expiresAt: string;
}

export interface OrganizationApprovalV1 {
  schemaVersion: 1;
  subject: RegistrationSubject;
  organizationId: string;
  approverWallet: `0x${string}`;
  role: "ip_admin" | "engineering_executive";
  approvedAt: string;
  statementHash: `0x${string}`;
  signature: `0x${string}`;
}

export interface ForgeObservationV1 {
  schemaVersion: 1;
  repositoryId: string;
  repositoryUrl: string;
  trustedRef: `refs/heads/${string}` | `refs/remotes/${string}`;
  proofCommitSha: string;
  challengeNonce: `0x${string}`;
  observedAt: string;
  forgeSignerId: string;
  signature: string;
}
```

The canonical repository-control statement is UTF-8 with a final newline and fields in this exact order:

```text
skill-asset-protocol/repository-control/v1
registration=<CAIP-10 registration ID>
ipId=<lowercase address>
wallet=<lowercase address>
artifactSha256=<lowercase 0x-prefixed SHA-256>
repository=<normalized HTTPS repository URL without trailing slash>
artifactCommit=<lowercase full commit SHA containing the registered artifact bytes>
artifactPath=<normalized relative POSIX path>
challengePath=<normalized relative POSIX path>
nonce=<lowercase 0x-prefixed 32-byte nonce>
issuedAt=<UTC ISO-8601>
expiresAt=<UTC ISO-8601>
```

The challenge file committed at `challengePath` contains the challenge object,
`statementHash`, and the EIP-191 wallet signature. It intentionally does not contain
its own proof commit hash: that would be self-referential. A verifier-provisioned forge
observer later signs `ForgeObservationV1`, binding the normalized repository URL,
configured ref, exact proof commit OID, wallet challenge nonce, and observation time.
The claimant may transport that observation but cannot choose its signer, checkout, or
ref. The verifier resolves `repositoryId` and URL through its own allow-list to a
pre-provisioned checkout, trusted ref, and permitted forge signer; neither path nor ref
is read from claimant CLI arguments. Verification requires:

1. `git cat-file -e <artifactCommit>^{commit}` and `git cat-file -e <proofCommit>^{commit}` succeed;
2. the forge observation's Ed25519 signature verifies against the configured forge signer and all URL/ref/nonce/OID bindings match;
3. the checkout's normalized `origin` URL equals the two signed `repositoryUrl` values;
4. `artifactCommitSha` is an ancestor of `proofCommitSha`;
5. `proofCommitSha` equals the forge-observed OID and is reachable from the configured trusted ref;
6. `git show <artifactCommit>:<artifactPath>` hashes to `subject.artifactHash`;
7. `git show <proofCommit>:<challengePath>` is byte-identical to the supplied signed challenge file;
8. `verifyMessage` recovers `subject.wallet` from the canonical statement;
9. the challenge was valid at `observedAt`, and `occurredAt` is not earlier than that observation.

The forge observation canonical order is `schemaVersion, repositoryId, repositoryUrl,
trustedRef, proofCommitSha, challengeNonce, observedAt, forgeSignerId`; its Ed25519
signature is base64 over canonical UTF-8 JSON. This establishes only that a trusted
forge observer reported that commit OID on that configured remote ref at the stated
time, and that a wallet signed matching artifact evidence contained in the exact
commit. Trust in the forge observer remains explicit. It does not prove current forge
account ownership, continuing remote hosting, originality, legal ownership, or safety.

The canonical organization-approval statement is also UTF-8 with a final newline and
uses this exact order:

```text
skill-asset-protocol/organization-approval/v1
registration=<CAIP-10 registration ID>
ipId=<lowercase address>
wallet=<lowercase address>
artifactSha256=<lowercase 0x-prefixed SHA-256>
declaredParentIpIds=<sorted comma-separated lowercase addresses, empty when none>
organizationId=<normalized lowercase organization identifier>
approverWallet=<lowercase address>
role=<ip_admin or engineering_executive>
approvedAt=<UTC ISO-8601>
```

`statementHash` is the lowercase `0x`-prefixed Keccak-256 of those bytes. The EIP-191
signature must recover `approverWallet`, and that wallet must appear in the injected
allow-list for `organizationId`. A signature from a self-declared but unlisted wallet
does not create `organization_approved`.

The repository-control `statementHash` uses the same lowercase `0x`-prefixed
Keccak-256 convention over its canonical statement bytes.

The append-only event union is:

```ts
export type AttestationEvent =
  | { type: "repository_control_verified"; eventId: string; sequence: number; occurredAt: string; subject: RegistrationSubject; challenge: RepositoryControlChallengeV1; forgeObservation: ForgeObservationV1; statementHash: `0x${string}`; signature: `0x${string}` }
  | { type: "organization_approved"; eventId: string; sequence: number; occurredAt: string; subject: RegistrationSubject; approval: OrganizationApprovalV1 }
  | { type: "challenge_opened"; eventId: string; sequence: number; occurredAt: string; conflictId: string; challengedRegistrationId: string; challengerRegistrationId: string; challengerWallet: `0x${string}`; evidenceUris: string[]; reason: "duplicate_bytes" | "misattributed_creator" | "unauthorized_registration"; statementHash: `0x${string}`; signature: `0x${string}` }
  | { type: "challenge_resolved"; eventId: string; sequence: number; occurredAt: string; conflictId: string; outcome: "upheld" | "rejected" | "inconclusive"; rationale: string; adminSignerId: string; statementHash: `0x${string}`; signature: `0x${string}` }
  | { type: "attestation_revoked"; eventId: string; sequence: number; occurredAt: string; registrationId: string; level: Exclude<AttestationLevel, "wallet_asserted">; reason: string; adminSignerId: string; statementHash: `0x${string}`; signature: `0x${string}` };
```

`safetyReviewStatus` is always stored and rendered separately; no attestation event changes it.

Challenge-opening signatures use EIP-191 and must recover the wallet of the existing
`challengerRegistrationId`. Resolution and revocation signatures use EIP-191 and must
recover the wallet provisioned for `adminSignerId`. Canonical signed field order is:

```text
challenge_opened: eventId, sequence, occurredAt, conflictId,
challengedRegistrationId, challengerRegistrationId, challengerWallet,
sorted evidenceUris, reason

challenge_resolved: eventId, sequence, occurredAt, conflictId, outcome, rationale,
adminSignerId

attestation_revoked: eventId, sequence, occurredAt, registrationId, level, reason,
adminSignerId
```

Each message begins with
`skill-asset-protocol/<event-type-with-hyphens>/v1\n`; `statementHash` is Keccak-256
of those canonical UTF-8 bytes. Unsigned events, embedded admin keys, unknown admins,
and signatures made by another wallet fail before reduction or append.

### Task 1: Define and reduce the append-only attestation model

**Files:**
- Create `phase0/src/attestations.ts`
- Create `phase0/tests/attestations.test.ts`

- [ ] **Step 1: Write failing reducer tests**

Use runtime-generated viem accounts (`generatePrivateKey()` in the test process) and assert:

```ts
const walletState = await reduceAttestationEvents([], { baseSubjects: [SUBJECT] });
assert.equal(walletState.registrations[REGISTRATION_ID].level, "wallet_asserted");
assert.equal(walletState.registrations[REGISTRATION_ID].claim, "wallet registered these bytes and declared this ancestry");
assert.equal(walletState.registrations[REGISTRATION_ID].safetyReviewStatus, "not_reviewed");

const verifiedState = await reduceAttestationEvents(
  [repositoryVerified],
  { baseSubjects: [SUBJECT], repositoryVerifier: TEST_REPOSITORY_VERIFIER }
);
assert.equal(verifiedState.registrations[REGISTRATION_ID].level, "repository_control_verified");

const revokedState = await reduceAttestationEvents(
  [repositoryVerified, revoked],
  {
    baseSubjects: [SUBJECT],
    repositoryVerifier: TEST_REPOSITORY_VERIFIER,
    adminSigners: ADMIN_SIGNERS
  }
);
assert.equal(revokedState.registrations[REGISTRATION_ID].level, "wallet_asserted");
assert.equal(revokedState.registrations[REGISTRATION_ID].status, "active");
assert.equal(revokedState.registrations[REGISTRATION_ID].revocations.at(-1).level, "repository_control_verified");

const baseSubjects = registrationSubjectsFromManifest(CONFIRMED_MANIFEST);
const baselineState = await reduceAttestationEvents([], { baseSubjects });
assert.equal(baselineState.registrations[REGISTRATION_ID].level, "wallet_asserted");
```

Add tests proving a `not-run` manifest yields no base subject, an attempted sidecar
event with `type: "wallet_asserted"` is structurally rejected, and rejecting
non-contiguous sequence, duplicate event ID, level escalation without prerequisite,
organization signer not in the passed allow-list, valid signature from the wrong
wallet, modified organization statement after signing, fabricated or tampered
repository event signature/statement hash, subject drift for one registration ID,
malformed hashes/addresses/URLs, and any display claim containing `authored by`,
`original`, or `safe`.
Explicitly assert a correctly wallet-signed repository event still fails with
`repository verifier context required` when the reducer is called without the injected
repository verifier; structural and wallet verification alone may not upgrade level.

Generate challenger and admin wallets at runtime. Assert an unsigned challenge, a
challenge signed by a wallet other than the challenger registration wallet, an
unsigned resolution/revocation, a self-declared admin wallet, an unknown admin ID, and
a tampered rationale/reason all fail without changing derived state. A valid admin
signature succeeds only when its signer ID resolves through the injected admin map.
Add a signed `attestation_revoked` event targeting `wallet_asserted` and require
structural rejection before admin-signature verification. Revoking repository or
organization evidence may downgrade the derived level and append revocation history,
but the confirmed-proof floor and base subject remain active and immutable.

- [ ] **Step 2: Run and verify red**

Run: `cd phase0 && node --import tsx --test tests/attestations.test.ts`

Expected: FAIL with `ERR_MODULE_NOT_FOUND` for `src/attestations`.

- [ ] **Step 3: Implement the schema, canonicalization, and reducer**

Export these exact entry points:

```ts
export function parseAttestationEvent(value: unknown): AttestationEvent;
export function canonicalRepositoryStatement(challenge: RepositoryControlChallengeV1): string;
export function repositoryStatementHash(challenge: RepositoryControlChallengeV1): `0x${string}`;
export function verifyRepositoryEventSignature(event: Extract<AttestationEvent, { type: "repository_control_verified" }>): Promise<void>;
export function canonicalOrganizationStatement(approval: Omit<OrganizationApprovalV1, "statementHash" | "signature">): string;
export function organizationStatementHash(approval: Omit<OrganizationApprovalV1, "statementHash" | "signature">): `0x${string}`;
export function verifyOrganizationApproval(approval: OrganizationApprovalV1, organizationSigners: Readonly<Record<string, readonly `0x${string}`[]>>): Promise<void>;
export function canonicalChallengeEventStatement(event: Extract<AttestationEvent, { type: "challenge_opened" }>): string;
export function canonicalAdminEventStatement(event: Extract<AttestationEvent, { type: "challenge_resolved" | "attestation_revoked" }>): string;
export function verifyChallengeEventSignature(event: Extract<AttestationEvent, { type: "challenge_opened" }>, subjects: Readonly<Record<string, RegistrationSubject>>): Promise<void>;
export function verifyAdminEventSignature(event: Extract<AttestationEvent, { type: "challenge_resolved" | "attestation_revoked" }>, adminSigners: Readonly<Record<string, `0x${string}`>>): Promise<void>;
export function registrationSubjectsFromManifest(manifest: RegistrationManifest): RegistrationSubject[];
export function reduceAttestationEvents(events: readonly AttestationEvent[], trust?: { organizationSigners?: Readonly<Record<string, readonly `0x${string}`[]>>; adminSigners?: Readonly<Record<string, `0x${string}`>>; baseSubjects?: readonly RegistrationSubject[]; repositoryVerifier?: (event: Extract<AttestationEvent, { type: "repository_control_verified" }>) => Promise<void> }): Promise<AttestationIndex>;
export function displayAttestation(index: AttestationIndex, registrationId: string): {
  level: AttestationLevel;
  status: AttestationStatus;
  claim: string;
  safetyReviewStatus: SafetyReviewStatus;
  warnings: string[];
};
```

`registrationSubjectsFromManifest` maps each confirmed `RegistrationProof` to
`registrationId = eip155:1315:<lowercase ipId>`, the manifest wallet, the artifact
`mediaHash`, and its declared parent IP IDs. It returns no subject for a `null` stage.
`reduceAttestationEvents` seeds every `trust.baseSubjects` entry at `wallet_asserted`, then
structurally parses every sidecar event, awaits `verifyRepositoryEventSignature`
and the required `trust.repositoryVerifier` before applying a repository event, and
awaits `verifyOrganizationApproval` before
applying an organization event. It verifies challenge openings against the existing
challenger subject wallet and resolution/revocation against `trust.adminSigners` before
changing conflict or attestation state. Repository-event signature verification recomputes
the canonical statement hash, requires `event.subject` to equal
`event.challenge.subject`, and recovers the subject wallet; it does not claim to repeat
the stronger Git ancestry/reachability checks without a checkout. Level precedence
is `organization_approved > repository_control_verified > wallet_asserted`, but
revocation removes only the named level and all dependent higher levels.
The reducer never accepts `wallet_asserted` as a sidecar event: only confirmed
`RegistrationProof` values mapped through `registrationSubjectsFromManifest` can
establish the base level. A local JSONL writer therefore cannot invent a registration
or a duplicate conflict by appending an unsigned base assertion.
It also never accepts `wallet_asserted` as a revocation target. A higher-level
revocation records `{ level, eventId, occurredAt, reason }` in a frozen `revocations`
array, downgrades to the strongest remaining evidence, and preserves the registration
status implied by open challenges; absent a challenge, the confirmed base remains
`active` rather than `revoked`.
`displayAttestation` uses only these claims:

```text
wallet_asserted: wallet registered these bytes and declared this ancestry
repository_control_verified: wallet signature and matching bytes were verified against a trusted forge observation and verifier-provisioned Git snapshot
organization_approved: named organization signer approved the Skill and Creator relationship
```

Every display includes `Safety review: <status>; authorship attestation does not prove safety.`
It also includes `Repository evidence relies on the named forge observer and snapshot;
it does not prove current remote account ownership or continuing hosting.` whenever the
repository level is active.

If any repository event exists and `repositoryVerifier` is absent, reduction throws
`repository verifier context required`. No exported reducer path may derive
`repository_control_verified` from structural parsing or wallet signature alone.

- [ ] **Step 4: Run the reducer tests**

Run: `cd phase0 && npm test && npm run typecheck`

Expected: PASS; existing registration tests remain green.

- [ ] **Step 5: Commit the model slice**

```bash
git add phase0/src/attestations.ts phase0/tests/attestations.test.ts
git commit -m "feat: model explicit registration attestation levels"
```

### Task 2: Detect duplicate bytes and preserve conflict/dispute history

**Files:**
- Modify `phase0/src/attestations.ts`
- Modify `phase0/tests/attestations.test.ts`

- [ ] **Step 1: Add failing duplicate/conflict tests**

Create two confirmed-manifest base subjects with the same `artifactHash` and different
wallets/registration IDs. Seed them through `baseSubjects`; do not fabricate sidecar
events for the base level. Assert one deterministic conflict:

```ts
const index = await reduceAttestationEvents([], { baseSubjects: [firstSubject, secondSubject] });
assert.deepEqual(index.conflicts, [{
  conflictId: deterministicConflictId(firstSubject, secondSubject),
  artifactHash: ARTIFACT_HASH,
  registrationIds: [FIRST_ID, SECOND_ID].sort(),
  status: "open",
  reason: "duplicate_bytes",
  outcome: null
}]);
assert.equal(index.registrations[FIRST_ID].status, "challenged");
assert.equal(index.registrations[SECOND_ID].status, "challenged");
```

Assert a later registrant never displaces the earlier record, an admin-signed resolution
appends an outcome without deleting either registration, and an admin-signed
revocation leaves all historical events visible. Unsigned equivalents fail closed.

- [ ] **Step 2: Run the duplicate tests and verify red**

Run: `cd phase0 && node --import tsx --test --test-name-pattern='duplicate|conflict|challenge|revocation' tests/attestations.test.ts`

Expected: FAIL because conflict derivation is not implemented.

- [ ] **Step 3: Implement deterministic conflicts**

Export `deterministicConflictId(a, b)` as `sha256:` plus SHA-256 of the sorted registration IDs joined by `\n`. `reduceAttestationEvents` must index all subjects by artifact hash, derive a pairwise conflict for different wallets, merge explicit challenge events by `conflictId`, and preserve `open`, `upheld`, `rejected`, or `inconclusive` outcome. Never use arrival order to choose an owner.

- [ ] **Step 4: Run all Phase 0 tests**

Run: `cd phase0 && npm test && npm run typecheck`

Expected: PASS; duplicate-byte conflict is deterministic across reversed event order.

- [ ] **Step 5: Commit conflict behavior**

```bash
git add phase0/src/attestations.ts phase0/tests/attestations.test.ts
git commit -m "feat: surface duplicate Skill registration conflicts"
```

### Task 3: Verify repository control offline against exact Git bytes

**Files:**
- Create `phase0/src/attestation-git.ts`
- Create `phase0/src/attestation-config.ts`
- Create `phase0/tests/attestation-git.test.ts`
- Modify `.gitignore`

- [ ] **Step 1: Write failing offline-verification tests**

Create a temporary Git repository with an HTTPS `origin`, configure a local test
identity, write and commit `skills/demo/SKILL.md` as `artifactCommitSha`, generate a
wallet at runtime, sign a challenge bound to that artifact commit, and commit the
signed challenge file as the later proof commit. Generate a separate Ed25519 forge key
at runtime and sign `ForgeObservationV1` over repository/ref/proof OID/nonce. Provision
an injected resolver with that one checkout, URL, ref, and permitted forge signer.
Assert `verifyRepositoryControl` returns `repository_control_verified`.

Add tamper tests for artifact bytes, challenge bytes, artifact commit, proof commit,
artifact path, recovered wallet, expiry, repository URL, forge-observed OID/ref/nonce,
forge signature, unknown forge signer, proof not descending from artifact, and absent
challenge path. Create a second claimant-controlled local repository with a copied
`origin` string and ref; prove it is never read because it is absent from the verifier
resolver. Replaying the event after changing either wallet or forge signature fails.

Add local-mapping tests for the production resolver. A valid owner-only mapping at an
absolute canonical path resolves the configured `checkoutKey`. Missing config, a
relative `PHASE0_ATTESTATION_CHECKOUTS_FILE`, symlinked config, permissions broader than
`0600`, unknown keys, relative/non-canonical/missing checkout paths, group/world-writable
checkout directories, an environment override to a non-default in-repository file,
missing trusted checkout keys, and extra keys not referenced by
`repository-trust.json` all fail closed. Use an injected filesystem metadata adapter
for ownership cases that cannot be created portably. Assert neither bundle data nor a
CLI `--repository-path` option can extend or override the mapping.

- [ ] **Step 2: Run and verify red**

Run: `cd phase0 && node --import tsx --test tests/attestation-git.test.ts`

Expected: FAIL because `src/attestation-git.ts` does not exist.

- [ ] **Step 3: Implement an injected Git reader**

Define:

```ts
export interface GitReader {
  commitExists(repositoryPath: string, commitSha: string): Promise<boolean>;
  readBlob(repositoryPath: string, commitSha: string, relativePath: string): Promise<Uint8Array>;
  isAncestor(repositoryPath: string, ancestor: string, descendant: string): Promise<boolean>;
  remoteUrl(repositoryPath: string, remoteName: string): Promise<string>;
}

export interface TrustedRepository {
  repositoryId: string;
  repositoryUrl: string;
  repositoryPath: string;
  trustedRef: `refs/heads/${string}` | `refs/remotes/${string}`;
  permittedForgeSignerIds: readonly string[];
}

export interface TrustedRepositoryResolver {
  resolve(repositoryId: string, normalizedRepositoryUrl: string): TrustedRepository;
}

export interface LocalCheckoutMapV1 {
  schemaVersion: 1;
  checkouts: Record<string, string>;
}

export class ExecGitReader implements GitReader {
  commitExists(repositoryPath: string, commitSha: string): Promise<boolean>;
  readBlob(repositoryPath: string, commitSha: string, relativePath: string): Promise<Uint8Array>;
  isAncestor(repositoryPath: string, ancestor: string, descendant: string): Promise<boolean>;
  remoteUrl(repositoryPath: string, remoteName: string): Promise<string>;
}

export async function verifyRepositoryControl(input: {
  challengeFile: Uint8Array;
  forgeObservation: ForgeObservationV1;
  eventId: string;
  sequence: number;
  occurredAt: string;
  now: Date;
  git: GitReader;
  repositories: TrustedRepositoryResolver;
  forgeSigners: Readonly<Record<string, string>>;
}): Promise<Extract<AttestationEvent, { type: "repository_control_verified" }>>;

export function canonicalForgeObservationBytes(observation: Omit<ForgeObservationV1, "signature">): Uint8Array;
export function verifyForgeObservation(observation: ForgeObservationV1, trusted: TrustedRepository, forgeSigners: Readonly<Record<string, string>>): void;
export function reverifyRepositoryEvent(event: Extract<AttestationEvent, { type: "repository_control_verified" }>, context: { git: GitReader; repositories: TrustedRepositoryResolver; forgeSigners: Readonly<Record<string, string>> }): Promise<void>;

// Exported from attestation-config.ts
export function loadLocalCheckoutMap(input: {
  env: Readonly<Record<string, string | undefined>>;
  phase0Root: string;
  referencedCheckoutKeys: readonly string[];
}): Promise<Readonly<Record<string, string>>>;
export function createTrustedRepositoryResolver(input: {
  trustConfig: unknown;
  checkoutPaths: Readonly<Record<string, string>>;
}): TrustedRepositoryResolver;
```

The untracked local file schema is exactly:

```json
{
  "schemaVersion": 1,
  "checkouts": {
    "example-checkout-key": "/canonical/absolute/path/to/verifier-checkout"
  }
}
```

Immediately after the existing `*.jsonl` rule, add these exact root `.gitignore` lines
so the intended log is addable while machine paths remain local:

```gitignore
!phase0/attestations.jsonl
phase0/.attestation-checkouts.local.json
```

`loadLocalCheckoutMap` uses the absolute path in
`PHASE0_ATTESTATION_CHECKOUTS_FILE` when set; otherwise it resolves
`.attestation-checkouts.local.json` beneath the injected canonical `phase0Root`. The
environment value is a path to ignored local configuration, never JSON and never a
checkout path itself. If the override resolves inside the repository, it must equal
the exact ignored default path; any other in-repository path is rejected. An override
outside the repository is allowed under the same ownership/permission checks and
cannot become a tracked repository file. The config must be an owner-matched,
non-symlink regular file
with mode `0600`. Every checkout value must already equal `realpath(value)`, be an
absolute existing directory owned by the current UID, and have neither group nor world
write bits. Keys must match `^[a-z0-9][a-z0-9._-]{0,127}$`; the set must equal—not
merely contain—the `checkoutKey` set referenced by tracked `repository-trust.json`.
Unknown schema fields fail. Returned paths are deep-frozen. No local checkout mapping
or absolute machine path is ever committed.

`repositories.resolve` is the only source of `repositoryPath`, `trustedRef`, and
permitted forge signer IDs. Its production implementation loads fixed verifier
configuration plus `loadLocalCheckoutMap`; no command option or bundle field can add a
mapping. Missing or untrusted local mapping fails before any Git process runs. Use
`execFile`, never a shell string. Pass `git -C <repo> cat-file -e
<sha>^{commit}`, `git -C <repo> show <sha>:<path>`, `git -C <repo> merge-base
--is-ancestor <ancestor> <descendant>`, and `git -C <repo> remote get-url origin` as
separate argv items. Normalize paths before invocation and reject absolute paths, `..`,
backslashes, NUL, or empty segments. Require configured full trusted refs matching
`^refs/(heads|remotes)/`.
Normalize the local `origin` with the same HTTPS normalizer used by the signed
challenge. Verify the wallet and configured forge signatures and compare exact
bytes/hashes before constructing an event. Call `reverifyRepositoryEvent` before
returning it. That replay verifier reconstructs the signed challenge-file bytes from
the event and repeats resolver, both signatures, Git ancestry, trusted-ref reachability,
artifact hash, and proof-blob checks; store load and append use the same function.

- [ ] **Step 4: Run verification tests and full Phase 0 suite**

Run: `cd phase0 && npm test && npm run typecheck`

Expected: PASS; tests perform local Git operations only and no network calls.

- [ ] **Step 5: Commit offline repository verification**

```bash
git add phase0/src/attestation-git.ts phase0/src/attestation-config.ts phase0/tests/attestation-git.test.ts .gitignore
git commit -m "feat: verify repository-control attestations offline"
```

### Task 4: Persist valid events append-only

**Files:**
- Create `phase0/src/attestation-store.ts`
- Create `phase0/tests/attestation-store.test.ts`
- Create `phase0/attestations.jsonl`
- Create `phase0/organization-signers.json`
- Create `phase0/attestation-admins.json`
- Create `phase0/repository-trust.json`
- Create `phase0/forge-signers.json`

- [ ] **Step 1: Write failing store tests**

Assert an absent file loads as `[]`; appending two events writes two newline-terminated
JSON objects; reopening revalidates wallet, forge, organization, challenger, and admin
signatures plus repository snapshot evidence; duplicate sequence/event IDs fail without
modifying the file; malformed trailing JSON fails closed; and no API can replace or
delete prior events. Direct generic append of a fabricated repository/admin event, or
construction without the required verifier trust context, must fail without a write.
An attempted `wallet_asserted` sidecar line must also fail replay; base subjects come
only from the confirmed manifest injected by the caller.
Start two append Promises with the same next sequence while holding the first writer at
an injected pre-write barrier. Exactly one may append; the other fails with
`attestation store locked`, and the final file contains one complete line. Test a
crash-left lock: normal append fails closed until explicit stale-lock recovery verifies
the recorded owner is absent and the caller supplies the exact lock token.
Inject a file-handle adapter whose `write` accepts at most three bytes per call. Assert
`writeAll` loops until the entire canonical JSONL record plus newline is durable and
replayable. Inject a zero-byte write and a throw after one short write; the first must
abort immediately, and the second may leave only a malformed trailing fragment that
subsequent replay rejects closed—neither may report a successful append or accept a
partial JSON object.

- [ ] **Step 2: Run and verify red**

Run: `cd phase0 && node --import tsx --test tests/attestation-store.test.ts`

Expected: FAIL because the store does not exist.

- [ ] **Step 3: Implement the append-only store**

Export `FileAttestationStore`. Its constructor contract is
`new FileAttestationStore(path, { baseSubjects, organizationSigners, adminSigners,
repositories, forgeSigners, git })`; `baseSubjects` must be the frozen result of
`registrationSubjectsFromManifest` for the confirmed manifest. `load()` returns
`Promise<AttestationEvent[]>`, `append(event)` returns `Promise<void>`, and
`nextSequence()` returns `Promise<number>`. Also expose
`recoverStaleLock({ expectedToken, isProcessAlive })` for explicit operator recovery.

`load` parses the entire log, runs `reverifyRepositoryEvent` for every persisted
repository event using the required verifier-controlled checkout/forge context, then
awaits `reduceAttestationEvents(events, { baseSubjects, organizationSigners, adminSigners,
repositoryVerifier })`.
Invalid/missing base subjects, repository/forge/organization/challenger/admin signatures, snapshot evidence,
statement hashes, or trust roots fail closed on every replay—not only ingestion.
`append` loads and validates the entire existing log, requires `event.sequence ===
events.length + 1`, rejects duplicate IDs, validates the candidate full log, opens with
append mode, passes one canonical JSON line plus newline to an exported
`writeAll(fileHandle, bytes)` helper, calls `FileHandle.sync()`, closes, and reloads to
confirm. `writeAll` advances a byte offset by each positive `bytesWritten`, repeats
until the full buffer is written, and throws on zero, negative, oversized, or missing
write counts; it never assumes one `FileHandle.write()` consumes the full buffer. The
entire replay/CAS/write/fsync
sequence runs while holding `<path>.lock`, acquired with `open("wx", 0o600)`. The lock
file contains schema version, PID, random token, target path, and acquired UTC time.
Release in `finally` only after rereading and matching this writer's token; fsync the
parent directory after lock creation, data append, and lock removal. An existing lock
never triggers an automatic retry or deletion.

Public `load()` and `nextSequence()` acquire the same lock before calling a private
`loadUnlocked()`; `append()` acquires it once and calls only the private helper. Readers
therefore never accept a partially visible append, and the implementation never tries
to acquire its own lock recursively.

`recoverStaleLock` rereads the lock, requires `expectedToken`, and uses the injected
process-liveness checker; it refuses recovery while the recorded PID is alive or when
the token/path differs. README recovery instructions require the operator to inspect
the lock and process first. Track
`phase0/attestations.jsonl` as a zero-byte file; do not invent an attestation for the
not-run manifest.

Create the trust-root file as:

```json
{
  "schemaVersion": 1,
  "organizations": {}
}
```

The loader rejects unknown keys, duplicate normalized wallets, non-address values, and
any field resembling a private key. An empty allow-list means organization approval is
unavailable, not implicitly trusted.

Create the remaining verifier configuration as:

```json
// phase0/attestation-admins.json
{ "schemaVersion": 1, "admins": {} }

// phase0/forge-signers.json
{ "schemaVersion": 1, "forgeSigners": {} }

// phase0/repository-trust.json
{ "schemaVersion": 1, "repositories": [] }
```

JSON files contain no comments in implementation; the labels above identify the three
separate files. A repository entry contains only `repositoryId`, normalized HTTPS URL,
`checkoutKey`, full trusted ref, and permitted forge signer IDs. The verifier supplies
`checkoutKey -> repositoryPath` only through the ignored, permission-checked local
mapping loaded by `attestation-config.ts` at process construction. Empty maps mean
admin actions and repository verification are unavailable. No event or bundle can
extend these trust roots.

- [ ] **Step 4: Run tests**

Run: `cd phase0 && npm test && npm run typecheck`

Expected: PASS with durable append and malformed-log cases green.

- [ ] **Step 5: Commit persistence**

```bash
git add phase0/src/attestation-store.ts phase0/tests/attestation-store.test.ts phase0/attestations.jsonl phase0/organization-signers.json phase0/attestation-admins.json phase0/repository-trust.json phase0/forge-signers.json
git commit -m "feat: persist append-only registration attestations"
```

### Task 5: Add explicit CLI surfaces and correct Phase 0 language

**Files:**
- Create `phase0/src/attestation-cli.ts`
- Modify `phase0/src/index.ts`
- Modify `phase0/package.json`
- Modify `phase0/README.md`

- [ ] **Step 1: Add CLI contract tests to `tests/attestations.test.ts`**

Test pure command handlers with injected store/Git reader and assert:

```text
attestation: wallet_asserted
claim: wallet registered these bytes and declared this ancestry
safety review: not_reviewed
warning: registration does not prove authorship, originality, legal ownership, or safety
```

`attestation-status --artifact-hash <hash>` must load `registrations.json`, seed every
confirmed proof through `registrationSubjectsFromManifest`, and then overlay the
sidecar events so every confirmed registration has at least `wallet_asserted`. It must
list every matching registration and conflict. `attestation-verify-repository --bundle
<path>` accepts a signed challenge plus forge observation but no repository path/ref;
the handler resolves verifier-provisioned configuration and appends only after full
replay verification succeeds. `attestation-verify-organization --bundle <path>` must load the
configured organization signer allow-list, verify the statement hash, recovered
wallet, and allow-list membership, and only then append `organization_approved`.
`attestation-append-challenge`, `attestation-resolve`, and `attestation-revoke` each
accept a pre-signed bundle, verify challenger/admin trust, and append rather than edit.
They never accept a private key or synthesize an unsigned privileged event.
`attestation-recover-lock --lock-token <exact-token>` prints the recorded lock metadata,
checks that PID liveness fails, and calls explicit stale recovery; it refuses active,
mismatched, or unreadable locks.
Add production-wiring CLI tests proving `attestation-verify-repository` fails before
Git execution with `repository snapshot mapping unavailable` when both the default
ignored file and environment override are absent; fails on insecure/untrusted mapping;
and succeeds with a temporary canonical `0600` mapping. `--repository-path` and
`--trusted-ref` must be rejected as unknown options rather than accepted and ignored.
`attestation-status` must continue to work without loading checkout configuration.

- [ ] **Step 2: Run the command tests and verify red**

Run: `cd phase0 && node --import tsx --test --test-name-pattern='CLI|status output' tests/attestations.test.ts`

Expected: FAIL because the CLI handlers do not exist.

- [ ] **Step 3: Implement command handlers and scripts**

Add scripts:

```json
"attestation-status": "node --import tsx src/index.ts attestation-status",
"attestation-verify-repository": "node --import tsx src/index.ts attestation-verify-repository",
"attestation-verify-organization": "node --import tsx src/index.ts attestation-verify-organization",
"attestation-append-challenge": "node --import tsx src/index.ts attestation-append-challenge",
"attestation-resolve": "node --import tsx src/index.ts attestation-resolve",
"attestation-conflicts": "node --import tsx src/index.ts attestation-conflicts",
"attestation-revoke": "node --import tsx src/index.ts attestation-revoke",
"attestation-recover-lock": "node --import tsx src/index.ts attestation-recover-lock"
```

Add parseArgs options `artifact-hash`, `registration-id`, `bundle`, and `lock-token`;
do not add repository-path or trusted-ref options. Construct
handlers with the fixed organization/admin/forge/repository configs and
the permission-checked ignored local checkout map, plus base subjects derived from the confirmed
`registrations.json` manifest; claimant arguments cannot override them. Public
keys/addresses are allowed in config, private keys are not. Commands emit
human-readable text by default and canonical JSON under `--json`. None calls
`storyChain()` or any network API.
Only the repository-verification command lazily calls `loadLocalCheckoutMap`; its
startup error names the config path and trust failure without printing checkout
contents. No command writes that local mapping.

- [ ] **Step 4: Rewrite README claims narrowly**

Use `registration and declared ancestry` for Phase 0. Include the three evidence
levels, exact verification commands, signed challenge/resolution/revocation behavior,
the forge-observer and verifier-snapshot trust assumptions, and this standing warning:

```text
An attestation records evidence about who made or approved a registration. It does not prove originality, legal ownership, absence of prior art, or Skill safety. Safety review is a separate status.
```

Also state: `repository_control_verified means a trusted forge observer and a
verifier-provisioned Git snapshot matched the wallet-signed bytes at an observation
time. It does not prove current remote account ownership or continuing hosting.`
Document the exact local checkout-map schema, default ignored path, optional
`PHASE0_ATTESTATION_CHECKOUTS_FILE` override, required `chmod 600`, canonical absolute
checkout path/permission rules, and missing-config error. Warn that this machine-local
file must never be staged or copied into an attestation bundle.

- [ ] **Step 5: Run full verification**

Run: `cd phase0 && npm test && npm run typecheck && npm run attestation-status -- --artifact-hash 0x$(printf '0%.0s' {1..64}) --json`

Expected: tests/typecheck PASS; status command returns JSON with an empty `registrations` array and `conflicts` array, not an authorship claim.

- [ ] **Step 6: Confirm no chain write or protected-corpus edit entered the slice**

Run: `git diff --exit-code -- CONTEXT.md docs/PRD.md docs/adr && ! rg -n -P '\bauthored by\b|(?<!not )\bproves? (?:originality|safety)\b|\bsafe Skill\b' phase0/src phase0/README.md`

Expected: exit 0 and no affirmative forbidden overclaim matches. Required negative
disclaimers such as `does not prove originality` and `does not prove safety` remain
allowed and visible.

Run:

```bash
git check-ignore phase0/.attestation-checkouts.local.json
! git ls-files | rg 'attestation-checkouts\.local\.json$'
! rg -n '"repositoryPath"\s*:|/(Users|home)/|[A-Za-z]:\\\\' phase0/repository-trust.json phase0/organization-signers.json phase0/attestation-admins.json phase0/forge-signers.json
```

Expected: the ignored local path is reported by `git check-ignore`; both negative
scans exit 0 with no tracked machine path.

- [ ] **Step 7: Commit CLI and documentation**

```bash
git add phase0/src/attestation-cli.ts phase0/src/index.ts phase0/package.json phase0/README.md phase0/tests/attestations.test.ts
git commit -m "feat: expose honest Phase 0 attestation status"
```

## Definition of done

- Every confirmed registration in `registrations.json` renders at least
  `wallet_asserted`, never bare “authored by.”
- `wallet_asserted` can originate only from a confirmed manifest proof; the sidecar
  schema rejects unsigned base-assertion events.
- The confirmed `wallet_asserted` floor is not a revocable sidecar level; signed admin
  revocation can remove only repository/organization evidence and never erase or mark
  the base registration revoked.
- Exact duplicate bytes under different wallets create a visible deterministic conflict.
- Repository evidence is replay-verified against the wallet signature, configured forge-observer signature, exact artifact/proof bytes, and verifier-provisioned checkout/ref; it is labeled snapshot evidence, not remote ownership proof.
- Production repository verification resolves checkout keys only through an ignored,
  owner-only, canonical absolute-path local mapping; missing/insecure/untrusted mappings
  fail before Git and no machine path is tracked.
- Organization approval is appended only after its canonical signature recovers an allow-listed signer and remains distinct from safety review.
- Challenge openings are signed by the challenger wallet; resolutions and revocations are signed by provisioned admins; unsigned/unknown-signer events never append or replay.
- JSONL append uses a tested write-all loop; short writes complete correctly and
  interrupted fragments are never accepted as valid replay.
- All tests generate signing keys at runtime; no `.env`, private key, testnet transaction, or network call is added.
- `CONTEXT.md`, `docs/PRD.md`, and `docs/adr/` remain unchanged.
