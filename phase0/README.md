# Phase 0 — Story provenance demo

From a funded Aeneid wallet, one command creates an SPG NFT collection and
registers a real three-level provenance graph:

```bash
cd phase0
npm install
cp .env.example .env        # add a throwaway testnet key
npm run demo
```

The demo checks the RPC's chain ID and the wallet's native-IP balance before it
does anything else. An exactly-zero balance exits nonzero before metadata is
fetched, `registrations.json` is changed, or a Story transaction is submitted,
and prints the wallet, network, and Aeneid faucet URL. Funding is always a human
step: <https://aeneid.faucet.story.foundation/>.

## What the command writes

The confirmed sequence is:

1. create an SPG NFT collection;
2. register the base **Skill** with commercial-remix PIL terms and a small,
   positive, testnet-only minting fee (`0.001 IP`);
3. register a declared **Derivative** of that Skill;
4. register a second-level Derivative whose parent is the first Derivative.

The three artifacts are committed under `fixtures/`; every registration hashes
the actual `SKILL.md` bytes with SHA-256. IP and NFT metadata JSON are each
serialized exactly once, hashed with SHA-256, embedded by default in a
retrievable `https://httpbin.org/base64/<base64url>` URI, fetched back, and
byte-compared before any Story write. `IP_METADATA_URI` and `NFT_METADATA_URI`
may override those defaults only when their fetched bytes match exactly.

Immediately after every confirmed transaction, the demo atomically replaces
`registrations.json`. The artifact records the network and wallet, SPG contract,
collection transaction, and each Skill/Derivative's `ipId`, `tokenId`,
transaction hash, inherited license-terms ID, parent IP IDs, minting-fee values,
and metadata URI/hash pairs. Native `bigint` values are persisted as decimal
strings. A rerun with the same chain and wallet skips confirmed stages and
resumes only the missing suffix; a different wallet is rejected rather than
overwriting the proof.

The committed artifact is deliberately `status: "not-run"` with null IDs. The
write path remains **unexecuted** until `registrations.json` contains confirmed
IDs and transaction hashes from a funded-wallet run.

Before each Derivative transaction, the CLI calls
`predictMintingLicenseFee(..., amount: 1)` and passes the returned `tokenAmount`
as an explicit `maxMintingFee` cap. In Story SDK 1.4.4, `0` means unlimited; the
explicit predicted cap is spend protection and exercises the paid-parent path,
not a workaround for a claimed SDK incompatibility.

## Network boundary and PRD criterion

This code targets **Story Aeneid testnet, chain ID 1315**, and never sends
mainnet transactions or real funds. The PRD's Phase-0 success criterion targets
**Story mainnet, chain ID 1514**, and requires broader proof than this testnet
write path. Aeneid results are useful engineering evidence; they **do not
satisfy the PRD Phase-0 success criterion**.

## Advanced commands

The individual commands remain available for targeted runs. They return only
after validating the SDK's optional proof fields, and registrations verify
metadata bytes before submitting a transaction.

```bash
npm run check

npm run create-collection -- --name Skills --symbol SKILL

npm run register-skill -- \
  --spg <spgNftContract> \
  --name "research-skill" \
  --description "base research Skill" \
  --skill-file fixtures/demo-base/SKILL.md \
  --rev-share 25 \
  --policy LAP \
  --minting-fee 1000000000000000

npm run register-derivative -- \
  --spg <spgNftContract> \
  --parent <parentIpId> \
  --license-terms-id <licenseTermsId> \
  --name "research-derivative" \
  --description "declared Derivative" \
  --skill-file fixtures/demo-child/SKILL.md
```

`register-derivative` predicts the parent's current minting fee immediately
before its write and uses that value as the cap. Explorer links use
<https://aeneid.explorer.story.foundation/>.

## Local verification

```bash
npm test
npm run typecheck
```

The tests use injected fakes only at filesystem, HTTP, RPC, and Story SDK
boundaries. They make no network calls and use no wallet key.
