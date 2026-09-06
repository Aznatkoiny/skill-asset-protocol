# Installed offline lifecycle evidence — 2026-09-05

**One installed offline attempt passed; eleven earlier attempts remain failed.**
The successful run qualifies the 43 named installed offline checks at source
commit `3ef2dbcb78bb7c04ec19aa34b0af7dc73eadeef2`. The failed attempts preserve
the actual host results and the sequence of compatibility fixes; none has been
relabeled. CDP execution and testnet transactions remain `not-run`; public release
remains `not-qualified`.

This repository archive retains the reviewed collection beyond GitHub Actions
artifact expiry. The twelve recorded attempts preserve their original outcomes
and source identities.

Each attempt directory contains the byte-identical `manifest.json`,
`events.jsonl`, and `summary.json` downloaded from its GitHub Actions artifact.
`provenance.json` is separately authored retention metadata: it records the
GitHub-reported run/artifact identity and archive digest, locally checked file
hashes, and the local verifier result. It is not original harness output.
The ZIP archives are not copied into the repository.

## First successful installed offline run

[Run 33993435474, attempt 1](https://github.com/Aznatkoiny/skill-asset-protocol/actions/runs/33993435474/attempts/1)
completed on Ubuntu 24.04 with root, systemd as PID1, and exactly Node 24.18.1.
The original manifest identifies source commit
`3ef2dbcb78bb7c04ec19aa34b0af7dc73eadeef2`, x64, and Linux kernel
`6.17.0-1022-azure`. The
[installed lifecycle job](https://github.com/Aznatkoiny/skill-asset-protocol/actions/runs/33993435474/job/101379614017)
passed installation, qualification, independent verification, artifact upload,
and final teardown. Artifact upload precedes teardown, so the successful final
step is a separate part of the run's qualification evidence.

The [original Actions artifact 9977391251](https://github.com/Aznatkoiny/skill-asset-protocol/actions/runs/33993435474/artifacts/9977391251)
is a 14,530-byte ZIP. Its downloaded SHA-256 matches the digest reported by the
GitHub artifact API:
`sha256:2b00a4e7e1b00bffdc805e043c59308e0ffb89fbfa0be86b2b36129c670e40f9`.
The three original files total 129,616 bytes and were retained byte-for-byte:

| Original file | Bytes | SHA-256 |
|---|---:|---|
| [manifest.json](success/33993435474-attempt-1/manifest.json) | 1,203 | `7c6a88a82d9c73cc3ba39f7449f8b1bb955d72d4d2bc494c3476169e56cb84d8` |
| [events.jsonl](success/33993435474-attempt-1/events.jsonl) | 128,128 | `25cdd1d43028e9ea4df6d8662370745b7ecf7e9c4d6fdc5718778932ab7f6d93` |
| [summary.json](success/33993435474-attempt-1/summary.json) | 285 | `f45a544542ea8598ad1f6fbf956511cdc905897e7c5d9b8f79af4e884829273a` |

The separately authored [provenance](success/33993435474-attempt-1/provenance.json)
records the original run/job/artifact links, successful required job steps,
archive and file hashes, and the exact local verifier source/runtime. Local
verification recomputed **43 of 43 checks**, with `failed: []`, `missing: []`,
`valid: true`, and `manifest.failure: null`. To repeat the check from the package
with source and locked dependencies at the qualified commit and Node 24.18.1:

```bash
node scripts/verify-lifecycle-evidence.mjs \
  evidence/2026-09-05-installed-offline-lifecycle/success/33993435474-attempt-1 \
  --commit 3ef2dbcb78bb7c04ec19aa34b0af7dc73eadeef2
```

Expected exit: `0`. The successful scope includes actual installation and PID1
binding, credential and filesystem boundaries, listeners, approval/retry/replay,
clean and forced restarts, rejected stale or changed admission evidence,
interrupted signing and retry, unresolved holds, charged-failure receipts,
and cleanup. External wallet, seller, and chain behavior is synthetic. The
bundle includes public signed receipts and verification keys, hashed provider
journal projections, and hashes of retained payment headers/payloads/signatures;
it does not include those raw payment authorizations. Content review found no
credential values, private keys, raw service logs, or customer data.

This result does not establish CDP execution, a Base Sepolia transaction, VM
reboot recovery, independently tested outbound-network denial, customer demand,
or public-release readiness. It does not enable the live entrypoints. The
qualified source SHA is distinct from any later documentation or merge commit.

The original Actions artifact expires at **2026-10-05T21:39:28Z**. The repository
copy preserves its original bytes beyond that download window.

## Original failed results

The links below identify distinct run IDs, all at attempt 1. The full source
commit, original failure object, and file digests remain in each directory.
“Records” counts emitted events, including cleanup observations; it does not
count completed lifecycle scenarios.

| GitHub run | Source commit | Original manifest stage and code | Records / required | Retained original files |
|---|---|---|---|---|
| [33989274082](https://github.com/Aznatkoiny/skill-asset-protocol/actions/runs/33989274082/attempts/1) | `afa5e20299f5782abd2c16a351c9f5cfb8c6e70e` | `authority bootstrap`; `QUALIFICATION_COMMAND_FAILED`, child `QUALIFICATION_WORKER_RELEASE` | 3 / 43 | [Manifest](failed/33989274082-attempt-1/manifest.json), [events](failed/33989274082-attempt-1/events.jsonl), [summary](failed/33989274082-attempt-1/summary.json), [provenance](failed/33989274082-attempt-1/provenance.json) |
| [33989404422](https://github.com/Aznatkoiny/skill-asset-protocol/actions/runs/33989404422/attempts/1) | `304fd17c4d9df5ad3e8369ad1da95b2cb550610e` | `install`; `QUALIFICATION_COMMAND_FAILED`, child `SYSTEMD_OUTPUT` | 6 / 43 | [Manifest](failed/33989404422-attempt-1/manifest.json), [events](failed/33989404422-attempt-1/events.jsonl), [summary](failed/33989404422-attempt-1/summary.json), [provenance](failed/33989404422-attempt-1/provenance.json) |
| [33989850514](https://github.com/Aznatkoiny/skill-asset-protocol/actions/runs/33989850514/attempts/1) | `3b4aec794f4ae30d06547ae264f3b8869f3aadb4` | `install`; `QUALIFICATION_COMMAND_FAILED`, child `SYSTEMD_EFFECTIVE` | 6 / 43 | [Manifest](failed/33989850514-attempt-1/manifest.json), [events](failed/33989850514-attempt-1/events.jsonl), [summary](failed/33989850514-attempt-1/summary.json), [provenance](failed/33989850514-attempt-1/provenance.json) |
| [33990002633](https://github.com/Aznatkoiny/skill-asset-protocol/actions/runs/33990002633/attempts/1) | `7b7844de1fb416c722c09796eea3cf770fcff99b` | `install`; `QUALIFICATION_COMMAND_FAILED`, child `SYSTEMD_EFFECTIVE` | 6 / 43 | [Manifest](failed/33990002633-attempt-1/manifest.json), [events](failed/33990002633-attempt-1/events.jsonl), [summary](failed/33990002633-attempt-1/summary.json), [provenance](failed/33990002633-attempt-1/provenance.json) |
| [33990254089](https://github.com/Aznatkoiny/skill-asset-protocol/actions/runs/33990254089/attempts/1) | `e349fa7e127189b4c719b6306a8720696b8b051b` | `install`; `QUALIFICATION_FAILED`, no child code recorded | 9 / 43 | [Manifest](failed/33990254089-attempt-1/manifest.json), [events](failed/33990254089-attempt-1/events.jsonl), [summary](failed/33990254089-attempt-1/summary.json), [provenance](failed/33990254089-attempt-1/provenance.json) |
| [33990723789](https://github.com/Aznatkoiny/skill-asset-protocol/actions/runs/33990723789/attempts/1) | `a437740eb7f5c28c3589b9be2bfb77d9367f1d2b` | `startup`; `QUALIFICATION_COMMAND_FAILED` from `systemctl`, no child code recorded | 10 / 43 | [Manifest](failed/33990723789-attempt-1/manifest.json), [events](failed/33990723789-attempt-1/events.jsonl), [summary](failed/33990723789-attempt-1/summary.json), [provenance](failed/33990723789-attempt-1/provenance.json) |
| [33991226160](https://github.com/Aznatkoiny/skill-asset-protocol/actions/runs/33991226160/attempts/1) | `9662fcadf3abb2938598a165f46e3b364ad02001` | `startup`; `QUALIFICATION_COMMAND_FAILED` from `systemctl`, no child code recorded | 10 / 43 | [Manifest](failed/33991226160-attempt-1/manifest.json), [events](failed/33991226160-attempt-1/events.jsonl), [summary](failed/33991226160-attempt-1/summary.json), [provenance](failed/33991226160-attempt-1/provenance.json) |
| [33991404339](https://github.com/Aznatkoiny/skill-asset-protocol/actions/runs/33991404339/attempts/1) | `ed5d28ef1a0bc9cd5efb52b9d3668181c636bb39` | `startup`; `QUALIFICATION_COMMAND_FAILED` from `systemctl`, no child code recorded | 10 / 43 | [Manifest](failed/33991404339-attempt-1/manifest.json), [events](failed/33991404339-attempt-1/events.jsonl), [summary](failed/33991404339-attempt-1/summary.json), [provenance](failed/33991404339-attempt-1/provenance.json) |
| [33991615870](https://github.com/Aznatkoiny/skill-asset-protocol/actions/runs/33991615870/attempts/1) | `5fac587bc6d4d45d8f77956df8350e717ea2ac93` | `reject.staleAttestation`; `QUALIFICATION_COMMAND_FAILED` from `setpriv`, child `AUTHORITY_RECOVERY_REQUIRED` | 31 / 43 | [Manifest](failed/33991615870-attempt-1/manifest.json), [events](failed/33991615870-attempt-1/events.jsonl), [summary](failed/33991615870-attempt-1/summary.json), [provenance](failed/33991615870-attempt-1/provenance.json) |
| [33992332238](https://github.com/Aznatkoiny/skill-asset-protocol/actions/runs/33992332238/attempts/1) | `1bf64fac38ceda30740c4ff64f3cfef8a72b3bfb` | `signing-interruption`; `QUALIFICATION_TIMEOUT`, label `signer_blocked` | 34 / 43 | [Manifest](failed/33992332238-attempt-1/manifest.json), [events](failed/33992332238-attempt-1/events.jsonl), [summary](failed/33992332238-attempt-1/summary.json), [provenance](failed/33992332238-attempt-1/provenance.json) |
| [33993060286](https://github.com/Aznatkoiny/skill-asset-protocol/actions/runs/33993060286/attempts/1) | `47c0ad0257333876144bdbac4aca59ffc30bb593` | `signing-interruption`; `QUALIFICATION_BACKGROUND_COMPLETED` from `setpriv`, child `QUALIFICATION_WORKER_INPUT`, label `signer_blocked` | 34 / 43 | [Manifest](failed/33993060286-attempt-1/manifest.json), [events](failed/33993060286-attempt-1/events.jsonl), [summary](failed/33993060286-attempt-1/summary.json), [provenance](failed/33993060286-attempt-1/provenance.json) |

All eleven summaries have `valid: false` and missing required events. The first five
have empty `failed` arrays; they do not mean those attempts passed. Their original
manifests record a failure and `release: null`. The first attempt contains only
the three host observations. The next three add cleanup observations. The fifth additionally
records `install.execution`, `install.status`, and `install.serviceStopped`, but
never reaches `install.pid1Bound` or service startup.

The sixth through eighth contain an `install.pid1Bound` event with `actual: true`
and a non-null release binding, then record an actual installed-start failure.
Their original summaries list `install.pid1Bound` in `failed` despite the
event's reported boolean. Both observations are preserved: the harness's hash
comparison was true, but independent qualification was incomplete. Neither
`startup.active` nor `startup.confinement` was emitted.

The ninth contains 31 passing recorded checks, including actual startup,
confinement, inherited socket identity, Agent/Kernel boundaries, automatic
payment, exact approval, clean and forced restarts, replay, stale-attestation
rejection, and cleanup. Its original summary has `failed: []` and 12 missing
checks. The stale-attestation rejection itself passed before the subsequent
isolation-report import failed; the manifest's stage label remained
`reject.staleAttestation`. Changed-release/configuration rejection and the
signing-interruption, retry-interruption, unresolved-payment, and charged-failure
scenarios remain missing in this attempt.

The tenth contains 34 passing recorded checks. It proceeds through renewed
isolation admission and rejection of changed release bytes, changed PID1
configuration, and the CDP profile. It then times out waiting for the
`signer_blocked` journal barrier in the signing-interruption scenario. Its
original summary has `failed: []`, nine missing checks, and `valid: false`.
Cleanup observations passed, but none of the four final monetary-recovery
scenarios is recorded as complete. The workflow's final teardown also passed;
that separate job-step result does not change the failed harness outcome.

The eleventh also contains 34 passing recorded checks and nine missing checks.
Its original manifest records the background worker exiting with
`QUALIFICATION_WORKER_INPUT` while the harness awaited `signer_blocked`, rather
than the preceding attempt's timeout. `QUALIFICATION_BACKGROUND_COMPLETED` is
the failure code for that early exit; it does not mean the scenario succeeded.
The summary remains `valid: false`. Cleanup observations and the separate final
workflow teardown passed, while the final monetary-recovery scenarios remain
incomplete.

These are partial host results, not a passing end-to-end installed qualification.
Each manifest records its exact host and Node runtime. External wallet, seller,
and chain behavior uses the fixed `offline-qualification` fixtures. The first
eight attempts contain no payment-scenario evidence. The ninth through eleventh retain signed
public receipts and provider-journal observations for the synthetic automatic
and approved payments; these are not CDP calls or Base Sepolia transactions.

## Later diagnosis, separate from the original artifacts

The following notes record investigation after the failed attempts. They do
not add facts to the immutable original manifests or turn an earlier missing
check into a pass. The successful attempt above supplies its own separate
complete evidence.

| Failed run | Later diagnosis and follow-up |
|---|---|
| 33989274082 | The hosted runner's `/opt` ancestor was root-owned but mode `0777`, violating the immutable-ancestor contract. The later workflow printed that mode and prepared `/opt` as root-owned `0755`; [304fd17](https://github.com/Aznatkoiny/skill-asset-protocol/commit/304fd17c4d9df5ad3e8369ad1da95b2cb550610e) changes provisioning while retaining the path checks. The original manifest records only the broader worker release error. |
| 33989404422 | systemd v255's `systemctl show` output omitted empty `EnvironmentFiles` and represented `LoadCredential` as `[unprintable]`. [3b4aec7](https://github.com/Aznatkoiny/skill-asset-protocol/commit/3b4aec794f4ae30d06547ae264f3b8869f3aadb4) reads those fields through typed PID1 replies. |
| 33989850514 | The retained artifact identifies only `SYSTEMD_EFFECTIVE`, without a specific property. [7b7844d](https://github.com/Aznatkoiny/skill-asset-protocol/commit/7b7844de1fb416c722c09796eea3cf770fcff99b) added public diagnostics for the next attempt; those diagnostics isolated the dependency decoding problem described below. |
| 33990002633 | Later diagnostics showed a quoted, escaped credential-mount dependency in the service's effective `After` list. [e349fa7](https://github.com/Aznatkoiny/skill-asset-protocol/commit/e349fa7e127189b4c719b6306a8720696b8b051b) adds strict decoding of that PID1 representation. The original artifact still records only `SYSTEMD_EFFECTIVE`. |
| 33990254089 | The installer returned `sealed_not_started`; the following manifest read failed. A later local exact-width measurement of **dependency entries alone: 40,192 entries, 9,952,689 bytes** exceeded the reader's 4 MiB bound. This was not a measurement of the full downloaded manifest and is not a field in the retained artifact. [a437740](https://github.com/Aznatkoiny/skill-asset-protocol/commit/a437740eb7f5c28c3589b9be2bfb77d9367f1d2b) adds a bounded 16 MiB contract and regression. The following run progressed to startup but still failed. |
| 33990723789 | Later service-journal inspection showed `LIVE_PREFLIGHT_FAILED` and `LIVE_CLEANUP_ENVIRONMENT`. The original public manifest records only the `systemctl` command failure at `startup`. The unexpected environment variable name was not yet known when this entry was retained; a diagnostics-only patch was pending. The verifier also cross-binds the configured Kernel UID/GID to the subsequent `startup.confinement` process observation, which this failed start never produced. This missing identity observation explains the original `install.pid1Bound` summary failure; it is not evidence that the captured PID1 projection was malformed. Neither diagnostic establishes a successful start or qualification. |
| 33991226160 | The names-only diagnostics added in [9662fca](https://github.com/Aznatkoiny/skill-asset-protocol/commit/9662fcadf3abb2938598a165f46e3b364ad02001) identified unexpected `SGX_AESM_ADDR` in both preflight and cleanup, with preflight cause `RELEASE_ENVIRONMENT`. The original manifest still records only the broader `systemctl` startup failure. [ed5d28e](https://github.com/Aznatkoiny/skill-asset-protocol/commit/ed5d28ef1a0bc9cd5efb52b9d3668181c636bb39) removes that incidental manager variable through the exact unit `UnsetEnvironment` list; the application allowlists continue to reject direct injection. No environment value is reproduced here. The missing startup process observation also leaves independent `install.pid1Bound` qualification incomplete. |
| 33991404339 | Later diagnostics confirmed that `SGX_AESM_ADDR` was removed and the cleanup environment error was gone, but preflight still rejected with `RELEASE_ENVIRONMENT`. A separate local reproduction using exactly Node 24.18.1 and an empty inherited environment showed that raw `process.env` has a special prototype rejected by the strict inert-record validator, while `{...process.env}` passes. [5fac587](https://github.com/Aznatkoiny/skill-asset-protocol/commit/5fac587bc6d4d45d8f77956df8350e717ea2ac93) takes one frozen snapshot at the trusted CLI boundary without relaxing the validator. These diagnostic findings are separate from the original manifest's generic startup failure. The missing `startup.confinement` observation again prevents independent PID1/identity qualification. |
| 33991615870 | After the valid report expired and installed startup correctly rejected it, the next `import-isolation` operation failed with `AUTHORITY_RECOVERY_REQUIRED`. Independent local recovery and admission reproductions confirmed a renewal deadlock involving expired but valid attestation history. A correction was pending at retention time; [1bf64fa](https://github.com/Aznatkoiny/skill-asset-protocol/commit/1bf64fac38ceda30740c4ff64f3cfef8a72b3bfb) subsequently corrected renewal admission. This diagnosis is separate from the original command failure and does not turn the 12 missing checks into passes. |
| 33992332238 | The original manifest identifies a timeout waiting for `signer_blocked`. Request/barrier diagnosis was still in progress when this attempt was retained. No specific root cause or corrective result is attributed to this artifact. The later workflow step completed teardown successfully, separately from the harness's cleanup events. |
| 33993060286 | The bounded diagnostics added in [47c0ad0](https://github.com/Aznatkoiny/skill-asset-protocol/commit/47c0ad0257333876144bdbac4aca59ffc30bb593) show the worker rejecting input before an HTTP request: only `provider_opened` is recorded, with zero unpaid requests, signer calls, and paid requests, and `snapshotCode: null`. Subsequently, a separate local reproduction using the exact worker imports and payload, `setpriv --no-new-privs`, and the spawned synchronous stdin reader failed eight of eight times with fd 0 `EAGAIN` after reading all 134 bytes but before EOF. The earlier Node-only probe had not reproduced it. [3ef2dbc](https://github.com/Aznatkoiny/skill-asset-protocol/commit/3ef2dbcb78bb7c04ec19aa34b0af7dc73eadeef2) adds a bounded asynchronous EOF reader, retaining the 16 KiB limit, fatal UTF-8 decoding, schema checks, and stable error code. These diagnoses are separate from this original manifest's `QUALIFICATION_WORKER_INPUT`. The subsequent passing run is retained separately above. This attempt's final workflow teardown passed, but its monetary-recovery scenario remains incomplete. |

## Failed-run integrity and expected rejection

At retention on 2026-09-05, each downloaded ZIP's SHA-256 matched the artifact
digest reported by the GitHub API. Each copied original file matched both the
ZIP member and the downloaded file hash; all 33 failed-run original files were checked.
The archive identities, digests, file sizes, and hashes are recorded in the
per-attempt provenance. File copying does not authenticate a new host run;
GitHub run/artifact provenance remains distinct from local hash recomputation.

To check the retained failed-run original files from `spikes/pi-wielder`:

```bash
python3 - <<'PY'
from pathlib import Path
import hashlib, json
root = Path('evidence/2026-09-05-installed-offline-lifecycle/failed')
for attempt in sorted(root.iterdir()):
    provenance = json.loads((attempt / 'provenance.json').read_text())
    for name, expected in provenance['retention']['files'].items():
        data = (attempt / name).read_bytes()
        assert len(data) == expected['bytes']
        assert 'sha256:' + hashlib.sha256(data).hexdigest() == expected['sha256']
    print(attempt.name, 'original file hashes match')
PY
```

With exactly Node 24.18.1 and the package's locked dependencies, the lifecycle
verifier must reject these attempts. For example:

```bash
node scripts/verify-lifecycle-evidence.mjs \
  evidence/2026-09-05-installed-offline-lifecycle/failed/33990254089-attempt-1 \
  --commit e349fa7e127189b4c719b6306a8720696b8b051b
```

Expected result: exit `1`, `LIFECYCLE_EVIDENCE_INVALID`. All eleven bundles were
rechecked with that expected rejection; the verifier file hash and Node version
used for the local recheck appear in provenance. A rejection is the correct
handling of incomplete evidence, not an installed qualification success. Use
the verifier and dependencies at an attempt's source revision when reproducing
that revision's behavior; later verifier changes do not rewrite its results.

The ninth attempt's original summary was also independently recomputed from
its retained events: 31 checks, no failed checks, 12 missing, `valid: false`.
That recomputation includes the supported receipt and journal checks but does
not clear the overall failed-run result or its recorded renewal failure.
The tenth summary was likewise recomputed: 34 checks, no failed checks, nine
missing, `valid: false`. The timeout remains a failure even though every emitted
check passed.
The eleventh summary was independently recomputed to the same counts and invalid
status. Its early worker failure remains distinct from the tenth attempt's timeout.

## Retention rules

Actions originally assigned these artifacts 30-day retention, with expiry
timestamps recorded in provenance. The repository copy preserves the original
files beyond that download window. No environment file, credential,
private key, SQLite database, raw service log, or payment header is retained
here. Each successful attempt belongs in its own `success/<run>-attempt-N/`
directory with its exact source revision and provenance. Do not combine its
events with a failed attempt or overwrite these files.

Both the repository and package ignore `*.jsonl`. The reviewed `events.jsonl`
files are explicitly tracked; ignore rules remain in force for other journals.
The collection contains no change to
the CDP, Base Sepolia, customer-demand, or public-release gates.
