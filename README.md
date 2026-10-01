# iHAT Identity Runtime

`ihat-identity-runtime` is the owner-local authority for this identity chain:

The current standalone package release is `0.1.0`; consumers must use this
current-only contract and must not fall back to the pre-release `0.0.0` API.

```text
Account -> pairwise ServiceAccount -> Device -> Session -> Revocation
```

It keeps external identities at the Account boundary, derives a different
opaque subject for each Service, requires a unique non-exportable proof key for
each Device, and sender-binds Sessions to the current Device key. A synced
Passkey may authenticate the user but is never accepted as Device identity.

## Production construction

Production callers use `IdentityRuntime::open_file` with an absolute state path,
an injected `PairwiseSubjectDeriver`, and a mandatory `RuntimeTrust`. The trust
bundle has no default and contains independent ports for installer bootstrap,
user authentication,
Device attestation, Device-key possession, Session sender proofs, revocation
authority, prepared-revocation execution authorization, recovery approvals,
and trusted time. A process cannot open the
runtime while omitting any of those checks. Each verifier must authenticate its
complete request/context and return the validity window from the verified
evidence; the runtime then enforces `issued <= trusted_now < expires`.

The first graph is created only through `bootstrap_initial_identity`. An
installer-root verifier must bind the signed, at-most-five-minute one-use bundle
to the complete request. The runtime requires an empty durable state, derives
the pairwise subject and a service-scoped opaque `session_ref`, then commits the
Account, ServiceAccount, first Device, first Session, replay IDs, and audit event
with one compare-and-swap. A failed derivation, validation, trust check, or
durable commit leaves the state empty. Product hosts must expose this API only
on their installer-owned bootstrap path; it is not a normal network command.
The same transaction also stores an immutable request digest and metadata-only
receipt. `reconcile_initial_bootstrap` can read that receipt after a lost
response, but only for the byte-equivalent runtime request; it performs no new
mutation, consumes no second proof, and appends no audit event. Ordinary
bootstrap replay remains rejected.

The derivation key stays in an OS or hardware custody provider; it is never
serialized into the runtime image. `MemoryDurableState` and all permissive
verifier implementations exist only under `tests/`.

`FileDurableState` requires a canonical, non-symlink parent with mode `0700`.
State, lock, rollback-anchor, and pending-anchor files are mode `0600`.
Mutations use an exclusive file lock, revision CAS, same-directory temporary
files, file `fsync`, atomic rename, and directory `fsync`. The pending anchor
lets restart finish only the exact prepared state/anchor pair. Images are
bounded to 4 MiB.

The durable image contains the authoritative graph, independent monotonic
subject/service/device/session epochs, consumed replay IDs, and an append-only
SHA-256 audit chain. Restart rejects an older revision, anchor mismatch, broken
audit chain, malformed image, or stale CAS.

The current image magic is `IHATID04`; it also carries bounded prepared
revocations, random preparation handles, cancellation tombstones, and the
durable revocation-receipt journal. A prepared target and its ancestors are
immutable until an exactly authorized commit or cancellation replaces the
preparation atomically. `IHATID03` is the explicit readable legacy image and
upgrades on the next mutation; only the current image may create new
preparations. `IHATID02`, a missing current-identity Session pointer map,
unknown state fields, and trailing payloads fail closed.
Existing `IHATID02` installations must be reprovisioned through the signed
installer bootstrap flow.

`read_device_peer_status` is the narrow read-only gateway view. It requires the
exact service, pairwise subject, and device reference, revalidates the durable
image, rollback anchor, and audit chain on every call, and returns only active
state plus the device epoch and posture revision. It exposes no global Account
or Session identifier and has no mutation or trust-verifier bypass. Subject,
Service, Device, or posture revocation makes the result inactive immediately.

## Device assertions

`issue_current_device_identity_evidence` accepts no Account ID, internal
Session ID, or `session_ref`. It resolves only the authoritative per-Device
pointer and returns the opaque reference inside the signed evidence. Ordinary
`issue_session` calls never select this pointer. Bootstrap initializes it;
`establish_device_identity_session` performs later `Absent` or exact
`Present { session_ref, session_epoch }` CAS establishment. A successful
Present replacement revokes an active prior slot and installs the replacement
in the same durable transaction, so concurrent stale rotations cannot win.
Current-route assertion and status lifetimes are both limited to 30 seconds.

Two injected `AssertionSigner` ports enable `issue_device_identity_evidence`; trusted
time is already mandatory in `RuntimeTrust`. Minting also requires a fresh
sender proof bound by `SessionSenderProofVerifier` to the exact request,
audience, nonce, current Session, and current Device key. The proof ID and nonce
are each durably one-use. Assertions are issued only from current, active
Account/ServiceAccount/Device/Session state and live for at most 300 seconds.
One signer emits the assertion and a distinct signer emits an exactly bound current-device
status with a maximum 30-second lifetime. The pair is signed before its nonce and sender proof
are committed atomically, so a caller never receives an assertion without its revocation status.
They contain pairwise identity and public key references; global Account IDs,
external subjects, private keys, and secrets are absent.

The wire DTO, closed decoder, canonical payload, verifier API, and JSON schema
belong to the independent `ihat-identity-assertion-contracts` 0.1.0 crate. This
runtime uses its exact `0.1.0` package from the installer-owned
`ecosystem-private` registry and re-exports its
public contract. PA, Crowsi, and other consumers should depend on that contract
package from the same registry rather than this runtime repository or a
source-tree path.

Canonical bytes begin with `IHAT-DEVICE-IDENTITY-ASSERTION-V1\n`; the shared
contract then emits the fixed field order as UTF-8 byte-length-prefixed records.
The `signature` field is excluded from its own payload. See
`fixtures/device-identity-assertion-v1.json` for deterministic emission evidence.

## Verification

```bash
cargo fmt --all -- --check
cargo check --offline --lib
cargo test --offline
cargo clippy --offline --lib -- -D warnings
```

`tests/multidevice_identity.rs` covers acceptance IDs `ID-01` through `ID-12`.
`tests/trust_boundary.rs` and
`fixtures/trust-boundary-acceptance-v1.json` cover `ID-13` through `ID-30`,
including rejected unsigned, unverified, stale, future, and replayed evidence.
Dedicated suites cover assertion interoperability, static production gates,
file durability, session-scoped revocation, atomic Device-to-Session cascade,
the `ID-50` installer bootstrap transaction, the `ID-52` exact bootstrap
reconciliation path, the `ID-51` current identity Session slot, and the `ID-54`
durable gateway peer-status view.
