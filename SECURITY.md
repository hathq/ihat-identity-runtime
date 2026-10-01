# Security boundary

The runtime is an identity authority, not an authenticator UI, secret store, or
provider credential broker. Untrusted request DTOs are never treated as proof.
Construction requires `RuntimeTrust`; there is no allow-all/default production
path. Its verifier ports authenticate installer-root bootstrap bundles, fresh
user evidence, Device attestation
and key possession, Session sender proof, revocation authority, and independent
recovery approvals. Test fakes are defined only in integration-test sources.

Each production verifier is part of the trusted computing base. It must verify
signature/trust chain, anti-phishing/user-verification policy where applicable,
and binding to every field of the supplied request or authentication context.
Returning a window without cryptographic verification is a security defect.
The runtime independently checks every returned window against its injected
trusted clock and rejects invalid, future, or expired evidence.

`InstallerBootstrapVerifier` must pin installer-root trust independently of
Device and Session keys and verify the signature over every bootstrap request
field. The host must keep `bootstrap_initial_identity` off its normal network
surface. Bundle and command IDs are durably one-use, the validity window is at
most five minutes, and bootstrap is rejected once any durable authority state
exists.
If the caller loses the committed response, reconciliation requires the exact
original runtime request and returns only the receipt stored in the same CAS as
the graph. A changed command, bundle, identity, key, Session, time window, or
signature is rejected. Reconciliation does not re-run an expired authenticator
ceremony and never creates or changes authority state.

## Enforced invariants

- email and display-name equality never link identities;
- every Service receives a distinct opaque pairwise subject;
- exportable keys, synced Passkeys as Device keys, duplicate keys, cross-Account
  subjects, and cross-Service subjects fail closed;
- Session creation, use, and assertion minting require a verified proof from
  the exact current Device sender key;
- subject, ServiceAccount, Device, and Session epochs are monotonic and scoped;
- recovery requires both an offline recovery authority and a separate bound
  authenticator with distinct authority IDs and keys, verified signatures, and
  current approval windows;
- every new revocation preparation requires a current proof from the configured
  authority;
- committing or cancelling a preparation additionally requires an exact,
  host-supplied execution authorization bound to its random durable handle and
  stored request; a handle alone is not authority;
- command, proof, approval, and identity-evidence nonce replay state is durable;
- audit entries are append-only and hash chained;
- assertion and current-status parsing are closed and bounded in the shared contract package.

The current identity route never guesses a Session from issue order or sender
fingerprint. It follows only the durable per-Device identity Session pointer.
Absent establishment succeeds only when no pointer exists; Present
establishment requires the exact opaque reference and epoch. A revoked pointer
can be replaced only with its exact post-revocation epoch, obtained through the
root/iHAT-authorized revocation and operator reprovisioning flow. The ordinary
browser path has no automatic revoked-slot recovery. A revoked Device remains
ineligible even with an exact Session pointer.

## Durable-state assumptions

`FileDurableState` rejects relative/non-canonical parents, symlinks, permissive
modes, oversized images, rollback-anchor mismatch, and concurrent stale CAS.
Atomic rename and fsync protect committed writes against ordinary process or
power interruption. A durable pending-anchor image closes the state-rename to
anchor-replacement gap: restart either finishes the exact prepared anchor or,
when the current state still matches its anchor, removes an unapplied pending
image. Any other state/anchor/pending combination fails closed as rollback.

Durable schema `IHATID04` is current. Its bounded prepared-revocation map
reserves both a receipt slot and the worst-case future serialized bytes before
the Begin operation can be published. Ordinary mutations must preserve every
prepared target, its ancestor records, and its descendants. Exact commit
atomically replaces one preparation with its receipt; exact cancellation
replaces it with a replay tombstone. Neither operation rechecks an expired live
authority window after preparation, but both require the separate execution
authorization verifier. `IHATID03` is accepted as the explicit
legacy image and upgrades on the next mutation. `IHATID02` cannot be opened or
auto-migrated because it has no authoritative identity Session pointer;
operators must reprovision from the signed bootstrap source.

Mode bits and a local anchor do not defend against root, kernel compromise, or
an attacker able to restore both state and anchor coherently. Deployments that
need protection from privileged full-filesystem rollback must bind the anchor
to TPM monotonic state or an independent remote witness. Live backups must
preserve state, anchor, and any pending anchor as one recovery unit.

Gateway peer authorization must call `read_device_peer_status` for the exact
root-signed service pairwise and device mapping before accepting a request.
The read fails closed for missing, ambiguous, rolled-back, tampered, or
audit-invalid state. A cached positive result is forbidden: every connection
must observe current durable state so a committed Device revocation cannot be
bypassed by a process restart.

The durable image is not a secret-custody boundary. It contains Account identity
records needed by the local authority, but never contains the pairwise
derivation key, assertion or status signing key, Device private key, Passkey secret, or
provider credential. Those keys must remain in independent OS/hardware custody.

## Assertion consumer boundary

Consumers pin issuer, audience, distinct assertion/status key IDs and trust
material, trusted time, and both shared canonical contracts. They must reject
expired evidence, unknown fields, invalid signatures, any mismatch between the
assertion and current status, stale epochs, inactive Device state, and nonce
replay. The evidence pair is authorization input, not a bearer credential or
recovery proof.
