use ihat_identity_assertion_contracts::{
    AssertionVerifier, current_status_matches_assertion, verify_assertion_at,
    verify_current_status_at,
};
use sha2::{Digest, Sha256};
use support::*;

const ISSUER: &str = "https://id.ihat.invalid";
const AUDIENCE: &str = "crowsi-policy-administrator";

struct Signer(&'static str, &'static [u8]);

struct FailingStatusSigner;

#[test]
// ID-38: iHAT creates a service-scoped opaque reference for every session.
fn same_device_sessions_receive_distinct_opaque_persisted_references() {
    let (mut runtime, service, device, session_a) = seeded_runtime();
    let session_b = issue(
        &mut runtime,
        "account-a",
        &service,
        &device,
        "raw-global-session-b",
    );
    assert_ne!(session_a.session_ref, session_b.session_ref);
    for session in [&session_a, &session_b] {
        assert!(session.session_ref.starts_with("sref_"));
        assert_eq!(session.session_ref.len(), 69);
        assert!(!session.session_ref.contains(&session.session_id));
    }
    let evidence_a = runtime
        .issue_device_identity_evidence(request(&service, &device, &session_a, "session-ref-a"))
        .unwrap();
    let evidence_b = runtime
        .issue_device_identity_evidence(request(&service, &device, &session_b, "session-ref-b"))
        .unwrap();
    assert_eq!(evidence_a.assertion.session_ref, session_a.session_ref);
    assert_eq!(evidence_b.assertion.session_ref, session_b.session_ref);
    assert_ne!(
        evidence_a.current_status.session_ref,
        evidence_b.current_status.session_ref
    );
}

impl AssertionSigner for Signer {
    fn issuer(&self) -> &str {
        ISSUER
    }
    fn key_id(&self) -> &str {
        self.0
    }
    fn sign(&self, payload: &[u8]) -> Result<String, RuntimeError> {
        Ok(signature(self.1, payload))
    }
}

impl AssertionVerifier for Signer {
    fn verify(&self, key_id: &str, payload: &[u8], signature: &str) -> bool {
        key_id == self.0 && signature == self.sign(payload).unwrap()
    }
}

impl AssertionSigner for FailingStatusSigner {
    fn issuer(&self) -> &str {
        ISSUER
    }
    fn key_id(&self) -> &str {
        "status-failing-key"
    }
    fn sign(&self, _payload: &[u8]) -> Result<String, RuntimeError> {
        Err(RuntimeError::SignatureInvalid)
    }
}
