use sha2::{Digest, Sha256};
use support::*;

const NOW: u64 = TEST_NOW;
const FIXTURE_NOW: u64 = 1_786_300_000;
const ISSUER: &str = "https://id.ihat.invalid";
const AUDIENCE: &str = "crowsi-local-bridge";

struct DeterministicSigner;
impl AssertionSigner for DeterministicSigner {
    fn issuer(&self) -> &str {
        ISSUER
    }
    fn key_id(&self) -> &str {
        "identity-signing-key-v1"
    }
    fn sign(&self, payload: &[u8]) -> Result<String, RuntimeError> {
        let mut digest = Sha256::new();
        digest.update(b"deterministic-test-signing-key\0");
        digest.update(payload);
        Ok(format!("sha256:{:x}", digest.finalize()))
    }
}

struct DeterministicVerifier;
impl AssertionVerifier for DeterministicVerifier {
    fn verify(&self, key_id: &str, payload: &[u8], signature: &str) -> bool {
        key_id == "identity-signing-key-v1"
            && DeterministicSigner.sign(payload).ok().as_deref() == Some(signature)
    }
}

struct DeterministicStatusSigner;
impl AssertionSigner for DeterministicStatusSigner {
    fn issuer(&self) -> &str {
        ISSUER
    }
    fn key_id(&self) -> &str {
        "current-status-signing-key-v1"
    }
    fn sign(&self, payload: &[u8]) -> Result<String, RuntimeError> {
        let mut digest = Sha256::new();
        digest.update(b"deterministic-status-signing-key\0");
        digest.update(payload);
        Ok(format!("sha256:{:x}", digest.finalize()))
    }
}

#[test]
fn assertion_contains_only_pairwise_device_context_and_current_epochs() {
    let (mut runtime, service, device, session) = seeded_runtime();
    let assertion = runtime
        .issue_device_identity_evidence(assertion_request(
            &service, &device, &session, "nonce-a", 300,
        ))
        .unwrap()
        .assertion;
    assert_eq!(assertion.schema, DEVICE_ASSERTION_SCHEMA);
    assert_eq!(assertion.issuer, ISSUER);
    assert_eq!(assertion.audience, AUDIENCE);
    assert_eq!(assertion.revocation_epochs.subject, INITIAL_EPOCH);
    assert_eq!(assertion.revocation_epochs.service, INITIAL_EPOCH);
    assert_eq!(assertion.revocation_epochs.device, INITIAL_EPOCH);
    assert_eq!(assertion.revocation_epochs.session, INITIAL_EPOCH);
    assert_eq!(
        assertion.expires_at_epoch_s - assertion.issued_at_epoch_s,
        300
    );
    let json = serde_json::to_string(&assertion).unwrap();
    assert!(!json.contains("account-a"));
    assert!(!json.contains("external_subject"));
    assert!(!json.contains("secret"));
    verify_assertion_at(&assertion, &DeterministicVerifier, ISSUER, AUDIENCE, NOW).unwrap();
    assert_eq!(decode_assertion_strict(json.as_bytes()).unwrap(), assertion);
}

#[test]
fn assertion_is_one_nonce_and_only_for_current_active_state() {
    let (mut runtime, service, device, session) = seeded_runtime();
    let request = assertion_request(&service, &device, &session, "nonce-once", 60);
    runtime
        .issue_device_identity_evidence(request.clone())
        .unwrap();
    assert_eq!(
        runtime.issue_device_identity_evidence(request).unwrap_err(),
        RuntimeError::ReplayDetected
    );
    runtime
        .revoke(RevokeRequest {
            command_id: "revoke-session-for-assertion".into(),
            target: RevocationTarget::Session {
                account_id: "account-a".into(),
                service_id: "service-a".into(),
                session_id: session.session_id.clone(),
            },
            expected_epoch: session.session_epoch,
            authority_id: "identity-authority".into(),
        })
        .unwrap();
    assert_eq!(
        runtime
            .issue_device_identity_evidence(assertion_request(
                &service,
                &device,
                &session,
                "nonce-after-revoke",
                60
            ))
            .unwrap_err(),
        RuntimeError::SessionRevoked
    );
}
