// Acceptance ledger: ID-13 ID-14 ID-15 ID-16 ID-17 ID-18 ID-19 ID-20 ID-21
// ID-22 ID-23 ID-24 ID-25 ID-26 ID-27 ID-28 ID-29 ID-30.

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU8, Ordering},
};

use serde_json::Value;
use sha2::{Digest, Sha256};
use support::*;

const VALID: u8 = 0;
const REJECT: u8 = 1;
const EXPIRED: u8 = 2;
const FUTURE: u8 = 3;
const INVALID: u8 = 4;

#[derive(Default)]
struct Controls {
    authentication: AtomicU8,
    attestation: AtomicU8,
    possession: AtomicU8,
    session: AtomicU8,
    revocation: AtomicU8,
    recovery: AtomicU8,
    bootstrap: AtomicU8,
    authentication_operations: Mutex<Vec<AuthenticationOperation>>,
}

#[derive(Clone)]
struct ScriptedVerifier(Arc<Controls>);

impl ScriptedVerifier {
    fn outcome(&self, value: &AtomicU8) -> Option<VerifiedEvidenceWindow> {
        match value.load(Ordering::SeqCst) {
            REJECT => None,
            EXPIRED => Some(VerifiedEvidenceWindow::new(TEST_NOW - 60, TEST_NOW)),
            FUTURE => Some(VerifiedEvidenceWindow::new(TEST_NOW + 1, TEST_NOW + 60)),
            INVALID => Some(VerifiedEvidenceWindow::new(TEST_NOW + 1, TEST_NOW + 1)),
            _ => Some(test_window()),
        }
    }
}

impl AuthenticationVerifier for ScriptedVerifier {
    fn verify(
        &self,
        evidence: &FreshAuthentication,
        context: &AuthenticationContext<'_>,
    ) -> Option<VerifiedEvidenceWindow> {
        self.0
            .authentication_operations
            .lock()
            .unwrap()
            .push(context.operation);
        if self.0.authentication.load(Ordering::SeqCst) == VALID {
            Some(VerifiedEvidenceWindow::new(
                evidence.issued_at,
                evidence.expires_at,
            ))
        } else {
            self.outcome(&self.0.authentication)
        }
    }
}

#[test]
fn every_authentication_bearing_mutation_invokes_the_bound_context_verifier() {
    let (mut runtime, controls) = runtime_and_controls();
    runtime
        .create_account(account_request("account-a", "create-a"))
        .unwrap();
    runtime
        .link_identity(AccountLinkRequest {
            command_id: "link-a".into(),
            account_id: "account-a".into(),
            incoming_identity: external_identity("https://issuer-b.invalid", "subject-b"),
            evidence: AccountLinkEvidence::DualFreshAuthentication {
                existing_identity: authentication("link-existing", "auth-key-a"),
                incoming_identity: authentication("link-incoming", "auth-key-b"),
            },
        })
        .unwrap();
    let service = runtime
        .create_service_account(service_request("account-a", "service-a"))
        .unwrap();
    let device = enroll(&mut runtime, "account-a", &service, "device-a", "key-old");
    runtime
        .rotate_device_key(rotation(&device, "key-new"))
        .unwrap();
    runtime
        .recover_device(recovery(&service, "recover-a"))
        .unwrap();
    runtime
        .close_service_account(CloseServiceAccountRequest {
            command_id: "close-a".into(),
            account_id: "account-a".into(),
            service_id: "service-a".into(),
            fresh_user_authentication: authentication("close-proof", "auth-key-a"),
            expected_service_epoch: service.service_epoch,
        })
        .unwrap();
    let operations = controls.authentication_operations.lock().unwrap();
    for expected in [
        AuthenticationOperation::AccountCreation,
        AuthenticationOperation::ExistingIdentityLink,
        AuthenticationOperation::IncomingIdentityLink,
        AuthenticationOperation::ServiceAccountCreation,
        AuthenticationOperation::DeviceEnrollment,
        AuthenticationOperation::DeviceKeyRotation,
        AuthenticationOperation::DeviceRecovery,
        AuthenticationOperation::ServiceAccountClosure,
    ] {
        assert!(operations.contains(&expected), "missing {expected:?}");
    }
}
