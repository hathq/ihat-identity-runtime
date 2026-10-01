pub use ihat_identity_runtime::*;
use sha2::{Digest, Sha256};

pub const TEST_NOW: u64 = 1_030;

#[derive(Clone, Copy)]
pub struct TestClock(pub u64);

impl TrustedClock for TestClock {
    fn now_epoch_seconds(&self) -> Result<u64, RuntimeError> {
        Ok(self.0)
    }
}

#[derive(Clone, Copy, Default)]
pub struct TestEvidenceVerifier;

impl AuthenticationVerifier for TestEvidenceVerifier {
    fn verify(
        &self,
        evidence: &FreshAuthentication,
        _context: &AuthenticationContext<'_>,
    ) -> Option<VerifiedEvidenceWindow> {
        Some(VerifiedEvidenceWindow::new(
            evidence.issued_at,
            evidence.expires_at,
        ))
    }
}

impl DeviceAttestationVerifier for TestEvidenceVerifier {
    fn verify_enrollment(
        &self,
        _request: &DeviceEnrollment,
        _purpose: DeviceEnrollmentPurpose,
    ) -> Option<VerifiedEvidenceWindow> {
        Some(test_window())
    }

    fn verify_rotation(&self, _request: &RotateDeviceKeyRequest) -> Option<VerifiedEvidenceWindow> {
        Some(test_window())
    }
}

impl DeviceKeyPossessionVerifier for TestEvidenceVerifier {
    fn verify_enrollment(
        &self,
        _request: &DeviceEnrollment,
        _purpose: DeviceEnrollmentPurpose,
    ) -> Option<VerifiedEvidenceWindow> {
        Some(test_window())
    }

    fn verify_rotation(&self, _request: &RotateDeviceKeyRequest) -> Option<VerifiedEvidenceWindow> {
        Some(test_window())
    }
}

impl SessionSenderProofVerifier for TestEvidenceVerifier {
    fn verify_issue(&self, _request: &SessionRequest) -> Option<VerifiedEvidenceWindow> {
        Some(test_window())
    }

    fn verify_authorization(&self, _proof: &SessionProof) -> Option<VerifiedEvidenceWindow> {
        Some(test_window())
    }

    fn verify_assertion(
        &self,
        _request: &DeviceIdentityAssertionRequest,
    ) -> Option<VerifiedEvidenceWindow> {
        Some(test_window())
    }
}

impl RevocationAuthorityVerifier for TestEvidenceVerifier {
    fn verify(&self, _request: &RevokeRequest) -> Option<VerifiedEvidenceWindow> {
        Some(test_window())
    }
}

impl RevocationPreparationVerifier for TestEvidenceVerifier {
    fn verify(
        &self,
        _action: RevocationPreparationAction,
        _handle: &RevocationPreparationHandle,
        _request: &RevokeRequest,
    ) -> bool {
        true
    }
}

impl RecoveryApprovalVerifier for TestEvidenceVerifier {
    fn verify(
        &self,
        _request: &RecoveryRequest,
        approval: &RecoveryApproval,
    ) -> Option<VerifiedEvidenceWindow> {
        Some(VerifiedEvidenceWindow::new(
            approval.approved_at,
            approval.approved_at + 60,
        ))
    }
}

impl InstallerBootstrapVerifier for TestEvidenceVerifier {
    fn verify(&self, request: &InitialBootstrapRequest) -> Option<VerifiedEvidenceWindow> {
        Some(VerifiedEvidenceWindow::new(
            request.bundle.issued_at_epoch_s,
            request.bundle.expires_at_epoch_s,
        ))
    }
}

pub fn test_window() -> VerifiedEvidenceWindow {
    VerifiedEvidenceWindow::new(TEST_NOW - 30, TEST_NOW + 30)
}

pub fn test_trust() -> RuntimeTrust {
    RuntimeTrust::new(
        RuntimeVerifiers {
            authentication: Box::new(TestEvidenceVerifier),
            attestation: Box::new(TestEvidenceVerifier),
            possession: Box::new(TestEvidenceVerifier),
            session: Box::new(TestEvidenceVerifier),
            revocation: Box::new(TestEvidenceVerifier),
            revocation_preparation: Box::new(TestEvidenceVerifier),
            recovery: Box::new(TestEvidenceVerifier),
            installer_bootstrap: Box::new(TestEvidenceVerifier),
        },
        Box::new(TestClock(TEST_NOW)),
    )
}
