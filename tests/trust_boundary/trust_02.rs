impl DeviceAttestationVerifier for ScriptedVerifier {
    fn verify_enrollment(
        &self,
        _: &DeviceEnrollment,
        _: DeviceEnrollmentPurpose,
    ) -> Option<VerifiedEvidenceWindow> {
        self.outcome(&self.0.attestation)
    }
    fn verify_rotation(&self, _: &RotateDeviceKeyRequest) -> Option<VerifiedEvidenceWindow> {
        self.outcome(&self.0.attestation)
    }
}

impl DeviceKeyPossessionVerifier for ScriptedVerifier {
    fn verify_enrollment(
        &self,
        _: &DeviceEnrollment,
        _: DeviceEnrollmentPurpose,
    ) -> Option<VerifiedEvidenceWindow> {
        self.outcome(&self.0.possession)
    }
    fn verify_rotation(&self, _: &RotateDeviceKeyRequest) -> Option<VerifiedEvidenceWindow> {
        self.outcome(&self.0.possession)
    }
}

impl SessionSenderProofVerifier for ScriptedVerifier {
    fn verify_issue(&self, _: &SessionRequest) -> Option<VerifiedEvidenceWindow> {
        self.outcome(&self.0.session)
    }
    fn verify_authorization(&self, _: &SessionProof) -> Option<VerifiedEvidenceWindow> {
        self.outcome(&self.0.session)
    }
    fn verify_assertion(
        &self,
        _: &DeviceIdentityAssertionRequest,
    ) -> Option<VerifiedEvidenceWindow> {
        self.outcome(&self.0.session)
    }
}

impl RevocationAuthorityVerifier for ScriptedVerifier {
    fn verify(&self, _: &RevokeRequest) -> Option<VerifiedEvidenceWindow> {
        self.outcome(&self.0.revocation)
    }
}

impl RevocationPreparationVerifier for ScriptedVerifier {
    fn verify(
        &self,
        _: RevocationPreparationAction,
        _: &RevocationPreparationHandle,
        _: &RevokeRequest,
    ) -> bool {
        true
    }
}

impl RecoveryApprovalVerifier for ScriptedVerifier {
    fn verify(
        &self,
        _: &RecoveryRequest,
        approval: &RecoveryApproval,
    ) -> Option<VerifiedEvidenceWindow> {
        match self.0.recovery.load(Ordering::SeqCst) {
            REJECT => None,
            EXPIRED => Some(VerifiedEvidenceWindow::new(approval.approved_at, TEST_NOW)),
            INVALID => Some(VerifiedEvidenceWindow::new(
                approval.approved_at,
                approval.approved_at,
            )),
            _ => Some(VerifiedEvidenceWindow::new(
                approval.approved_at,
                approval.approved_at + 60,
            )),
        }
    }
}

impl InstallerBootstrapVerifier for ScriptedVerifier {
    fn verify(&self, request: &InitialBootstrapRequest) -> Option<VerifiedEvidenceWindow> {
        if self.0.bootstrap.load(Ordering::SeqCst) == VALID {
            Some(VerifiedEvidenceWindow::new(
                request.bundle.issued_at_epoch_s,
                request.bundle.expires_at_epoch_s,
            ))
        } else {
            self.outcome(&self.0.bootstrap)
        }
    }
}

fn runtime_and_controls() -> (IdentityRuntime, Arc<Controls>) {
    let controls = Arc::new(Controls::default());
    let verifier = ScriptedVerifier(controls.clone());
    let trust = RuntimeTrust::new(
        RuntimeVerifiers {
            authentication: Box::new(verifier.clone()),
            attestation: Box::new(verifier.clone()),
            possession: Box::new(verifier.clone()),
            session: Box::new(verifier.clone()),
            revocation: Box::new(verifier.clone()),
            revocation_preparation: Box::new(verifier.clone()),
            recovery: Box::new(verifier.clone()),
            installer_bootstrap: Box::new(verifier),
        },
        Box::new(TestClock(TEST_NOW)),
    );
    (runtime_with_trust(trust), controls)
}
