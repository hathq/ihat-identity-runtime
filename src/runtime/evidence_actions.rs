use crate::{
    DeviceIdentityAssertionRequest, EvidenceKind, RecoveryApproval, RecoveryRequest,
    RevocationPreparationAction, RevocationPreparationHandle, RevokeRequest, RuntimeError,
    SessionProof, SessionRequest,
};

use super::IdentityRuntime;

impl IdentityRuntime {
    pub(crate) fn verify_session_issue(
        &self,
        request: &SessionRequest,
    ) -> Result<(), RuntimeError> {
        self.verify_optional_window(
            EvidenceKind::SessionSenderProof,
            self.trust.session.verify_issue(request),
        )
    }

    pub(crate) fn verify_session_authorization(
        &self,
        proof: &SessionProof,
    ) -> Result<(), RuntimeError> {
        self.verify_optional_window(
            EvidenceKind::SessionSenderProof,
            self.trust.session.verify_authorization(proof),
        )
    }

    pub(crate) fn verify_assertion_sender(
        &self,
        request: &DeviceIdentityAssertionRequest,
    ) -> Result<(), RuntimeError> {
        self.verify_optional_window(
            EvidenceKind::SessionSenderProof,
            self.trust.session.verify_assertion(request),
        )
    }

    pub(crate) fn verify_revocation_authority(
        &self,
        request: &RevokeRequest,
    ) -> Result<(), RuntimeError> {
        self.verify_optional_window(
            EvidenceKind::RevocationAuthority,
            self.trust.revocation.verify(request),
        )
    }

    pub(crate) fn verify_revocation_preparation(
        &self,
        action: RevocationPreparationAction,
        handle: &RevocationPreparationHandle,
        request: &RevokeRequest,
    ) -> Result<(), RuntimeError> {
        self.trust
            .revocation_preparation
            .verify(action, handle, request)
            .then_some(())
            .ok_or(RuntimeError::EvidenceUnverified(
                EvidenceKind::RevocationExecutionAuthorization,
            ))
    }

    pub(crate) fn verify_recovery_approval(
        &self,
        request: &RecoveryRequest,
        approval: &RecoveryApproval,
    ) -> Result<(), RuntimeError> {
        let verified = self.trust.recovery.verify(request, approval).ok_or(
            RuntimeError::EvidenceUnverified(EvidenceKind::RecoveryApproval),
        )?;
        if verified.issued_at_epoch_s != approval.approved_at {
            return Err(RuntimeError::EvidenceUnverified(
                EvidenceKind::RecoveryApproval,
            ));
        }
        self.verify_window(EvidenceKind::RecoveryApproval, verified)
    }
}
