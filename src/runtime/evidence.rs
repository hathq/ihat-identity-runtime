use crate::{
    AuthenticationContext, EvidenceKind, FreshAuthentication, RuntimeError, VerifiedEvidenceWindow,
};

use super::IdentityRuntime;

impl IdentityRuntime {
    pub(crate) fn verify_authentication(
        &self,
        evidence: &FreshAuthentication,
        context: AuthenticationContext<'_>,
    ) -> Result<(), RuntimeError> {
        let verified = self.trust.authentication.verify(evidence, &context).ok_or(
            RuntimeError::EvidenceUnverified(EvidenceKind::Authentication),
        )?;
        let declared = VerifiedEvidenceWindow::new(evidence.issued_at, evidence.expires_at);
        if verified != declared {
            return Err(RuntimeError::EvidenceUnverified(
                EvidenceKind::Authentication,
            ));
        }
        self.verify_window(EvidenceKind::Authentication, verified)
    }

    pub(crate) fn verify_optional_window(
        &self,
        kind: EvidenceKind,
        verified: Option<VerifiedEvidenceWindow>,
    ) -> Result<(), RuntimeError> {
        let verified = verified.ok_or(RuntimeError::EvidenceUnverified(kind))?;
        self.verify_window(kind, verified)
    }

    pub(crate) fn verify_window(
        &self,
        kind: EvidenceKind,
        verified: VerifiedEvidenceWindow,
    ) -> Result<(), RuntimeError> {
        if verified.expires_at_epoch_s <= verified.issued_at_epoch_s {
            return Err(RuntimeError::EvidenceWindowInvalid(kind));
        }
        let now = self
            .trust
            .clock
            .now_epoch_seconds()
            .map_err(|_| RuntimeError::TrustedClockUnavailable)?;
        if now < verified.issued_at_epoch_s {
            return Err(RuntimeError::EvidenceFromFuture(kind));
        }
        if now >= verified.expires_at_epoch_s {
            return Err(RuntimeError::EvidenceExpired(kind));
        }
        Ok(())
    }
}
