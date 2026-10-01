use crate::{
    AuthorizationDecision, LifecycleStatus, RevocationScope, RuntimeError, SessionProof,
    validation::id,
};

use super::{IdentityRuntime, guards};

impl IdentityRuntime {
    pub fn authorize_session(
        &mut self,
        proof: SessionProof,
    ) -> Result<AuthorizationDecision, RuntimeError> {
        validate_proof_ids(&proof)?;
        self.verify_session_authorization(&proof)?;
        self.unused(&[&proof.proof_id])?;
        let account = guards::account(&self.state, &proof.account_id)?;
        if self.state.revoked_subjects.contains(&proof.account_id) {
            return Err(RuntimeError::SubjectRevoked);
        }
        let service = guards::bound_service(
            &self.state,
            &proof.account_id,
            &proof.service_id,
            &proof.pairwise_subject,
        )?;
        if service.status == LifecycleStatus::Closed {
            return Err(RuntimeError::ServiceAccountClosed);
        }
        if self
            .state
            .retired_keys
            .contains(&proof.sender_key_fingerprint)
        {
            return Err(RuntimeError::RetiredDeviceKey);
        }
        let session = self.session_for_proof(&proof)?;
        if session.status != LifecycleStatus::Active {
            return Err(RuntimeError::SessionRevoked);
        }
        let device = self.device_for_proof(&proof)?;
        if device.status != LifecycleStatus::Active {
            return Err(RuntimeError::DeviceRevoked);
        }
        if proof.sender_key_fingerprint != device.key_fingerprint
            || proof.sender_key_fingerprint != session.sender_key_fingerprint
        {
            return Err(RuntimeError::SenderBindingMismatch);
        }
        guards::epoch(
            RevocationScope::Subject,
            proof.subject_epoch,
            account.subject_epoch,
        )?;
        guards::epoch(
            RevocationScope::ServiceAccount,
            proof.service_epoch,
            service.service_epoch,
        )?;
        guards::epoch(
            RevocationScope::Device,
            proof.device_epoch,
            device.device_epoch,
        )?;
        guards::epoch(
            RevocationScope::Session,
            proof.session_epoch,
            session.session_epoch,
        )?;
        let before = self.before();
        self.consume(&[&proof.proof_id]);
        self.finish(before, "session-authorized", &proof.proof_id)?;
        Ok(AuthorizationDecision::Authorized)
    }
}

fn validate_proof_ids(value: &SessionProof) -> Result<(), RuntimeError> {
    for (value, field) in [
        (&value.proof_id, "proof_id"),
        (&value.account_id, "account_id"),
        (&value.service_id, "service_id"),
        (&value.pairwise_subject, "pairwise_subject"),
        (&value.device_id, "device_id"),
        (&value.session_id, "session_id"),
        (&value.session_ref, "session_ref"),
        (&value.sender_key_fingerprint, "sender_key_fingerprint"),
    ] {
        id(value, field)?;
    }
    Ok(())
}
