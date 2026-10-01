use crate::{
    LifecycleStatus, RevocationScope, RuntimeError, SessionRecord, SessionRequest,
    state::session_key, validation::id,
};

use super::{IdentityRuntime, guards};

impl IdentityRuntime {
    pub fn issue_session(
        &mut self,
        request: SessionRequest,
    ) -> Result<SessionRecord, RuntimeError> {
        validate_request_ids(&request)?;
        self.verify_session_issue(&request)?;
        self.unused(&[&request.command_id, &request.proof_id])?;
        let account = guards::account(&self.state, &request.account_id)?;
        if self.state.revoked_subjects.contains(&request.account_id) {
            return Err(RuntimeError::SubjectRevoked);
        }
        guards::epoch(
            RevocationScope::Subject,
            request.expected_subject_epoch,
            account.subject_epoch,
        )?;
        let service = guards::bound_service(
            &self.state,
            &request.account_id,
            &request.service_id,
            &request.pairwise_subject,
        )?;
        if service.status == LifecycleStatus::Closed {
            return Err(RuntimeError::ServiceAccountClosed);
        }
        guards::epoch(
            RevocationScope::ServiceAccount,
            request.expected_service_epoch,
            service.service_epoch,
        )?;
        let device = self.device_for_session(&request)?;
        if device.status != LifecycleStatus::Active {
            return Err(RuntimeError::DeviceRevoked);
        }
        if request.sender_key_fingerprint != device.key_fingerprint {
            return Err(RuntimeError::SenderBindingMismatch);
        }
        guards::epoch(
            RevocationScope::Device,
            request.expected_device_epoch,
            device.device_epoch,
        )?;
        self.ensure_session_capacity(&request)?;
        let key = session_key(
            &request.account_id,
            &request.service_id,
            &request.session_id,
        );
        if self.state.sessions.contains_key(&key) {
            return Err(RuntimeError::AlreadyExists("session"));
        }
        let session_ref = self.fresh_session_ref(&request.service_id)?;
        let before = self.before();
        let record = SessionRecord {
            account_id: request.account_id.clone(),
            service_id: request.service_id.clone(),
            pairwise_subject: request.pairwise_subject,
            device_id: request.device_id,
            session_id: request.session_id,
            session_ref,
            sender_key_fingerprint: request.sender_key_fingerprint,
            session_epoch: crate::INITIAL_EPOCH,
            status: LifecycleStatus::Active,
        };
        self.state.sessions.insert(key, record.clone());
        self.consume(&[&request.command_id, &request.proof_id]);
        self.finish(before, "session-issued", &request.command_id)?;
        Ok(record)
    }
}

fn validate_request_ids(value: &SessionRequest) -> Result<(), RuntimeError> {
    for (value, field) in [
        (&value.command_id, "command_id"),
        (&value.account_id, "account_id"),
        (&value.service_id, "service_id"),
        (&value.pairwise_subject, "pairwise_subject"),
        (&value.device_id, "device_id"),
        (&value.session_id, "session_id"),
        (&value.sender_key_fingerprint, "sender_key_fingerprint"),
        (&value.proof_id, "proof_id"),
    ] {
        id(value, field)?;
    }
    Ok(())
}
