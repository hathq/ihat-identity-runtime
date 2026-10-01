use crate::{
    AccountRecord, CurrentDeviceIdentityAssertionRequest, ExpectedCurrentSession, LifecycleStatus,
    RuntimeError, SessionRecord, state::device_key,
};

use super::{IdentityRuntime, current_identity_context};

impl IdentityRuntime {
    pub(crate) fn resolve_current_identity(
        &self,
        request: &CurrentDeviceIdentityAssertionRequest,
    ) -> Result<(AccountRecord, SessionRecord), RuntimeError> {
        let service = current_identity_context::unique_service(
            self,
            &request.service_id,
            &request.pairwise_subject,
        )?;
        let account = self
            .state
            .accounts
            .get(&service.account_id)
            .cloned()
            .ok_or(RuntimeError::AuditIntegrityViolation)?;
        if self.state.revoked_subjects.contains(&account.account_id) {
            return Err(RuntimeError::SubjectRevoked);
        }
        if service.status != LifecycleStatus::Active {
            return Err(RuntimeError::ServiceAccountClosed);
        }
        let device = self
            .state
            .devices
            .get(&device_key(
                &account.account_id,
                &service.service_id,
                &request.device_id,
            ))
            .cloned()
            .ok_or(RuntimeError::NotFound("device"))?;
        current_identity_context::validate_device(
            self,
            &device,
            &request.session_sender_key_fingerprint,
        )?;
        let session = self.current_identity_session(
            &account.account_id,
            &service.service_id,
            &device.device_id,
        )?;
        if session.account_id != account.account_id
            || session.service_id != service.service_id
            || session.pairwise_subject != service.pairwise_subject
            || session.device_id != device.device_id
        {
            return Err(RuntimeError::AuditIntegrityViolation);
        }
        if session.sender_key_fingerprint != request.session_sender_key_fingerprint {
            return Err(RuntimeError::SenderBindingMismatch);
        }
        if session.status != LifecycleStatus::Active {
            return Err(RuntimeError::SessionRevoked);
        }
        Ok((account, session))
    }

    pub(crate) fn expected_identity_session_key(
        &self,
        account: &str,
        service: &str,
        device: &str,
        expected: &ExpectedCurrentSession,
    ) -> Result<Option<String>, RuntimeError> {
        let pointer = self
            .state
            .current_identity_sessions
            .get(&device_key(account, service, device));
        match (expected, pointer) {
            (ExpectedCurrentSession::Absent, None) => Ok(None),
            (
                ExpectedCurrentSession::Present {
                    session_ref,
                    session_epoch,
                },
                Some(key),
            ) => {
                let session = self
                    .state
                    .sessions
                    .get(key)
                    .ok_or(RuntimeError::AuditIntegrityViolation)?;
                if session.session_ref == *session_ref && session.session_epoch == *session_epoch {
                    Ok(Some(key.clone()))
                } else {
                    Err(RuntimeError::InvalidRequest("current_identity_session_cas"))
                }
            }
            _ => Err(RuntimeError::InvalidRequest("current_identity_session_cas")),
        }
    }

    fn current_identity_session(
        &self,
        account: &str,
        service: &str,
        device: &str,
    ) -> Result<SessionRecord, RuntimeError> {
        let pointer = self
            .state
            .current_identity_sessions
            .get(&device_key(account, service, device))
            .ok_or(RuntimeError::NotFound("current_identity_session"))?;
        self.state
            .sessions
            .get(pointer)
            .cloned()
            .ok_or(RuntimeError::AuditIntegrityViolation)
    }
}
