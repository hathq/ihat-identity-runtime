use crate::{
    EstablishDeviceIdentitySessionRequest, LifecycleStatus, RevocationScope, RuntimeError,
    SessionRecord,
    state::{device_key, session_key},
};

use super::{IdentityRuntime, current_identity_session_request, guards};

impl IdentityRuntime {
    pub fn establish_device_identity_session(
        &mut self,
        request: EstablishDeviceIdentitySessionRequest,
    ) -> Result<SessionRecord, RuntimeError> {
        current_identity_session_request::validate(&request)?;
        let proof = current_identity_session_request::session_request(&request);
        self.verify_session_issue(&proof)?;
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
        if service.status != LifecycleStatus::Active {
            return Err(RuntimeError::ServiceAccountClosed);
        }
        guards::epoch(
            RevocationScope::ServiceAccount,
            request.expected_service_epoch,
            service.service_epoch,
        )?;
        let device = self.device_for_session(&proof)?;
        if device.status != LifecycleStatus::Active || device.posture != "compliant" {
            return Err(RuntimeError::DeviceRevoked);
        }
        if self
            .state
            .retired_keys
            .contains(&request.sender_key_fingerprint)
        {
            return Err(RuntimeError::RetiredDeviceKey);
        }
        if request.sender_key_fingerprint != device.key_fingerprint {
            return Err(RuntimeError::SenderBindingMismatch);
        }
        guards::epoch(
            RevocationScope::Device,
            request.expected_device_epoch,
            device.device_epoch,
        )?;
        let key = session_key(
            &request.account_id,
            &request.service_id,
            &request.session_id,
        );
        if self.state.sessions.contains_key(&key) {
            return Err(RuntimeError::AlreadyExists("session"));
        }
        let previous = self.expected_identity_session_key(
            &request.account_id,
            &request.service_id,
            &request.device_id,
            &request.expected_current_session,
        )?;
        let replacing_active = previous.as_ref().is_some_and(|key| {
            self.state
                .sessions
                .get(key)
                .is_some_and(|session| session.status == LifecycleStatus::Active)
        });
        self.ensure_session_capacity_replacing(&proof, replacing_active)?;
        let session_ref = self.fresh_session_ref(&request.service_id)?;
        let before = self.before();
        if let Some(previous) = previous {
            let session = self
                .state
                .sessions
                .get_mut(&previous)
                .ok_or(RuntimeError::AuditIntegrityViolation)?;
            if session.status == LifecycleStatus::Active {
                session.session_epoch = session
                    .session_epoch
                    .checked_add(1)
                    .ok_or(RuntimeError::PersistenceFailure)?;
                session.status = LifecycleStatus::Revoked;
            }
        }
        let output = SessionRecord {
            account_id: request.account_id.clone(),
            service_id: request.service_id.clone(),
            pairwise_subject: request.pairwise_subject,
            device_id: request.device_id.clone(),
            session_id: request.session_id,
            session_ref,
            sender_key_fingerprint: request.sender_key_fingerprint,
            session_epoch: crate::INITIAL_EPOCH,
            status: LifecycleStatus::Active,
        };
        self.state.sessions.insert(key.clone(), output.clone());
        self.state.current_identity_sessions.insert(
            device_key(&request.account_id, &request.service_id, &request.device_id),
            key,
        );
        self.consume(&[&request.command_id, &request.proof_id]);
        self.finish(
            before,
            "device-identity-session-established",
            &request.command_id,
        )?;
        Ok(output)
    }
}
