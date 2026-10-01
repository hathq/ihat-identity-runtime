use crate::{
    AuthenticationOperation, DeviceEnrollment, DeviceRecord, LifecycleStatus, RevocationScope,
    RuntimeError,
    state::device_key as record_key,
    validation::{MAX_DEVICES_PER_ACCOUNT, device_key, fresh, id},
};

use super::{IdentityRuntime, guards};

impl IdentityRuntime {
    pub fn enroll_device(
        &mut self,
        request: DeviceEnrollment,
    ) -> Result<DeviceRecord, RuntimeError> {
        self.validate_enrollment(&request, AuthenticationOperation::DeviceEnrollment)?;
        self.unused(&[&request.command_id, &request.user_authentication.proof_id])?;
        if self.state.devices.values().any(|value| {
            value.account_id == request.account_id && value.device_id == request.device_id
        }) {
            return Err(RuntimeError::AlreadyExists("device"));
        }
        self.ensure_unique_device_key(&request.proof_key.fingerprint)?;
        let count = self
            .state
            .devices
            .values()
            .filter(|value| value.account_id == request.account_id)
            .count();
        if count >= MAX_DEVICES_PER_ACCOUNT {
            return Err(RuntimeError::LimitExceeded {
                field: "devices_per_account",
                limit: MAX_DEVICES_PER_ACCOUNT,
            });
        }
        let before = self.before();
        let record = self.device_record(&request);
        let key = record_key(&request.account_id, &request.service_id, &request.device_id);
        self.state.devices.insert(key, record.clone());
        self.consume(&[&request.command_id, &request.user_authentication.proof_id]);
        self.finish(before, "device-enrolled", &request.command_id)?;
        Ok(record)
    }

    pub(crate) fn validate_enrollment(
        &self,
        request: &DeviceEnrollment,
        operation: AuthenticationOperation,
    ) -> Result<(), RuntimeError> {
        for (value, field) in [
            (&request.command_id, "command_id"),
            (&request.account_id, "account_id"),
            (&request.service_id, "service_id"),
            (&request.pairwise_subject, "pairwise_subject"),
            (&request.device_id, "device_id"),
        ] {
            id(value, field)?;
        }
        fresh(&request.user_authentication)?;
        device_key(&request.proof_key)?;
        self.verify_enrollment_evidence(request, operation)?;
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
        )
    }

    pub(crate) fn ensure_unique_device_key(&self, fingerprint: &str) -> Result<(), RuntimeError> {
        if self.state.retired_keys.contains(fingerprint)
            || self
                .state
                .devices
                .values()
                .any(|value| value.key_fingerprint == fingerprint)
        {
            return Err(RuntimeError::DuplicateDeviceKey);
        }
        Ok(())
    }

    pub(crate) fn device_record(&self, request: &DeviceEnrollment) -> DeviceRecord {
        DeviceRecord {
            account_id: request.account_id.clone(),
            service_id: request.service_id.clone(),
            pairwise_subject: request.pairwise_subject.clone(),
            device_id: request.device_id.clone(),
            key_fingerprint: request.proof_key.fingerprint.clone(),
            posture: "compliant".into(),
            posture_revision: crate::INITIAL_EPOCH,
            device_epoch: crate::INITIAL_EPOCH,
            status: LifecycleStatus::Active,
        }
    }
}
