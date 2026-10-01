use crate::{
    DEVICE_ASSERTION_SCHEMA, DeviceIdentityAssertionRequest, DeviceIdentityAssertionV1,
    DeviceIdentityEvidenceV1, DevicePostureV1, LifecycleStatus, MAX_ASSERTION_TTL_SECONDS,
    RevocationEpochsV1, RuntimeError, canonical_assertion_payload,
    state::{device_key, session_key},
    validation::{id, text},
};

use super::{IdentityRuntime, guards};

impl IdentityRuntime {
    pub fn issue_device_identity_evidence(
        &mut self,
        request: DeviceIdentityAssertionRequest,
    ) -> Result<DeviceIdentityEvidenceV1, RuntimeError> {
        validate_request(&request)?;
        if request.ttl_seconds == 0 || request.ttl_seconds > MAX_ASSERTION_TTL_SECONDS {
            return Err(RuntimeError::InvalidRequest("assertion_ttl"));
        }
        let nonce_key = format!("device-assertion:{}:{}", request.audience, request.nonce);
        self.unused(&[&nonce_key, &request.sender_proof_id])?;
        let account = guards::account(&self.state, &request.account_id)?;
        if self.state.revoked_subjects.contains(&request.account_id) {
            return Err(RuntimeError::SubjectRevoked);
        }
        let service = guards::bound_service(
            &self.state,
            &request.account_id,
            &request.service_id,
            &request.pairwise_subject,
        )?;
        if service.status != LifecycleStatus::Active {
            return Err(RuntimeError::ServiceAccountClosed);
        }
        let device = self
            .state
            .devices
            .get(&device_key(
                &request.account_id,
                &request.service_id,
                &request.device_id,
            ))
            .cloned()
            .ok_or(RuntimeError::NotFound("device"))?;
        if device.status != LifecycleStatus::Active || device.posture != "compliant" {
            return Err(RuntimeError::DeviceRevoked);
        }
        let session = self
            .state
            .sessions
            .get(&session_key(
                &request.account_id,
                &request.service_id,
                &request.session_id,
            ))
            .cloned()
            .ok_or(RuntimeError::NotFound("session"))?;
        if session.status != LifecycleStatus::Active {
            return Err(RuntimeError::SessionRevoked);
        }
        if session.device_id != device.device_id
            || session.pairwise_subject != service.pairwise_subject
            || session.sender_key_fingerprint != device.key_fingerprint
            || request.sender_key_fingerprint != device.key_fingerprint
            || request.sender_key_fingerprint != session.sender_key_fingerprint
        {
            return Err(RuntimeError::SenderBindingMismatch);
        }
        self.verify_assertion_sender(&request)?;
        let signer = self
            .assertion_signer
            .as_ref()
            .ok_or(RuntimeError::SignerUnavailable)?;
        let status_signer = self
            .status_signer
            .as_ref()
            .ok_or(RuntimeError::StatusSignerUnavailable)?;
        let issued = self
            .trust
            .clock
            .now_epoch_seconds()
            .map_err(|_| RuntimeError::TrustedClockUnavailable)?;
        let expires = issued
            .checked_add(request.ttl_seconds)
            .ok_or(RuntimeError::InvalidRequest("assertion_time"))?;
        let mut assertion = DeviceIdentityAssertionV1 {
            schema: DEVICE_ASSERTION_SCHEMA.into(),
            issuer: signer.issuer().into(),
            audience: request.audience,
            service_id: service.service_id,
            pairwise_subject: service.pairwise_subject,
            device_id: device.device_id,
            device_proof_key_ref: format!("device-proof:{}", device.key_fingerprint),
            session_ref: session.session_ref,
            device_posture: DevicePostureV1 {
                state: device.posture,
                revision: device.posture_revision,
            },
            revocation_epochs: RevocationEpochsV1 {
                subject: account.subject_epoch,
                service: service.service_epoch,
                device: device.device_epoch,
                session: session.session_epoch,
            },
            issued_at_epoch_s: issued,
            expires_at_epoch_s: expires,
            nonce: request.nonce,
            key_id: signer.key_id().into(),
            signature: String::new(),
        };
        assertion.signature = signer.sign(&canonical_assertion_payload(&assertion))?;
        let wire = serde_json::to_vec(&assertion)
            .map_err(|_| RuntimeError::InvalidRequest("device_assertion"))?;
        crate::decode_assertion_strict(&wire)
            .map_err(|_| RuntimeError::InvalidRequest("device_assertion"))?;
        let current_status = super::current_status::build(&assertion, status_signer.as_ref())?;
        let before = self.before();
        self.consume(&[&nonce_key, &request.sender_proof_id]);
        self.finish(before, "device-assertion-issued", &nonce_key)?;
        Ok(DeviceIdentityEvidenceV1 {
            assertion,
            current_status,
        })
    }
}

fn validate_request(value: &DeviceIdentityAssertionRequest) -> Result<(), RuntimeError> {
    for (value, field) in [
        (&value.account_id, "account_id"),
        (&value.service_id, "service_id"),
        (&value.pairwise_subject, "pairwise_subject"),
        (&value.device_id, "device_id"),
        (&value.session_id, "session_id"),
        (&value.audience, "audience"),
        (&value.nonce, "nonce"),
        (&value.sender_key_fingerprint, "sender_key_fingerprint"),
        (&value.sender_proof_id, "sender_proof_id"),
    ] {
        id(value, field)?;
    }
    text(&value.audience, "audience", 256)
}
