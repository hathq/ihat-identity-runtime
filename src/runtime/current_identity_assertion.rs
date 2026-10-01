use crate::{
    CurrentDeviceIdentityAssertionRequest, DeviceIdentityAssertionRequest,
    DeviceIdentityEvidenceV1, MAX_CURRENT_IDENTITY_TTL_SECONDS, RuntimeError,
    validation::{id, text},
};

use super::IdentityRuntime;

impl IdentityRuntime {
    pub fn issue_current_device_identity_evidence(
        &mut self,
        request: CurrentDeviceIdentityAssertionRequest,
    ) -> Result<DeviceIdentityEvidenceV1, RuntimeError> {
        validate(&request)?;
        let (account, session) = self.resolve_current_identity(&request)?;
        self.issue_device_identity_evidence(DeviceIdentityAssertionRequest {
            account_id: account.account_id,
            service_id: request.service_id,
            pairwise_subject: request.pairwise_subject,
            device_id: request.device_id,
            session_id: session.session_id,
            audience: request.audience,
            nonce: request.identity_nonce,
            ttl_seconds: request.ttl_seconds,
            sender_key_fingerprint: request.session_sender_key_fingerprint,
            sender_proof_id: request.session_sender_proof_id,
        })
    }
}

fn validate(value: &CurrentDeviceIdentityAssertionRequest) -> Result<(), RuntimeError> {
    for (value, field) in [
        (&value.service_id, "service_id"),
        (&value.pairwise_subject, "pairwise_subject"),
        (&value.device_id, "device_id"),
        (&value.audience, "audience"),
        (&value.identity_nonce, "identity_nonce"),
        (
            &value.session_sender_key_fingerprint,
            "session_sender_key_fingerprint",
        ),
        (&value.session_sender_proof_id, "session_sender_proof_id"),
    ] {
        id(value, field)?;
    }
    text(&value.audience, "audience", 256)?;
    if value.identity_nonce == value.session_sender_proof_id {
        return Err(RuntimeError::InvalidRequest(
            "current_identity_replay_alias",
        ));
    }
    if !(1..=MAX_CURRENT_IDENTITY_TTL_SECONDS).contains(&value.ttl_seconds) {
        return Err(RuntimeError::InvalidRequest("current_identity_ttl"));
    }
    Ok(())
}
