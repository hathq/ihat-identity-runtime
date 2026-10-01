use crate::{EstablishDeviceIdentitySessionRequest, RuntimeError, SessionRequest, validation::id};

pub(super) fn session_request(value: &EstablishDeviceIdentitySessionRequest) -> SessionRequest {
    SessionRequest {
        command_id: value.command_id.clone(),
        account_id: value.account_id.clone(),
        service_id: value.service_id.clone(),
        pairwise_subject: value.pairwise_subject.clone(),
        device_id: value.device_id.clone(),
        session_id: value.session_id.clone(),
        sender_key_fingerprint: value.sender_key_fingerprint.clone(),
        proof_id: value.proof_id.clone(),
        expected_subject_epoch: value.expected_subject_epoch,
        expected_service_epoch: value.expected_service_epoch,
        expected_device_epoch: value.expected_device_epoch,
    }
}

pub(super) fn validate(value: &EstablishDeviceIdentitySessionRequest) -> Result<(), RuntimeError> {
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
    if value.command_id == value.proof_id {
        return Err(RuntimeError::InvalidRequest(
            "identity_session_replay_alias",
        ));
    }
    Ok(())
}
