use crate::{
    InitialBootstrapRequest, RuntimeError,
    hash::digest_fields,
    validation::{device_key, external, id, text},
};

pub(super) fn validate(value: &InitialBootstrapRequest) -> Result<(), RuntimeError> {
    for (value, field) in [
        (&value.command_id, "command_id"),
        (&value.account_id, "account_id"),
        (&value.service_id, "service_id"),
        (&value.device_id, "device_id"),
        (&value.session_id, "session_id"),
        (&value.sender_key_fingerprint, "sender_key_fingerprint"),
        (&value.bundle.bundle_id, "bootstrap.bundle_id"),
        (&value.bundle.root_key_id, "bootstrap.root_key_id"),
    ] {
        id(value, field)?;
    }
    external(&value.primary_identity)?;
    device_key(&value.proof_key)?;
    text(&value.bundle.signature, "bootstrap.signature", 1_024)?;
    if value.sender_key_fingerprint != value.proof_key.fingerprint {
        return Err(RuntimeError::SenderBindingMismatch);
    }
    let lifetime = value
        .bundle
        .expires_at_epoch_s
        .checked_sub(value.bundle.issued_at_epoch_s)
        .ok_or(RuntimeError::InvalidRequest("bootstrap_window"))?;
    if lifetime > 300 {
        return Err(RuntimeError::InvalidRequest("bootstrap_window"));
    }
    Ok(())
}

pub(super) fn digest(value: &InitialBootstrapRequest) -> Result<String, RuntimeError> {
    let identity = serde_json::to_vec(&value.primary_identity)
        .map_err(|_| RuntimeError::PersistenceFailure)?;
    let proof_key =
        serde_json::to_vec(&value.proof_key).map_err(|_| RuntimeError::PersistenceFailure)?;
    let issued = value.bundle.issued_at_epoch_s.to_string();
    let expires = value.bundle.expires_at_epoch_s.to_string();
    Ok(digest_fields(
        "ihat-initial-bootstrap-request-v1",
        &[
            value.command_id.as_bytes(),
            value.account_id.as_bytes(),
            &identity,
            value.service_id.as_bytes(),
            value.device_id.as_bytes(),
            &proof_key,
            value.session_id.as_bytes(),
            value.sender_key_fingerprint.as_bytes(),
            value.bundle.bundle_id.as_bytes(),
            value.bundle.root_key_id.as_bytes(),
            issued.as_bytes(),
            expires.as_bytes(),
            value.bundle.signature.as_bytes(),
        ],
    ))
}
