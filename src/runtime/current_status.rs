use crate::{
    AssertionSigner, CURRENT_DEVICE_STATUS_SCHEMA, CurrentDeviceStatusV1,
    DeviceIdentityAssertionV1, RuntimeError, canonical_current_status_payload,
    decode_current_status_strict,
};

pub(super) fn build(
    assertion: &DeviceIdentityAssertionV1,
    signer: &dyn AssertionSigner,
) -> Result<CurrentDeviceStatusV1, RuntimeError> {
    if signer.issuer() != assertion.issuer || signer.key_id() == assertion.key_id {
        return Err(RuntimeError::InvalidRequest("identity_signer_separation"));
    }
    let maximum_expiry = assertion
        .issued_at_epoch_s
        .checked_add(30)
        .ok_or(RuntimeError::InvalidRequest("current_status_time"))?;
    let mut status = CurrentDeviceStatusV1 {
        schema: CURRENT_DEVICE_STATUS_SCHEMA.into(),
        issuer: assertion.issuer.clone(),
        audience: assertion.audience.clone(),
        service_id: assertion.service_id.clone(),
        pairwise_subject: assertion.pairwise_subject.clone(),
        device_id: assertion.device_id.clone(),
        device_proof_key_ref: assertion.device_proof_key_ref.clone(),
        session_ref: assertion.session_ref.clone(),
        device_posture: assertion.device_posture.clone(),
        revocation_epochs: assertion.revocation_epochs.clone(),
        issued_at_epoch_s: assertion.issued_at_epoch_s,
        expires_at_epoch_s: assertion.expires_at_epoch_s.min(maximum_expiry),
        nonce: assertion.nonce.clone(),
        key_id: signer.key_id().into(),
        signature: String::new(),
    };
    status.signature = signer.sign(&canonical_current_status_payload(&status))?;
    let wire = serde_json::to_vec(&status)
        .map_err(|_| RuntimeError::InvalidRequest("current_device_status"))?;
    decode_current_status_strict(&wire)
        .map_err(|_| RuntimeError::InvalidRequest("current_device_status"))?;
    Ok(status)
}
