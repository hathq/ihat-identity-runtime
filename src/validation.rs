use crate::{
    DeviceKeyCustody, DeviceProofKey, ExternalIdentity, FreshAuthentication, RuntimeError,
};

pub const INITIAL_EPOCH: u64 = 1;
pub const MAX_ID_BYTES: usize = 128;
pub const MAX_PUBLIC_KEY_BYTES: usize = 4096;
pub const MAX_ATTESTATION_BYTES: usize = 8192;
pub const MAX_WIRE_BYTES: usize = 16 * 1024;
pub const MAX_DEVICES_PER_ACCOUNT: usize = 64;
pub const MAX_ACCOUNTS: usize = 64;
pub const MAX_IDENTITIES_PER_ACCOUNT: usize = 16;
pub const MAX_SERVICES_PER_ACCOUNT: usize = 64;
pub const MAX_SESSIONS_PER_DEVICE: usize = 64;
pub const MAX_RECOVERY_APPROVALS: usize = 4;

pub(crate) fn id(value: &str, field: &'static str) -> Result<(), RuntimeError> {
    if value.len() > MAX_ID_BYTES {
        return Err(RuntimeError::LimitExceeded {
            field,
            limit: MAX_ID_BYTES,
        });
    }
    if value.is_empty()
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._:/".contains(&b))
    {
        return Err(RuntimeError::InvalidIdentifier(field));
    }
    Ok(())
}

pub(crate) fn text(value: &str, field: &'static str, limit: usize) -> Result<(), RuntimeError> {
    if value.is_empty() || value.len() > limit || value.chars().any(char::is_control) {
        return Err(RuntimeError::LimitExceeded { field, limit });
    }
    Ok(())
}

pub(crate) fn fresh(value: &FreshAuthentication) -> Result<(), RuntimeError> {
    id(&value.proof_id, "authentication.proof_id")?;
    id(&value.authenticator_id, "authentication.authenticator_id")?;
    id(
        &value.authenticator_key_fingerprint,
        "authentication.key_fingerprint",
    )?;
    if !value.user_verified
        || value.expires_at <= value.issued_at
        || value.expires_at - value.issued_at > 300
    {
        return Err(RuntimeError::FreshAuthenticationRequired);
    }
    Ok(())
}

pub(crate) fn external(value: &ExternalIdentity) -> Result<(), RuntimeError> {
    text(&value.issuer, "identity.issuer", 512)?;
    text(&value.subject, "identity.subject", 512)?;
    if value
        .email
        .as_ref()
        .is_some_and(|v| text(v, "identity.email", 256).is_err())
        || value
            .display_name
            .as_ref()
            .is_some_and(|v| text(v, "identity.display_name", 256).is_err())
    {
        return Err(RuntimeError::InvalidRequest("identity.attributes"));
    }
    Ok(())
}

pub(crate) fn device_key(value: &DeviceProofKey) -> Result<(), RuntimeError> {
    id(&value.fingerprint, "device.key_fingerprint")?;
    match value.custody {
        DeviceKeyCustody::SyncedPasskey => {
            return Err(RuntimeError::SyncedPasskeyIsNotDeviceIdentity);
        }
        DeviceKeyCustody::Exportable => return Err(RuntimeError::ExportableDeviceKey),
        DeviceKeyCustody::HardwareNonExportable | DeviceKeyCustody::SoftwareNonExportable => {}
    }
    if value.spki.is_empty() || value.spki.len() > MAX_PUBLIC_KEY_BYTES {
        return Err(RuntimeError::LimitExceeded {
            field: "device_public_key",
            limit: MAX_PUBLIC_KEY_BYTES,
        });
    }
    if value.attestation.is_empty() || value.attestation.len() > MAX_ATTESTATION_BYTES {
        return Err(RuntimeError::LimitExceeded {
            field: "device_attestation",
            limit: MAX_ATTESTATION_BYTES,
        });
    }
    Ok(())
}
