use crate::{DeviceRecord, LifecycleStatus, RuntimeError, ServiceAccountRecord};

use super::IdentityRuntime;

pub(super) fn unique_service(
    runtime: &IdentityRuntime,
    service: &str,
    subject: &str,
) -> Result<ServiceAccountRecord, RuntimeError> {
    let mut values = runtime
        .state
        .services
        .values()
        .filter(|value| value.service_id == service && value.pairwise_subject == subject);
    let value = values
        .next()
        .cloned()
        .ok_or(RuntimeError::NotFound("service"))?;
    if values.next().is_some() {
        return Err(RuntimeError::AuditIntegrityViolation);
    }
    Ok(value)
}

pub(super) fn validate_device(
    runtime: &IdentityRuntime,
    device: &DeviceRecord,
    sender: &str,
) -> Result<(), RuntimeError> {
    if device.status != LifecycleStatus::Active || device.posture != "compliant" {
        return Err(RuntimeError::DeviceRevoked);
    }
    if runtime.state.retired_keys.contains(sender) {
        return Err(RuntimeError::RetiredDeviceKey);
    }
    if device.key_fingerprint != sender {
        return Err(RuntimeError::SenderBindingMismatch);
    }
    Ok(())
}
