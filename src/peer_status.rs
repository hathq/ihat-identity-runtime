use std::path::Path;

use crate::{
    LifecycleStatus, RuntimeError, audit,
    state::{State, service_key},
    store::{DurableState, FileDurableState, decode_state},
    validation::id,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DevicePeerStatus {
    pub active: bool,
    pub device_epoch: u64,
    pub posture_revision: u64,
}

/// Reads one exact service-local device status from the durable authority state.
///
/// This inspection exposes no account identifier, session identifier, key material,
/// or mutation capability. The durable image, rollback anchor, and audit chain are
/// verified on every call.
///
/// # Errors
///
/// Returns an error for an invalid or ambiguous binding, missing state, unsafe path,
/// rollback, tampering, or audit failure.
pub fn read_device_peer_status(
    path: impl AsRef<Path>,
    service_id: &str,
    pairwise_subject: &str,
    device_id: &str,
) -> Result<DevicePeerStatus, RuntimeError> {
    id(service_id, "peer_status.service_id")?;
    id(pairwise_subject, "peer_status.pairwise_subject")?;
    id(device_id, "peer_status.device_id")?;
    let store = FileDurableState::open(path)?;
    let image = store.read()?.ok_or(RuntimeError::PersistenceFailure)?;
    let state = decode_state(&image)?;
    audit::verify(&state.audit)?;
    current(&state, service_id, pairwise_subject, device_id)
}

fn current(
    state: &State,
    service_id: &str,
    pairwise_subject: &str,
    device_id: &str,
) -> Result<DevicePeerStatus, RuntimeError> {
    let mut matches = state.devices.values().filter(|value| {
        value.service_id == service_id
            && value.pairwise_subject == pairwise_subject
            && value.device_id == device_id
    });
    let device = matches
        .next()
        .ok_or(RuntimeError::NotFound("peer_device"))?;
    if matches.next().is_some() {
        return Err(RuntimeError::PersistenceFailure);
    }
    let account = state
        .accounts
        .get(&device.account_id)
        .ok_or(RuntimeError::PersistenceFailure)?;
    let service = state
        .services
        .get(&service_key(&device.account_id, service_id))
        .ok_or(RuntimeError::PersistenceFailure)?;
    if service.pairwise_subject != pairwise_subject {
        return Err(RuntimeError::PersistenceFailure);
    }
    Ok(DevicePeerStatus {
        active: !state.revoked_subjects.contains(&account.account_id)
            && service.status == LifecycleStatus::Active
            && device.status == LifecycleStatus::Active
            && device.posture == "compliant",
        device_epoch: device.device_epoch,
        posture_revision: device.posture_revision,
    })
}
