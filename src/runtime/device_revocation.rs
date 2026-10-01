use crate::{
    LifecycleStatus, RevocationReceipt, RevocationScope, RevocationTarget, RevokeDeviceRequest,
    RevokeRequest, RuntimeError, state::device_key,
};

use super::{IdentityRuntime, guards};

impl IdentityRuntime {
    /// Atomically revokes one device and every active session bound to it.
    ///
    /// # Errors
    /// Rejects invalid authority evidence, stale epochs, overflow, or persistence failure.
    pub fn revoke_device(
        &mut self,
        request: RevokeDeviceRequest,
    ) -> Result<RevocationReceipt, RuntimeError> {
        self.revoke(RevokeRequest {
            command_id: request.command_id,
            target: RevocationTarget::Device {
                account_id: request.account_id,
                service_id: request.service_id,
                device_id: request.device_id,
            },
            expected_epoch: request.expected_device_epoch,
            authority_id: request.authority_id,
        })
    }
}

pub(super) fn apply_device_revocation(
    state: &mut crate::state::State,
    account_id: &str,
    service_id: &str,
    device_id: &str,
    expected_epoch: u64,
) -> Result<(u64, u64), RuntimeError> {
    let key = device_key(account_id, service_id, device_id);
    let device = state
        .devices
        .get(&key)
        .ok_or(RuntimeError::NotFound("device"))?;
    guards::epoch(RevocationScope::Device, expected_epoch, device.device_epoch)?;
    let previous = device.device_epoch;
    previous
        .checked_add(1)
        .ok_or(RuntimeError::PersistenceFailure)?;
    let sessions = state
        .sessions
        .iter()
        .filter(|(_, session)| {
            session.account_id == account_id
                && session.service_id == service_id
                && session.device_id == device_id
                && session.status == LifecycleStatus::Active
        })
        .map(|(key, session)| {
            session
                .session_epoch
                .checked_add(1)
                .ok_or(RuntimeError::PersistenceFailure)?;
            Ok(key.clone())
        })
        .collect::<Result<Vec<_>, RuntimeError>>()?;
    let device = state
        .devices
        .get_mut(&key)
        .ok_or(RuntimeError::NotFound("device"))?;
    device.device_epoch = previous + 1;
    device.status = LifecycleStatus::Revoked;
    for key in &sessions {
        let session = state
            .sessions
            .get_mut(key)
            .ok_or(RuntimeError::PersistenceFailure)?;
        session.session_epoch += 1;
        session.status = LifecycleStatus::Revoked;
    }
    let count = u64::try_from(sessions.len()).map_err(|_| RuntimeError::PersistenceFailure)?;
    Ok((previous, count))
}
