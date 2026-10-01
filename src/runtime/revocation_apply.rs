use crate::{
    LifecycleStatus, RevocationScope, RevocationTarget, RevokeRequest, RuntimeError,
    state::{service_key, session_key},
};

use super::guards;

pub(super) fn apply(
    state: &mut crate::state::State,
    request: &RevokeRequest,
) -> Result<(u64, u64), RuntimeError> {
    match &request.target {
        RevocationTarget::Subject { account_id } => {
            let record = state
                .accounts
                .get_mut(account_id)
                .ok_or(RuntimeError::NotFound("account"))?;
            guards::epoch(
                RevocationScope::Subject,
                request.expected_epoch,
                record.subject_epoch,
            )?;
            let previous = record.subject_epoch;
            record.subject_epoch = previous
                .checked_add(1)
                .ok_or(RuntimeError::PersistenceFailure)?;
            state.revoked_subjects.insert(account_id.clone());
            Ok((previous, 0))
        }
        RevocationTarget::ServiceAccount {
            account_id,
            service_id,
        } => {
            let key = service_key(account_id, service_id);
            let record = state
                .services
                .get_mut(&key)
                .ok_or(RuntimeError::NotFound("service_account"))?;
            guards::epoch(
                RevocationScope::ServiceAccount,
                request.expected_epoch,
                record.service_epoch,
            )?;
            let previous = record.service_epoch;
            record.service_epoch = previous
                .checked_add(1)
                .ok_or(RuntimeError::PersistenceFailure)?;
            record.status = LifecycleStatus::Closed;
            revoke_service_descendants(state, account_id, service_id)?;
            Ok((previous, 0))
        }
        RevocationTarget::Device {
            account_id,
            service_id,
            device_id,
        } => super::device_revocation::apply_device_revocation(
            state,
            account_id,
            service_id,
            device_id,
            request.expected_epoch,
        ),
        RevocationTarget::Session {
            account_id,
            service_id,
            session_id,
        } => {
            let key = session_key(account_id, service_id, session_id);
            let record = state
                .sessions
                .get_mut(&key)
                .ok_or(RuntimeError::NotFound("session"))?;
            guards::epoch(
                RevocationScope::Session,
                request.expected_epoch,
                record.session_epoch,
            )?;
            let previous = record.session_epoch;
            record.session_epoch = previous
                .checked_add(1)
                .ok_or(RuntimeError::PersistenceFailure)?;
            record.status = LifecycleStatus::Revoked;
            Ok((previous, 0))
        }
    }
}

fn revoke_service_descendants(
    state: &mut crate::state::State,
    account: &str,
    service: &str,
) -> Result<(), RuntimeError> {
    if state
        .devices
        .values()
        .filter(|value| value.account_id == account && value.service_id == service)
        .any(|value| value.device_epoch == u64::MAX)
        || state
            .sessions
            .values()
            .filter(|value| value.account_id == account && value.service_id == service)
            .any(|value| value.session_epoch == u64::MAX)
    {
        return Err(RuntimeError::PersistenceFailure);
    }
    for device in state
        .devices
        .values_mut()
        .filter(|value| value.account_id == account && value.service_id == service)
    {
        device.status = LifecycleStatus::Revoked;
        device.device_epoch += 1;
    }
    for session in state
        .sessions
        .values_mut()
        .filter(|value| value.account_id == account && value.service_id == service)
    {
        session.status = LifecycleStatus::Revoked;
        session.session_epoch += 1;
    }
    Ok(())
}
