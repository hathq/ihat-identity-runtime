use crate::{RevokeRequest, RuntimeError, state, validation};
use std::collections::BTreeSet;

use super::{revocation::MAX_REVOCATION_RECEIPTS, revocation_preparation_capacity};

pub(super) fn preflight(state: &state::State, request: &RevokeRequest) -> Result<(), RuntimeError> {
    validation::id(&request.command_id, "command_id")?;
    validation::id(&request.authority_id, "authority_id")?;
    super::revocation_validation::validate_target(&request.target)?;
    if state
        .revocation_receipts
        .len()
        .saturating_add(state.prepared_revocations.len())
        >= MAX_REVOCATION_RECEIPTS
    {
        return Err(RuntimeError::LimitExceeded {
            field: "revocation_receipts",
            limit: MAX_REVOCATION_RECEIPTS,
        });
    }
    if state.replay.contains(&request.command_id)
        || state.revocation_receipts.contains_key(&request.command_id)
        || state.prepared_revocations.contains_key(&request.command_id)
        || state.prepared_revocations.values().any(|value| {
            super::revocation_preparation_overlap::overlaps(
                state,
                &value.request.target,
                &request.target,
            )
        })
    {
        return Err(RuntimeError::ReplayDetected);
    }
    let mut future = state.clone();
    super::revocation::apply_revocation(&mut future, request)?;
    Ok(())
}

pub(super) fn validate_state(state: &state::State) -> Result<(), RuntimeError> {
    if state
        .revocation_receipts
        .len()
        .saturating_add(state.prepared_revocations.len())
        > MAX_REVOCATION_RECEIPTS
    {
        return Err(RuntimeError::PersistenceFailure);
    }
    let mut handles = BTreeSet::new();
    for (command, cancelled) in &state.cancelled_revocation_preparations {
        if !state.replay.contains(command)
            || state.prepared_revocations.contains_key(command)
            || state.revocation_receipts.contains_key(command)
            || cancelled.request.command_id != *command
            || !lower_hex_32(&cancelled.preparation_id)
            || !handles.insert(cancelled.preparation_id.as_str())
        {
            return Err(RuntimeError::PersistenceFailure);
        }
    }
    for (command, value) in &state.revocation_receipts {
        if value.request.command_id != *command
            || value
                .preparation_id
                .as_ref()
                .is_some_and(|digest| !lower_hex_32(digest))
            || value
                .preparation_id
                .as_deref()
                .is_some_and(|digest| !handles.insert(digest))
        {
            return Err(RuntimeError::PersistenceFailure);
        }
    }
    let values = state.prepared_revocations.iter().collect::<Vec<_>>();
    for (index, (key, value)) in values.iter().enumerate() {
        if *key != &value.request.command_id
            || !lower_hex_32(&value.preparation_id)
            || !handles.insert(value.preparation_id.as_str())
            || !lower_hex_32(&value.begin_command_digest_sha256)
            || value.future_bytes
                < revocation_preparation_capacity::required_for_existing(state, &value.request)?
            || state.replay.contains(&value.request.command_id)
            || state
                .revocation_receipts
                .contains_key(&value.request.command_id)
        {
            return Err(RuntimeError::PersistenceFailure);
        }
        validation::id(&value.request.command_id, "command_id")?;
        validation::id(&value.request.authority_id, "authority_id")?;
        super::revocation_validation::validate_target(&value.request.target)?;
        let mut future = state.clone();
        super::revocation::apply_revocation(&mut future, &value.request)?;
        if values[index + 1..].iter().any(|(_, other)| {
            super::revocation_preparation_overlap::overlaps(
                state,
                &value.request.target,
                &other.request.target,
            )
        }) {
            return Err(RuntimeError::PersistenceFailure);
        }
    }
    revocation_preparation_capacity::require(state)
}

fn lower_hex_32(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
