use crate::{RevocationReceipt, RevokeRequest, RuntimeError, audit, state, store};

use super::revocation::apply_revocation;

const FUTURE_MARGIN_BYTES: usize = 256;

pub(super) fn reservation(
    current: &state::State,
    begin_digest: &str,
    preparation_id: &str,
    request: &RevokeRequest,
) -> Result<usize, RuntimeError> {
    let mut reserved = FUTURE_MARGIN_BYTES;
    for _ in 0..8 {
        let prepared = prepared_image(current, begin_digest, preparation_id, request, reserved)?;
        let final_image = committed_image(&prepared, request)?;
        let needed = encoded_len(&final_image)?
            .saturating_sub(encoded_len(&prepared)?)
            .saturating_add(FUTURE_MARGIN_BYTES);
        if needed <= reserved {
            return Ok(reserved);
        }
        reserved = needed;
    }
    Err(RuntimeError::PersistenceFailure)
}

pub(super) fn require(state: &state::State) -> Result<(), RuntimeError> {
    let reserved = state
        .prepared_revocations
        .values()
        .try_fold(0_usize, |sum, value| sum.checked_add(value.future_bytes))
        .ok_or(RuntimeError::PersistenceFailure)?;
    if encoded_len(state)?
        .checked_add(reserved)
        .is_none_or(|value| value > store::MAX_DURABLE_IMAGE_BYTES)
    {
        return Err(RuntimeError::LimitExceeded {
            field: "durable_image",
            limit: store::MAX_DURABLE_IMAGE_BYTES,
        });
    }
    Ok(())
}

pub(super) fn required_for_existing(
    current: &state::State,
    request: &RevokeRequest,
) -> Result<usize, RuntimeError> {
    let final_image = committed_image(current, request)?;
    Ok(encoded_len(&final_image)?.saturating_sub(encoded_len(current)?))
}

fn prepared_image(
    current: &state::State,
    begin_digest: &str,
    preparation_id: &str,
    request: &RevokeRequest,
    future_bytes: usize,
) -> Result<state::State, RuntimeError> {
    let mut value = current.clone();
    value.prepared_revocations.insert(
        request.command_id.clone(),
        state::PreparedRevocation {
            preparation_id: preparation_id.to_owned(),
            begin_command_digest_sha256: begin_digest.to_owned(),
            request: request.clone(),
            future_bytes,
        },
    );
    advance(&mut value, "revocation-prepared", &request.command_id)?;
    Ok(value)
}

fn committed_image(
    prepared: &state::State,
    request: &RevokeRequest,
) -> Result<state::State, RuntimeError> {
    let mut value = prepared.clone();
    value.prepared_revocations.remove(&request.command_id);
    let (previous, revoked_session_count) = apply_revocation(&mut value, request)?;
    value.replay.insert(request.command_id.clone());
    let receipt = RevocationReceipt {
        target: request.target.clone(),
        previous_epoch: previous,
        current_epoch: previous
            .checked_add(1)
            .ok_or(RuntimeError::PersistenceFailure)?,
        audit_sequence: value.audit.len() as u64 + 1,
        revoked_session_count,
    };
    value.revocation_receipts.insert(
        request.command_id.clone(),
        state::CommittedRevocation {
            request: request.clone(),
            receipt,
            preparation_id: prepared
                .prepared_revocations
                .get(&request.command_id)
                .map(|value| value.preparation_id.clone()),
        },
    );
    advance(
        &mut value,
        "reserved-revocation-committed",
        &request.command_id,
    )?;
    Ok(value)
}

fn advance(state: &mut state::State, event: &str, command: &str) -> Result<(), RuntimeError> {
    state.revision = state
        .revision
        .checked_add(1)
        .ok_or(RuntimeError::PersistenceFailure)?;
    audit::append(&mut state.audit, event, command);
    Ok(())
}

fn encoded_len(state: &state::State) -> Result<usize, RuntimeError> {
    serde_json::to_vec(state)
        .map(|value| value.len().saturating_add(16))
        .map_err(|_| RuntimeError::PersistenceFailure)
}
