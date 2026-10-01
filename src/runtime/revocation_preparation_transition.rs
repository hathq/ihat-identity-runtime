use crate::{RuntimeError, state};

pub(super) fn preserve(
    before: &state::State,
    after: &state::State,
    event: &str,
    command: &str,
) -> Result<(), RuntimeError> {
    let expected_count = match event {
        "revocation-prepared" => before.prepared_revocations.len().checked_add(1),
        "reserved-revocation-committed" | "prepared-revocation-cancelled" => {
            before.prepared_revocations.len().checked_sub(1)
        }
        _ => Some(before.prepared_revocations.len()),
    };
    if expected_count != Some(after.prepared_revocations.len()) {
        return Err(RuntimeError::PersistenceFailure);
    }
    for (id, prepared) in &before.prepared_revocations {
        match after.prepared_revocations.get(id) {
            Some(current) if current == prepared => {
                if !super::revocation_preparation_snapshot::unchanged(
                    before,
                    after,
                    &prepared.request.target,
                ) {
                    return Err(RuntimeError::InvalidRequest("prepared_revocation_conflict"));
                }
            }
            None if event == "reserved-revocation-committed" && command == id => {
                let committed = after.revocation_receipts.get(id).is_some_and(|value| {
                    value.request == prepared.request
                        && value.preparation_id.as_deref() == Some(prepared.preparation_id.as_str())
                });
                if !committed {
                    return Err(RuntimeError::PersistenceFailure);
                }
            }
            None if event == "prepared-revocation-cancelled" && command == id => {
                let cancelled =
                    after
                        .cancelled_revocation_preparations
                        .get(id)
                        .is_some_and(|value| {
                            value.preparation_id == prepared.preparation_id
                                && value.request == prepared.request
                        });
                if !super::revocation_preparation_snapshot::unchanged(
                    before,
                    after,
                    &prepared.request.target,
                ) || !after.replay.contains(id)
                    || !cancelled
                {
                    return Err(RuntimeError::PersistenceFailure);
                }
            }
            _ => return Err(RuntimeError::PersistenceFailure),
        }
    }
    Ok(())
}
