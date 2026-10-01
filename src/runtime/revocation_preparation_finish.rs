use crate::{
    RevocationPreparationAction, RevocationPreparationHandle, RevocationReceipt, RuntimeError,
    state,
};

use super::IdentityRuntime;

impl IdentityRuntime {
    pub fn commit_prepared_revocation(
        &mut self,
        handle: &RevocationPreparationHandle,
    ) -> Result<RevocationReceipt, RuntimeError> {
        super::revocation_preparation::require_digest(&handle.preparation_id)?;
        if let Some(current) =
            self.state.revocation_receipts.values().find(|value| {
                value.preparation_id.as_deref() == Some(handle.preparation_id.as_str())
            })
        {
            let request = current.request.clone();
            self.verify_revocation_preparation(
                RevocationPreparationAction::Commit,
                handle,
                &request,
            )?;
            return Ok(current.receipt.clone());
        }
        let prepared = self
            .state
            .prepared_revocations
            .values()
            .find(|value| value.preparation_id == handle.preparation_id)
            .ok_or(RuntimeError::InvalidRequest("revocation_not_prepared"))?;
        let request = prepared.request.clone();
        self.verify_revocation_preparation(RevocationPreparationAction::Commit, handle, &request)?;
        let before = self.before();
        let (previous, revoked_session_count) =
            super::revocation::apply_revocation(&mut self.state, &request)
                .map_err(|_| RuntimeError::PersistenceFailure)?;
        self.state.prepared_revocations.remove(&request.command_id);
        self.state.replay.insert(request.command_id.clone());
        let receipt = RevocationReceipt {
            target: request.target.clone(),
            previous_epoch: previous,
            current_epoch: previous
                .checked_add(1)
                .ok_or(RuntimeError::PersistenceFailure)?,
            audit_sequence: self.state.audit.len() as u64 + 1,
            revoked_session_count,
        };
        self.state.revocation_receipts.insert(
            request.command_id.clone(),
            state::CommittedRevocation {
                request: request.clone(),
                receipt: receipt.clone(),
                preparation_id: Some(handle.preparation_id.clone()),
            },
        );
        self.finish(before, "reserved-revocation-committed", &request.command_id)
            .map_err(|error| match error {
                RuntimeError::DatabaseRollbackDetected => RuntimeError::PersistenceFailure,
                other => other,
            })?;
        Ok(receipt)
    }

    pub fn cancel_prepared_revocation(
        &mut self,
        handle: &RevocationPreparationHandle,
    ) -> Result<(), RuntimeError> {
        super::revocation_preparation::require_digest(&handle.preparation_id)?;
        let Some(prepared) = self
            .state
            .prepared_revocations
            .values()
            .find(|value| value.preparation_id == handle.preparation_id)
        else {
            let cancelled = self
                .state
                .cancelled_revocation_preparations
                .values()
                .find(|value| value.preparation_id == handle.preparation_id)
                .ok_or(RuntimeError::InvalidRequest("revocation_not_prepared"))?;
            let request = cancelled.request.clone();
            return self.verify_revocation_preparation(
                RevocationPreparationAction::Cancel,
                handle,
                &request,
            );
        };
        let command_id = prepared.request.command_id.clone();
        let request = prepared.request.clone();
        self.verify_revocation_preparation(RevocationPreparationAction::Cancel, handle, &request)?;
        let before = self.before();
        self.state.prepared_revocations.remove(&command_id);
        self.state.replay.insert(command_id.clone());
        self.state.cancelled_revocation_preparations.insert(
            command_id.clone(),
            state::CancelledPreparedRevocation {
                preparation_id: handle.preparation_id.clone(),
                request,
            },
        );
        self.finish(before, "prepared-revocation-cancelled", &command_id)
    }
}
