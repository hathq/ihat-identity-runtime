use crate::{RevocationPreparationHandle, RevokeRequest, RuntimeError, state};

use super::{IdentityRuntime, revocation_preparation_capacity, revocation_preparation_guard};

impl IdentityRuntime {
    pub fn prepare_revocation(
        &mut self,
        begin_command_digest_sha256: &str,
        request: RevokeRequest,
    ) -> Result<RevocationPreparationHandle, RuntimeError> {
        require_digest(begin_command_digest_sha256)?;
        self.verify_revocation_authority(&request)?;
        if let Some(current) = self.state.prepared_revocations.get(&request.command_id) {
            exact(current, begin_command_digest_sha256, &request)?;
            return Ok(RevocationPreparationHandle {
                preparation_id: current.preparation_id.clone(),
            });
        }
        revocation_preparation_guard::preflight(&self.state, &request)?;
        let preparation_id = random_preparation_id(&self.state)?;
        let future_bytes = revocation_preparation_capacity::reservation(
            &self.state,
            begin_command_digest_sha256,
            &preparation_id,
            &request,
        )?;
        let before = self.before();
        self.state.prepared_revocations.insert(
            request.command_id.clone(),
            state::PreparedRevocation {
                preparation_id: preparation_id.clone(),
                begin_command_digest_sha256: begin_command_digest_sha256.to_owned(),
                request: request.clone(),
                future_bytes,
            },
        );
        self.finish(before, "revocation-prepared", &request.command_id)?;
        Ok(RevocationPreparationHandle { preparation_id })
    }
}

fn exact(
    prepared: &state::PreparedRevocation,
    begin_command_digest_sha256: &str,
    request: &RevokeRequest,
) -> Result<(), RuntimeError> {
    if prepared.begin_command_digest_sha256 == begin_command_digest_sha256
        && prepared.request == *request
    {
        Ok(())
    } else {
        Err(RuntimeError::ReplayDetected)
    }
}

fn random_preparation_id(state: &state::State) -> Result<String, RuntimeError> {
    for _ in 0..8 {
        let mut random = [0_u8; 32];
        getrandom::fill(&mut random).map_err(|_| RuntimeError::PersistenceFailure)?;
        let value = crate::hash::hex(&random);
        let used = state
            .prepared_revocations
            .values()
            .any(|entry| entry.preparation_id == value)
            || state
                .revocation_receipts
                .values()
                .any(|entry| entry.preparation_id.as_ref() == Some(&value))
            || state
                .cancelled_revocation_preparations
                .values()
                .any(|entry| entry.preparation_id == value);
        if !used {
            return Ok(value);
        }
    }
    Err(RuntimeError::PersistenceFailure)
}

pub(super) fn require_digest(value: &str) -> Result<(), RuntimeError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(RuntimeError::InvalidRequest("begin_command_digest"))
    }
}
