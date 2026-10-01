use crate::{RevocationReceipt, RevokeRequest, RuntimeError, validation::id};

use super::{IdentityRuntime, revocation_validation::validate_target};

pub(super) use super::revocation_apply::apply as apply_revocation;

pub(crate) const MAX_REVOCATION_RECEIPTS: usize = 4_096;

impl IdentityRuntime {
    pub fn revoke(&mut self, request: RevokeRequest) -> Result<RevocationReceipt, RuntimeError> {
        id(&request.command_id, "command_id")?;
        id(&request.authority_id, "authority_id")?;
        validate_target(&request.target)?;
        if let Some(committed) = self.state.revocation_receipts.get(&request.command_id) {
            return if committed.request == request {
                Ok(committed.receipt.clone())
            } else {
                Err(RuntimeError::ReplayDetected)
            };
        }
        self.verify_revocation_authority(&request)?;
        if self
            .state
            .revocation_receipts
            .len()
            .saturating_add(self.state.prepared_revocations.len())
            >= MAX_REVOCATION_RECEIPTS
        {
            return Err(RuntimeError::LimitExceeded {
                field: "revocation_receipts",
                limit: MAX_REVOCATION_RECEIPTS,
            });
        }
        self.unused(&[&request.command_id])?;
        let before = self.before();
        let (previous, revoked_session_count) = apply_revocation(&mut self.state, &request)?;
        self.consume(&[&request.command_id]);
        let receipt = RevocationReceipt {
            target: request.target.clone(),
            previous_epoch: previous,
            current_epoch: previous + 1,
            audit_sequence: self.state.audit.len() as u64 + 1,
            revoked_session_count,
        };
        self.state.revocation_receipts.insert(
            request.command_id.clone(),
            crate::state::CommittedRevocation {
                request: request.clone(),
                receipt: receipt.clone(),
                preparation_id: None,
            },
        );
        self.finish(before.clone(), "identity-revoked", &request.command_id)?;
        Ok(receipt)
    }
}
