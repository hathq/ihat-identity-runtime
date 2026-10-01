use crate::{
    AccountLinkEvidence, AccountLinkRequest, AccountRecord, AuthenticationContext,
    AuthenticationOperation, RuntimeError,
    validation::{MAX_IDENTITIES_PER_ACCOUNT, external, fresh, id},
};

use super::{IdentityRuntime, guards};

impl IdentityRuntime {
    pub fn link_identity(
        &mut self,
        request: AccountLinkRequest,
    ) -> Result<AccountRecord, RuntimeError> {
        id(&request.command_id, "command_id")?;
        id(&request.account_id, "account_id")?;
        external(&request.incoming_identity)?;
        let (existing, incoming) = match &request.evidence {
            AccountLinkEvidence::AttributeMatchOnly { .. } => {
                return Err(RuntimeError::AttributeOnlyLinkForbidden);
            }
            AccountLinkEvidence::DualFreshAuthentication {
                existing_identity,
                incoming_identity,
            } => {
                fresh(existing_identity)?;
                fresh(incoming_identity)?;
                self.verify_link_authentications(&request, existing_identity, incoming_identity)?;
                (existing_identity, incoming_identity)
            }
        };
        self.unused(&[&request.command_id, &existing.proof_id, &incoming.proof_id])?;
        if self.state.accounts.values().any(|value| {
            value.account_id != request.account_id
                && value.identities.contains(&request.incoming_identity)
        }) {
            return Err(RuntimeError::WrongAccount);
        }
        let current = guards::account(&self.state, &request.account_id)?;
        if current.identities.len() >= MAX_IDENTITIES_PER_ACCOUNT {
            return Err(RuntimeError::LimitExceeded {
                field: "identities_per_account",
                limit: MAX_IDENTITIES_PER_ACCOUNT,
            });
        }
        let before = self.before();
        let record = self.state.accounts.get_mut(&request.account_id).unwrap();
        if !record.identities.contains(&request.incoming_identity) {
            record.identities.push(request.incoming_identity);
        }
        let output = record.clone();
        self.consume(&[&request.command_id, &existing.proof_id, &incoming.proof_id]);
        self.finish(before, "external-identity-linked", &request.command_id)?;
        Ok(output)
    }

    fn verify_link_authentications(
        &self,
        request: &AccountLinkRequest,
        existing: &crate::FreshAuthentication,
        incoming: &crate::FreshAuthentication,
    ) -> Result<(), RuntimeError> {
        self.verify_authentication(
            existing,
            AuthenticationContext {
                operation: AuthenticationOperation::ExistingIdentityLink,
                command_id: &request.command_id,
                account_id: &request.account_id,
                service_id: None,
                device_id: None,
                external_identity: None,
            },
        )?;
        self.verify_authentication(
            incoming,
            AuthenticationContext {
                operation: AuthenticationOperation::IncomingIdentityLink,
                command_id: &request.command_id,
                account_id: &request.account_id,
                service_id: None,
                device_id: None,
                external_identity: Some(&request.incoming_identity),
            },
        )
    }
}
