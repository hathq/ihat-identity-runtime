use crate::{
    AccountRecord, AuthenticationContext, AuthenticationOperation, LifecycleStatus, RuntimeError,
    ServiceAccountRecord, ServiceAccountRequest,
    state::service_key,
    validation::{MAX_ACCOUNTS, MAX_SERVICES_PER_ACCOUNT, external, fresh, id},
};

use super::{IdentityRuntime, guards};

impl IdentityRuntime {
    pub fn create_account(
        &mut self,
        request: crate::AccountRequest,
    ) -> Result<AccountRecord, RuntimeError> {
        id(&request.command_id, "command_id")?;
        id(&request.account_id, "account_id")?;
        external(&request.primary_identity)?;
        fresh(&request.authentication)?;
        self.verify_authentication(
            &request.authentication,
            AuthenticationContext {
                operation: AuthenticationOperation::AccountCreation,
                command_id: &request.command_id,
                account_id: &request.account_id,
                service_id: None,
                device_id: None,
                external_identity: Some(&request.primary_identity),
            },
        )?;
        self.unused(&[&request.command_id, &request.authentication.proof_id])?;
        if self.state.accounts.len() >= MAX_ACCOUNTS {
            return Err(RuntimeError::LimitExceeded {
                field: "accounts",
                limit: MAX_ACCOUNTS,
            });
        }
        if self.state.accounts.contains_key(&request.account_id) {
            return Err(RuntimeError::AlreadyExists("account"));
        }
        if self
            .state
            .accounts
            .values()
            .any(|value| value.identities.contains(&request.primary_identity))
        {
            return Err(RuntimeError::WrongAccount);
        }
        let before = self.before();
        let record = AccountRecord {
            account_id: request.account_id.clone(),
            identities: vec![request.primary_identity],
            subject_epoch: crate::INITIAL_EPOCH,
        };
        self.state
            .accounts
            .insert(request.account_id, record.clone());
        self.consume(&[&request.command_id, &request.authentication.proof_id]);
        self.finish(before, "account-created", &request.command_id)?;
        Ok(record)
    }

    pub fn create_service_account(
        &mut self,
        request: ServiceAccountRequest,
    ) -> Result<ServiceAccountRecord, RuntimeError> {
        id(&request.command_id, "command_id")?;
        id(&request.account_id, "account_id")?;
        id(&request.service_id, "service_id")?;
        fresh(&request.authentication)?;
        self.verify_authentication(
            &request.authentication,
            AuthenticationContext {
                operation: AuthenticationOperation::ServiceAccountCreation,
                command_id: &request.command_id,
                account_id: &request.account_id,
                service_id: Some(&request.service_id),
                device_id: None,
                external_identity: None,
            },
        )?;
        self.unused(&[&request.command_id, &request.authentication.proof_id])?;
        let account = guards::account(&self.state, &request.account_id)?;
        guards::epoch(
            crate::RevocationScope::Subject,
            request.expected_subject_epoch,
            account.subject_epoch,
        )?;
        self.ensure_service_capacity(&request.account_id)?;
        let key = service_key(&request.account_id, &request.service_id);
        if self.state.services.contains_key(&key) {
            return Err(RuntimeError::AlreadyExists("service_account"));
        }
        let before = self.before();
        let record = ServiceAccountRecord {
            account_id: request.account_id.clone(),
            service_id: request.service_id.clone(),
            pairwise_subject: self
                .pairwise_deriver
                .derive(&request.account_id, &request.service_id)?,
            service_epoch: crate::INITIAL_EPOCH,
            status: LifecycleStatus::Active,
        };
        self.state.services.insert(key, record.clone());
        self.consume(&[&request.command_id, &request.authentication.proof_id]);
        self.finish(before, "service-account-created", &request.command_id)?;
        Ok(record)
    }

    fn ensure_service_capacity(&self, account_id: &str) -> Result<(), RuntimeError> {
        let count = self
            .state
            .services
            .values()
            .filter(|value| value.account_id == account_id)
            .count();
        if count >= MAX_SERVICES_PER_ACCOUNT {
            return Err(RuntimeError::LimitExceeded {
                field: "services_per_account",
                limit: MAX_SERVICES_PER_ACCOUNT,
            });
        }
        Ok(())
    }
}
