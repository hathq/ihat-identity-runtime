use crate::{
    AuthenticationContext, AuthenticationOperation, CloseServiceAccountRequest, LifecycleStatus,
    RevocationScope, RuntimeError, ServiceAccountRecord,
    state::service_key,
    validation::{fresh, id},
};

use super::{IdentityRuntime, guards};

impl IdentityRuntime {
    pub fn close_service_account(
        &mut self,
        request: CloseServiceAccountRequest,
    ) -> Result<ServiceAccountRecord, RuntimeError> {
        id(&request.command_id, "command_id")?;
        id(&request.account_id, "account_id")?;
        id(&request.service_id, "service_id")?;
        fresh(&request.fresh_user_authentication)?;
        self.verify_authentication(
            &request.fresh_user_authentication,
            AuthenticationContext {
                operation: AuthenticationOperation::ServiceAccountClosure,
                command_id: &request.command_id,
                account_id: &request.account_id,
                service_id: Some(&request.service_id),
                device_id: None,
                external_identity: None,
            },
        )?;
        self.unused(&[
            &request.command_id,
            &request.fresh_user_authentication.proof_id,
        ])?;
        let current = guards::service(&self.state, &request.account_id, &request.service_id)?;
        guards::epoch(
            RevocationScope::ServiceAccount,
            request.expected_service_epoch,
            current.service_epoch,
        )?;
        let before = self.before();
        let key = service_key(&request.account_id, &request.service_id);
        let service = self.state.services.get_mut(&key).unwrap();
        service.service_epoch += 1;
        service.status = LifecycleStatus::Closed;
        for device in self.state.devices.values_mut().filter(|value| {
            value.account_id == request.account_id && value.service_id == request.service_id
        }) {
            device.status = LifecycleStatus::Revoked;
            device.device_epoch += 1;
        }
        for session in self.state.sessions.values_mut().filter(|value| {
            value.account_id == request.account_id && value.service_id == request.service_id
        }) {
            session.status = LifecycleStatus::Revoked;
            session.session_epoch += 1;
        }
        let output = self.state.services[&key].clone();
        self.consume(&[
            &request.command_id,
            &request.fresh_user_authentication.proof_id,
        ]);
        self.finish(before, "service-account-closed", &request.command_id)?;
        Ok(output)
    }
}
