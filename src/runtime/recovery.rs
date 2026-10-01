use std::collections::BTreeSet;

use crate::{
    AuthenticationOperation, DeviceRecord, LifecycleStatus, RecoveryApproval,
    RecoveryAuthorityKind, RecoveryRequest, RevocationScope, RuntimeError,
    state::device_key,
    validation::{MAX_RECOVERY_APPROVALS, id},
};

use super::{IdentityRuntime, guards};

impl IdentityRuntime {
    pub fn recover_device(
        &mut self,
        request: RecoveryRequest,
    ) -> Result<DeviceRecord, RuntimeError> {
        id(&request.command_id, "command_id")?;
        id(&request.account_id, "account_id")?;
        id(&request.affected_device_id, "affected_device_id")?;
        if request.account_id != request.replacement.account_id {
            return Err(RuntimeError::WrongAccount);
        }
        if request.affected_device_id == request.replacement.device_id {
            return Err(RuntimeError::InvalidRequest("recovery_reuses_device_id"));
        }
        let account = guards::account(&self.state, &request.account_id)?;
        guards::epoch(
            RevocationScope::Subject,
            request.expected_subject_epoch,
            account.subject_epoch,
        )?;
        self.validate_enrollment(
            &request.replacement,
            AuthenticationOperation::DeviceRecovery,
        )?;
        self.ensure_unique_device_key(&request.replacement.proof_key.fingerprint)?;
        let affected = self.affected_device(&request)?;
        validate_approvals(
            &request.approvals,
            &affected,
            &request.replacement.proof_key.fingerprint,
        )?;
        for approval in &request.approvals {
            self.verify_recovery_approval(&request, approval)?;
        }
        let mut replay = vec![
            request.command_id.as_str(),
            request.replacement.command_id.as_str(),
            request.replacement.user_authentication.proof_id.as_str(),
        ];
        replay.extend(
            request
                .approvals
                .iter()
                .map(|value| value.approval_id.as_str()),
        );
        self.unused(&replay)?;
        if self.state.devices.values().any(|value| {
            value.account_id == request.account_id
                && value.device_id == request.replacement.device_id
        }) {
            return Err(RuntimeError::AlreadyExists("device"));
        }
        let before = self.before();
        let affected_key = device_key(
            &affected.account_id,
            &affected.service_id,
            &affected.device_id,
        );
        let old = self.state.devices.get_mut(&affected_key).unwrap();
        old.status = LifecycleStatus::Revoked;
        old.device_epoch += 1;
        for session in self.state.sessions.values_mut().filter(|value| {
            value.account_id == affected.account_id
                && value.service_id == affected.service_id
                && value.device_id == affected.device_id
        }) {
            session.status = LifecycleStatus::Revoked;
            session.session_epoch += 1;
        }
        let output = self.device_record(&request.replacement);
        let replacement_key = device_key(&output.account_id, &output.service_id, &output.device_id);
        self.state.devices.insert(replacement_key, output.clone());
        self.consume(&replay);
        self.finish(before, "device-recovered", &request.command_id)?;
        Ok(output)
    }

    fn affected_device(&self, request: &RecoveryRequest) -> Result<DeviceRecord, RuntimeError> {
        self.state
            .devices
            .values()
            .find(|value| {
                value.account_id == request.account_id
                    && value.device_id == request.affected_device_id
            })
            .cloned()
            .ok_or(RuntimeError::NotFound("affected_device"))
    }
}

fn validate_approvals(
    approvals: &[RecoveryApproval],
    affected: &DeviceRecord,
    replacement_key: &str,
) -> Result<(), RuntimeError> {
    if approvals.len() < 2 {
        return Err(RuntimeError::InsufficientRecoveryAuthorities);
    }
    if approvals.len() > MAX_RECOVERY_APPROVALS {
        return Err(RuntimeError::LimitExceeded {
            field: "recovery_approvals",
            limit: MAX_RECOVERY_APPROVALS,
        });
    }
    let mut ids = BTreeSet::new();
    let mut keys = BTreeSet::new();
    let mut kinds = BTreeSet::new();
    for approval in approvals {
        id(&approval.approval_id, "recovery.approval_id")?;
        id(&approval.authority_id, "recovery.authority_id")?;
        id(&approval.key_fingerprint, "recovery.key_fingerprint")?;
        let allowed = matches!(
            approval.kind,
            RecoveryAuthorityKind::IndependentOfflineRecovery
                | RecoveryAuthorityKind::IndependentBoundAuthenticator
        );
        if !allowed
            || approval.authority_id == affected.device_id
            || approval.key_fingerprint == affected.key_fingerprint
            || approval.key_fingerprint == replacement_key
            || !ids.insert(&approval.authority_id)
            || !keys.insert(&approval.key_fingerprint)
            || !kinds.insert(approval.kind as u8)
        {
            return Err(RuntimeError::RecoveryAuthorityNotIndependent);
        }
    }
    let offline = approvals
        .iter()
        .any(|v| v.kind == RecoveryAuthorityKind::IndependentOfflineRecovery);
    let bound = approvals
        .iter()
        .any(|v| v.kind == RecoveryAuthorityKind::IndependentBoundAuthenticator);
    if !offline || !bound {
        return Err(RuntimeError::RecoveryAuthorityNotIndependent);
    }
    Ok(())
}
