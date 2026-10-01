use crate::{
    AccountRecord, DeviceRecord, EvidenceKind, InitialBootstrapReceipt, InitialBootstrapRequest,
    LifecycleStatus, RuntimeError, ServiceAccountRecord, SessionRecord, VerifiedEvidenceWindow,
    state::{InitialBootstrapCommit, device_key as device_record_key, service_key, session_key},
    validation::id,
};

use super::{IdentityRuntime, bootstrap_validation};

impl IdentityRuntime {
    pub fn bootstrap_initial_identity(
        &mut self,
        request: InitialBootstrapRequest,
    ) -> Result<InitialBootstrapReceipt, RuntimeError> {
        bootstrap_validation::validate(&request)?;
        let request_digest = bootstrap_validation::digest(&request)?;
        self.verify_bootstrap_bundle(&request)?;
        self.unused(&[&request.command_id, &request.bundle.bundle_id])?;
        if !self.bootstrap_state_is_empty() {
            return Err(RuntimeError::AlreadyExists("initial_bootstrap"));
        }
        let pairwise_subject = self
            .pairwise_deriver
            .derive(&request.account_id, &request.service_id)?;
        id(&pairwise_subject, "pairwise_subject")?;
        let session_ref = self.fresh_session_ref(&request.service_id)?;
        let account = AccountRecord {
            account_id: request.account_id.clone(),
            identities: vec![request.primary_identity],
            subject_epoch: crate::INITIAL_EPOCH,
        };
        let service_account = ServiceAccountRecord {
            account_id: request.account_id.clone(),
            service_id: request.service_id.clone(),
            pairwise_subject: pairwise_subject.clone(),
            service_epoch: crate::INITIAL_EPOCH,
            status: LifecycleStatus::Active,
        };
        let device = DeviceRecord {
            account_id: request.account_id.clone(),
            service_id: request.service_id.clone(),
            pairwise_subject: pairwise_subject.clone(),
            device_id: request.device_id.clone(),
            key_fingerprint: request.proof_key.fingerprint,
            posture: "compliant".into(),
            posture_revision: crate::INITIAL_EPOCH,
            device_epoch: crate::INITIAL_EPOCH,
            status: LifecycleStatus::Active,
        };
        let session = SessionRecord {
            account_id: request.account_id.clone(),
            service_id: request.service_id.clone(),
            pairwise_subject,
            device_id: request.device_id.clone(),
            session_id: request.session_id.clone(),
            session_ref,
            sender_key_fingerprint: request.sender_key_fingerprint,
            session_epoch: crate::INITIAL_EPOCH,
            status: LifecycleStatus::Active,
        };
        let before = self.before();
        let audit_sequence = before.audit.last().map_or(1, |event| event.sequence + 1);
        let receipt = InitialBootstrapReceipt {
            account: account.clone(),
            service_account: service_account.clone(),
            device: device.clone(),
            session: session.clone(),
            audit_sequence,
        };
        self.state
            .accounts
            .insert(request.account_id.clone(), account.clone());
        self.state.services.insert(
            service_key(&request.account_id, &request.service_id),
            service_account.clone(),
        );
        self.state.devices.insert(
            device_record_key(&request.account_id, &request.service_id, &request.device_id),
            device.clone(),
        );
        let session_key = session_key(
            &request.account_id,
            &request.service_id,
            &request.session_id,
        );
        self.state
            .sessions
            .insert(session_key.clone(), session.clone());
        self.state.current_identity_sessions.insert(
            device_record_key(&request.account_id, &request.service_id, &request.device_id),
            session_key,
        );
        self.consume(&[&request.command_id, &request.bundle.bundle_id]);
        self.state.initial_bootstrap = Some(InitialBootstrapCommit {
            request_digest,
            receipt: receipt.clone(),
        });
        self.finish(before, "initial-bootstrap-completed", &request.command_id)?;
        Ok(receipt)
    }

    fn verify_bootstrap_bundle(
        &self,
        request: &InitialBootstrapRequest,
    ) -> Result<(), RuntimeError> {
        let verified =
            self.trust
                .bootstrap
                .verify(request)
                .ok_or(RuntimeError::EvidenceUnverified(
                    EvidenceKind::InstallerBootstrap,
                ))?;
        let declared = VerifiedEvidenceWindow::new(
            request.bundle.issued_at_epoch_s,
            request.bundle.expires_at_epoch_s,
        );
        if verified != declared {
            return Err(RuntimeError::EvidenceUnverified(
                EvidenceKind::InstallerBootstrap,
            ));
        }
        self.verify_window(EvidenceKind::InstallerBootstrap, verified)
    }

    fn bootstrap_state_is_empty(&self) -> bool {
        self.state.accounts.is_empty()
            && self.state.services.is_empty()
            && self.state.devices.is_empty()
            && self.state.sessions.is_empty()
            && self.state.current_identity_sessions.is_empty()
            && self.state.revoked_subjects.is_empty()
            && self.state.retired_keys.is_empty()
            && self.state.replay.is_empty()
            && self.state.audit.is_empty()
            && self.state.initial_bootstrap.is_none()
    }
}
