use crate::*;

impl IdentityRuntimeContract for IdentityRuntime {
    fn bootstrap_initial_identity(
        &mut self,
        value: InitialBootstrapRequest,
    ) -> Result<InitialBootstrapReceipt, RuntimeError> {
        self.bootstrap_initial_identity(value)
    }
    fn reconcile_initial_bootstrap(
        &self,
        value: InitialBootstrapRequest,
    ) -> Result<InitialBootstrapReceipt, RuntimeError> {
        self.reconcile_initial_bootstrap(value)
    }
    fn create_account(&mut self, value: AccountRequest) -> Result<AccountRecord, RuntimeError> {
        self.create_account(value)
    }
    fn link_identity(&mut self, value: AccountLinkRequest) -> Result<AccountRecord, RuntimeError> {
        self.link_identity(value)
    }
    fn create_service_account(
        &mut self,
        value: ServiceAccountRequest,
    ) -> Result<ServiceAccountRecord, RuntimeError> {
        self.create_service_account(value)
    }
    fn enroll_device(&mut self, value: DeviceEnrollment) -> Result<DeviceRecord, RuntimeError> {
        self.enroll_device(value)
    }
    fn issue_session(&mut self, value: SessionRequest) -> Result<SessionRecord, RuntimeError> {
        self.issue_session(value)
    }
    fn establish_device_identity_session(
        &mut self,
        value: EstablishDeviceIdentitySessionRequest,
    ) -> Result<SessionRecord, RuntimeError> {
        self.establish_device_identity_session(value)
    }
    fn authorize_session(
        &mut self,
        value: SessionProof,
    ) -> Result<AuthorizationDecision, RuntimeError> {
        self.authorize_session(value)
    }
    fn revoke(&mut self, value: RevokeRequest) -> Result<RevocationReceipt, RuntimeError> {
        self.revoke(value)
    }
    fn prepare_revocation(
        &mut self,
        begin_command_digest_sha256: &str,
        value: RevokeRequest,
    ) -> Result<RevocationPreparationHandle, RuntimeError> {
        self.prepare_revocation(begin_command_digest_sha256, value)
    }
    fn commit_prepared_revocation(
        &mut self,
        value: &RevocationPreparationHandle,
    ) -> Result<RevocationReceipt, RuntimeError> {
        self.commit_prepared_revocation(value)
    }
    fn cancel_prepared_revocation(
        &mut self,
        value: &RevocationPreparationHandle,
    ) -> Result<(), RuntimeError> {
        self.cancel_prepared_revocation(value)
    }
    fn revoke_device(
        &mut self,
        value: RevokeDeviceRequest,
    ) -> Result<RevocationReceipt, RuntimeError> {
        self.revoke_device(value)
    }
    fn revocation_snapshot(&self) -> Result<RevocationSnapshot, RuntimeError> {
        self.revocation_snapshot()
    }
    fn recover_device(&mut self, value: RecoveryRequest) -> Result<DeviceRecord, RuntimeError> {
        self.recover_device(value)
    }
    fn rotate_device_key(
        &mut self,
        value: RotateDeviceKeyRequest,
    ) -> Result<DeviceRecord, RuntimeError> {
        self.rotate_device_key(value)
    }
    fn close_service_account(
        &mut self,
        value: CloseServiceAccountRequest,
    ) -> Result<ServiceAccountRecord, RuntimeError> {
        self.close_service_account(value)
    }
    fn identity_graph(&self) -> Result<IdentityGraph, RuntimeError> {
        self.identity_graph()
    }
    fn audit_events(&self) -> Result<Vec<AuditEvent>, RuntimeError> {
        self.audit_events()
    }
    fn verify_audit(&self) -> Result<AuditVerification, RuntimeError> {
        self.verify_audit()
    }
    fn ingest_wire(&mut self, value: &[u8]) -> Result<(), RuntimeError> {
        self.ingest_wire(value)
    }
    fn issue_device_identity_evidence(
        &mut self,
        value: DeviceIdentityAssertionRequest,
    ) -> Result<DeviceIdentityEvidenceV1, RuntimeError> {
        self.issue_device_identity_evidence(value)
    }
    fn issue_current_device_identity_evidence(
        &mut self,
        value: CurrentDeviceIdentityAssertionRequest,
    ) -> Result<DeviceIdentityEvidenceV1, RuntimeError> {
        self.issue_current_device_identity_evidence(value)
    }
    fn restart(&mut self) -> Result<(), RuntimeError> {
        self.restart()
    }
    fn snapshot_persistent_store_for_test(&self) -> Result<PersistedImage, RuntimeError> {
        self.snapshot_persistent_store_for_test()
    }
    fn restore_persistent_store_for_test(
        &mut self,
        value: PersistedImage,
    ) -> Result<(), RuntimeError> {
        self.restore_persistent_store_for_test(value)
    }
    fn attempt_audit_overwrite_for_test(
        &mut self,
        sequence: u64,
        replacement: AuditEvent,
    ) -> Result<(), RuntimeError> {
        self.attempt_audit_overwrite_for_test(sequence, replacement)
    }
    fn corrupt_audit_bytes_for_test(&mut self, sequence: u64) -> Result<(), RuntimeError> {
        self.corrupt_audit_bytes_for_test(sequence)
    }
}
