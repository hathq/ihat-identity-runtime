use crate::*;

pub trait IdentityRuntimeContract {
    fn bootstrap_initial_identity(
        &mut self,
        request: InitialBootstrapRequest,
    ) -> Result<InitialBootstrapReceipt, RuntimeError>;
    fn reconcile_initial_bootstrap(
        &self,
        request: InitialBootstrapRequest,
    ) -> Result<InitialBootstrapReceipt, RuntimeError>;
    fn create_account(&mut self, request: AccountRequest) -> Result<AccountRecord, RuntimeError>;
    fn link_identity(&mut self, request: AccountLinkRequest)
    -> Result<AccountRecord, RuntimeError>;
    fn create_service_account(
        &mut self,
        request: ServiceAccountRequest,
    ) -> Result<ServiceAccountRecord, RuntimeError>;
    fn enroll_device(&mut self, request: DeviceEnrollment) -> Result<DeviceRecord, RuntimeError>;
    fn issue_session(&mut self, request: SessionRequest) -> Result<SessionRecord, RuntimeError>;
    fn establish_device_identity_session(
        &mut self,
        request: EstablishDeviceIdentitySessionRequest,
    ) -> Result<SessionRecord, RuntimeError>;
    fn authorize_session(
        &mut self,
        proof: SessionProof,
    ) -> Result<AuthorizationDecision, RuntimeError>;
    fn revoke(&mut self, request: RevokeRequest) -> Result<RevocationReceipt, RuntimeError>;
    fn prepare_revocation(
        &mut self,
        begin_command_digest_sha256: &str,
        request: RevokeRequest,
    ) -> Result<RevocationPreparationHandle, RuntimeError>;
    fn commit_prepared_revocation(
        &mut self,
        handle: &RevocationPreparationHandle,
    ) -> Result<RevocationReceipt, RuntimeError>;
    fn cancel_prepared_revocation(
        &mut self,
        handle: &RevocationPreparationHandle,
    ) -> Result<(), RuntimeError>;
    fn revoke_device(
        &mut self,
        request: RevokeDeviceRequest,
    ) -> Result<RevocationReceipt, RuntimeError>;
    fn revocation_snapshot(&self) -> Result<RevocationSnapshot, RuntimeError>;
    fn recover_device(&mut self, request: RecoveryRequest) -> Result<DeviceRecord, RuntimeError>;
    fn rotate_device_key(
        &mut self,
        request: RotateDeviceKeyRequest,
    ) -> Result<DeviceRecord, RuntimeError>;
    fn close_service_account(
        &mut self,
        request: CloseServiceAccountRequest,
    ) -> Result<ServiceAccountRecord, RuntimeError>;
    fn identity_graph(&self) -> Result<IdentityGraph, RuntimeError>;
    fn audit_events(&self) -> Result<Vec<AuditEvent>, RuntimeError>;
    fn verify_audit(&self) -> Result<AuditVerification, RuntimeError>;
    fn ingest_wire(&mut self, wire: &[u8]) -> Result<(), RuntimeError>;
    fn issue_device_identity_evidence(
        &mut self,
        request: DeviceIdentityAssertionRequest,
    ) -> Result<DeviceIdentityEvidenceV1, RuntimeError>;
    fn issue_current_device_identity_evidence(
        &mut self,
        request: CurrentDeviceIdentityAssertionRequest,
    ) -> Result<DeviceIdentityEvidenceV1, RuntimeError>;
    fn restart(&mut self) -> Result<(), RuntimeError>;
    fn snapshot_persistent_store_for_test(&self) -> Result<PersistedImage, RuntimeError>;
    fn restore_persistent_store_for_test(
        &mut self,
        image: PersistedImage,
    ) -> Result<(), RuntimeError>;
    fn attempt_audit_overwrite_for_test(
        &mut self,
        sequence: u64,
        replacement: AuditEvent,
    ) -> Result<(), RuntimeError>;
    fn corrupt_audit_bytes_for_test(&mut self, sequence: u64) -> Result<(), RuntimeError>;
}
