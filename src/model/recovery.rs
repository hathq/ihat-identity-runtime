#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryAuthorityKind {
    IndependentOfflineRecovery,
    IndependentBoundAuthenticator,
    OnlineIdentityAuthority,
    DeviceKey,
    SessionSender,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryApproval {
    pub approval_id: String,
    pub authority_id: String,
    pub key_fingerprint: String,
    pub kind: RecoveryAuthorityKind,
    pub approved_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryRequest {
    pub command_id: String,
    pub account_id: String,
    pub affected_device_id: String,
    pub replacement: crate::DeviceEnrollment,
    pub approvals: Vec<RecoveryApproval>,
    pub expected_subject_epoch: u64,
}
