use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionRequest {
    pub command_id: String,
    pub account_id: String,
    pub service_id: String,
    pub pairwise_subject: String,
    pub device_id: String,
    pub session_id: String,
    pub sender_key_fingerprint: String,
    pub proof_id: String,
    pub expected_subject_epoch: u64,
    pub expected_service_epoch: u64,
    pub expected_device_epoch: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionRecord {
    pub account_id: String,
    pub service_id: String,
    pub pairwise_subject: String,
    pub device_id: String,
    pub session_id: String,
    pub session_ref: String,
    pub sender_key_fingerprint: String,
    pub session_epoch: u64,
    pub status: crate::LifecycleStatus,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionProof {
    pub proof_id: String,
    pub account_id: String,
    pub service_id: String,
    pub pairwise_subject: String,
    pub device_id: String,
    pub session_id: String,
    pub session_ref: String,
    pub sender_key_fingerprint: String,
    pub subject_epoch: u64,
    pub service_epoch: u64,
    pub device_epoch: u64,
    pub session_epoch: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorizationDecision {
    Authorized,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExpectedCurrentSession {
    Absent,
    Present {
        session_ref: String,
        session_epoch: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EstablishDeviceIdentitySessionRequest {
    pub command_id: String,
    pub account_id: String,
    pub service_id: String,
    pub pairwise_subject: String,
    pub device_id: String,
    pub session_id: String,
    pub sender_key_fingerprint: String,
    pub proof_id: String,
    pub expected_subject_epoch: u64,
    pub expected_service_epoch: u64,
    pub expected_device_epoch: u64,
    pub expected_current_session: ExpectedCurrentSession,
}
