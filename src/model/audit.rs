use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub sequence: u64,
    pub event_type: String,
    pub command_id: String,
    pub previous_hash: String,
    pub event_hash: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditVerification {
    pub entry_count: usize,
    pub head_hash: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PersistedImage(pub Vec<u8>);
