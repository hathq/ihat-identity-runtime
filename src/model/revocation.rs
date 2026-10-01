use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RevocationScope {
    Subject,
    ServiceAccount,
    Device,
    Session,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RevocationTarget {
    Subject {
        account_id: String,
    },
    ServiceAccount {
        account_id: String,
        service_id: String,
    },
    Device {
        account_id: String,
        service_id: String,
        device_id: String,
    },
    Session {
        account_id: String,
        service_id: String,
        session_id: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevokeRequest {
    pub command_id: String,
    pub target: RevocationTarget,
    pub expected_epoch: u64,
    pub authority_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevokeDeviceRequest {
    pub command_id: String,
    pub account_id: String,
    pub service_id: String,
    pub device_id: String,
    pub expected_device_epoch: u64,
    pub authority_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationPreparationHandle {
    pub preparation_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationReceipt {
    pub target: RevocationTarget,
    pub previous_epoch: u64,
    pub current_epoch: u64,
    pub audit_sequence: u64,
    pub revoked_session_count: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RevocationSnapshot {
    pub subject_epochs: BTreeMap<String, u64>,
    pub service_epochs: BTreeMap<(String, String), u64>,
    pub device_epochs: BTreeMap<(String, String, String), u64>,
    pub session_epochs: BTreeMap<(String, String, String), u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LifecycleStatus {
    Active,
    Revoked,
    Closed,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IdentityGraph {
    pub accounts: Vec<crate::AccountRecord>,
    pub service_accounts: Vec<crate::ServiceAccountRecord>,
    pub devices: Vec<crate::DeviceRecord>,
    pub sessions: Vec<crate::SessionRecord>,
}
