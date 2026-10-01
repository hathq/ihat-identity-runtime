use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstallerBootstrapBundle {
    pub bundle_id: String,
    pub root_key_id: String,
    pub issued_at_epoch_s: u64,
    pub expires_at_epoch_s: u64,
    pub signature: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InitialBootstrapRequest {
    pub command_id: String,
    pub account_id: String,
    pub primary_identity: crate::ExternalIdentity,
    pub service_id: String,
    pub device_id: String,
    pub proof_key: crate::DeviceProofKey,
    pub session_id: String,
    pub sender_key_fingerprint: String,
    pub bundle: InstallerBootstrapBundle,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InitialBootstrapReceipt {
    pub account: crate::AccountRecord,
    pub service_account: crate::ServiceAccountRecord,
    pub device: crate::DeviceRecord,
    pub session: crate::SessionRecord,
    pub audit_sequence: u64,
}
