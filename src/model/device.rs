use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceKeyCustody {
    HardwareNonExportable,
    SoftwareNonExportable,
    Exportable,
    SyncedPasskey,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceProofKey {
    pub fingerprint: String,
    pub spki: Vec<u8>,
    pub custody: DeviceKeyCustody,
    pub attestation: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceEnrollment {
    pub command_id: String,
    pub account_id: String,
    pub service_id: String,
    pub pairwise_subject: String,
    pub device_id: String,
    pub proof_key: DeviceProofKey,
    pub user_authentication: crate::FreshAuthentication,
    pub expected_subject_epoch: u64,
    pub expected_service_epoch: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRecord {
    pub account_id: String,
    pub service_id: String,
    pub pairwise_subject: String,
    pub device_id: String,
    pub key_fingerprint: String,
    pub posture: String,
    pub posture_revision: u64,
    pub device_epoch: u64,
    pub status: crate::LifecycleStatus,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RotateDeviceKeyRequest {
    pub command_id: String,
    pub account_id: String,
    pub service_id: String,
    pub device_id: String,
    pub retired_key_fingerprint: String,
    pub replacement_key: DeviceProofKey,
    pub fresh_user_authentication: Option<crate::FreshAuthentication>,
    pub expected_device_epoch: u64,
}
