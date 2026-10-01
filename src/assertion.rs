use std::time::{SystemTime, UNIX_EPOCH};

use ihat_identity_assertion_contracts::{CurrentDeviceStatusV1, DeviceIdentityAssertionV1};

use crate::RuntimeError;

pub const MAX_CURRENT_IDENTITY_TTL_SECONDS: u64 = 30;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceIdentityAssertionRequest {
    pub account_id: String,
    pub service_id: String,
    pub pairwise_subject: String,
    pub device_id: String,
    pub session_id: String,
    pub audience: String,
    pub nonce: String,
    pub ttl_seconds: u64,
    pub sender_key_fingerprint: String,
    pub sender_proof_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CurrentDeviceIdentityAssertionRequest {
    pub service_id: String,
    pub pairwise_subject: String,
    pub device_id: String,
    pub audience: String,
    pub identity_nonce: String,
    pub ttl_seconds: u64,
    pub session_sender_key_fingerprint: String,
    pub session_sender_proof_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceIdentityEvidenceV1 {
    pub assertion: DeviceIdentityAssertionV1,
    pub current_status: CurrentDeviceStatusV1,
}

pub trait AssertionSigner: Send + Sync {
    fn issuer(&self) -> &str;
    fn key_id(&self) -> &str;
    fn sign(&self, canonical_payload: &[u8]) -> Result<String, RuntimeError>;
}

pub trait TrustedClock: Send + Sync {
    fn now_epoch_seconds(&self) -> Result<u64, RuntimeError>;
}

pub struct SystemClock;

impl TrustedClock for SystemClock {
    fn now_epoch_seconds(&self) -> Result<u64, RuntimeError> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|value| value.as_secs())
            .map_err(|_| RuntimeError::InvalidRequest("trusted_clock"))
    }
}
