//! Durable owner-local identity authority for pairwise service accounts.

#![forbid(unsafe_code)]

mod assertion;
mod audit;
mod contract;
mod contract_impl;
mod error;
mod hash;
mod model;
mod pairwise;
mod peer_status;
mod reasons;
mod runtime;
mod state;
mod store;
mod trust;
mod trust_bundle;
mod validation;

pub use assertion::{
    AssertionSigner, CurrentDeviceIdentityAssertionRequest, DeviceIdentityAssertionRequest,
    DeviceIdentityEvidenceV1, MAX_CURRENT_IDENTITY_TTL_SECONDS, SystemClock, TrustedClock,
};
pub use contract::IdentityRuntimeContract;
pub use error::RuntimeError;
pub use ihat_identity_assertion_contracts::{
    AssertionError, AssertionVerifier, CURRENT_DEVICE_STATUS_SCHEMA, CurrentDeviceStatusV1,
    DEVICE_IDENTITY_ASSERTION_SCHEMA, DeviceIdentityAssertionV1, DevicePostureV1,
    RevocationEpochsV1, canonical_assertion_payload, canonical_current_status_payload,
    current_status_matches_assertion, decode_assertion_strict, decode_current_status_strict,
    verify_assertion_at, verify_current_status_at,
};
pub use model::*;
pub use pairwise::PairwiseSubjectDeriver;
pub use peer_status::{DevicePeerStatus, read_device_peer_status};
pub use reasons::*;
pub use runtime::IdentityRuntime;
pub use store::{DurableState, FileDurableState};
#[doc(hidden)]
pub use store::{DurableStateFailpoint, arm_durable_state_failpoint};
pub use trust::*;
pub use trust_bundle::*;
pub use validation::*;
