use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthenticatorKind {
    DeviceBoundPasskey,
    SyncedPasskey,
    IndependentRecovery,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FreshAuthentication {
    pub proof_id: String,
    pub authenticator_id: String,
    pub authenticator_key_fingerprint: String,
    pub kind: AuthenticatorKind,
    pub user_verified: bool,
    pub issued_at: u64,
    pub expires_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalIdentity {
    pub issuer: String,
    pub subject: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountRequest {
    pub command_id: String,
    pub account_id: String,
    pub primary_identity: ExternalIdentity,
    pub authentication: FreshAuthentication,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountRecord {
    pub account_id: String,
    pub identities: Vec<ExternalIdentity>,
    pub subject_epoch: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AccountLinkEvidence {
    DualFreshAuthentication {
        existing_identity: FreshAuthentication,
        incoming_identity: FreshAuthentication,
    },
    AttributeMatchOnly {
        email: String,
        display_name: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountLinkRequest {
    pub command_id: String,
    pub account_id: String,
    pub incoming_identity: ExternalIdentity,
    pub evidence: AccountLinkEvidence,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceAccountRequest {
    pub command_id: String,
    pub account_id: String,
    pub service_id: String,
    pub expected_subject_epoch: u64,
    pub authentication: FreshAuthentication,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceAccountRecord {
    pub account_id: String,
    pub service_id: String,
    pub pairwise_subject: String,
    pub service_epoch: u64,
    pub status: crate::LifecycleStatus,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CloseServiceAccountRequest {
    pub command_id: String,
    pub account_id: String,
    pub service_id: String,
    pub fresh_user_authentication: FreshAuthentication,
    pub expected_service_epoch: u64,
}
