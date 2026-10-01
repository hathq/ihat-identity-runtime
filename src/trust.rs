use crate::{
    DeviceEnrollment, DeviceIdentityAssertionRequest, ExternalIdentity, FreshAuthentication,
    InitialBootstrapRequest, RecoveryApproval, RecoveryRequest, RevokeRequest,
    RotateDeviceKeyRequest, SessionProof, SessionRequest,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvidenceKind {
    Authentication,
    DeviceAttestation,
    DeviceKeyPossession,
    SessionSenderProof,
    RevocationAuthority,
    RevocationExecutionAuthorization,
    RecoveryApproval,
    InstallerBootstrap,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedEvidenceWindow {
    pub issued_at_epoch_s: u64,
    pub expires_at_epoch_s: u64,
}

impl VerifiedEvidenceWindow {
    pub const fn new(issued_at_epoch_s: u64, expires_at_epoch_s: u64) -> Self {
        Self {
            issued_at_epoch_s,
            expires_at_epoch_s,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthenticationOperation {
    AccountCreation,
    ExistingIdentityLink,
    IncomingIdentityLink,
    ServiceAccountCreation,
    DeviceEnrollment,
    DeviceRecovery,
    DeviceKeyRotation,
    ServiceAccountClosure,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceEnrollmentPurpose {
    Enrollment,
    RecoveryReplacement,
}

#[derive(Clone, Copy, Debug)]
pub struct AuthenticationContext<'a> {
    pub operation: AuthenticationOperation,
    pub command_id: &'a str,
    pub account_id: &'a str,
    pub service_id: Option<&'a str>,
    pub device_id: Option<&'a str>,
    pub external_identity: Option<&'a ExternalIdentity>,
}

pub trait AuthenticationVerifier: Send + Sync {
    fn verify(
        &self,
        evidence: &FreshAuthentication,
        context: &AuthenticationContext<'_>,
    ) -> Option<VerifiedEvidenceWindow>;
}

pub trait DeviceAttestationVerifier: Send + Sync {
    fn verify_enrollment(
        &self,
        request: &DeviceEnrollment,
        purpose: DeviceEnrollmentPurpose,
    ) -> Option<VerifiedEvidenceWindow>;
    fn verify_rotation(&self, request: &RotateDeviceKeyRequest) -> Option<VerifiedEvidenceWindow>;
}

pub trait DeviceKeyPossessionVerifier: Send + Sync {
    fn verify_enrollment(
        &self,
        request: &DeviceEnrollment,
        purpose: DeviceEnrollmentPurpose,
    ) -> Option<VerifiedEvidenceWindow>;
    fn verify_rotation(&self, request: &RotateDeviceKeyRequest) -> Option<VerifiedEvidenceWindow>;
}

pub trait SessionSenderProofVerifier: Send + Sync {
    fn verify_issue(&self, request: &SessionRequest) -> Option<VerifiedEvidenceWindow>;
    fn verify_authorization(&self, proof: &SessionProof) -> Option<VerifiedEvidenceWindow>;
    fn verify_assertion(
        &self,
        request: &DeviceIdentityAssertionRequest,
    ) -> Option<VerifiedEvidenceWindow>;
}

pub trait RevocationAuthorityVerifier: Send + Sync {
    fn verify(&self, request: &RevokeRequest) -> Option<VerifiedEvidenceWindow>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RevocationPreparationAction {
    Commit,
    Cancel,
}

pub trait RevocationPreparationVerifier: Send + Sync {
    fn verify(
        &self,
        action: RevocationPreparationAction,
        handle: &crate::RevocationPreparationHandle,
        request: &RevokeRequest,
    ) -> bool;
}

pub trait RecoveryApprovalVerifier: Send + Sync {
    fn verify(
        &self,
        request: &RecoveryRequest,
        approval: &RecoveryApproval,
    ) -> Option<VerifiedEvidenceWindow>;
}

pub trait InstallerBootstrapVerifier: Send + Sync {
    fn verify(&self, request: &InitialBootstrapRequest) -> Option<VerifiedEvidenceWindow>;
}
