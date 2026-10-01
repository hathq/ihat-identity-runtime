use crate::{
    TrustedClock,
    trust::{
        AuthenticationVerifier, DeviceAttestationVerifier, DeviceKeyPossessionVerifier,
        InstallerBootstrapVerifier, RecoveryApprovalVerifier, RevocationAuthorityVerifier,
        RevocationPreparationVerifier, SessionSenderProofVerifier,
    },
};

pub struct RuntimeVerifiers {
    pub authentication: Box<dyn AuthenticationVerifier>,
    pub attestation: Box<dyn DeviceAttestationVerifier>,
    pub possession: Box<dyn DeviceKeyPossessionVerifier>,
    pub session: Box<dyn SessionSenderProofVerifier>,
    pub revocation: Box<dyn RevocationAuthorityVerifier>,
    pub revocation_preparation: Box<dyn RevocationPreparationVerifier>,
    pub recovery: Box<dyn RecoveryApprovalVerifier>,
    pub installer_bootstrap: Box<dyn InstallerBootstrapVerifier>,
}

pub struct RuntimeTrust {
    pub(crate) authentication: Box<dyn AuthenticationVerifier>,
    pub(crate) attestation: Box<dyn DeviceAttestationVerifier>,
    pub(crate) possession: Box<dyn DeviceKeyPossessionVerifier>,
    pub(crate) session: Box<dyn SessionSenderProofVerifier>,
    pub(crate) revocation: Box<dyn RevocationAuthorityVerifier>,
    pub(crate) revocation_preparation: Box<dyn RevocationPreparationVerifier>,
    pub(crate) recovery: Box<dyn RecoveryApprovalVerifier>,
    pub(crate) bootstrap: Box<dyn InstallerBootstrapVerifier>,
    pub(crate) clock: Box<dyn TrustedClock>,
}

impl RuntimeTrust {
    pub fn new(verifiers: RuntimeVerifiers, clock: Box<dyn TrustedClock>) -> Self {
        Self {
            authentication: verifiers.authentication,
            attestation: verifiers.attestation,
            possession: verifiers.possession,
            session: verifiers.session,
            revocation: verifiers.revocation,
            revocation_preparation: verifiers.revocation_preparation,
            recovery: verifiers.recovery,
            bootstrap: verifiers.installer_bootstrap,
            clock,
        }
    }
}
