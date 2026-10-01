use crate::{EvidenceKind, RevocationScope};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuntimeError {
    NotImplemented,
    FreshAuthenticationRequired,
    EvidenceUnverified(EvidenceKind),
    EvidenceExpired(EvidenceKind),
    EvidenceFromFuture(EvidenceKind),
    EvidenceWindowInvalid(EvidenceKind),
    TrustedClockUnavailable,
    AttributeOnlyLinkForbidden,
    WrongAccount,
    WrongService,
    ExportableDeviceKey,
    SyncedPasskeyIsNotDeviceIdentity,
    DuplicateDeviceKey,
    SenderBindingMismatch,
    DeviceRevoked,
    SessionRevoked,
    SubjectRevoked,
    ServiceAccountClosed,
    StaleEpoch {
        scope: RevocationScope,
        presented: u64,
        current: u64,
    },
    RecoveryAuthorityNotIndependent,
    InsufficientRecoveryAuthorities,
    RetiredDeviceKey,
    ReplayDetected,
    UnknownField(String),
    RequestTooLarge {
        limit: usize,
    },
    LimitExceeded {
        field: &'static str,
        limit: usize,
    },
    DatabaseRollbackDetected,
    AuditImmutable,
    AuditIntegrityViolation,
    InvalidIdentifier(&'static str),
    InvalidRequest(&'static str),
    AlreadyExists(&'static str),
    NotFound(&'static str),
    SignerUnavailable,
    StatusSignerUnavailable,
    SignatureInvalid,
    PersistenceFailure,
}

impl RuntimeError {
    pub fn reason_code(&self) -> &'static str {
        use RuntimeError::*;
        match self {
            FreshAuthenticationRequired => "fresh-user-verification-required",
            EvidenceUnverified(EvidenceKind::Authentication) => {
                "authentication-evidence-unverified"
            }
            EvidenceUnverified(EvidenceKind::DeviceAttestation) => "device-attestation-unverified",
            EvidenceUnverified(EvidenceKind::DeviceKeyPossession) => {
                "device-key-possession-unverified"
            }
            EvidenceUnverified(EvidenceKind::SessionSenderProof) => {
                "session-sender-proof-unverified"
            }
            EvidenceUnverified(EvidenceKind::RevocationAuthority) => {
                "revocation-authority-unverified"
            }
            EvidenceUnverified(EvidenceKind::RevocationExecutionAuthorization) => {
                "revocation-execution-authorization-unverified"
            }
            EvidenceUnverified(EvidenceKind::RecoveryApproval) => "recovery-approval-unverified",
            EvidenceUnverified(EvidenceKind::InstallerBootstrap) => {
                "installer-bootstrap-unverified"
            }
            EvidenceExpired(_) => "trusted-evidence-expired",
            EvidenceFromFuture(_) => "trusted-evidence-from-future",
            EvidenceWindowInvalid(_) => "trusted-evidence-window-invalid",
            TrustedClockUnavailable => "trusted-clock-unavailable",
            AttributeOnlyLinkForbidden => "attribute-only-account-link-forbidden",
            WrongAccount => "identity-account-mismatch",
            WrongService => "pairwise-service-mismatch",
            ExportableDeviceKey => "device-key-exportable",
            SyncedPasskeyIsNotDeviceIdentity => "synced-passkey-not-device-identity",
            DuplicateDeviceKey => "duplicate-device-proof-key",
            SenderBindingMismatch => "session-sender-binding-mismatch",
            DeviceRevoked => "device-revoked",
            SessionRevoked => "session-revoked",
            SubjectRevoked => "subject-revoked",
            ServiceAccountClosed => "service-account-closed",
            StaleEpoch { .. } => "revocation-epoch-stale",
            RecoveryAuthorityNotIndependent => "recovery-authority-not-independent",
            InsufficientRecoveryAuthorities => "recovery-authorities-insufficient",
            RetiredDeviceKey => "device-key-retired",
            ReplayDetected => "identity-operation-replayed",
            UnknownField(_) => "identity-wire-unknown-field",
            RequestTooLarge { .. } | LimitExceeded { .. } => "identity-input-limit-exceeded",
            DatabaseRollbackDetected => "identity-database-rollback-detected",
            AuditImmutable | AuditIntegrityViolation => "identity-audit-integrity-failed",
            InvalidIdentifier(_) | InvalidRequest(_) => "identity-request-invalid",
            AlreadyExists(_) => "identity-record-already-exists",
            NotFound(_) => "identity-record-not-found",
            SignerUnavailable => "device-assertion-signer-unavailable",
            StatusSignerUnavailable => "current-device-status-signer-unavailable",
            SignatureInvalid => "device-assertion-signature-invalid",
            PersistenceFailure => "identity-persistence-failed",
            NotImplemented => "identity-runtime-not-implemented",
        }
    }
}
