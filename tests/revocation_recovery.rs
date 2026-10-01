mod support;

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use support::*;

#[test]
fn exact_revocation_receipt_recovers_after_commit_and_restart_without_second_epoch() {
    let root = TempDirectory::new("revocation-recovery");
    let path = root.path.join("identity.state");
    let mut runtime = file_runtime(&path);
    let service = create_account_and_service(&mut runtime, "account-a", "service-a");
    let device = enroll(&mut runtime, "account-a", &service, "device-a", "key-a");
    let session = issue(&mut runtime, "account-a", &service, &device, "session-a");
    let request = RevokeRequest {
        command_id: "durable-final-revoke".into(),
        target: RevocationTarget::Session {
            account_id: session.account_id.clone(),
            service_id: session.service_id.clone(),
            session_id: session.session_id.clone(),
        },
        expected_epoch: session.session_epoch,
        authority_id: "identity-authority".into(),
    };
    let committed = runtime.revoke(request.clone()).expect("commit revocation");
    let audit = runtime.audit_events().expect("audit");
    drop(runtime);

    let mut restarted = file_runtime_with_revocation(&path, RejectRevocation);
    let recovered = restarted
        .revoke(request.clone())
        .expect("recover exact receipt");
    assert_eq!(recovered, committed);
    assert_eq!(restarted.audit_events().expect("audit"), audit);
    assert_eq!(
        restarted
            .revocation_snapshot()
            .expect("snapshot")
            .session_epochs[&(
            session.account_id.clone(),
            session.service_id.clone(),
            session.session_id.clone(),
        )],
        session.session_epoch + 1
    );

    let mut substituted = request.clone();
    substituted.expected_epoch += 1;
    assert_eq!(
        restarted.revoke(substituted),
        Err(RuntimeError::ReplayDetected)
    );

    let mut uncommitted = request;
    uncommitted.command_id = "uncommitted-after-trust-rotation".into();
    assert_eq!(
        restarted.revoke(uncommitted),
        Err(RuntimeError::EvidenceUnverified(
            EvidenceKind::RevocationAuthority
        ))
    );
}

fn file_runtime(path: &Path) -> IdentityRuntime {
    IdentityRuntime::open_file(path, Box::new(TestPairwiseDeriver), test_trust())
        .expect("file runtime")
}

fn file_runtime_with_revocation(
    path: &Path,
    revocation: impl RevocationAuthorityVerifier + 'static,
) -> IdentityRuntime {
    let trust = RuntimeTrust::new(
        RuntimeVerifiers {
            authentication: Box::new(TestEvidenceVerifier),
            attestation: Box::new(TestEvidenceVerifier),
            possession: Box::new(TestEvidenceVerifier),
            session: Box::new(TestEvidenceVerifier),
            revocation: Box::new(revocation),
            revocation_preparation: Box::new(TestEvidenceVerifier),
            recovery: Box::new(TestEvidenceVerifier),
            installer_bootstrap: Box::new(TestEvidenceVerifier),
        },
        Box::new(TestClock(TEST_NOW)),
    );
    IdentityRuntime::open_file(path, Box::new(TestPairwiseDeriver), trust).expect("file runtime")
}

struct RejectRevocation;

impl RevocationAuthorityVerifier for RejectRevocation {
    fn verify(&self, _request: &RevokeRequest) -> Option<VerifiedEvidenceWindow> {
        None
    }
}

struct TempDirectory {
    path: PathBuf,
}

impl TempDirectory {
    fn new(label: &str) -> Self {
        let mut random = [0_u8; 8];
        getrandom::fill(&mut random).expect("random");
        let path = std::env::temp_dir().join(format!(
            "ihat-identity-{label}-{}-{}",
            std::process::id(),
            u64::from_be_bytes(random)
        ));
        fs::create_dir(&path).expect("temp directory");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("mode");
        Self { path }
    }
}

impl Drop for TempDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

include!("revocation_recovery/crash_anchor.rs");
