use std::{
    fs,
    io::Write,
    os::unix::fs::{PermissionsExt, symlink},
    path::{Path, PathBuf},
    sync::{Arc, Barrier},
    thread,
};

use support::*;

#[test]
fn file_store_reopens_with_replay_epochs_and_audit_intact() {
    let directory = TempDirectory::new("reopen");
    let path = directory.path.join("identity.state");
    let proof;
    let expected_graph;
    let expected_revocations;
    {
        let mut runtime = file_runtime(&path);
        let service = create_account_and_service(&mut runtime, "account-a", "service-a");
        let device = enroll(&mut runtime, "account-a", &service, "device-a", "key-a");
        let session = issue(&mut runtime, "account-a", &service, &device, "session-a");
        proof = session_proof(&session, "persistent-one-use-proof");
        runtime.authorize_session(proof.clone()).unwrap();
        runtime
            .revoke(RevokeRequest {
                command_id: "persistent-session-revoke".into(),
                target: RevocationTarget::Session {
                    account_id: "account-a".into(),
                    service_id: "service-a".into(),
                    session_id: "session-a".into(),
                },
                expected_epoch: session.session_epoch,
                authority_id: "identity-authority".into(),
            })
            .unwrap();
        expected_graph = runtime.identity_graph().unwrap();
        expected_revocations = runtime.revocation_snapshot().unwrap();
    }
    let mut reopened = file_runtime(&path);
    assert_eq!(reopened.identity_graph().unwrap(), expected_graph);
    assert_eq!(
        reopened.revocation_snapshot().unwrap(),
        expected_revocations
    );
    assert_eq!(
        reopened.authorize_session(proof).unwrap_err(),
        RuntimeError::ReplayDetected
    );
    assert!(reopened.verify_audit().unwrap().entry_count >= 5);
    assert_owner_only(&directory.path, &path);
}

#[test]
fn file_store_detects_persisted_audit_or_anchor_tampering() {
    let directory = TempDirectory::new("tamper");
    let path = directory.path.join("identity.state");
    let mut runtime = file_runtime(&path);
    create_account_and_service(&mut runtime, "account-a", "service-a");
    drop(runtime);
    let mut bytes = fs::read(&path).unwrap();
    let needle = b"account-created";
    let offset = bytes
        .windows(needle.len())
        .position(|part| part == needle)
        .unwrap();
    bytes[offset..offset + needle.len()].copy_from_slice(b"account-forged!");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&path)
        .unwrap();
    file.write_all(&bytes).unwrap();
    file.sync_all().unwrap();
    assert!(matches!(
        IdentityRuntime::open_file(&path, Box::new(TestPairwiseDeriver), test_trust()),
        Err(RuntimeError::DatabaseRollbackDetected | RuntimeError::AuditIntegrityViolation)
    ));
}
