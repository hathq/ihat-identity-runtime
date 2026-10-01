use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use support::*;

#[test]
// ID-50: an installer-root bundle materializes the first complete identity atomically.
fn empty_bootstrap_succeeds_once_and_replay_is_rejected_after_reopen() {
    let directory = TempDirectory::new();
    let path = directory.path.join("identity.state");
    let mut runtime =
        IdentityRuntime::open_file(&path, Box::new(TestPairwiseDeriver), test_trust())
            .expect("runtime");
    let request = bootstrap_request("bootstrap-bundle-01");
    let receipt = runtime
        .bootstrap_initial_identity(request.clone())
        .expect("initial bootstrap");
    assert_eq!(receipt.account.account_id, "account-bootstrap");
    assert_eq!(receipt.service_account.service_id, "service:crowsi");
    assert_eq!(receipt.device.device_id, "device-bootstrap-a");
    assert!(receipt.session.session_ref.starts_with("sref_"));
    assert_eq!(runtime.identity_graph().unwrap().sessions.len(), 1);
    drop(runtime);

    let mut reopened =
        IdentityRuntime::open_file(&path, Box::new(TestPairwiseDeriver), test_trust())
            .expect("reopen");
    assert_eq!(
        reopened.bootstrap_initial_identity(request),
        Err(RuntimeError::ReplayDetected)
    );
    assert_eq!(
        reopened.bootstrap_initial_identity(bootstrap_request("bootstrap-bundle-02")),
        Err(RuntimeError::AlreadyExists("initial_bootstrap"))
    );
}

#[test]
fn persistence_failpoint_rolls_back_every_bootstrap_record_and_replay_id() {
    let empty = runtime().snapshot_persistent_store_for_test().unwrap();
    let control = StoreControl::new(empty);
    let mut runtime = IdentityRuntime::open_store_for_test(
        Box::new(control.store()),
        Box::new(TestPairwiseDeriver),
        test_trust(),
    )
    .expect("runtime");
    assert_eq!(
        runtime.bootstrap_initial_identity(bootstrap_request("bootstrap-fail")),
        Err(RuntimeError::PersistenceFailure)
    );
    assert_eq!(runtime.identity_graph().unwrap(), IdentityGraph::default());
    let mut reopened = IdentityRuntime::open_store_for_test(
        Box::new(control.store()),
        Box::new(TestPairwiseDeriver),
        test_trust(),
    )
    .expect("reopen");
    control.allow_commit();
    assert!(
        reopened
            .bootstrap_initial_identity(bootstrap_request("bootstrap-fail"))
            .is_ok()
    );
}

#[test]
fn invalid_sender_binding_fails_before_any_bootstrap_mutation() {
    let mut runtime = runtime();
    let mut request = bootstrap_request("bootstrap-invalid-sender");
    request.sender_key_fingerprint = "another-device-key".into();
    assert_eq!(
        runtime.bootstrap_initial_identity(request),
        Err(RuntimeError::SenderBindingMismatch)
    );
    assert_eq!(runtime.identity_graph().unwrap(), IdentityGraph::default());
}

#[test]
fn invalid_window_and_pairwise_derivation_fail_before_any_mutation() {
    let mut runtime = runtime();
    let mut request = bootstrap_request("bootstrap-invalid-window");
    request.bundle.expires_at_epoch_s = request.bundle.issued_at_epoch_s - 1;
    assert_eq!(
        runtime.bootstrap_initial_identity(request),
        Err(RuntimeError::InvalidRequest("bootstrap_window"))
    );
    assert_eq!(runtime.identity_graph().unwrap(), IdentityGraph::default());

    let mut runtime = runtime_with_pairwise_deriver(Box::new(FailingPairwiseDeriver));
    assert_eq!(
        runtime.bootstrap_initial_identity(bootstrap_request("bootstrap-pairwise-fail")),
        Err(RuntimeError::PersistenceFailure)
    );
    assert_eq!(runtime.identity_graph().unwrap(), IdentityGraph::default());
}
