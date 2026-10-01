#[test]
fn pre_wal_state_anchor_pair_opens_without_pending_image() {
    let directory = TempDirectory::new("pre-wal");
    let path = directory.path.join("identity.state");
    let expected = {
        let mut runtime = file_runtime(&path);
        create_account_and_service(&mut runtime, "account-a", "service-a");
        runtime.identity_graph().unwrap()
    };
    let pending = directory.path.join(".identity.state.anchor.pending");
    assert!(!pending.exists());
    let reopened = file_runtime(&path);
    assert_eq!(reopened.identity_graph().unwrap(), expected);
    assert!(!pending.exists());
}

#[test]
fn stale_pending_image_is_removed_only_when_current_anchor_is_exact() {
    let directory = TempDirectory::new("stale-pending");
    let path = directory.path.join("identity.state");
    let expected = {
        let mut runtime = file_runtime(&path);
        create_account_and_service(&mut runtime, "account-a", "service-a");
        runtime.identity_graph().unwrap()
    };
    let pending = directory.path.join(".identity.state.anchor.pending");
    fs::write(&pending, b"uncommitted-future-anchor").unwrap();
    fs::set_permissions(&pending, fs::Permissions::from_mode(0o600)).unwrap();
    let reopened = file_runtime(&path);
    assert_eq!(reopened.identity_graph().unwrap(), expected);
    assert!(!pending.exists());
}

#[test]
fn mismatched_state_anchor_and_pending_images_fail_closed() {
    let directory = TempDirectory::new("three-image-mismatch");
    let path = directory.path.join("identity.state");
    drop(file_runtime(&path));
    let anchor = directory.path.join(".identity.state.anchor");
    let pending = directory.path.join(".identity.state.anchor.pending");
    fs::write(&anchor, b"wrong-current-anchor").unwrap();
    fs::write(&pending, b"wrong-pending-anchor").unwrap();
    fs::set_permissions(&pending, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(matches!(
        IdentityRuntime::open_file(&path, Box::new(TestPairwiseDeriver), test_trust()),
        Err(RuntimeError::DatabaseRollbackDetected)
    ));
}
