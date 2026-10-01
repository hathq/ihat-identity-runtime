#[test]
fn exact_prepare_retry_still_requires_current_revocation_authority() {
    let revocation_allowed = Arc::new(AtomicBool::new(true));
    let preparation_allowed = Arc::new(AtomicBool::new(true));
    let trust = controlled_preparation_trust(revocation_allowed.clone(), preparation_allowed);
    let mut fixture = preparation_fixture_with(runtime_with_trust(trust));
    let request = session_revocation("authorized-prepare-retry", &fixture.session_a);
    let handle = fixture
        .runtime
        .prepare_revocation(BEGIN_A, request.clone())
        .expect("initial preparation");
    let prepared = fixture
        .runtime
        .snapshot_persistent_store_for_test()
        .expect("prepared image");

    revocation_allowed.store(false, Ordering::SeqCst);
    assert_eq!(
        fixture.runtime.prepare_revocation(BEGIN_A, request.clone()),
        Err(RuntimeError::EvidenceUnverified(
            EvidenceKind::RevocationAuthority,
        ))
    );
    assert_eq!(
        fixture
            .runtime
            .snapshot_persistent_store_for_test()
            .expect("unchanged prepared image"),
        prepared
    );

    revocation_allowed.store(true, Ordering::SeqCst);
    assert_eq!(
        fixture.runtime.prepare_revocation(BEGIN_A, request),
        Ok(handle)
    );
}

#[test]
fn exact_commit_is_idempotent_and_every_retry_requires_execution_authority() {
    let revocation_allowed = Arc::new(AtomicBool::new(true));
    let preparation_allowed = Arc::new(AtomicBool::new(true));
    let trust = controlled_preparation_trust(revocation_allowed, preparation_allowed.clone());
    let mut fixture = preparation_fixture_with(runtime_with_trust(trust));
    let handle = fixture
        .runtime
        .prepare_revocation(
            BEGIN_A,
            session_revocation("authorized-commit", &fixture.session_a),
        )
        .expect("prepared handle");
    let prepared = fixture
        .runtime
        .snapshot_persistent_store_for_test()
        .expect("prepared image");

    preparation_allowed.store(false, Ordering::SeqCst);
    assert_eq!(
        fixture.runtime.commit_prepared_revocation(&handle),
        Err(RuntimeError::EvidenceUnverified(
            EvidenceKind::RevocationExecutionAuthorization,
        ))
    );
    assert_eq!(
        fixture
            .runtime
            .snapshot_persistent_store_for_test()
            .unwrap(),
        prepared
    );

    preparation_allowed.store(true, Ordering::SeqCst);
    let receipt = fixture
        .runtime
        .commit_prepared_revocation(&handle)
        .expect("authorized commit");
    let committed = fixture
        .runtime
        .snapshot_persistent_store_for_test()
        .unwrap();
    preparation_allowed.store(false, Ordering::SeqCst);
    assert_eq!(
        fixture.runtime.commit_prepared_revocation(&handle),
        Err(RuntimeError::EvidenceUnverified(
            EvidenceKind::RevocationExecutionAuthorization,
        ))
    );
    preparation_allowed.store(true, Ordering::SeqCst);
    assert_eq!(
        fixture.runtime.commit_prepared_revocation(&handle),
        Ok(receipt)
    );
    assert_eq!(
        fixture
            .runtime
            .snapshot_persistent_store_for_test()
            .unwrap(),
        committed
    );
}
