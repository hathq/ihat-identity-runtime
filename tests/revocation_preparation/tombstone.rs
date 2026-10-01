#[test]
fn cancel_tombstone_is_idempotent_and_every_retry_requires_authority() {
    let revocation_allowed = Arc::new(AtomicBool::new(true));
    let preparation_allowed = Arc::new(AtomicBool::new(true));
    let trust = controlled_preparation_trust(revocation_allowed, preparation_allowed.clone());
    let mut fixture = preparation_fixture_with(runtime_with_trust(trust));
    let request = device_revocation("authorized-cancel", &fixture.device_a);
    let handle = fixture
        .runtime
        .prepare_revocation(BEGIN_A, request.clone())
        .expect("prepared handle");

    preparation_allowed.store(false, Ordering::SeqCst);
    assert_eq!(
        fixture.runtime.cancel_prepared_revocation(&handle),
        Err(RuntimeError::EvidenceUnverified(
            EvidenceKind::RevocationExecutionAuthorization,
        ))
    );
    preparation_allowed.store(true, Ordering::SeqCst);
    fixture
        .runtime
        .cancel_prepared_revocation(&handle)
        .expect("authorized cancellation");
    let cancelled = fixture
        .runtime
        .snapshot_persistent_store_for_test()
        .unwrap();
    let payload: Value = serde_json::from_slice(&cancelled.0[16..]).unwrap();
    let tombstone = payload["cancelled_revocation_preparations"]
        .get(&request.command_id)
        .unwrap();
    assert_eq!(tombstone["preparation_id"], handle.preparation_id);
    assert_eq!(
        serde_json::from_value::<RevokeRequest>(tombstone["request"].clone()).unwrap(),
        request
    );

    preparation_allowed.store(false, Ordering::SeqCst);
    assert_eq!(
        fixture.runtime.cancel_prepared_revocation(&handle),
        Err(RuntimeError::EvidenceUnverified(
            EvidenceKind::RevocationExecutionAuthorization,
        ))
    );
    preparation_allowed.store(true, Ordering::SeqCst);
    fixture
        .runtime
        .cancel_prepared_revocation(&handle)
        .expect("authorized idempotent cancellation");
    assert_eq!(
        fixture
            .runtime
            .snapshot_persistent_store_for_test()
            .unwrap(),
        cancelled
    );
}
