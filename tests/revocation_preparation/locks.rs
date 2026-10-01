#[test]
fn device_preparation_locks_same_target_descendant_and_ancestor_mutations() {
    let mut fixture = preparation_fixture();
    let handle = fixture
        .runtime
        .prepare_revocation(
            BEGIN_A,
            device_revocation("lock-device-a", &fixture.device_a),
        )
        .expect("device preparation");
    let locked_graph = fixture.runtime.identity_graph().expect("locked graph");
    let locked_image = fixture
        .runtime
        .snapshot_persistent_store_for_test()
        .unwrap();

    for request in [
        device_revocation("mutate-locked-device", &fixture.device_a),
        session_revocation("mutate-locked-session", &fixture.session_a),
        service_revocation("mutate-locked-service", &fixture.service),
        subject_revocation("mutate-locked-subject", &fixture.service.account_id),
    ] {
        assert_eq!(
            fixture.runtime.revoke(request),
            Err(RuntimeError::InvalidRequest("prepared_revocation_conflict"))
        );
        assert_eq!(fixture.runtime.identity_graph().unwrap(), locked_graph);
        assert_eq!(
            fixture
                .runtime
                .snapshot_persistent_store_for_test()
                .unwrap(),
            locked_image
        );
    }

    fixture
        .runtime
        .revoke(session_revocation(
            "mutate-disjoint-session",
            &fixture.session_b,
        ))
        .expect("disjoint mutation remains available");
    let receipt = fixture
        .runtime
        .commit_prepared_revocation(&handle)
        .expect("locked revocation still commits");
    assert_eq!(receipt.previous_epoch, fixture.device_a.device_epoch);
    assert_eq!(receipt.current_epoch, fixture.device_a.device_epoch + 1);
}

#[test]
fn overlapping_preparations_are_rejected_but_disjoint_target_is_allowed() {
    let mut fixture = preparation_fixture();
    let device_handle = fixture
        .runtime
        .prepare_revocation(
            BEGIN_A,
            device_revocation("prepare-device-lock", &fixture.device_a),
        )
        .expect("device preparation");

    for request in [
        device_revocation("prepare-same-device", &fixture.device_a),
        session_revocation("prepare-device-session", &fixture.session_a),
        service_revocation("prepare-device-service", &fixture.service),
        subject_revocation("prepare-device-subject", &fixture.service.account_id),
    ] {
        assert_eq!(
            fixture.runtime.prepare_revocation(BEGIN_B, request),
            Err(RuntimeError::ReplayDetected)
        );
    }

    let disjoint = fixture
        .runtime
        .prepare_revocation(
            BEGIN_B,
            session_revocation("prepare-disjoint-session", &fixture.session_b),
        )
        .expect("disjoint preparation");
    fixture
        .runtime
        .cancel_prepared_revocation(&disjoint)
        .expect("cancel disjoint preparation");
    fixture
        .runtime
        .cancel_prepared_revocation(&device_handle)
        .expect("cancel device preparation");
}

#[test]
fn exact_cancel_tombstone_consumes_command_and_releases_target_lock() {
    let mut fixture = preparation_fixture();
    let request = device_revocation("cancel-and-release", &fixture.device_a);
    let handle = fixture
        .runtime
        .prepare_revocation(BEGIN_A, request.clone())
        .expect("device preparation");
    fixture
        .runtime
        .cancel_prepared_revocation(&handle)
        .expect("cancel preparation");
    fixture
        .runtime
        .cancel_prepared_revocation(&handle)
        .expect("idempotent cancel");

    assert_eq!(
        fixture.runtime.prepare_revocation(BEGIN_A, request),
        Err(RuntimeError::ReplayDetected)
    );
    let replacement = fixture
        .runtime
        .prepare_revocation(
            BEGIN_B,
            device_revocation("prepare-after-cancel", &fixture.device_a),
        )
        .expect("released target lock");
    fixture
        .runtime
        .cancel_prepared_revocation(&replacement)
        .expect("cleanup replacement preparation");
}
