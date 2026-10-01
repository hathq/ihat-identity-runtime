#[test]
fn prepared_and_committed_records_reopen_with_exact_idempotence() {
    let mut fixture = preparation_fixture();
    let request = session_revocation("reopen-prepared", &fixture.session_a);
    let handle = fixture
        .runtime
        .prepare_revocation(BEGIN_A, request.clone())
        .expect("prepare before reopen");
    let control = PreparationImageControl::new(
        fixture
            .runtime
            .snapshot_persistent_store_for_test()
            .expect("prepared image"),
    );
    let mut reopened =
        preparation_runtime_from_control(&control, test_trust()).expect("reopen prepared state");
    assert_eq!(
        reopened.prepare_revocation(BEGIN_A, request),
        Ok(handle.clone())
    );
    let receipt = reopened
        .commit_prepared_revocation(&handle)
        .expect("commit after reopen");
    let committed_image = control.image();

    let mut committed =
        preparation_runtime_from_control(&control, test_trust()).expect("reopen committed state");
    assert_eq!(
        committed.commit_prepared_revocation(&handle),
        Ok(receipt.clone())
    );
    assert_eq!(control.image(), committed_image);
    assert_eq!(receipt.previous_epoch, fixture.session_a.session_epoch);
    assert_eq!(receipt.current_epoch, fixture.session_a.session_epoch + 1);
}

#[test]
fn reopen_rejects_malformed_underreserved_and_overlapping_preparations() {
    let mut fixture = preparation_fixture();
    fixture
        .runtime
        .prepare_revocation(
            BEGIN_A,
            session_revocation("validate-prepared", &fixture.session_a),
        )
        .expect("prepared record");
    let image = fixture
        .runtime
        .snapshot_persistent_store_for_test()
        .expect("prepared image");

    let malformed = map_preparation_image(&image, |payload| {
        let prepared = payload["prepared_revocations"]
            .as_object_mut()
            .unwrap()
            .values_mut()
            .next()
            .unwrap();
        prepared["preparation_id"] = json!("not-a-digest");
    });
    assert_preparation_reopen_fails(malformed);

    let underreserved = map_preparation_image(&image, |payload| {
        let prepared = payload["prepared_revocations"]
            .as_object_mut()
            .unwrap()
            .values_mut()
            .next()
            .unwrap();
        prepared["future_bytes"] = json!(0);
    });
    assert_preparation_reopen_fails(underreserved);

    let overlapping = map_preparation_image(&image, |payload| {
        let prepared = payload["prepared_revocations"].as_object_mut().unwrap();
        let mut duplicate = prepared.values().next().unwrap().clone();
        duplicate["preparation_id"] = json!(BEGIN_B);
        duplicate["request"]["command_id"] = json!("validate-overlapping");
        prepared.insert("validate-overlapping".into(), duplicate);
    });
    assert_preparation_reopen_fails(overlapping);
}

#[test]
fn reopen_rejects_cancel_tombstone_that_is_not_bound_to_its_exact_command() {
    let mut fixture = preparation_fixture();
    let handle = fixture
        .runtime
        .prepare_revocation(
            BEGIN_A,
            device_revocation("validate-cancelled", &fixture.device_a),
        )
        .expect("prepared record");
    fixture
        .runtime
        .cancel_prepared_revocation(&handle)
        .expect("cancelled record");
    let image = fixture
        .runtime
        .snapshot_persistent_store_for_test()
        .expect("cancelled image");
    let substituted = map_preparation_image(&image, |payload| {
        let cancelled = payload["cancelled_revocation_preparations"]
            .as_object_mut()
            .unwrap()
            .values_mut()
            .next()
            .unwrap();
        cancelled["request"]["command_id"] = json!("substituted-command");
    });
    assert_preparation_reopen_fails(substituted);
}

fn assert_preparation_reopen_fails(image: PersistedImage) {
    let control = PreparationImageControl::new(image);
    assert!(matches!(
        preparation_runtime_from_control(&control, test_trust()),
        Err(RuntimeError::PersistenceFailure)
    ));
}
