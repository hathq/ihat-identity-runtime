#[test]
fn preparation_rejects_stale_and_replayed_commands_before_durable_mutation() {
    let mut fixture = preparation_fixture();
    let original = fixture
        .runtime
        .snapshot_persistent_store_for_test()
        .expect("original image");

    let mut stale = session_revocation("prepare-stale", &fixture.session_a);
    stale.expected_epoch += 1;
    assert_eq!(
        fixture.runtime.prepare_revocation(BEGIN_A, stale),
        Err(RuntimeError::StaleEpoch {
            scope: RevocationScope::Session,
            presented: fixture.session_a.session_epoch + 1,
            current: fixture.session_a.session_epoch,
        })
    );
    assert_eq!(
        fixture
            .runtime
            .snapshot_persistent_store_for_test()
            .expect("unchanged image"),
        original
    );

    let replayed = session_revocation("issue-session-a", &fixture.session_a);
    assert_eq!(
        fixture.runtime.prepare_revocation(BEGIN_A, replayed),
        Err(RuntimeError::ReplayDetected)
    );
    assert_eq!(
        fixture
            .runtime
            .snapshot_persistent_store_for_test()
            .expect("unchanged image"),
        original
    );
}

#[test]
fn receipt_and_preparation_slots_share_one_bounded_capacity() {
    let mut fixture = preparation_fixture();
    fixture
        .runtime
        .prepare_revocation(
            BEGIN_A,
            session_revocation("capacity-prepared", &fixture.session_a),
        )
        .expect("one prepared slot");
    let prepared = fixture
        .runtime
        .snapshot_persistent_store_for_test()
        .expect("prepared image");
    let full = insert_synthetic_receipts(&prepared, 4_095);
    let control = PreparationImageControl::new(full);
    let mut reopened = preparation_runtime_from_control(&control, test_trust())
        .expect("combined capacity boundary must reopen");
    let before = control.image();

    assert_eq!(
        reopened.prepare_revocation(
            BEGIN_B,
            session_revocation("capacity-overflow", &fixture.session_b),
        ),
        Err(RuntimeError::LimitExceeded {
            field: "revocation_receipts",
            limit: 4_096,
        })
    );
    assert_eq!(control.image(), before);
}

#[test]
fn preparation_handles_are_random_distinct_and_not_caller_guessable() {
    let mut fixture = preparation_fixture();
    let first = fixture
        .runtime
        .prepare_revocation(
            BEGIN_A,
            session_revocation("random-handle-a", &fixture.session_a),
        )
        .expect("first handle");
    let second = fixture
        .runtime
        .prepare_revocation(
            BEGIN_B,
            session_revocation("random-handle-b", &fixture.session_b),
        )
        .expect("second handle");

    for handle in [&first, &second] {
        assert_eq!(handle.preparation_id.len(), 64);
        assert!(
            handle
                .preparation_id
                .bytes()
                .all(|byte| { byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte) })
        );
        assert_ne!(handle.preparation_id, BEGIN_A);
        assert_ne!(handle.preparation_id, BEGIN_B);
    }
    assert_ne!(first, second);

    let wrong = changed_handle(&first);
    assert_eq!(
        fixture.runtime.commit_prepared_revocation(&wrong),
        Err(RuntimeError::InvalidRequest("revocation_not_prepared"))
    );
    assert_eq!(
        fixture.runtime.cancel_prepared_revocation(&wrong),
        Err(RuntimeError::InvalidRequest("revocation_not_prepared"))
    );
}
