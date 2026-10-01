#[test]
fn absent_cas_initializes_new_devices_once_and_survives_restart() {
    let (mut runtime, service, device_a, current_a) = seeded();
    let device_b = enroll(&mut runtime, "account-a", &service, "device-b", "key-b");
    let device_c = enroll(&mut runtime, "account-a", &service, "device-c", "key-c");
    let first = establish(
        &mut runtime,
        &service,
        &device_b,
        "device-b-current-a",
        ExpectedCurrentSession::Absent,
    );
    let current_c = establish(
        &mut runtime,
        &service,
        &device_c,
        "device-c-current-a",
        ExpectedCurrentSession::Absent,
    );
    assert_eq!(
        runtime
            .establish_device_identity_session(establish_request(
                &service,
                &device_b,
                "device-b-current-b",
                ExpectedCurrentSession::Absent,
            ))
            .expect_err("Absent CAS cannot overwrite a present slot"),
        RuntimeError::InvalidRequest("current_identity_session_cas")
    );
    let rotated_b = establish(
        &mut runtime,
        &service,
        &device_b,
        "device-b-current-rotated",
        ExpectedCurrentSession::Present {
            session_ref: first.session_ref,
            session_epoch: first.session_epoch,
        },
    );
    runtime.restart().expect("restart");
    for (device, expected, nonce) in [
        (&device_a, &current_a, "device-a-after-b-rotation"),
        (&device_b, &rotated_b, "device-b-after-restart"),
        (&device_c, &current_c, "device-c-after-b-rotation"),
    ] {
        let evidence = runtime
            .issue_current_device_identity_evidence(current(&service, device, nonce))
            .expect("independent A/B/C current identity");
        assert_eq!(evidence.assertion.session_ref, expected.session_ref);
    }
}

#[test]
fn concurrent_stale_present_cas_cannot_overwrite_the_winner() {
    let (mut runtime, service, device, initial) = seeded();
    let expected = ExpectedCurrentSession::Present {
        session_ref: initial.session_ref.clone(),
        session_epoch: initial.session_epoch,
    };
    let winner = establish(
        &mut runtime,
        &service,
        &device,
        "winner-session",
        expected.clone(),
    );
    assert_eq!(
        runtime
            .establish_device_identity_session(establish_request(
                &service,
                &device,
                "loser-session",
                expected,
            ))
            .expect_err("stale Present CAS"),
        RuntimeError::InvalidRequest("current_identity_session_cas")
    );
    let evidence = runtime
        .issue_current_device_identity_evidence(current(&service, &device, "winner-remains"))
        .expect("winner remains current");
    assert_eq!(evidence.assertion.session_ref, winner.session_ref);
    assert!(
        runtime
            .identity_graph()
            .expect("graph")
            .sessions
            .iter()
            .all(|value| value.session_id != "loser-session")
    );
}
