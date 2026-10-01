#[test]
fn id_51_session_rotation_needs_no_session_locator_or_config_exchange() {
    // ID-51: current evidence follows only the durable per-device slot.
    let (mut runtime, service, device, old_session) = seeded();
    let old = runtime
        .issue_current_device_identity_evidence(current(&service, &device, "before-rotation"))
        .expect("current evidence");
    assert_eq!(old.assertion.session_ref, old_session.session_ref);
    assert!(current_status_matches_assertion(
        &old.current_status,
        &old.assertion
    ));
    assert_eq!(
        old.assertion.expires_at_epoch_s - old.assertion.issued_at_epoch_s,
        30
    );
    assert_eq!(
        old.current_status.expires_at_epoch_s,
        old.assertion.expires_at_epoch_s
    );

    let ordinary = issue(
        &mut runtime,
        "account-a",
        &service,
        &device,
        "ordinary-session",
    );
    let still_old = runtime
        .issue_current_device_identity_evidence(current(&service, &device, "ordinary-ignored"))
        .expect("ordinary session does not own reserved slot");
    assert_eq!(still_old.assertion.session_ref, old_session.session_ref);
    assert_ne!(still_old.assertion.session_ref, ordinary.session_ref);

    let new_session = establish(
        &mut runtime,
        &service,
        &device,
        "session-b",
        ExpectedCurrentSession::Present {
            session_ref: old_session.session_ref.clone(),
            session_epoch: old_session.session_epoch,
        },
    );
    runtime.restart().expect("durable restart");

    let new = runtime
        .issue_current_device_identity_evidence(current(&service, &device, "after-rotation"))
        .expect("current evidence after rotation");
    assert_eq!(new.assertion.session_ref, new_session.session_ref);
    assert_ne!(new.assertion.session_ref, old.assertion.session_ref);
    let wire = serde_json::to_string(&serde_json::json!({
        "assertion": new.assertion,
        "current_status": new.current_status,
    }))
    .expect("evidence json");
    assert!(!wire.contains("account-a"));
    assert!(!wire.contains("session-b"));
    let old_record = runtime
        .identity_graph()
        .expect("graph")
        .sessions
        .into_iter()
        .find(|value| value.session_ref == old_session.session_ref)
        .expect("old slot record");
    assert_eq!(old_record.status, LifecycleStatus::Revoked);
    assert_eq!(old_record.session_epoch, old_session.session_epoch + 1);
}

#[test]
fn missing_or_revoked_slot_rejects_but_ordinary_sessions_never_select_current() {
    let (mut runtime, service, device) = base();
    issue(&mut runtime, "account-a", &service, &device, "ordinary-a");
    issue(&mut runtime, "account-a", &service, &device, "ordinary-b");
    assert_eq!(
        runtime
            .issue_current_device_identity_evidence(current(&service, &device, "no-slot"))
            .expect_err("ordinary sessions cannot imply current"),
        RuntimeError::NotFound("current_identity_session")
    );

    let session = establish(
        &mut runtime,
        &service,
        &device,
        "current-a",
        ExpectedCurrentSession::Absent,
    );
    runtime
        .revoke(RevokeRequest {
            command_id: "revoke-only-session".into(),
            target: RevocationTarget::Session {
                account_id: "account-a".into(),
                service_id: service.service_id.clone(),
                session_id: session.session_id,
            },
            expected_epoch: session.session_epoch,
            authority_id: "identity-authority".into(),
        })
        .expect("revoke");
    assert_eq!(
        runtime
            .issue_current_device_identity_evidence(current(&service, &device, "revoked-slot"))
            .expect_err("revoked slot"),
        RuntimeError::SessionRevoked
    );
}

#[test]
fn bootstrap_atomically_initializes_the_reserved_identity_session_slot() {
    let mut runtime = signed(runtime());
    let receipt = runtime
        .bootstrap_initial_identity(bootstrap_request("identity-slot-bootstrap"))
        .expect("bootstrap");
    let evidence = runtime
        .issue_current_device_identity_evidence(current(
            &receipt.service_account,
            &receipt.device,
            "after-bootstrap",
        ))
        .expect("bootstrap session is current");
    assert_eq!(evidence.assertion.session_ref, receipt.session.session_ref);
}
