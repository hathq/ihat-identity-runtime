#[test]
fn present_rotation_succeeds_at_the_active_session_limit_without_growth() {
    let (mut runtime, service, device, initial) = seeded();
    for index in 1..MAX_SESSIONS_PER_DEVICE {
        issue(
            &mut runtime,
            "account-a",
            &service,
            &device,
            &format!("ordinary-limit-{index}"),
        );
    }
    let active_before = active_sessions(&runtime, &device);
    assert_eq!(active_before, MAX_SESSIONS_PER_DEVICE);
    establish(
        &mut runtime,
        &service,
        &device,
        "rotation-at-limit",
        ExpectedCurrentSession::Present {
            session_ref: initial.session_ref,
            session_epoch: initial.session_epoch,
        },
    );
    assert_eq!(active_sessions(&runtime, &device), active_before);
}

#[test]
fn revoked_slot_can_be_reestablished_by_exact_present_cas() {
    let (mut runtime, service, device, initial) = seeded();
    runtime
        .revoke(RevokeRequest {
            command_id: "revoke-current-for-reestablish".into(),
            target: RevocationTarget::Session {
                account_id: "account-a".into(),
                service_id: service.service_id.clone(),
                session_id: initial.session_id.clone(),
            },
            expected_epoch: initial.session_epoch,
            authority_id: "identity-authority".into(),
        })
        .expect("revoke current session");
    let revoked = runtime
        .identity_graph()
        .expect("graph")
        .sessions
        .into_iter()
        .find(|value| value.session_ref == initial.session_ref)
        .expect("revoked slot");
    assert_eq!(
        runtime
            .establish_device_identity_session(establish_request(
                &service,
                &device,
                "stale-pre-revoke-epoch",
                ExpectedCurrentSession::Present {
                    session_ref: revoked.session_ref.clone(),
                    session_epoch: initial.session_epoch,
                },
            ))
            .expect_err("pre-revocation epoch is stale"),
        RuntimeError::InvalidRequest("current_identity_session_cas")
    );
    let revoked_epoch = revoked.session_epoch;
    let revoked_ref = revoked.session_ref.clone();
    let replacement = establish(
        &mut runtime,
        &service,
        &device,
        "reestablished-current",
        ExpectedCurrentSession::Present {
            session_ref: revoked.session_ref,
            session_epoch: revoked.session_epoch,
        },
    );
    let evidence = runtime
        .issue_current_device_identity_evidence(current(&service, &device, "after-reestablish"))
        .expect("replacement is current");
    assert_eq!(evidence.assertion.session_ref, replacement.session_ref);
    let old_after = runtime
        .identity_graph()
        .expect("graph")
        .sessions
        .into_iter()
        .find(|value| value.session_ref == revoked_ref)
        .expect("old revoked slot");
    assert_eq!(old_after.status, LifecycleStatus::Revoked);
    assert_eq!(old_after.session_epoch, revoked_epoch);
}

fn active_sessions(runtime: &IdentityRuntime, device: &DeviceRecord) -> usize {
    runtime
        .identity_graph()
        .expect("graph")
        .sessions
        .iter()
        .filter(|value| {
            value.device_id == device.device_id && value.status == LifecycleStatus::Active
        })
        .count()
}
