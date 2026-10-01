#[test]
fn wrong_route_sender_and_retired_sender_fail_closed() {
    let (mut runtime, service, device, _) = seeded();
    for (field, expected) in [
        ("service", RuntimeError::NotFound("service")),
        ("pairwise", RuntimeError::NotFound("service")),
        ("device", RuntimeError::NotFound("device")),
    ] {
        let mut request = current(&service, &device, field);
        match field {
            "service" => request.service_id = "wrong-service".into(),
            "pairwise" => request.pairwise_subject = "wrong-subject".into(),
            _ => request.device_id = "wrong-device".into(),
        }
        assert_eq!(
            runtime
                .issue_current_device_identity_evidence(request)
                .expect_err("wrong route"),
            expected
        );
    }
    let mut wrong = current(&service, &device, "wrong-sender");
    wrong.session_sender_key_fingerprint = "attacker-key".into();
    assert_eq!(
        runtime
            .issue_current_device_identity_evidence(wrong)
            .expect_err("wrong sender"),
        RuntimeError::SenderBindingMismatch
    );

    let rotated = runtime
        .rotate_device_key(RotateDeviceKeyRequest {
            command_id: "rotate-device-key".into(),
            account_id: "account-a".into(),
            service_id: service.service_id.clone(),
            device_id: device.device_id.clone(),
            retired_key_fingerprint: device.key_fingerprint.clone(),
            replacement_key: device_key("key-b"),
            fresh_user_authentication: Some(authentication("rotate-auth", "auth-key-a")),
            expected_device_epoch: device.device_epoch,
        })
        .expect("rotate device key");
    assert_eq!(
        runtime
            .issue_current_device_identity_evidence(current(&service, &device, "retired"))
            .expect_err("retired sender"),
        RuntimeError::RetiredDeviceKey
    );
    assert_eq!(
        runtime
            .issue_current_device_identity_evidence(current(&service, &rotated, "no-new-session"))
            .expect_err("new sender has no session"),
        RuntimeError::SenderBindingMismatch
    );
}

#[test]
fn revoked_device_subject_and_closed_service_each_reject() {
    let (mut runtime, service, device, _) = seeded();
    runtime
        .revoke_device(RevokeDeviceRequest {
            command_id: "revoke-device".into(),
            account_id: "account-a".into(),
            service_id: service.service_id.clone(),
            device_id: device.device_id.clone(),
            expected_device_epoch: device.device_epoch,
            authority_id: "identity-authority".into(),
        })
        .expect("revoke device");
    assert_eq!(
        runtime
            .issue_current_device_identity_evidence(current(&service, &device, "revoked-device"))
            .expect_err("revoked device"),
        RuntimeError::DeviceRevoked
    );

    let (mut runtime, service, device, _) = seeded();
    runtime
        .close_service_account(CloseServiceAccountRequest {
            command_id: "close-service".into(),
            account_id: "account-a".into(),
            service_id: service.service_id.clone(),
            fresh_user_authentication: authentication("close-auth", "auth-key-a"),
            expected_service_epoch: service.service_epoch,
        })
        .expect("close service");
    assert_eq!(
        runtime
            .issue_current_device_identity_evidence(current(&service, &device, "closed-service"))
            .expect_err("closed service"),
        RuntimeError::ServiceAccountClosed
    );

    let (mut runtime, service, device, _) = seeded();
    runtime
        .revoke(RevokeRequest {
            command_id: "revoke-subject".into(),
            target: RevocationTarget::Subject {
                account_id: "account-a".into(),
            },
            expected_epoch: INITIAL_EPOCH,
            authority_id: "identity-authority".into(),
        })
        .expect("revoke subject");
    assert_eq!(
        runtime
            .issue_current_device_identity_evidence(current(&service, &device, "revoked-subject"))
            .expect_err("revoked subject"),
        RuntimeError::SubjectRevoked
    );
}
