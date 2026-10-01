#[test]
fn id_11_device_key_rotation_requires_fresh_user_proof_and_retires_old_key() {
    // ID-11: key rotation requires fresh user proof plus a new unique
    // non-exportable key; the retired key cannot issue or use Sessions.
    let mut runtime = runtime();
    let service = create_account_and_service(&mut runtime, "account-a", "service-a");
    let device = enroll(&mut runtime, "account-a", &service, "device-a", "key-old");
    let old_session = issue(&mut runtime, "account-a", &service, &device, "session-old");

    let no_user_proof = RotateDeviceKeyRequest {
        command_id: "rotate-without-user-proof".into(),
        account_id: "account-a".into(),
        service_id: "service-a".into(),
        device_id: "device-a".into(),
        retired_key_fingerprint: "key-old".into(),
        replacement_key: device_key("key-new"),
        fresh_user_authentication: None,
        expected_device_epoch: device.device_epoch,
    };
    assert_eq!(
        runtime.rotate_device_key(no_user_proof).unwrap_err(),
        RuntimeError::FreshAuthenticationRequired
    );

    let rotated = runtime
        .rotate_device_key(RotateDeviceKeyRequest {
            command_id: "rotate-with-fresh-user-proof".into(),
            account_id: "account-a".into(),
            service_id: "service-a".into(),
            device_id: "device-a".into(),
            retired_key_fingerprint: "key-old".into(),
            replacement_key: device_key("key-new"),
            fresh_user_authentication: Some(authentication("rotation-proof", "auth-key-a")),
            expected_device_epoch: device.device_epoch,
        })
        .expect("fresh user proof must authorize an atomic key rotation");
    assert_eq!(rotated.key_fingerprint, "key-new");
    assert_eq!(
        runtime
            .authorize_session(session_proof(&old_session, "retired-key-proof"))
            .unwrap_err(),
        RuntimeError::RetiredDeviceKey
    );
}

#[test]
fn id_12_closing_service_account_revokes_only_that_service_descendants() {
    // ID-12: closing one pairwise ServiceAccount revokes its Devices and
    // Sessions without changing another ServiceAccount for the same Account.
    let mut runtime = runtime();
    runtime
        .create_account(account_request("account-a", "create-account-a"))
        .expect("initial account registration must succeed");
    let service_a = runtime
        .create_service_account(service_request("account-a", "service-a"))
        .unwrap();
    let service_b = runtime
        .create_service_account(service_request("account-a", "service-b"))
        .unwrap();
    let device_a = enroll(&mut runtime, "account-a", &service_a, "device-a", "key-a");
    let device_b = enroll(&mut runtime, "account-a", &service_b, "device-b", "key-b");
    let session_a = issue(
        &mut runtime,
        "account-a",
        &service_a,
        &device_a,
        "session-a",
    );
    let session_b = issue(
        &mut runtime,
        "account-a",
        &service_b,
        &device_b,
        "session-b",
    );
    let before = runtime.revocation_snapshot().unwrap();

    let closed = runtime
        .close_service_account(CloseServiceAccountRequest {
            command_id: "close-service-a".into(),
            account_id: "account-a".into(),
            service_id: "service-a".into(),
            fresh_user_authentication: authentication("close-proof", "auth-key-a"),
            expected_service_epoch: service_a.service_epoch,
        })
        .unwrap();
    assert_eq!(closed.status, LifecycleStatus::Closed);
    assert_eq!(
        runtime
            .authorize_session(session_proof(&session_a, "closed-service-proof"))
            .unwrap_err(),
        RuntimeError::ServiceAccountClosed
    );
    assert_eq!(
        runtime
            .authorize_session(session_proof(&session_b, "other-service-proof"))
            .unwrap(),
        AuthorizationDecision::Authorized
    );
    let after = runtime.revocation_snapshot().unwrap();
    assert_eq!(
        after
            .service_epochs
            .get(&("account-a".into(), "service-b".into())),
        before
            .service_epochs
            .get(&("account-a".into(), "service-b".into()))
    );
}
