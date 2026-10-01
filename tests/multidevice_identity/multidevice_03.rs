#[test]
fn id_07_session_sender_is_bound_to_exact_registered_device_key() {
    // ID-07: issuing and using a Session both require proof by the exact current
    // device key; changing only the claimed device_id is insufficient.
    let mut runtime = runtime();
    let service = create_account_and_service(&mut runtime, "account-a", "service-a");
    let device = enroll(&mut runtime, "account-a", &service, "device-a", "key-a");

    let mut wrong_issue = session_request("account-a", &service, &device, "session-wrong");
    wrong_issue.sender_key_fingerprint = "key-attacker".into();
    assert_eq!(
        runtime.issue_session(wrong_issue).unwrap_err(),
        RuntimeError::SenderBindingMismatch
    );

    let session = issue(&mut runtime, "account-a", &service, &device, "session-a");
    let mut wrong_use = session_proof(&session, "proof-wrong-sender");
    wrong_use.sender_key_fingerprint = "key-attacker".into();
    assert_eq!(
        runtime.authorize_session(wrong_use).unwrap_err(),
        RuntimeError::SenderBindingMismatch
    );
    assert_eq!(
        runtime
            .authorize_session(session_proof(&session, "proof-correct-sender"))
            .unwrap(),
        AuthorizationDecision::Authorized
    );
}

#[test]
fn id_08_device_session_and_subject_revocation_use_independent_monotonic_epochs() {
    // ID-08: Subject, Device, and Session are independent canonical revocation
    // dimensions; each transition is monotonic and only its intended scope dies.
    let mut runtime = runtime();
    let service = create_account_and_service(&mut runtime, "account-a", "service-a");
    let device_a = enroll(&mut runtime, "account-a", &service, "device-a", "key-a");
    let device_b = enroll(&mut runtime, "account-a", &service, "device-b", "key-b");
    let device_c = enroll(&mut runtime, "account-a", &service, "device-c", "key-c");
    let session_a = issue(&mut runtime, "account-a", &service, &device_a, "session-a");
    let session_b = issue(&mut runtime, "account-a", &service, &device_b, "session-b");
    let session_c = issue(&mut runtime, "account-a", &service, &device_c, "session-c");
    let before = runtime.revocation_snapshot().unwrap();

    let device_target = RevocationTarget::Device {
        account_id: "account-a".into(),
        service_id: "service-a".into(),
        device_id: "device-a".into(),
    };
    let device_receipt = runtime
        .revoke(RevokeRequest {
            command_id: "revoke-device-a".into(),
            target: device_target,
            expected_epoch: device_a.device_epoch,
            authority_id: "identity-authority".into(),
        })
        .unwrap();
    assert_eq!(
        device_receipt.current_epoch,
        device_receipt.previous_epoch + 1
    );
    assert_eq!(
        runtime
            .authorize_session(session_proof(&session_a, "proof-revoked-device"))
            .unwrap_err(),
        RuntimeError::SessionRevoked
    );
    assert_eq!(
        runtime
            .authorize_session(session_proof(&session_b, "proof-healthy-device"))
            .unwrap(),
        AuthorizationDecision::Authorized
    );

    let session_receipt = runtime
        .revoke(RevokeRequest {
            command_id: "revoke-session-b".into(),
            target: RevocationTarget::Session {
                account_id: "account-a".into(),
                service_id: "service-a".into(),
                session_id: "session-b".into(),
            },
            expected_epoch: session_b.session_epoch,
            authority_id: "identity-authority".into(),
        })
        .unwrap();
    assert_eq!(
        session_receipt.current_epoch,
        session_receipt.previous_epoch + 1
    );
    assert_eq!(
        runtime
            .authorize_session(session_proof(&session_b, "proof-revoked-session"))
            .unwrap_err(),
        RuntimeError::SessionRevoked
    );

    let subject_before = *before.subject_epochs.get("account-a").unwrap();
    let subject_receipt = runtime
        .revoke(RevokeRequest {
            command_id: "revoke-subject-a".into(),
            target: RevocationTarget::Subject {
                account_id: "account-a".into(),
            },
            expected_epoch: subject_before,
            authority_id: "identity-authority".into(),
        })
        .unwrap();
    assert_eq!(subject_receipt.current_epoch, subject_before + 1);
    let after = runtime.revocation_snapshot().unwrap();
    assert_eq!(
        runtime
            .authorize_session(session_proof(&session_c, "proof-revoked-subject"))
            .unwrap_err(),
        RuntimeError::SubjectRevoked
    );
    assert_eq!(
        after
            .device_epochs
            .get(&("account-a".into(), "service-a".into(), "device-b".into())),
        before
            .device_epochs
            .get(&("account-a".into(), "service-a".into(), "device-b".into()))
    );
}
