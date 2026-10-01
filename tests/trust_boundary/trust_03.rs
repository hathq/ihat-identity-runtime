#[test]
fn id_13_through_15_authentication_requires_time_and_verification() {
    let (mut runtime, controls) = runtime_and_controls();
    let mut expired = account_request("expired", "id-13");
    expired.authentication.issued_at = TEST_NOW - 60;
    expired.authentication.expires_at = TEST_NOW;
    assert_eq!(
        runtime.create_account(expired).unwrap_err(),
        RuntimeError::EvidenceExpired(EvidenceKind::Authentication)
    );
    let mut future = account_request("future", "id-14");
    future.authentication.issued_at = TEST_NOW + 1;
    future.authentication.expires_at = TEST_NOW + 61;
    assert_eq!(
        runtime.create_account(future).unwrap_err(),
        RuntimeError::EvidenceFromFuture(EvidenceKind::Authentication)
    );
    controls.authentication.store(REJECT, Ordering::SeqCst);
    assert_eq!(
        runtime
            .create_account(account_request("unsigned", "id-15"))
            .unwrap_err(),
        RuntimeError::EvidenceUnverified(EvidenceKind::Authentication)
    );
}

#[test]
fn id_16_through_18_device_attestation_possession_and_time_are_verified() {
    let (mut runtime, controls) = runtime_and_controls();
    let service = create_account_and_service(&mut runtime, "account-a", "service-a");
    controls.attestation.store(REJECT, Ordering::SeqCst);
    assert_eq!(
        runtime
            .enroll_device(enrollment("account-a", &service, "device-a", "key-a"))
            .unwrap_err(),
        RuntimeError::EvidenceUnverified(EvidenceKind::DeviceAttestation)
    );
    controls.attestation.store(VALID, Ordering::SeqCst);
    controls.possession.store(REJECT, Ordering::SeqCst);
    assert_eq!(
        runtime
            .enroll_device(enrollment("account-a", &service, "device-a", "key-a"))
            .unwrap_err(),
        RuntimeError::EvidenceUnverified(EvidenceKind::DeviceKeyPossession)
    );
    controls.possession.store(EXPIRED, Ordering::SeqCst);
    assert_eq!(
        runtime
            .enroll_device(enrollment("account-a", &service, "device-a", "key-a"))
            .unwrap_err(),
        RuntimeError::EvidenceExpired(EvidenceKind::DeviceKeyPossession)
    );
}

#[test]
fn id_19_through_21_session_sender_proof_is_required_for_issue_and_use() {
    let (mut runtime, controls) = runtime_and_controls();
    let service = create_account_and_service(&mut runtime, "account-a", "service-a");
    let device = enroll(&mut runtime, "account-a", &service, "device-a", "key-a");
    controls.session.store(REJECT, Ordering::SeqCst);
    assert_eq!(
        runtime
            .issue_session(session_request("account-a", &service, &device, "session-a"))
            .unwrap_err(),
        RuntimeError::EvidenceUnverified(EvidenceKind::SessionSenderProof)
    );
    controls.session.store(VALID, Ordering::SeqCst);
    let session = issue(&mut runtime, "account-a", &service, &device, "session-a");
    controls.session.store(REJECT, Ordering::SeqCst);
    assert_eq!(
        runtime
            .authorize_session(session_proof(&session, "id-20"))
            .unwrap_err(),
        RuntimeError::EvidenceUnverified(EvidenceKind::SessionSenderProof)
    );
    controls.session.store(EXPIRED, Ordering::SeqCst);
    assert_eq!(
        runtime
            .authorize_session(session_proof(&session, "id-21"))
            .unwrap_err(),
        RuntimeError::EvidenceExpired(EvidenceKind::SessionSenderProof)
    );
}

#[test]
fn id_22_and_23_revocation_requires_current_authority_proof() {
    let (mut runtime, controls) = runtime_and_controls();
    runtime
        .create_account(account_request("account-a", "create-a"))
        .unwrap();
    controls.revocation.store(REJECT, Ordering::SeqCst);
    assert_eq!(
        runtime.revoke(subject_revoke("id-22")).unwrap_err(),
        RuntimeError::EvidenceUnverified(EvidenceKind::RevocationAuthority)
    );
    controls.revocation.store(EXPIRED, Ordering::SeqCst);
    assert_eq!(
        runtime.revoke(subject_revoke("id-23")).unwrap_err(),
        RuntimeError::EvidenceExpired(EvidenceKind::RevocationAuthority)
    );
}

#[test]
fn id_24_through_26_recovery_verifies_approvals_and_replacement_key() {
    let (mut runtime, controls) = runtime_and_controls();
    let service = create_account_and_service(&mut runtime, "account-a", "service-a");
    enroll(&mut runtime, "account-a", &service, "device-a", "key-a");
    controls.recovery.store(REJECT, Ordering::SeqCst);
    assert_eq!(
        runtime
            .recover_device(recovery(&service, "id-24"))
            .unwrap_err(),
        RuntimeError::EvidenceUnverified(EvidenceKind::RecoveryApproval)
    );
    controls.recovery.store(FUTURE, Ordering::SeqCst);
    let mut future = recovery(&service, "id-25");
    for approval in &mut future.approvals {
        approval.approved_at = TEST_NOW + 1;
    }
    assert_eq!(
        runtime.recover_device(future).unwrap_err(),
        RuntimeError::EvidenceFromFuture(EvidenceKind::RecoveryApproval)
    );
    controls.recovery.store(VALID, Ordering::SeqCst);
    controls.possession.store(REJECT, Ordering::SeqCst);
    assert_eq!(
        runtime
            .recover_device(recovery(&service, "id-26"))
            .unwrap_err(),
        RuntimeError::EvidenceUnverified(EvidenceKind::DeviceKeyPossession)
    );
}
