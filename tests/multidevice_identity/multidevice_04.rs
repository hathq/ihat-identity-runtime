#[test]
fn id_09_stale_epoch_rollback_replay_and_unknown_fields_fail_closed() {
    // ID-09: current durable epochs and replay state are authoritative. Stale
    // claims, database rollback, duplicate proof IDs, and unknown fields fail.
    let mut runtime = runtime();
    let service = create_account_and_service(&mut runtime, "account-a", "service-a");
    let device = enroll(&mut runtime, "account-a", &service, "device-a", "key-a");
    let session = issue(&mut runtime, "account-a", &service, &device, "session-a");
    let old_image = runtime.snapshot_persistent_store_for_test().unwrap();

    let proof = session_proof(&session, "one-use-proof");
    assert_eq!(
        runtime.authorize_session(proof.clone()).unwrap(),
        AuthorizationDecision::Authorized
    );
    assert_eq!(
        runtime.authorize_session(proof).unwrap_err(),
        RuntimeError::ReplayDetected
    );

    let mut stale = session_proof(&session, "stale-epoch-proof");
    stale.subject_epoch = INITIAL_EPOCH - 1;
    assert_eq!(
        runtime.authorize_session(stale).unwrap_err(),
        RuntimeError::StaleEpoch {
            scope: RevocationScope::Subject,
            presented: INITIAL_EPOCH - 1,
            current: INITIAL_EPOCH,
        }
    );

    let unknown = br#"{"operation":"authorize-session","proof_id":"wire-proof","admin":true}"#;
    assert_eq!(
        runtime.ingest_wire(unknown).unwrap_err(),
        RuntimeError::UnknownField("admin".into())
    );

    runtime
        .revoke(RevokeRequest {
            command_id: "advance-session-epoch".into(),
            target: RevocationTarget::Session {
                account_id: "account-a".into(),
                service_id: "service-a".into(),
                session_id: "session-a".into(),
            },
            expected_epoch: session.session_epoch,
            authority_id: "identity-authority".into(),
        })
        .unwrap();
    runtime
        .restore_persistent_store_for_test(old_image)
        .expect("the harness must simulate an out-of-band rollback");
    assert_eq!(
        runtime.restart().unwrap_err(),
        RuntimeError::DatabaseRollbackDetected
    );
}

#[test]
fn id_10_recovery_requires_two_independent_authorities_and_revokes_sessions() {
    // ID-10: recovery needs two distinct healthy authorities, neither derived
    // from the affected Device/Session, and revokes every affected Session.
    let mut runtime = runtime();
    let service = create_account_and_service(&mut runtime, "account-a", "service-a");
    let device = enroll(&mut runtime, "account-a", &service, "device-a", "key-a");
    let session = issue(&mut runtime, "account-a", &service, &device, "session-a");
    let replacement = enrollment("account-a", &service, "device-recovered", "key-recovered");
    let offline = RecoveryApproval {
        approval_id: "approval-offline".into(),
        authority_id: "offline-recovery".into(),
        key_fingerprint: "offline-key".into(),
        kind: RecoveryAuthorityKind::IndependentOfflineRecovery,
        approved_at: 1_010,
    };

    assert_eq!(
        runtime
            .recover_device(RecoveryRequest {
                command_id: "recover-one-authority".into(),
                account_id: "account-a".into(),
                affected_device_id: "device-a".into(),
                replacement: replacement.clone(),
                approvals: vec![offline.clone()],
                expected_subject_epoch: INITIAL_EPOCH,
            })
            .unwrap_err(),
        RuntimeError::InsufficientRecoveryAuthorities
    );

    let compromised = RecoveryApproval {
        approval_id: "approval-compromised".into(),
        authority_id: "device-a".into(),
        key_fingerprint: "key-a".into(),
        kind: RecoveryAuthorityKind::DeviceKey,
        approved_at: 1_011,
    };
    assert_eq!(
        runtime
            .recover_device(RecoveryRequest {
                command_id: "recover-compromised-authority".into(),
                account_id: "account-a".into(),
                affected_device_id: "device-a".into(),
                replacement: replacement.clone(),
                approvals: vec![offline.clone(), compromised],
                expected_subject_epoch: INITIAL_EPOCH,
            })
            .unwrap_err(),
        RuntimeError::RecoveryAuthorityNotIndependent
    );

    let second = RecoveryApproval {
        approval_id: "approval-independent-authenticator".into(),
        authority_id: "healthy-authenticator".into(),
        key_fingerprint: "healthy-authenticator-key".into(),
        kind: RecoveryAuthorityKind::IndependentBoundAuthenticator,
        approved_at: 1_012,
    };
    let recovered = runtime
        .recover_device(RecoveryRequest {
            command_id: "recover-two-authorities".into(),
            account_id: "account-a".into(),
            affected_device_id: "device-a".into(),
            replacement,
            approvals: vec![offline, second],
            expected_subject_epoch: INITIAL_EPOCH,
        })
        .expect("two independent authorities must recover to a fresh device key");
    assert_eq!(recovered.key_fingerprint, "key-recovered");
    assert_eq!(
        runtime
            .authorize_session(session_proof(&session, "post-recovery-old-session"))
            .unwrap_err(),
        RuntimeError::SessionRevoked
    );
}
