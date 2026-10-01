#[test]
fn authoritative_graph_revocation_and_replay_state_survive_restart() {
    let mut runtime = runtime();
    let service = create_account_and_service(&mut runtime, "account-a", "service-a");
    let device = enroll(&mut runtime, "account-a", &service, "device-a", "key-a");
    let session = issue(&mut runtime, "account-a", &service, &device, "session-a");
    let proof = session_proof(&session, "durable-replay-proof");
    runtime.authorize_session(proof.clone()).unwrap();
    runtime
        .revoke(RevokeRequest {
            command_id: "durable-device-revoke".into(),
            target: RevocationTarget::Device {
                account_id: "account-a".into(),
                service_id: "service-a".into(),
                device_id: "device-a".into(),
            },
            expected_epoch: device.device_epoch,
            authority_id: "identity-authority".into(),
        })
        .unwrap();
    let graph_before = runtime.identity_graph().unwrap();
    let revocation_before = runtime.revocation_snapshot().unwrap();
    let audit_before = runtime.verify_audit().unwrap();

    runtime.restart().expect("a clean restart must succeed");
    assert_eq!(runtime.identity_graph().unwrap(), graph_before);
    assert_eq!(runtime.revocation_snapshot().unwrap(), revocation_before);
    assert_eq!(runtime.verify_audit().unwrap(), audit_before);
    assert_eq!(
        runtime.authorize_session(proof).unwrap_err(),
        RuntimeError::ReplayDetected
    );
}

#[test]
fn audit_is_append_only_and_out_of_band_tampering_is_detected() {
    let mut runtime = runtime();
    create_account_and_service(&mut runtime, "account-a", "service-a");
    let events = runtime.audit_events().unwrap();
    assert!(!events.is_empty());
    for pair in events.windows(2) {
        assert_eq!(pair[1].sequence, pair[0].sequence + 1);
        assert_eq!(pair[1].previous_hash, pair[0].event_hash);
    }

    let mut replacement = events[0].clone();
    replacement.event_type = "forged".into();
    assert_eq!(
        runtime
            .attempt_audit_overwrite_for_test(events[0].sequence, replacement)
            .unwrap_err(),
        RuntimeError::AuditImmutable
    );
    runtime
        .corrupt_audit_bytes_for_test(events[0].sequence)
        .expect("the harness must simulate out-of-band storage corruption");
    assert_eq!(
        runtime.verify_audit().unwrap_err(),
        RuntimeError::AuditIntegrityViolation
    );
}

#[test]
fn wire_and_identity_cardinality_limits_fail_closed_at_exact_boundaries() {
    let mut runtime = runtime();
    assert_eq!(
        runtime
            .ingest_wire(&vec![b'x'; MAX_WIRE_BYTES + 1])
            .unwrap_err(),
        RuntimeError::RequestTooLarge {
            limit: MAX_WIRE_BYTES,
        }
    );

    runtime
        .create_account(account_request("account-a", "create-account-a"))
        .unwrap();
    let mut oversized_service = service_request("account-a", "service-a");
    oversized_service.service_id = "s".repeat(MAX_ID_BYTES + 1);
    assert_eq!(
        runtime
            .create_service_account(oversized_service)
            .unwrap_err(),
        RuntimeError::LimitExceeded {
            field: "service_id",
            limit: MAX_ID_BYTES,
        }
    );

    let service = runtime
        .create_service_account(service_request("account-a", "service-a"))
        .unwrap();
    let mut oversized_key = enrollment("account-a", &service, "device-big-key", "key-big");
    oversized_key.proof_key.spki = vec![0; MAX_PUBLIC_KEY_BYTES + 1];
    assert_eq!(
        runtime.enroll_device(oversized_key).unwrap_err(),
        RuntimeError::LimitExceeded {
            field: "device_public_key",
            limit: MAX_PUBLIC_KEY_BYTES,
        }
    );

    for index in 0..MAX_DEVICES_PER_ACCOUNT {
        enroll(
            &mut runtime,
            "account-a",
            &service,
            &format!("device-{index}"),
            &format!("key-{index}"),
        );
    }
    assert_eq!(
        runtime
            .enroll_device(enrollment(
                "account-a",
                &service,
                "device-over-limit",
                "key-over-limit",
            ))
            .unwrap_err(),
        RuntimeError::LimitExceeded {
            field: "devices_per_account",
            limit: MAX_DEVICES_PER_ACCOUNT,
        }
    );
}
