#[test]
fn assertion_ttl_signature_audience_and_unknown_fields_fail_closed() {
    let (mut runtime, service, device, session) = seeded_runtime();
    assert_eq!(
        runtime
            .issue_device_identity_evidence(assertion_request(
                &service,
                &device,
                &session,
                "nonce-too-long",
                301
            ))
            .unwrap_err(),
        RuntimeError::InvalidRequest("assertion_ttl")
    );
    let assertion = runtime
        .issue_device_identity_evidence(assertion_request(
            &service,
            &device,
            &session,
            "nonce-valid",
            60,
        ))
        .unwrap()
        .assertion;
    assert_eq!(
        verify_assertion_at(
            &assertion,
            &DeterministicVerifier,
            ISSUER,
            "wrong-audience",
            NOW
        )
        .unwrap_err(),
        AssertionError::ContextMismatch
    );
    assert_eq!(
        verify_assertion_at(
            &assertion,
            &DeterministicVerifier,
            ISSUER,
            AUDIENCE,
            NOW + 60
        )
        .unwrap_err(),
        AssertionError::TimeInvalid
    );
    let mut json = serde_json::to_value(&assertion).unwrap();
    json.as_object_mut()
        .unwrap()
        .insert("global_subject".into(), "forbidden".into());
    assert_eq!(
        decode_assertion_strict(&serde_json::to_vec(&json).unwrap()).unwrap_err(),
        AssertionError::ContractInvalid
    );
}

#[test]
fn published_fixture_uses_the_shared_canonical_contract() {
    let fixture = include_bytes!("../../fixtures/device-identity-assertion-v1.json");
    let assertion = decode_assertion_strict(fixture).unwrap();
    verify_assertion_at(
        &assertion,
        &DeterministicVerifier,
        ISSUER,
        AUDIENCE,
        FIXTURE_NOW,
    )
    .unwrap();
}

fn seeded_runtime() -> (
    IdentityRuntime,
    ServiceAccountRecord,
    DeviceRecord,
    SessionRecord,
) {
    let mut runtime = runtime().with_identity_signers(
        Box::new(DeterministicSigner),
        Box::new(DeterministicStatusSigner),
    );
    let service = create_account_and_service(&mut runtime, "account-a", "service-a");
    let device = enroll(&mut runtime, "account-a", &service, "device-a", "key-a");
    let session = issue(&mut runtime, "account-a", &service, &device, "session-a");
    (runtime, service, device, session)
}

fn assertion_request(
    service: &ServiceAccountRecord,
    device: &DeviceRecord,
    session: &SessionRecord,
    nonce: &str,
    ttl_seconds: u64,
) -> DeviceIdentityAssertionRequest {
    DeviceIdentityAssertionRequest {
        account_id: "account-a".into(),
        service_id: service.service_id.clone(),
        pairwise_subject: service.pairwise_subject.clone(),
        device_id: device.device_id.clone(),
        session_id: session.session_id.clone(),
        audience: AUDIENCE.into(),
        nonce: nonce.into(),
        ttl_seconds,
        sender_key_fingerprint: device.key_fingerprint.clone(),
        sender_proof_id: format!("assertion-proof-{nonce}"),
    }
}
