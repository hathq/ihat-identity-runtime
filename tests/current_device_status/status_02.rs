#[test]
// ID-31: assertion and independently signed current status are emitted atomically.
fn identity_evidence_contains_exact_current_device_status() {
    let (mut runtime, service, device, session) = seeded_runtime();
    let evidence = runtime
        .issue_device_identity_evidence(request(&service, &device, &session, "status-01"))
        .unwrap();
    assert!(current_status_matches_assertion(
        &evidence.current_status,
        &evidence.assertion
    ));
    assert_ne!(evidence.assertion.key_id, evidence.current_status.key_id);
    assert_eq!(
        evidence.current_status.expires_at_epoch_s - evidence.current_status.issued_at_epoch_s,
        30
    );
    verify_assertion_at(
        &evidence.assertion,
        &assertion_signer(),
        ISSUER,
        AUDIENCE,
        TEST_NOW,
    )
    .unwrap();
    verify_current_status_at(
        &evidence.current_status,
        &status_signer(),
        ISSUER,
        AUDIENCE,
        TEST_NOW,
    )
    .unwrap();
}

#[test]
// ID-32: a status-signing failure commits neither nonce nor sender proof.
fn status_signing_failure_is_atomic_and_retryable() {
    let (runtime, service, device, session) = seeded_runtime();
    let mut runtime =
        runtime.with_identity_signers(Box::new(assertion_signer()), Box::new(FailingStatusSigner));
    let request = request(&service, &device, &session, "status-failure");
    assert_eq!(
        runtime
            .issue_device_identity_evidence(request.clone())
            .unwrap_err(),
        RuntimeError::SignatureInvalid
    );
    let mut runtime =
        runtime.with_identity_signers(Box::new(assertion_signer()), Box::new(status_signer()));
    runtime
        .issue_device_identity_evidence(request)
        .expect("retry");
}

#[test]
// ID-33: assertion and status signer identities must be distinct.
fn duplicate_signer_identity_is_rejected_before_commit() {
    let (runtime, service, device, session) = seeded_runtime();
    let duplicate = Signer("assertion-key-v1", b"different-material");
    let mut runtime =
        runtime.with_identity_signers(Box::new(assertion_signer()), Box::new(duplicate));
    let request = request(&service, &device, &session, "duplicate-signer");
    assert_eq!(
        runtime
            .issue_device_identity_evidence(request.clone())
            .unwrap_err(),
        RuntimeError::InvalidRequest("identity_signer_separation")
    );
    let mut runtime =
        runtime.with_identity_signers(Box::new(assertion_signer()), Box::new(status_signer()));
    runtime
        .issue_device_identity_evidence(request)
        .expect("retry");
}
