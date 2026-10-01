#[test]
fn id_27_and_28_assertion_minting_requires_one_use_sender_proof() {
    let (mut runtime, controls, service, device, session) = assertion_runtime();
    controls.session.store(REJECT, Ordering::SeqCst);
    assert_eq!(
        runtime
            .issue_device_identity_evidence(assertion_request(&service, &device, &session, "id-27"))
            .unwrap_err(),
        RuntimeError::EvidenceUnverified(EvidenceKind::SessionSenderProof)
    );
    controls.session.store(VALID, Ordering::SeqCst);
    let request = assertion_request(&service, &device, &session, "id-28");
    runtime
        .issue_device_identity_evidence(request.clone())
        .unwrap();
    assert_eq!(
        runtime.issue_device_identity_evidence(request).unwrap_err(),
        RuntimeError::ReplayDetected
    );
}

#[test]
fn id_29_and_30_invalid_window_or_clock_fail_closed() {
    let (mut runtime, controls) = runtime_and_controls();
    let service = create_account_and_service(&mut runtime, "account-a", "service-a");
    let device = enroll(&mut runtime, "account-a", &service, "device-a", "key-a");
    controls.session.store(INVALID, Ordering::SeqCst);
    assert_eq!(
        runtime
            .issue_session(session_request("account-a", &service, &device, "invalid"))
            .unwrap_err(),
        RuntimeError::EvidenceWindowInvalid(EvidenceKind::SessionSenderProof)
    );
    let verifier = ScriptedVerifier(Arc::new(Controls::default()));
    let trust = RuntimeTrust::new(
        RuntimeVerifiers {
            authentication: Box::new(verifier.clone()),
            attestation: Box::new(verifier.clone()),
            possession: Box::new(verifier.clone()),
            session: Box::new(verifier.clone()),
            revocation: Box::new(verifier.clone()),
            revocation_preparation: Box::new(verifier.clone()),
            recovery: Box::new(verifier.clone()),
            installer_bootstrap: Box::new(verifier),
        },
        Box::new(FailingClock),
    );
    let mut runtime = runtime_with_trust(trust);
    assert_eq!(
        runtime
            .create_account(account_request("clock", "id-30"))
            .unwrap_err(),
        RuntimeError::TrustedClockUnavailable
    );
}

#[test]
fn id_50_installer_bootstrap_requires_verified_current_root_bundle() {
    let (mut runtime, controls) = runtime_and_controls();
    controls.bootstrap.store(REJECT, Ordering::SeqCst);
    assert_eq!(
        runtime.bootstrap_initial_identity(bootstrap_request("id-50-unverified")),
        Err(RuntimeError::EvidenceUnverified(
            EvidenceKind::InstallerBootstrap
        ))
    );
    assert_eq!(runtime.identity_graph().unwrap(), IdentityGraph::default());

    controls.bootstrap.store(VALID, Ordering::SeqCst);
    let mut expired = bootstrap_request("id-50-expired");
    expired.bundle.issued_at_epoch_s = TEST_NOW - 60;
    expired.bundle.expires_at_epoch_s = TEST_NOW;
    assert_eq!(
        runtime.bootstrap_initial_identity(expired),
        Err(RuntimeError::EvidenceExpired(
            EvidenceKind::InstallerBootstrap
        ))
    );
    assert_eq!(runtime.identity_graph().unwrap(), IdentityGraph::default());
}

#[test]
fn acceptance_catalog_is_complete_and_matches_reason_codes() {
    let value: Value = serde_json::from_slice(include_bytes!(
        "../../fixtures/trust-boundary-acceptance-v1.json"
    ))
    .unwrap();
    let cases = value["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 18);
    for (offset, case) in cases.iter().enumerate() {
        assert_eq!(case["id"], format!("ID-{}", offset + 13));
        assert!(case["expected"].as_str().unwrap().contains('-'));
    }
}
