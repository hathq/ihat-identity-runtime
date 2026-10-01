#[test]
fn nonce_and_sender_proof_are_each_durable_one_use() {
    let (mut runtime, service, device, _) = seeded();
    let request = current(&service, &device, "one-use");
    runtime
        .issue_current_device_identity_evidence(request.clone())
        .expect("first use");
    assert_eq!(
        runtime
            .issue_current_device_identity_evidence(request.clone())
            .expect_err("exact replay"),
        RuntimeError::ReplayDetected
    );
    let mut proof_replay = current(&service, &device, "new-nonce");
    proof_replay.session_sender_proof_id = request.session_sender_proof_id.clone();
    assert_eq!(
        runtime
            .issue_current_device_identity_evidence(proof_replay)
            .expect_err("proof replay"),
        RuntimeError::ReplayDetected
    );
    let mut nonce_replay = current(&service, &device, "one-use");
    nonce_replay.session_sender_proof_id = "fresh-proof".into();
    assert_eq!(
        runtime
            .issue_current_device_identity_evidence(nonce_replay)
            .expect_err("nonce replay"),
        RuntimeError::ReplayDetected
    );
    runtime.restart().expect("restart");
    assert_eq!(
        runtime
            .issue_current_device_identity_evidence(request)
            .expect_err("restart must not revive replay"),
        RuntimeError::ReplayDetected
    );
}

#[test]
fn current_identity_ttl_is_closed_to_the_current_status_window() {
    let (mut runtime, service, device, _) = seeded();
    let mut request = current(&service, &device, "ttl-too-long");
    request.ttl_seconds = 31;
    assert_eq!(
        runtime
            .issue_current_device_identity_evidence(request)
            .expect_err("TTL above current-status maximum"),
        RuntimeError::InvalidRequest("current_identity_ttl")
    );
}
