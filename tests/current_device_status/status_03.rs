fn seeded_runtime() -> (
    IdentityRuntime,
    ServiceAccountRecord,
    DeviceRecord,
    SessionRecord,
) {
    let mut runtime =
        runtime().with_identity_signers(Box::new(assertion_signer()), Box::new(status_signer()));
    let service = create_account_and_service(&mut runtime, "account-a", "service:crowsi");
    let device = enroll(&mut runtime, "account-a", &service, "device-a", "key-a");
    let session = issue(&mut runtime, "account-a", &service, &device, "session-a");
    (runtime, service, device, session)
}

fn request(
    service: &ServiceAccountRecord,
    device: &DeviceRecord,
    session: &SessionRecord,
    nonce: &str,
) -> DeviceIdentityAssertionRequest {
    DeviceIdentityAssertionRequest {
        account_id: "account-a".into(),
        service_id: service.service_id.clone(),
        pairwise_subject: service.pairwise_subject.clone(),
        device_id: device.device_id.clone(),
        session_id: session.session_id.clone(),
        audience: AUDIENCE.into(),
        nonce: nonce.into(),
        ttl_seconds: 120,
        sender_key_fingerprint: device.key_fingerprint.clone(),
        sender_proof_id: format!("proof-{nonce}"),
    }
}

fn assertion_signer() -> Signer {
    Signer("assertion-key-v1", b"assertion-key")
}
fn status_signer() -> Signer {
    Signer("status-key-v1", b"status-key")
}

fn signature(key: &[u8], payload: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(key);
    digest.update(b"\0");
    digest.update(payload);
    format!("sha256:{:x}", digest.finalize())
}
