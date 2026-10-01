struct FailingClock;
impl TrustedClock for FailingClock {
    fn now_epoch_seconds(&self) -> Result<u64, RuntimeError> {
        Err(RuntimeError::TrustedClockUnavailable)
    }
}

struct Signer;
impl AssertionSigner for Signer {
    fn issuer(&self) -> &str {
        "https://id.ihat.invalid"
    }
    fn key_id(&self) -> &str {
        "test-key"
    }
    fn sign(&self, payload: &[u8]) -> Result<String, RuntimeError> {
        Ok(format!("sha256:{:x}", Sha256::digest(payload)))
    }
}

struct StatusSigner;
impl AssertionSigner for StatusSigner {
    fn issuer(&self) -> &str {
        "https://id.ihat.invalid"
    }
    fn key_id(&self) -> &str {
        "status-test-key"
    }
    fn sign(&self, payload: &[u8]) -> Result<String, RuntimeError> {
        let mut digest = Sha256::new();
        digest.update(b"status\0");
        digest.update(payload);
        Ok(format!("sha256:{:x}", digest.finalize()))
    }
}

fn subject_revoke(command_id: &str) -> RevokeRequest {
    RevokeRequest {
        command_id: command_id.into(),
        target: RevocationTarget::Subject {
            account_id: "account-a".into(),
        },
        expected_epoch: INITIAL_EPOCH,
        authority_id: "authority-a".into(),
    }
}

fn recovery(service: &ServiceAccountRecord, command: &str) -> RecoveryRequest {
    let mut replacement = enrollment(
        "account-a",
        service,
        &format!("device-{command}"),
        &format!("key-{command}"),
    );
    replacement.command_id = format!("replacement-{command}");
    replacement.user_authentication = authentication(&format!("auth-{command}"), "auth-key-a");
    RecoveryRequest {
        command_id: command.into(),
        account_id: "account-a".into(),
        affected_device_id: "device-a".into(),
        replacement,
        approvals: vec![
            RecoveryApproval {
                approval_id: format!("offline-{command}"),
                authority_id: "offline-authority".into(),
                key_fingerprint: "offline-key".into(),
                kind: RecoveryAuthorityKind::IndependentOfflineRecovery,
                approved_at: TEST_NOW - 10,
            },
            RecoveryApproval {
                approval_id: format!("bound-{command}"),
                authority_id: "bound-authority".into(),
                key_fingerprint: "bound-key".into(),
                kind: RecoveryAuthorityKind::IndependentBoundAuthenticator,
                approved_at: TEST_NOW - 10,
            },
        ],
        expected_subject_epoch: INITIAL_EPOCH,
    }
}

fn rotation(device: &DeviceRecord, replacement: &str) -> RotateDeviceKeyRequest {
    RotateDeviceKeyRequest {
        command_id: format!("rotate-{replacement}"),
        account_id: device.account_id.clone(),
        service_id: device.service_id.clone(),
        device_id: device.device_id.clone(),
        retired_key_fingerprint: device.key_fingerprint.clone(),
        replacement_key: device_key(replacement),
        fresh_user_authentication: Some(authentication(
            &format!("auth-rotate-{replacement}"),
            "auth-key-a",
        )),
        expected_device_epoch: device.device_epoch,
    }
}

fn assertion_runtime() -> (
    IdentityRuntime,
    Arc<Controls>,
    ServiceAccountRecord,
    DeviceRecord,
    SessionRecord,
) {
    let (runtime, controls) = runtime_and_controls();
    let mut runtime = runtime.with_identity_signers(Box::new(Signer), Box::new(StatusSigner));
    let service = create_account_and_service(&mut runtime, "account-a", "service-a");
    let device = enroll(&mut runtime, "account-a", &service, "device-a", "key-a");
    let session = issue(&mut runtime, "account-a", &service, &device, "session-a");
    (runtime, controls, service, device, session)
}

fn assertion_request(
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
        audience: "crowsi-local-bridge".into(),
        nonce: nonce.into(),
        ttl_seconds: 60,
        sender_key_fingerprint: device.key_fingerprint.clone(),
        sender_proof_id: format!("proof-{nonce}"),
    }
}
