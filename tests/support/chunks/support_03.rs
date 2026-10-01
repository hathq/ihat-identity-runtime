pub fn authentication(proof_id: &str, key: &str) -> FreshAuthentication {
    FreshAuthentication {
        proof_id: proof_id.into(),
        authenticator_id: format!("authenticator-{key}"),
        authenticator_key_fingerprint: key.into(),
        kind: AuthenticatorKind::DeviceBoundPasskey,
        user_verified: true,
        issued_at: 1_000,
        expires_at: 1_060,
    }
}

pub fn synced_authentication(proof_id: &str, key: &str) -> FreshAuthentication {
    FreshAuthentication {
        kind: AuthenticatorKind::SyncedPasskey,
        ..authentication(proof_id, key)
    }
}

pub fn external_identity(issuer: &str, subject: &str) -> ExternalIdentity {
    ExternalIdentity {
        issuer: issuer.into(),
        subject: subject.into(),
        email: Some("owner@example.invalid".into()),
        display_name: Some("Owner".into()),
    }
}

pub fn bootstrap_request(bundle_id: &str) -> InitialBootstrapRequest {
    InitialBootstrapRequest {
        command_id: format!("command-{bundle_id}"),
        account_id: "account-bootstrap".into(),
        primary_identity: external_identity("https://installer.invalid", "owner-bootstrap"),
        service_id: "service:crowsi".into(),
        device_id: "device-bootstrap-a".into(),
        proof_key: DeviceProofKey {
            fingerprint: "bootstrap-device-key".into(),
            spki: vec![1, 2, 3, 4],
            custody: DeviceKeyCustody::HardwareNonExportable,
            attestation: vec![5, 6, 7, 8],
        },
        session_id: "session-bootstrap-a".into(),
        sender_key_fingerprint: "bootstrap-device-key".into(),
        bundle: InstallerBootstrapBundle {
            bundle_id: bundle_id.into(),
            root_key_id: "installer-root-key:1".into(),
            issued_at_epoch_s: TEST_NOW - 10,
            expires_at_epoch_s: TEST_NOW + 10,
            signature: "test-root-signature".into(),
        },
    }
}

pub fn account_request(account_id: &str, command_id: &str) -> AccountRequest {
    AccountRequest {
        command_id: command_id.into(),
        account_id: account_id.into(),
        primary_identity: external_identity(
            "https://issuer-a.invalid",
            &format!("subject-{account_id}"),
        ),
        authentication: authentication(&format!("proof-{command_id}"), "auth-key-a"),
    }
}

pub fn service_request(account_id: &str, service_id: &str) -> ServiceAccountRequest {
    ServiceAccountRequest {
        command_id: format!("create-{account_id}-{service_id}"),
        account_id: account_id.into(),
        service_id: service_id.into(),
        expected_subject_epoch: INITIAL_EPOCH,
        authentication: authentication(&format!("proof-{account_id}-{service_id}"), "auth-key-a"),
    }
}

pub fn device_key(fingerprint: &str) -> DeviceProofKey {
    DeviceProofKey {
        fingerprint: fingerprint.into(),
        spki: format!("spki:{fingerprint}").into_bytes(),
        custody: DeviceKeyCustody::HardwareNonExportable,
        attestation: format!("attestation:{fingerprint}").into_bytes(),
    }
}

pub fn enrollment(
    account_id: &str,
    service: &ServiceAccountRecord,
    device_id: &str,
    fingerprint: &str,
) -> DeviceEnrollment {
    DeviceEnrollment {
        command_id: format!("enroll-{account_id}-{device_id}"),
        account_id: account_id.into(),
        service_id: service.service_id.clone(),
        pairwise_subject: service.pairwise_subject.clone(),
        device_id: device_id.into(),
        proof_key: device_key(fingerprint),
        user_authentication: authentication(&format!("proof-enroll-{device_id}"), "auth-key-a"),
        expected_subject_epoch: INITIAL_EPOCH,
        expected_service_epoch: service.service_epoch,
    }
}

pub fn session_request(
    account_id: &str,
    service: &ServiceAccountRecord,
    device: &DeviceRecord,
    session_id: &str,
) -> SessionRequest {
    SessionRequest {
        command_id: format!("issue-{session_id}"),
        account_id: account_id.into(),
        service_id: service.service_id.clone(),
        pairwise_subject: service.pairwise_subject.clone(),
        device_id: device.device_id.clone(),
        session_id: session_id.into(),
        sender_key_fingerprint: device.key_fingerprint.clone(),
        proof_id: format!("issue-proof-{session_id}"),
        expected_subject_epoch: INITIAL_EPOCH,
        expected_service_epoch: service.service_epoch,
        expected_device_epoch: device.device_epoch,
    }
}

pub fn session_proof(session: &SessionRecord, proof_id: &str) -> SessionProof {
    SessionProof {
        proof_id: proof_id.into(),
        account_id: session.account_id.clone(),
        service_id: session.service_id.clone(),
        pairwise_subject: session.pairwise_subject.clone(),
        device_id: session.device_id.clone(),
        session_id: session.session_id.clone(),
        session_ref: session.session_ref.clone(),
        sender_key_fingerprint: session.sender_key_fingerprint.clone(),
        subject_epoch: INITIAL_EPOCH,
        service_epoch: INITIAL_EPOCH,
        device_epoch: INITIAL_EPOCH,
        session_epoch: session.session_epoch,
    }
}
