mod support;

use sha2::{Digest, Sha256};
use support::*;

const AUDIENCE: &str = "crowsi-device-agent";

struct TestSigner(&'static str);

impl AssertionSigner for TestSigner {
    fn issuer(&self) -> &str {
        "https://id.ihat.invalid"
    }

    fn key_id(&self) -> &str {
        self.0
    }

    fn sign(&self, payload: &[u8]) -> Result<String, RuntimeError> {
        let mut digest = Sha256::new();
        digest.update(self.0.as_bytes());
        digest.update(payload);
        Ok(format!("sha256:{:x}", digest.finalize()))
    }
}

fn signed(runtime: IdentityRuntime) -> IdentityRuntime {
    runtime.with_identity_signers(
        Box::new(TestSigner("identity-key")),
        Box::new(TestSigner("status-key")),
    )
}

fn base() -> (IdentityRuntime, ServiceAccountRecord, DeviceRecord) {
    base_from(signed(runtime()))
}

fn base_from(
    mut runtime: IdentityRuntime,
) -> (IdentityRuntime, ServiceAccountRecord, DeviceRecord) {
    let service = create_account_and_service(&mut runtime, "account-a", "service-a");
    let device = enroll(&mut runtime, "account-a", &service, "device-a", "key-a");
    (runtime, service, device)
}

fn seeded() -> (
    IdentityRuntime,
    ServiceAccountRecord,
    DeviceRecord,
    SessionRecord,
) {
    let (mut runtime, service, device) = base();
    let session = establish(
        &mut runtime,
        &service,
        &device,
        "session-a",
        ExpectedCurrentSession::Absent,
    );
    (runtime, service, device, session)
}

fn establish(
    runtime: &mut IdentityRuntime,
    service: &ServiceAccountRecord,
    device: &DeviceRecord,
    session_id: &str,
    expected: ExpectedCurrentSession,
) -> SessionRecord {
    runtime
        .establish_device_identity_session(establish_request(service, device, session_id, expected))
        .expect("current identity session")
}

fn establish_request(
    service: &ServiceAccountRecord,
    device: &DeviceRecord,
    session_id: &str,
    expected: ExpectedCurrentSession,
) -> EstablishDeviceIdentitySessionRequest {
    let session = session_request("account-a", service, device, session_id);
    EstablishDeviceIdentitySessionRequest {
        command_id: session.command_id,
        account_id: session.account_id,
        service_id: session.service_id,
        pairwise_subject: session.pairwise_subject,
        device_id: session.device_id,
        session_id: session.session_id,
        sender_key_fingerprint: session.sender_key_fingerprint,
        proof_id: session.proof_id,
        expected_subject_epoch: session.expected_subject_epoch,
        expected_service_epoch: session.expected_service_epoch,
        expected_device_epoch: session.expected_device_epoch,
        expected_current_session: expected,
    }
}

fn current(
    service: &ServiceAccountRecord,
    device: &DeviceRecord,
    nonce: &str,
) -> CurrentDeviceIdentityAssertionRequest {
    CurrentDeviceIdentityAssertionRequest {
        service_id: service.service_id.clone(),
        pairwise_subject: service.pairwise_subject.clone(),
        device_id: device.device_id.clone(),
        audience: AUDIENCE.into(),
        identity_nonce: nonce.into(),
        ttl_seconds: 30,
        session_sender_key_fingerprint: device.key_fingerprint.clone(),
        session_sender_proof_id: format!("sender-proof-{nonce}"),
    }
}

include!("current_identity_resolution/id_51.rs");
include!("current_identity_resolution/fail_closed.rs");
include!("current_identity_resolution/replay.rs");
include!("current_identity_resolution/establish_cas.rs");
include!("current_identity_resolution/establish_recovery.rs");
include!("current_identity_resolution/establish_failpoint.rs");
