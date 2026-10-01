const BEGIN_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const BEGIN_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

struct PreparationFixture {
    runtime: IdentityRuntime,
    service: ServiceAccountRecord,
    device_a: DeviceRecord,
    session_a: SessionRecord,
    session_b: SessionRecord,
}

fn preparation_fixture() -> PreparationFixture {
    preparation_fixture_with(runtime())
}

fn preparation_fixture_with(mut runtime: IdentityRuntime) -> PreparationFixture {
    let service = create_account_and_service(&mut runtime, "account-a", "service-a");
    let device_a = enroll(&mut runtime, "account-a", &service, "device-a", "key-a");
    let device_b = enroll(&mut runtime, "account-a", &service, "device-b", "key-b");
    let session_a = issue(&mut runtime, "account-a", &service, &device_a, "session-a");
    let session_b = issue(&mut runtime, "account-a", &service, &device_b, "session-b");
    PreparationFixture {
        runtime,
        service,
        device_a,
        session_a,
        session_b,
    }
}

fn session_revocation(command: &str, session: &SessionRecord) -> RevokeRequest {
    RevokeRequest {
        command_id: command.into(),
        target: RevocationTarget::Session {
            account_id: session.account_id.clone(),
            service_id: session.service_id.clone(),
            session_id: session.session_id.clone(),
        },
        expected_epoch: session.session_epoch,
        authority_id: "identity-authority".into(),
    }
}

fn device_revocation(command: &str, device: &DeviceRecord) -> RevokeRequest {
    RevokeRequest {
        command_id: command.into(),
        target: RevocationTarget::Device {
            account_id: device.account_id.clone(),
            service_id: device.service_id.clone(),
            device_id: device.device_id.clone(),
        },
        expected_epoch: device.device_epoch,
        authority_id: "identity-authority".into(),
    }
}

fn service_revocation(command: &str, service: &ServiceAccountRecord) -> RevokeRequest {
    RevokeRequest {
        command_id: command.into(),
        target: RevocationTarget::ServiceAccount {
            account_id: service.account_id.clone(),
            service_id: service.service_id.clone(),
        },
        expected_epoch: service.service_epoch,
        authority_id: "identity-authority".into(),
    }
}

fn subject_revocation(command: &str, account_id: &str) -> RevokeRequest {
    RevokeRequest {
        command_id: command.into(),
        target: RevocationTarget::Subject {
            account_id: account_id.into(),
        },
        expected_epoch: INITIAL_EPOCH,
        authority_id: "identity-authority".into(),
    }
}

fn changed_handle(handle: &RevocationPreparationHandle) -> RevocationPreparationHandle {
    let mut value = handle.preparation_id.clone();
    let replacement = if value.starts_with('f') { "e" } else { "f" };
    value.replace_range(..1, replacement);
    RevocationPreparationHandle {
        preparation_id: value,
    }
}
