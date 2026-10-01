mod support;

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use support::*;

#[test]
// ID-54: a durable peer read reflects A revocation immediately without changing active B.
fn device_peer_status_reads_exact_current_device_and_survives_reopen() {
    let root = TempDirectory::new("peer-status");
    let path = root.path.join("identity.state");
    let mut runtime = file_runtime(&path);
    let service = create_account_and_service(&mut runtime, "account-a", "service:crowsi");
    let device_a = enroll(&mut runtime, "account-a", &service, "device-a", "key-a");
    let device_b = enroll(&mut runtime, "account-a", &service, "device-b", "key-b");
    let active = read_device_peer_status(
        &path,
        &service.service_id,
        &service.pairwise_subject,
        &device_a.device_id,
    )
    .expect("active A");
    assert!(active.active);
    assert_eq!(active.device_epoch, device_a.device_epoch);

    runtime
        .revoke_device(RevokeDeviceRequest {
            command_id: "revoke-device-a-for-peer".into(),
            account_id: device_a.account_id.clone(),
            service_id: service.service_id.clone(),
            device_id: device_a.device_id.clone(),
            expected_device_epoch: device_a.device_epoch,
            authority_id: "identity-authority".into(),
        })
        .expect("revoke A");
    drop(runtime);
    let revoked = read_device_peer_status(
        &path,
        &service.service_id,
        &service.pairwise_subject,
        &device_a.device_id,
    )
    .expect("revoked A");
    let sibling = read_device_peer_status(
        &path,
        &service.service_id,
        &service.pairwise_subject,
        &device_b.device_id,
    )
    .expect("active B");
    assert!(!revoked.active);
    assert_eq!(revoked.device_epoch, device_a.device_epoch + 1);
    assert!(sibling.active);
    assert_eq!(sibling.device_epoch, device_b.device_epoch);
}

#[test]
fn device_peer_status_rejects_wrong_binding_missing_state_and_anchor_tamper() {
    let root = TempDirectory::new("peer-status-tamper");
    let path = root.path.join("identity.state");
    let mut runtime = file_runtime(&path);
    let service = create_account_and_service(&mut runtime, "account-a", "service:crowsi");
    let device = enroll(&mut runtime, "account-a", &service, "device-a", "key-a");
    drop(runtime);
    for (service_id, subject, device_id) in [
        (
            "service:other",
            service.pairwise_subject.as_str(),
            device.device_id.as_str(),
        ),
        (
            service.service_id.as_str(),
            "psu_wrong",
            device.device_id.as_str(),
        ),
        (
            service.service_id.as_str(),
            service.pairwise_subject.as_str(),
            "device-b",
        ),
    ] {
        assert!(read_device_peer_status(&path, service_id, subject, device_id).is_err());
    }
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .expect("name");
    fs::write(root.path.join(format!(".{name}.anchor")), b"tampered\n").expect("tamper");
    assert!(
        read_device_peer_status(
            &path,
            &service.service_id,
            &service.pairwise_subject,
            &device.device_id,
        )
        .is_err()
    );
    assert!(
        read_device_peer_status(
            root.path.join("missing.state"),
            &service.service_id,
            &service.pairwise_subject,
            &device.device_id,
        )
        .is_err()
    );
}

fn file_runtime(path: &Path) -> IdentityRuntime {
    IdentityRuntime::open_file(path, Box::new(TestPairwiseDeriver), test_trust())
        .expect("file runtime")
}

struct TempDirectory {
    path: PathBuf,
}

impl TempDirectory {
    fn new(label: &str) -> Self {
        let mut random = [0_u8; 8];
        getrandom::fill(&mut random).expect("random");
        let path = std::env::temp_dir().join(format!(
            "ihat-identity-{label}-{}-{}",
            std::process::id(),
            u64::from_be_bytes(random)
        ));
        fs::create_dir(&path).expect("temp directory");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("mode");
        Self { path }
    }
}

impl Drop for TempDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
