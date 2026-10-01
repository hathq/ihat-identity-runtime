pub fn create_account_and_service(
    runtime: &mut impl IdentityRuntimeContract,
    account_id: &str,
    service_id: &str,
) -> ServiceAccountRecord {
    runtime
        .create_account(account_request(account_id, &format!("create-{account_id}")))
        .expect("production runtime must create an account");
    runtime
        .create_service_account(service_request(account_id, service_id))
        .expect("production runtime must create a pairwise service account")
}

pub fn enroll(
    runtime: &mut impl IdentityRuntimeContract,
    account_id: &str,
    service: &ServiceAccountRecord,
    device_id: &str,
    fingerprint: &str,
) -> DeviceRecord {
    runtime
        .enroll_device(enrollment(account_id, service, device_id, fingerprint))
        .expect("production runtime must enroll a device")
}

pub fn issue(
    runtime: &mut impl IdentityRuntimeContract,
    account_id: &str,
    service: &ServiceAccountRecord,
    device: &DeviceRecord,
    session_id: &str,
) -> SessionRecord {
    runtime
        .issue_session(session_request(account_id, service, device, session_id))
        .expect("production runtime must issue a sender-bound session")
}
