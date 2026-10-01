#[test]
fn id_05_synced_passkey_authenticates_user_but_never_identifies_device() {
    // ID-05: a synced Passkey may supply fresh user authentication, but it can
    // never be accepted as the physical device proof key.
    let mut runtime = runtime();
    let service = create_account_and_service(&mut runtime, "account-a", "service-a");

    let mut invalid = enrollment("account-a", &service, "device-a", "synced-passkey-key");
    invalid.proof_key.custody = DeviceKeyCustody::SyncedPasskey;
    invalid.user_authentication = synced_authentication("synced-user-proof", "synced-passkey-key");
    assert_eq!(
        runtime.enroll_device(invalid).unwrap_err(),
        RuntimeError::SyncedPasskeyIsNotDeviceIdentity
    );

    let mut valid = enrollment("account-a", &service, "device-a", "device-key-a");
    valid.user_authentication = synced_authentication("synced-user-proof-2", "user-passkey-key");
    runtime
        .enroll_device(valid)
        .expect("synced user auth plus a distinct device key must enroll");
}

#[test]
fn id_06_duplicate_device_key_and_wrong_account_enrollment_are_rejected() {
    // ID-06: one device proof key has one device owner; neither another device
    // ID nor another Account may claim it.
    let mut runtime = runtime();
    let service_a = create_account_and_service(&mut runtime, "account-a", "service-a");
    enroll(
        &mut runtime,
        "account-a",
        &service_a,
        "device-a",
        "shared-key",
    );

    assert_eq!(
        runtime
            .enroll_device(enrollment(
                "account-a",
                &service_a,
                "device-a-duplicate",
                "shared-key",
            ))
            .unwrap_err(),
        RuntimeError::DuplicateDeviceKey
    );

    let service_b = create_account_and_service(&mut runtime, "account-b", "service-a");
    let mut wrong_account = enrollment("account-b", &service_b, "device-wrong-account", "new-key");
    wrong_account.pairwise_subject = service_a.pairwise_subject;
    assert_eq!(
        runtime.enroll_device(wrong_account).unwrap_err(),
        RuntimeError::WrongAccount
    );
}
