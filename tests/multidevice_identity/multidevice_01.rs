use support::*;

#[test]
fn normal_registration_materializes_the_authoritative_identity_chain() {
    let mut runtime = runtime();
    let service = create_account_and_service(&mut runtime, "account-a", "service-a");
    let device = enroll(&mut runtime, "account-a", &service, "device-a", "key-a");
    let session = issue(&mut runtime, "account-a", &service, &device, "session-a");

    let graph = runtime.identity_graph().unwrap();
    assert_eq!(graph.accounts.len(), 1);
    assert_eq!(graph.service_accounts, vec![service.clone()]);
    assert_eq!(graph.devices, vec![device.clone()]);
    assert_eq!(graph.sessions, vec![session.clone()]);
    assert_eq!(service.account_id, "account-a");
    assert_eq!(device.pairwise_subject, service.pairwise_subject);
    assert_eq!(session.device_id, device.device_id);

    let revocation = runtime.revocation_snapshot().unwrap();
    assert_eq!(
        revocation.subject_epochs.get("account-a"),
        Some(&INITIAL_EPOCH)
    );
    assert_eq!(
        revocation
            .device_epochs
            .get(&("account-a".into(), "service-a".into(), "device-a".into())),
        Some(&INITIAL_EPOCH)
    );
    assert_eq!(
        revocation.session_epochs.get(&(
            "account-a".into(),
            "service-a".into(),
            "session-a".into()
        )),
        Some(&INITIAL_EPOCH)
    );
}

#[test]
fn id_01_account_link_requires_fresh_proof_from_both_identities() {
    // ID-01: linking requires independent fresh authentication of the existing
    // identity and the incoming identity in the same bounded transaction.
    let mut runtime = runtime();
    runtime
        .create_account(account_request("account-a", "create-account-a"))
        .expect("initial account registration must succeed");

    let incoming = external_identity("https://issuer-b.invalid", "subject-b");
    let mut stale_existing = authentication("existing-stale", "auth-key-a");
    stale_existing.expires_at = stale_existing.issued_at;
    let rejected = runtime
        .link_identity(AccountLinkRequest {
            command_id: "link-with-stale-proof".into(),
            account_id: "account-a".into(),
            incoming_identity: incoming.clone(),
            evidence: AccountLinkEvidence::DualFreshAuthentication {
                existing_identity: stale_existing,
                incoming_identity: authentication("incoming-fresh", "auth-key-b"),
            },
        })
        .expect_err("a stale proof on either side must fail closed");
    assert_eq!(rejected, RuntimeError::FreshAuthenticationRequired);

    let linked = runtime
        .link_identity(AccountLinkRequest {
            command_id: "link-with-two-fresh-proofs".into(),
            account_id: "account-a".into(),
            incoming_identity: incoming.clone(),
            evidence: AccountLinkEvidence::DualFreshAuthentication {
                existing_identity: authentication("existing-fresh", "auth-key-a"),
                incoming_identity: authentication("incoming-fresh-2", "auth-key-b"),
            },
        })
        .expect("two fresh proofs must authorize linking");
    assert!(linked.identities.contains(&incoming));
}

#[test]
fn id_02_matching_email_or_display_name_never_links_accounts() {
    // ID-02: email and display-name equality are attributes, never link proof.
    let mut runtime = runtime();
    runtime
        .create_account(account_request("account-a", "create-account-a"))
        .expect("initial account registration must succeed");

    let error = runtime
        .link_identity(AccountLinkRequest {
            command_id: "attribute-only-link".into(),
            account_id: "account-a".into(),
            incoming_identity: external_identity("https://issuer-b.invalid", "subject-b"),
            evidence: AccountLinkEvidence::AttributeMatchOnly {
                email: "owner@example.invalid".into(),
                display_name: "Owner".into(),
            },
        })
        .expect_err("matching attributes must not merge identities");
    assert_eq!(error, RuntimeError::AttributeOnlyLinkForbidden);
}

#[test]
fn id_03_one_account_gets_distinct_pairwise_subjects_for_each_service() {
    // ID-03: Account -> ServiceAccount is pairwise and a subject from one
    // service cannot be replayed at another service.
    let mut runtime = runtime();
    runtime
        .create_account(account_request("account-a", "create-account-a"))
        .expect("initial account registration must succeed");
    let service_a = runtime
        .create_service_account(service_request("account-a", "service-a"))
        .expect("service-a account must be created");
    let service_b = runtime
        .create_service_account(service_request("account-a", "service-b"))
        .expect("service-b account must be created");
    assert_ne!(service_a.pairwise_subject, service_b.pairwise_subject);

    let mut cross_service = enrollment("account-a", &service_b, "device-cross", "key-cross");
    cross_service.pairwise_subject = service_a.pairwise_subject;
    assert_eq!(
        runtime.enroll_device(cross_service).unwrap_err(),
        RuntimeError::WrongService
    );
}

#[test]
fn id_04_device_enrollment_requires_unique_non_exportable_public_key() {
    // ID-04: the device proof is a distinct non-exportable public-key identity,
    // not a UID, hostname, bearer token, or user authenticator credential ID.
    let mut runtime = runtime();
    let service = create_account_and_service(&mut runtime, "account-a", "service-a");

    let mut exportable = enrollment("account-a", &service, "device-a", "key-a");
    exportable.proof_key.custody = DeviceKeyCustody::Exportable;
    assert_eq!(
        runtime.enroll_device(exportable).unwrap_err(),
        RuntimeError::ExportableDeviceKey
    );

    let enrolled = runtime
        .enroll_device(enrollment("account-a", &service, "device-a", "key-a"))
        .expect("a unique attested non-exportable key must enroll");
    assert_eq!(enrolled.key_fingerprint, "key-a");
}
