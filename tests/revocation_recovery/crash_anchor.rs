#[test]
fn exact_revocation_recovers_across_both_anchor_commit_crash_cuts() {
    for (label, failpoint) in [
        ("after-state", DurableStateFailpoint::AfterStateCommit),
        ("after-anchor", DurableStateFailpoint::AfterAnchorCommit),
    ] {
        let root = TempDirectory::new(label);
        let path = root.path.join("identity.state");
        let pending = root.path.join(".identity.state.anchor.pending");
        let mut runtime = file_runtime(&path);
        let service = create_account_and_service(&mut runtime, "account-a", "service-a");
        let device = enroll(&mut runtime, "account-a", &service, "device-a", "key-a");
        let session = issue(&mut runtime, "account-a", &service, &device, "session-a");
        let request = RevokeRequest {
            command_id: format!("durable-final-revoke-{label}"),
            target: RevocationTarget::Session {
                account_id: session.account_id.clone(),
                service_id: session.service_id.clone(),
                session_id: session.session_id.clone(),
            },
            expected_epoch: session.session_epoch,
            authority_id: "identity-authority".into(),
        };

        arm_durable_state_failpoint(Some(failpoint));
        assert_eq!(
            runtime.revoke(request.clone()),
            Err(RuntimeError::PersistenceFailure)
        );
        assert!(pending.exists());
        drop(runtime);

        let mut restarted = file_runtime_with_revocation(&path, RejectRevocation);
        let recovered = restarted
            .revoke(request.clone())
            .expect("recover exact revocation receipt");
        assert_eq!(recovered.target, request.target);
        assert_eq!(recovered.previous_epoch, session.session_epoch);
        assert_eq!(recovered.current_epoch, session.session_epoch + 1);
        assert!(!pending.exists());
        assert_eq!(
            restarted
                .revocation_snapshot()
                .expect("snapshot")
                .session_epochs[&(session.account_id, session.service_id, session.session_id,)],
            session.session_epoch + 1
        );
    }
}
