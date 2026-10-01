#[test]
fn prepare_recovers_across_each_anchor_commit_crash_cut() {
    for (label, failpoint) in preparation_failpoints() {
        let directory = PreparationTempDirectory::new(&format!("prepare-{label}"));
        let path = directory.path.join("identity.state");
        let mut fixture = preparation_fixture_with(preparation_file_runtime(&path));
        let request = session_revocation(&format!("prepare-crash-{label}"), &fixture.session_a);

        arm_durable_state_failpoint(Some(failpoint));
        assert_eq!(
            fixture.runtime.prepare_revocation(BEGIN_A, request.clone()),
            Err(RuntimeError::PersistenceFailure)
        );
        drop(fixture);

        let mut reopened = preparation_file_runtime(&path);
        let handle = reopened
            .prepare_revocation(BEGIN_A, request)
            .expect("recover exact prepared handle");
        reopened
            .commit_prepared_revocation(&handle)
            .expect("recovered preparation commits");
    }
}

#[test]
fn commit_recovers_across_each_anchor_commit_crash_cut() {
    for (label, failpoint) in preparation_failpoints() {
        let directory = PreparationTempDirectory::new(&format!("commit-{label}"));
        let path = directory.path.join("identity.state");
        let mut fixture = preparation_fixture_with(preparation_file_runtime(&path));
        let handle = fixture
            .runtime
            .prepare_revocation(
                BEGIN_A,
                session_revocation(&format!("commit-crash-{label}"), &fixture.session_a),
            )
            .expect("prepared handle");
        let previous = fixture.session_a.session_epoch;

        arm_durable_state_failpoint(Some(failpoint));
        assert_eq!(
            fixture.runtime.commit_prepared_revocation(&handle),
            Err(RuntimeError::PersistenceFailure)
        );
        drop(fixture);

        let mut reopened = preparation_file_runtime(&path);
        let receipt = reopened
            .commit_prepared_revocation(&handle)
            .expect("recover exact committed receipt");
        assert_eq!(receipt.previous_epoch, previous);
        assert_eq!(receipt.current_epoch, previous + 1);
        assert_eq!(reopened.commit_prepared_revocation(&handle), Ok(receipt));
    }
}

#[test]
fn cancel_recovers_tombstone_and_releases_lock_at_each_crash_cut() {
    for (label, failpoint) in preparation_failpoints() {
        let directory = PreparationTempDirectory::new(&format!("cancel-{label}"));
        let path = directory.path.join("identity.state");
        let mut fixture = preparation_fixture_with(preparation_file_runtime(&path));
        let device = fixture.device_a.clone();
        let handle = fixture
            .runtime
            .prepare_revocation(
                BEGIN_A,
                device_revocation(&format!("cancel-crash-{label}"), &device),
            )
            .expect("prepared handle");

        arm_durable_state_failpoint(Some(failpoint));
        assert_eq!(
            fixture.runtime.cancel_prepared_revocation(&handle),
            Err(RuntimeError::PersistenceFailure)
        );
        drop(fixture);

        let mut reopened = preparation_file_runtime(&path);
        reopened
            .cancel_prepared_revocation(&handle)
            .expect("recover exact cancellation");
        reopened
            .cancel_prepared_revocation(&handle)
            .expect("idempotent recovered cancellation");
        let replacement = reopened
            .prepare_revocation(
                BEGIN_B,
                device_revocation(&format!("after-cancel-crash-{label}"), &device),
            )
            .expect("cancelled target lock released");
        reopened
            .cancel_prepared_revocation(&replacement)
            .expect("cleanup replacement preparation");
    }
}

fn preparation_failpoints() -> [(&'static str, DurableStateFailpoint); 2] {
    [
        ("after-state", DurableStateFailpoint::AfterStateCommit),
        ("after-anchor", DurableStateFailpoint::AfterAnchorCommit),
    ]
}
