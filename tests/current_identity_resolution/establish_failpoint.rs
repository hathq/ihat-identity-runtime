use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

#[derive(Default)]
struct EstablishFailpointStore {
    current: Option<PersistedImage>,
    revision: Option<u64>,
    fail_next: Arc<AtomicBool>,
}

impl DurableState for EstablishFailpointStore {
    fn read(&self) -> Result<Option<PersistedImage>, RuntimeError> {
        Ok(self.current.clone())
    }

    fn compare_and_swap(
        &mut self,
        expected: Option<u64>,
        replacement: PersistedImage,
    ) -> Result<(), RuntimeError> {
        if self.fail_next.load(Ordering::SeqCst) {
            return Err(RuntimeError::PersistenceFailure);
        }
        if self.revision != expected {
            return Err(RuntimeError::DatabaseRollbackDetected);
        }
        self.revision = Some(expected.map_or(0, |value| value + 1));
        self.current = Some(replacement);
        Ok(())
    }
}

#[test]
fn failed_rotation_cas_rolls_back_old_slot_new_record_and_replay_consumption() {
    let fail_next = Arc::new(AtomicBool::new(false));
    let store = EstablishFailpointStore {
        current: None,
        revision: None,
        fail_next: fail_next.clone(),
    };
    let runtime = IdentityRuntime::open_store_for_test(
        Box::new(store),
        Box::new(TestPairwiseDeriver),
        test_trust(),
    )
    .expect("runtime");
    let (mut runtime, service, device) = base_from(signed(runtime));
    let old = establish(
        &mut runtime,
        &service,
        &device,
        "failpoint-old",
        ExpectedCurrentSession::Absent,
    );
    let request = establish_request(
        &service,
        &device,
        "failpoint-new",
        ExpectedCurrentSession::Present {
            session_ref: old.session_ref.clone(),
            session_epoch: old.session_epoch,
        },
    );
    fail_next.store(true, Ordering::SeqCst);
    assert_eq!(
        runtime
            .establish_device_identity_session(request.clone())
            .expect_err("injected durable failure"),
        RuntimeError::PersistenceFailure
    );
    fail_next.store(false, Ordering::SeqCst);
    let graph = runtime.identity_graph().expect("rolled back graph");
    let old_after = graph
        .sessions
        .iter()
        .find(|value| value.session_ref == old.session_ref)
        .expect("old slot retained");
    assert_eq!(old_after.status, LifecycleStatus::Active);
    assert!(
        graph
            .sessions
            .iter()
            .all(|value| value.session_id != "failpoint-new")
    );
    runtime
        .establish_device_identity_session(request)
        .expect("failed command and proof were not consumed");
}
