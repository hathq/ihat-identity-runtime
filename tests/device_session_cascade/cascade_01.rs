use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

use support::*;

#[test]
// ID-49: one atomic device revocation cascades only to that device's active sessions.
fn device_revocation_cascades_all_child_sessions_and_survives_reopen() {
    let mut runtime = runtime();
    let service = create_account_and_service(&mut runtime, "account-a", "service-a");
    let device_a = enroll(&mut runtime, "account-a", &service, "device-a", "key-a");
    let device_b = enroll(&mut runtime, "account-a", &service, "device-b", "key-b");
    let session_a1 = issue(&mut runtime, "account-a", &service, &device_a, "session-a1");
    let session_a2 = issue(&mut runtime, "account-a", &service, &device_a, "session-a2");
    let session_b = issue(&mut runtime, "account-a", &service, &device_b, "session-b");
    let receipt = runtime
        .revoke_device(request(&device_a))
        .expect("atomic cascade");
    assert_eq!(receipt.revoked_session_count, 2);
    let graph = runtime.identity_graph().expect("graph");
    for id in [session_a1.session_id, session_a2.session_id] {
        let value = graph
            .sessions
            .iter()
            .find(|session| session.session_id == id)
            .unwrap();
        assert_eq!(value.status, LifecycleStatus::Revoked);
        assert_eq!(value.session_epoch, INITIAL_EPOCH + 1);
    }
    let sibling = graph
        .sessions
        .iter()
        .find(|value| value.session_id == session_b.session_id)
        .unwrap();
    assert_eq!(sibling.status, LifecycleStatus::Active);
    assert_eq!(sibling.session_epoch, session_b.session_epoch);
    runtime.restart().expect("reopen");
    assert_eq!(runtime.identity_graph().unwrap(), graph);
}

#[test]
fn cascade_persistence_failpoint_rolls_back_device_and_every_session() {
    let (image, device) = seeded_image();
    let control = StoreControl::new(image, true);
    let before = control.image();
    let mut runtime = IdentityRuntime::open_store_for_test(
        Box::new(control.store()),
        Box::new(TestPairwiseDeriver),
        test_trust(),
    )
    .expect("runtime");
    let graph = runtime.identity_graph().unwrap();
    assert_eq!(
        runtime.revoke_device(request(&device)),
        Err(RuntimeError::PersistenceFailure)
    );
    assert_eq!(runtime.identity_graph().unwrap(), graph);
    assert_eq!(control.image(), before);
    let reopened = IdentityRuntime::open_store_for_test(
        Box::new(control.store()),
        Box::new(TestPairwiseDeriver),
        test_trust(),
    )
    .expect("reopen");
    assert_eq!(reopened.identity_graph().unwrap(), graph);
}

#[test]
fn child_epoch_overflow_rejects_before_any_device_or_session_mutation() {
    let (image, device) = seeded_image();
    let overflow = with_session_epoch(image, u64::MAX);
    let control = StoreControl::new(overflow, false);
    let mut runtime = IdentityRuntime::open_store_for_test(
        Box::new(control.store()),
        Box::new(TestPairwiseDeriver),
        test_trust(),
    )
    .expect("runtime");
    let graph = runtime.identity_graph().unwrap();
    assert_eq!(
        runtime.revoke_device(request(&device)),
        Err(RuntimeError::PersistenceFailure)
    );
    assert_eq!(runtime.identity_graph().unwrap(), graph);
}
