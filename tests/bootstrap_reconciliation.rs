mod support;

use support::*;

#[test]
// ID-52: a lost bootstrap response reconciles only the exact committed request.
fn id_52_exact_bootstrap_reconciliation_survives_restart_without_new_audit() {
    let mut runtime = runtime();
    let request = bootstrap_request("bootstrap-reconcile-01");
    let committed = runtime
        .bootstrap_initial_identity(request.clone())
        .expect("commit bootstrap");
    let audit = runtime.audit_events().expect("audit before reconcile");

    runtime.restart().expect("restart");
    let reconciled = runtime
        .reconcile_initial_bootstrap(request)
        .expect("reconcile committed bootstrap");

    assert_eq!(reconciled, committed);
    assert_eq!(
        runtime.audit_events().expect("audit after reconcile"),
        audit
    );
}

#[test]
fn reconciliation_before_a_commit_is_not_a_bootstrap_or_a_mutation() {
    let runtime = runtime();
    assert_eq!(
        runtime.reconcile_initial_bootstrap(bootstrap_request("bootstrap-absent")),
        Err(RuntimeError::NotFound("initial_bootstrap_receipt"))
    );
    assert_eq!(
        runtime.identity_graph().expect("graph"),
        IdentityGraph::default()
    );
    assert!(runtime.audit_events().expect("audit").is_empty());
}

#[test]
fn every_bootstrap_binding_substitution_is_rejected() {
    let mut runtime = runtime();
    let original = bootstrap_request("bootstrap-reconcile-binding");
    runtime
        .bootstrap_initial_identity(original.clone())
        .expect("commit bootstrap");

    for changed in substitutions(&original) {
        assert_eq!(
            runtime.reconcile_initial_bootstrap(changed),
            Err(RuntimeError::InvalidRequest("initial_bootstrap_reconcile"))
        );
    }
}

fn substitutions(original: &InitialBootstrapRequest) -> Vec<InitialBootstrapRequest> {
    vec![
        changed(original, |v| v.command_id.push_str("-changed")),
        changed(original, |v| v.account_id.push_str("-changed")),
        changed(original, |v| v.primary_identity.issuer.push_str("/changed")),
        changed(original, |v| {
            v.primary_identity.subject.push_str("-changed")
        }),
        changed(original, |v| v.service_id.push_str(":changed")),
        changed(original, |v| v.device_id.push_str("-changed")),
        changed(original, |v| v.proof_key.spki.push(9)),
        changed(original, |v| v.proof_key.attestation.push(9)),
        changed(original, |v| v.session_id.push_str("-changed")),
        changed(original, |v| {
            v.proof_key.fingerprint.push_str("-changed");
            v.sender_key_fingerprint.push_str("-changed");
        }),
        changed(original, |v| v.bundle.bundle_id.push_str("-changed")),
        changed(original, |v| v.bundle.root_key_id.push_str("-changed")),
        changed(original, |v| v.bundle.issued_at_epoch_s += 1),
        changed(original, |v| v.bundle.expires_at_epoch_s += 1),
        changed(original, |v| v.bundle.signature.push_str("-changed")),
    ]
}

fn changed(
    original: &InitialBootstrapRequest,
    mutate: impl FnOnce(&mut InitialBootstrapRequest),
) -> InitialBootstrapRequest {
    let mut value = original.clone();
    mutate(&mut value);
    value
}
