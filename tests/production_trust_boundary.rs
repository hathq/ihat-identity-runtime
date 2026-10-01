use std::{collections::BTreeSet, fs, path::Path};

use serde_json::Value;

#[test]
fn production_construction_has_no_optional_or_allow_all_trust_path() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let core = read(root.join("src/runtime/core.rs"));
    let trust = read(root.join("src/trust.rs"));
    let assertion = read(root.join("src/assertion.rs"));
    assert!(core.contains("trust: RuntimeTrust"));
    assert!(!core.contains("Box::new(SystemClock)"));
    for forbidden in [
        "with_assertion_ports",
        "with_assertion_signer",
        "deterministic_test_clock",
        "FixedClock",
        "AllowAll",
        "NoopVerifier",
        "TestEvidenceVerifier",
    ] {
        assert!(
            !read_tree(root.join("src")).contains(forbidden),
            "{forbidden}"
        );
    }
    for required in [
        "AuthenticationVerifier",
        "DeviceAttestationVerifier",
        "DeviceKeyPossessionVerifier",
        "SessionSenderProofVerifier",
        "RevocationAuthorityVerifier",
        "RecoveryApprovalVerifier",
        "InstallerBootstrapVerifier",
    ] {
        assert!(trust.contains(required), "{required}");
    }
    assert!(assertion.contains("sender_key_fingerprint"));
    assert!(assertion.contains("sender_proof_id"));
    assert!(core.contains("with_identity_signers"));
    assert!(core.contains("status_signer"));
}

#[test]
fn every_acceptance_reason_is_a_published_current_reason_code() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let catalog: Value = serde_json::from_str(&read(
        root.join("fixtures/trust-boundary-acceptance-v1.json"),
    ))
    .unwrap();
    let reasons: Value =
        serde_json::from_str(&read(root.join("schemas/runtime-reason-codes-v1.json"))).unwrap();
    let published: BTreeSet<_> = reasons["reason_codes"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    for case in catalog["cases"].as_array().unwrap() {
        assert!(published.contains(case["expected"].as_str().unwrap()));
    }
}

fn read(path: impl AsRef<Path>) -> String {
    fs::read_to_string(path).unwrap()
}

fn read_tree(root: impl AsRef<Path>) -> String {
    let mut output = String::new();
    for entry in fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            output.push_str(&read_tree(path));
        } else if path.extension().and_then(|value| value.to_str()) == Some("rs") {
            output.push_str(&read(path));
        }
    }
    output
}
