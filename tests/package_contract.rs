use std::{collections::BTreeSet, fs, path::Path};

use serde_json::Value;

#[test]
fn schemas_reason_codes_and_fixture_are_valid_bounded_json() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let command = json(root.join("schemas/identity-runtime-command-v1.schema.json"));
    assert_eq!(command["additionalProperties"], false);
    assert_eq!(command["maxProperties"], 3);

    let reasons = json(root.join("schemas/runtime-reason-codes-v1.json"));
    let values = reasons["reason_codes"].as_array().unwrap();
    let unique: BTreeSet<_> = values.iter().filter_map(Value::as_str).collect();
    assert_eq!(unique.len(), values.len());

    let fixture = fs::read(root.join("fixtures/device-identity-assertion-v1.json")).unwrap();
    assert!(fixture.len() < 16_384);
    ihat_identity_runtime::decode_assertion_strict(&fixture).unwrap();
}

fn json(path: impl AsRef<Path>) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}
