use serde_json::Value;

use super::{decode_state, encode_state};
use crate::{PersistedImage, RuntimeError, state::State};

fn raw_with_payload(image: &PersistedImage, payload: &Value) -> PersistedImage {
    let mut bytes = image.0[..16].to_vec();
    bytes.extend(serde_json::to_vec(payload).expect("json"));
    PersistedImage(bytes)
}

#[test]
fn v4_state_reads_v3_and_rejects_v2_missing_slot_map_unknown_and_trailing_payloads() {
    let image = encode_state(&State::new()).expect("v4 state");
    assert_eq!(&image.0[..8], b"IHATID04");

    let mut v3 = image.clone();
    v3.0[..8].copy_from_slice(b"IHATID03");
    let mut v3_payload: Value = serde_json::from_slice(&v3.0[16..]).expect("payload");
    v3_payload
        .as_object_mut()
        .expect("object")
        .remove("revocation_receipts");
    assert!(decode_state(&raw_with_payload(&v3, &v3_payload)).is_ok());

    let mut v2 = image.clone();
    v2.0[..8].copy_from_slice(b"IHATID02");
    assert!(matches!(
        decode_state(&v2),
        Err(RuntimeError::PersistenceFailure)
    ));

    let mut payload: Value = serde_json::from_slice(&image.0[16..]).expect("payload");
    payload
        .as_object_mut()
        .expect("object")
        .remove("current_identity_sessions");
    assert!(matches!(
        decode_state(&raw_with_payload(&image, &payload)),
        Err(RuntimeError::PersistenceFailure)
    ));

    payload
        .as_object_mut()
        .expect("object")
        .insert("current_identity_sessions".into(), serde_json::json!({}));
    payload
        .as_object_mut()
        .expect("object")
        .insert("unknown".into(), true.into());
    assert!(matches!(
        decode_state(&raw_with_payload(&image, &payload)),
        Err(RuntimeError::PersistenceFailure)
    ));

    let mut trailing = image;
    trailing.0.extend_from_slice(b" {}");
    assert!(matches!(
        decode_state(&trailing),
        Err(RuntimeError::PersistenceFailure)
    ));
}
