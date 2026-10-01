use serde_json::Value;

use crate::{IDENTITY_WIRE_SCHEMA, MAX_WIRE_BYTES, RuntimeError, validation::id};

use super::IdentityRuntime;

const MAX_FIELDS: usize = 32;
const MAX_ARRAY_ITEMS: usize = 64;
const MAX_DEPTH: usize = 8;
const MAX_STRING_BYTES: usize = 4096;

impl IdentityRuntime {
    pub fn ingest_wire(&mut self, wire: &[u8]) -> Result<(), RuntimeError> {
        if wire.len() > MAX_WIRE_BYTES {
            return Err(RuntimeError::RequestTooLarge {
                limit: MAX_WIRE_BYTES,
            });
        }
        let value: Value =
            serde_json::from_slice(wire).map_err(|_| RuntimeError::InvalidRequest("wire_json"))?;
        bounded(&value, 0)?;
        let object = value
            .as_object()
            .ok_or(RuntimeError::InvalidRequest("wire_object"))?;
        for key in object.keys() {
            if !["schema", "operation", "proof_id"].contains(&key.as_str()) {
                return Err(RuntimeError::UnknownField(key.clone()));
            }
        }
        if object
            .get("schema")
            .is_some_and(|value| value.as_str() != Some(IDENTITY_WIRE_SCHEMA))
        {
            return Err(RuntimeError::InvalidRequest("wire_schema"));
        }
        let operation = object
            .get("operation")
            .and_then(Value::as_str)
            .ok_or(RuntimeError::InvalidRequest("wire_operation"))?;
        if operation != "authorize-session" {
            return Err(RuntimeError::InvalidRequest("wire_operation"));
        }
        let proof_id = object
            .get("proof_id")
            .and_then(Value::as_str)
            .ok_or(RuntimeError::InvalidRequest("wire_proof_id"))?;
        id(proof_id, "proof_id")
    }
}

fn bounded(value: &Value, depth: usize) -> Result<(), RuntimeError> {
    if depth > MAX_DEPTH {
        return Err(RuntimeError::LimitExceeded {
            field: "wire_depth",
            limit: MAX_DEPTH,
        });
    }
    match value {
        Value::String(value) if value.len() > MAX_STRING_BYTES => {
            Err(RuntimeError::LimitExceeded {
                field: "wire_string",
                limit: MAX_STRING_BYTES,
            })
        }
        Value::Array(values) if values.len() > MAX_ARRAY_ITEMS => {
            Err(RuntimeError::LimitExceeded {
                field: "wire_array",
                limit: MAX_ARRAY_ITEMS,
            })
        }
        Value::Object(values) if values.len() > MAX_FIELDS => Err(RuntimeError::LimitExceeded {
            field: "wire_fields",
            limit: MAX_FIELDS,
        }),
        Value::Array(values) => {
            for value in values {
                bounded(value, depth + 1)?;
            }
            Ok(())
        }
        Value::Object(values) => {
            for value in values.values() {
                bounded(value, depth + 1)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}
