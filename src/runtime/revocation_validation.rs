use crate::{RevocationTarget, RuntimeError, validation::id};

pub(crate) fn validate_target(value: &RevocationTarget) -> Result<(), RuntimeError> {
    let values: Vec<(&str, &'static str)> = match value {
        RevocationTarget::Subject { account_id } => vec![(account_id, "account_id")],
        RevocationTarget::ServiceAccount {
            account_id,
            service_id,
        } => vec![(account_id, "account_id"), (service_id, "service_id")],
        RevocationTarget::Device {
            account_id,
            service_id,
            device_id,
        } => vec![
            (account_id, "account_id"),
            (service_id, "service_id"),
            (device_id, "device_id"),
        ],
        RevocationTarget::Session {
            account_id,
            service_id,
            session_id,
        } => vec![
            (account_id, "account_id"),
            (service_id, "service_id"),
            (session_id, "session_id"),
        ],
    };
    for (value, field) in values {
        id(value, field)?;
    }
    Ok(())
}
