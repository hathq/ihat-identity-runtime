use crate::{AuditEvent, AuditVerification, RuntimeError, hash::digest_fields};

const GENESIS: &str = "sha256:ihat-identity-audit-genesis-v1";

pub(crate) fn append(events: &mut Vec<AuditEvent>, event_type: &str, command_id: &str) {
    let sequence = events.last().map_or(1, |event| event.sequence + 1);
    let previous_hash = events
        .last()
        .map_or_else(|| GENESIS.to_owned(), |event| event.event_hash.clone());
    let event_hash = event_hash(sequence, event_type, command_id, &previous_hash);
    events.push(AuditEvent {
        sequence,
        event_type: event_type.into(),
        command_id: command_id.into(),
        previous_hash,
        event_hash,
    });
}

pub(crate) fn verify(events: &[AuditEvent]) -> Result<AuditVerification, RuntimeError> {
    let mut previous = GENESIS.to_owned();
    for (index, event) in events.iter().enumerate() {
        if event.sequence != index as u64 + 1
            || event.previous_hash != previous
            || event.event_hash
                != event_hash(
                    event.sequence,
                    &event.event_type,
                    &event.command_id,
                    &event.previous_hash,
                )
        {
            return Err(RuntimeError::AuditIntegrityViolation);
        }
        previous = event.event_hash.clone();
    }
    Ok(AuditVerification {
        entry_count: events.len(),
        head_hash: previous,
    })
}

fn event_hash(sequence: u64, event_type: &str, command_id: &str, previous: &str) -> String {
    let sequence = sequence.to_string();
    format!(
        "sha256:{}",
        digest_fields(
            "ihat-identity-audit-event-v1",
            &[
                sequence.as_bytes(),
                event_type.as_bytes(),
                command_id.as_bytes(),
                previous.as_bytes(),
            ],
        )
    )
}
