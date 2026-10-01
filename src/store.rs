mod file;
mod file_anchor;
mod file_failpoint;
mod file_io;
#[cfg(test)]
mod tests_schema;

pub use file::FileDurableState;
#[doc(hidden)]
pub use file_failpoint::{DurableStateFailpoint, arm_durable_state_failpoint};

use crate::{PersistedImage, RuntimeError, state::State};

const MAGIC: &[u8; 8] = b"IHATID04";
const LEGACY_MAGIC: &[u8; 8] = b"IHATID03";
pub const MAX_DURABLE_IMAGE_BYTES: usize = 4 * 1024 * 1024;

pub trait DurableState: Send {
    fn read(&self) -> Result<Option<PersistedImage>, RuntimeError>;
    fn compare_and_swap(
        &mut self,
        expected_revision: Option<u64>,
        replacement: PersistedImage,
    ) -> Result<(), RuntimeError>;
    fn replace_for_test(&mut self, _replacement: PersistedImage) -> Result<(), RuntimeError> {
        Err(RuntimeError::InvalidRequest(
            "production_store_test_mutation",
        ))
    }
}

pub(crate) fn encode_state(state: &State) -> Result<PersistedImage, RuntimeError> {
    let payload = serde_json::to_vec(state).map_err(|_| RuntimeError::PersistenceFailure)?;
    let mut bytes = Vec::with_capacity(MAGIC.len() + 8 + payload.len());
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&state.revision.to_be_bytes());
    bytes.extend_from_slice(&payload);
    if bytes.len() > MAX_DURABLE_IMAGE_BYTES {
        return Err(RuntimeError::LimitExceeded {
            field: "durable_image",
            limit: MAX_DURABLE_IMAGE_BYTES,
        });
    }
    Ok(PersistedImage(bytes))
}

pub(crate) fn decode_state(image: &PersistedImage) -> Result<State, RuntimeError> {
    if image.0.len() < 16
        || image.0.len() > MAX_DURABLE_IMAGE_BYTES
        || &image.0[..8] != MAGIC && &image.0[..8] != LEGACY_MAGIC
    {
        return Err(RuntimeError::PersistenceFailure);
    }
    let state: State =
        serde_json::from_slice(&image.0[16..]).map_err(|_| RuntimeError::PersistenceFailure)?;
    if state.revision != image_revision(image)? {
        return Err(RuntimeError::PersistenceFailure);
    }
    Ok(state)
}

pub(crate) fn image_revision(image: &PersistedImage) -> Result<u64, RuntimeError> {
    let bytes: [u8; 8] = image
        .0
        .get(8..16)
        .ok_or(RuntimeError::PersistenceFailure)?
        .try_into()
        .map_err(|_| RuntimeError::PersistenceFailure)?;
    Ok(u64::from_be_bytes(bytes))
}
