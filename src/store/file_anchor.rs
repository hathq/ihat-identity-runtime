use std::path::Path;

use crate::{PersistedImage, RuntimeError, hash::digest_fields};

use super::{file_failpoint::DurableStateFailpoint, file_io, image_revision};

pub(super) fn recover(
    parent: &Path,
    state_path: &Path,
    anchor_path: &Path,
    pending_path: &Path,
) -> Result<Option<PersistedImage>, RuntimeError> {
    let state = file_io::read_bounded(state_path)?;
    let anchor = file_io::read_bounded(anchor_path)?;
    let pending = file_io::read_bounded(pending_path)?;
    let Some(bytes) = state else {
        return recover_absent(parent, anchor, pending, pending_path);
    };
    let image = PersistedImage(bytes);
    let expected = anchor_bytes(&image)?;
    let anchored = anchor.as_deref() == Some(expected.as_slice());
    match pending {
        None if anchored => Ok(Some(image)),
        None => Err(RuntimeError::DatabaseRollbackDetected),
        Some(prepared) if prepared == expected => {
            file_io::atomic_write(parent, anchor_path, &expected)?;
            file_io::remove_durable(parent, pending_path)?;
            Ok(Some(image))
        }
        Some(_) if anchored => {
            file_io::remove_durable(parent, pending_path)?;
            Ok(Some(image))
        }
        Some(_) => Err(RuntimeError::DatabaseRollbackDetected),
    }
}

pub(super) fn commit(
    parent: &Path,
    state_path: &Path,
    anchor_path: &Path,
    pending_path: &Path,
    replacement: &PersistedImage,
) -> Result<(), RuntimeError> {
    let anchor = anchor_bytes(replacement)?;
    file_io::atomic_write(parent, pending_path, &anchor)?;
    file_io::atomic_write(parent, state_path, &replacement.0).map_err(commit_unknown)?;
    super::file_failpoint::trip(DurableStateFailpoint::AfterStateCommit).map_err(commit_unknown)?;
    file_io::atomic_write(parent, anchor_path, &anchor).map_err(commit_unknown)?;
    super::file_failpoint::trip(DurableStateFailpoint::AfterAnchorCommit)
        .map_err(commit_unknown)?;
    file_io::remove_durable(parent, pending_path).map_err(commit_unknown)
}

fn recover_absent(
    parent: &Path,
    anchor: Option<Vec<u8>>,
    pending: Option<Vec<u8>>,
    pending_path: &Path,
) -> Result<Option<PersistedImage>, RuntimeError> {
    if anchor.is_some() {
        return Err(RuntimeError::DatabaseRollbackDetected);
    }
    if pending.is_some() {
        file_io::remove_durable(parent, pending_path)?;
    }
    Ok(None)
}

fn anchor_bytes(image: &PersistedImage) -> Result<Vec<u8>, RuntimeError> {
    let revision = image_revision(image)?;
    let digest = digest_fields("ihat-identity-durable-anchor-v1", &[&image.0]);
    Ok(format!("IHAT-ANCHOR-V1\n{revision}\n{digest}\n").into_bytes())
}

fn commit_unknown(_: RuntimeError) -> RuntimeError {
    RuntimeError::PersistenceFailure
}
