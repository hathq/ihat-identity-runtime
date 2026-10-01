use std::{
    fs::File,
    path::{Path, PathBuf},
};

use crate::{PersistedImage, RuntimeError};

use super::{DurableState, file_io, image_revision};

#[derive(Clone, Debug)]
pub struct FileDurableState {
    state: PathBuf,
    anchor: PathBuf,
    pending_anchor: PathBuf,
    lock: PathBuf,
    parent: PathBuf,
}

impl FileDurableState {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, RuntimeError> {
        let state = path.as_ref();
        let parent = state
            .parent()
            .ok_or(RuntimeError::InvalidRequest("durable_parent"))?;
        file_io::secure_parent(parent)?;
        if state.parent() != Some(parent) || state.file_name().is_none() {
            return Err(RuntimeError::InvalidRequest("durable_path"));
        }
        let name = state
            .file_name()
            .and_then(|v| v.to_str())
            .ok_or(RuntimeError::InvalidRequest("durable_filename"))?;
        let value = Self {
            state: state.into(),
            anchor: parent.join(format!(".{name}.anchor")),
            pending_anchor: parent.join(format!(".{name}.anchor.pending")),
            lock: parent.join(format!(".{name}.lock")),
            parent: parent.into(),
        };
        for path in [
            &value.state,
            &value.anchor,
            &value.pending_anchor,
            &value.lock,
        ] {
            file_io::reject_symlink(path)?;
        }
        Ok(value)
    }

    fn read_locked(&self) -> Result<Option<PersistedImage>, RuntimeError> {
        super::file_anchor::recover(
            &self.parent,
            &self.state,
            &self.anchor,
            &self.pending_anchor,
        )
    }

    fn lock(&self) -> Result<File, RuntimeError> {
        let file = file_io::open_lock(&self.lock)?;
        file.lock().map_err(|_| RuntimeError::PersistenceFailure)?;
        Ok(file)
    }
}

impl DurableState for FileDurableState {
    fn read(&self) -> Result<Option<PersistedImage>, RuntimeError> {
        let lock = self.lock()?;
        let result = self.read_locked();
        lock.unlock()
            .map_err(|_| RuntimeError::PersistenceFailure)?;
        result
    }

    fn compare_and_swap(
        &mut self,
        expected: Option<u64>,
        replacement: PersistedImage,
    ) -> Result<(), RuntimeError> {
        let lock = self.lock()?;
        let current = self.read_locked();
        let result = current.and_then(|value| {
            let revision = value.as_ref().map(image_revision).transpose()?;
            if revision != expected {
                return Err(RuntimeError::DatabaseRollbackDetected);
            }
            let next = image_revision(&replacement)?;
            let required = expected.map_or(0, |value| value + 1);
            if next != required {
                return Err(RuntimeError::PersistenceFailure);
            }
            super::file_anchor::commit(
                &self.parent,
                &self.state,
                &self.anchor,
                &self.pending_anchor,
                &replacement,
            )
        });
        lock.unlock()
            .map_err(|_| RuntimeError::PersistenceFailure)?;
        result
    }
}
