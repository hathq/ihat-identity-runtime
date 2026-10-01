use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
};

use crate::{RuntimeError, store::MAX_DURABLE_IMAGE_BYTES};

pub(crate) fn secure_parent(parent: &Path) -> Result<(), RuntimeError> {
    if !parent.is_absolute() {
        return Err(RuntimeError::InvalidRequest("durable_path_absolute"));
    }
    if !parent.exists() {
        fs::create_dir_all(parent).map_err(|_| RuntimeError::PersistenceFailure)?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
            .map_err(|_| RuntimeError::PersistenceFailure)?;
    }
    let metadata = fs::symlink_metadata(parent).map_err(|_| RuntimeError::PersistenceFailure)?;
    let canonical = parent
        .canonicalize()
        .map_err(|_| RuntimeError::PersistenceFailure)?;
    if metadata.file_type().is_symlink()
        || canonical != parent
        || metadata.permissions().mode() & 0o777 != 0o700
    {
        return Err(RuntimeError::InvalidRequest("durable_parent_security"));
    }
    Ok(())
}

pub(crate) fn reject_symlink(path: &Path) -> Result<(), RuntimeError> {
    match fs::symlink_metadata(path) {
        Ok(value) if value.file_type().is_symlink() => {
            Err(RuntimeError::InvalidRequest("durable_symlink"))
        }
        Ok(value) if value.permissions().mode() & 0o777 != 0o600 => {
            Err(RuntimeError::InvalidRequest("durable_file_permissions"))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(RuntimeError::PersistenceFailure),
    }
}

pub(crate) fn open_lock(path: &Path) -> Result<File, RuntimeError> {
    reject_symlink(path)?;
    let existed = path.exists();
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| RuntimeError::PersistenceFailure)?;
    if !existed {
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|_| RuntimeError::PersistenceFailure)?;
    }
    reject_symlink(path)?;
    Ok(file)
}

pub(crate) fn read_bounded(path: &Path) -> Result<Option<Vec<u8>>, RuntimeError> {
    reject_symlink(path)?;
    if !path.exists() {
        return Ok(None);
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| RuntimeError::PersistenceFailure)?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_DURABLE_IMAGE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| RuntimeError::PersistenceFailure)?;
    if bytes.len() > MAX_DURABLE_IMAGE_BYTES {
        return Err(RuntimeError::LimitExceeded {
            field: "durable_image",
            limit: MAX_DURABLE_IMAGE_BYTES,
        });
    }
    Ok(Some(bytes))
}

pub(crate) fn atomic_write(parent: &Path, target: &Path, bytes: &[u8]) -> Result<(), RuntimeError> {
    let mut random = [0_u8; 8];
    getrandom::fill(&mut random).map_err(|_| RuntimeError::PersistenceFailure)?;
    let suffix = u64::from_be_bytes(random);
    let name = target
        .file_name()
        .and_then(|v| v.to_str())
        .ok_or(RuntimeError::InvalidRequest("durable_filename"))?;
    let temporary = parent.join(format!(".{name}.tmp.{}.{suffix}", std::process::id()));
    let result = write_and_rename(&temporary, target, bytes);
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result?;
    File::open(parent)
        .and_then(|file| file.sync_all())
        .map_err(|_| RuntimeError::PersistenceFailure)
}

pub(crate) fn remove_durable(parent: &Path, target: &Path) -> Result<(), RuntimeError> {
    reject_symlink(target)?;
    fs::remove_file(target).map_err(|_| RuntimeError::PersistenceFailure)?;
    File::open(parent)
        .and_then(|file| file.sync_all())
        .map_err(|_| RuntimeError::PersistenceFailure)
}

fn write_and_rename(temp: &Path, target: &Path, bytes: &[u8]) -> Result<(), RuntimeError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(temp)
        .map_err(|_| RuntimeError::PersistenceFailure)?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| RuntimeError::PersistenceFailure)?;
    fs::rename(temp, target).map_err(|_| RuntimeError::PersistenceFailure)?;
    fs::set_permissions(target, fs::Permissions::from_mode(0o600))
        .map_err(|_| RuntimeError::PersistenceFailure)
}
