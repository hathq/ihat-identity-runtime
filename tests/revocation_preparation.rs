mod support;

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

use serde_json::{Value, json};
use support::*;

include!("revocation_preparation/preparation_support_01.rs");
include!("revocation_preparation/preparation_support_02.rs");
include!("revocation_preparation/preparation_support_03.rs");
include!("revocation_preparation/preflight.rs");
include!("revocation_preparation/authorization.rs");
include!("revocation_preparation/tombstone.rs");
include!("revocation_preparation/locks.rs");
include!("revocation_preparation/persistence.rs");
include!("revocation_preparation/crash.rs");
