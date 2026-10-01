use std::cell::Cell;

use crate::RuntimeError;

thread_local! {
    static ARMED: Cell<u8> = const { Cell::new(0) };
}

#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum DurableStateFailpoint {
    AfterStateCommit = 1,
    AfterAnchorCommit = 2,
}

#[doc(hidden)]
pub fn arm_durable_state_failpoint(value: Option<DurableStateFailpoint>) {
    ARMED.with(|armed| armed.set(value.map_or(0, |stage| stage as u8)));
}

pub(super) fn trip(value: DurableStateFailpoint) -> Result<(), RuntimeError> {
    let matched = ARMED.with(|armed| {
        let matched = armed.get() == value as u8;
        if matched {
            armed.set(0);
        }
        matched
    });
    if matched {
        Err(RuntimeError::PersistenceFailure)
    } else {
        Ok(())
    }
}
