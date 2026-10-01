use crate::{RuntimeError, hash::hex};

use super::IdentityRuntime;

const RANDOM_BYTES: usize = 32;
const MAX_COLLISION_ATTEMPTS: usize = 8;

impl IdentityRuntime {
    pub(super) fn fresh_session_ref(&self, service_id: &str) -> Result<String, RuntimeError> {
        for _ in 0..MAX_COLLISION_ATTEMPTS {
            let mut random = [0_u8; RANDOM_BYTES];
            getrandom::fill(&mut random).map_err(|_| RuntimeError::PersistenceFailure)?;
            let candidate = format!("sref_{}", hex(&random));
            let collision = self.state.sessions.values().any(|session| {
                session.service_id == service_id && session.session_ref == candidate
            });
            if !collision {
                return Ok(candidate);
            }
        }
        Err(RuntimeError::PersistenceFailure)
    }
}
