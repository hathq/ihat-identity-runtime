use crate::state::{device_key, session_key};
use crate::{DeviceRecord, RuntimeError, SessionProof, SessionRecord, SessionRequest};

use super::IdentityRuntime;

impl IdentityRuntime {
    pub(crate) fn device_for_session(
        &self,
        request: &SessionRequest,
    ) -> Result<DeviceRecord, RuntimeError> {
        self.state
            .devices
            .get(&device_key(
                &request.account_id,
                &request.service_id,
                &request.device_id,
            ))
            .cloned()
            .ok_or(RuntimeError::NotFound("device"))
    }

    pub(crate) fn device_for_proof(
        &self,
        proof: &SessionProof,
    ) -> Result<DeviceRecord, RuntimeError> {
        self.state
            .devices
            .get(&device_key(
                &proof.account_id,
                &proof.service_id,
                &proof.device_id,
            ))
            .cloned()
            .ok_or(RuntimeError::NotFound("device"))
    }

    pub(crate) fn session_for_proof(
        &self,
        proof: &SessionProof,
    ) -> Result<SessionRecord, RuntimeError> {
        let session = self
            .state
            .sessions
            .get(&session_key(
                &proof.account_id,
                &proof.service_id,
                &proof.session_id,
            ))
            .cloned()
            .ok_or(RuntimeError::NotFound("session"))?;
        if session.device_id != proof.device_id
            || session.pairwise_subject != proof.pairwise_subject
            || session.session_ref != proof.session_ref
        {
            return Err(RuntimeError::SenderBindingMismatch);
        }
        Ok(session)
    }

    pub(crate) fn ensure_session_capacity(
        &self,
        request: &SessionRequest,
    ) -> Result<(), RuntimeError> {
        self.ensure_session_capacity_replacing(request, false)
    }

    pub(crate) fn ensure_session_capacity_replacing(
        &self,
        request: &SessionRequest,
        replacing_active: bool,
    ) -> Result<(), RuntimeError> {
        let count = self
            .state
            .sessions
            .values()
            .filter(|value| {
                value.account_id == request.account_id
                    && value.service_id == request.service_id
                    && value.device_id == request.device_id
                    && value.status == crate::LifecycleStatus::Active
            })
            .count();
        let retained = count.saturating_sub(usize::from(replacing_active));
        if retained >= crate::MAX_SESSIONS_PER_DEVICE {
            return Err(RuntimeError::LimitExceeded {
                field: "sessions_per_device",
                limit: crate::MAX_SESSIONS_PER_DEVICE,
            });
        }
        Ok(())
    }
}
