use crate::{
    LifecycleStatus, RevocationScope, RotateDeviceKeyRequest, RuntimeError,
    state::device_key as record_key,
    validation::{device_key, fresh, id},
};

use super::{IdentityRuntime, guards};

impl IdentityRuntime {
    pub fn rotate_device_key(
        &mut self,
        request: RotateDeviceKeyRequest,
    ) -> Result<crate::DeviceRecord, RuntimeError> {
        for (value, field) in [
            (&request.command_id, "command_id"),
            (&request.account_id, "account_id"),
            (&request.service_id, "service_id"),
            (&request.device_id, "device_id"),
            (&request.retired_key_fingerprint, "retired_key_fingerprint"),
        ] {
            id(value, field)?;
        }
        let authentication = request
            .fresh_user_authentication
            .as_ref()
            .ok_or(RuntimeError::FreshAuthenticationRequired)?;
        fresh(authentication)?;
        device_key(&request.replacement_key)?;
        self.verify_rotation_evidence(&request)?;
        self.unused(&[&request.command_id, &authentication.proof_id])?;
        self.ensure_unique_device_key(&request.replacement_key.fingerprint)?;
        let key = record_key(&request.account_id, &request.service_id, &request.device_id);
        let current = self
            .state
            .devices
            .get(&key)
            .cloned()
            .ok_or(RuntimeError::NotFound("device"))?;
        if current.status != LifecycleStatus::Active {
            return Err(RuntimeError::DeviceRevoked);
        }
        if current.key_fingerprint != request.retired_key_fingerprint {
            return Err(RuntimeError::SenderBindingMismatch);
        }
        guards::epoch(
            RevocationScope::Device,
            request.expected_device_epoch,
            current.device_epoch,
        )?;
        let before = self.before();
        self.state
            .retired_keys
            .insert(request.retired_key_fingerprint.clone());
        let device = self.state.devices.get_mut(&key).unwrap();
        device.key_fingerprint = request.replacement_key.fingerprint;
        device.device_epoch += 1;
        device.posture_revision += 1;
        let output = device.clone();
        self.consume(&[&request.command_id, &authentication.proof_id]);
        self.finish(before, "device-key-rotated", &request.command_id)?;
        Ok(output)
    }
}
