use crate::{
    AuditEvent, AuditVerification, IdentityGraph, PersistedImage, RevocationSnapshot, RuntimeError,
    audit, store::decode_state,
};

use super::IdentityRuntime;

impl IdentityRuntime {
    pub fn identity_graph(&self) -> Result<IdentityGraph, RuntimeError> {
        audit::verify(&self.state.audit)?;
        Ok(self.state.graph())
    }

    pub fn revocation_snapshot(&self) -> Result<RevocationSnapshot, RuntimeError> {
        audit::verify(&self.state.audit)?;
        Ok(self.state.revocations())
    }

    pub fn audit_events(&self) -> Result<Vec<AuditEvent>, RuntimeError> {
        audit::verify(&self.state.audit)?;
        Ok(self.state.audit.clone())
    }

    pub fn verify_audit(&self) -> Result<AuditVerification, RuntimeError> {
        audit::verify(&self.state.audit)
    }

    pub fn restart(&mut self) -> Result<(), RuntimeError> {
        let image = self.store.read()?.ok_or(RuntimeError::PersistenceFailure)?;
        let loaded = decode_state(&image)?;
        if loaded.revision < self.rollback_anchor {
            return Err(RuntimeError::DatabaseRollbackDetected);
        }
        audit::verify(&loaded.audit)?;
        super::revocation_preparation_guard::validate_state(&loaded)?;
        self.rollback_anchor = self.rollback_anchor.max(loaded.revision);
        self.state = loaded;
        Ok(())
    }

    pub fn snapshot_persistent_store_for_test(&self) -> Result<PersistedImage, RuntimeError> {
        self.store.read()?.ok_or(RuntimeError::PersistenceFailure)
    }

    pub fn restore_persistent_store_for_test(
        &mut self,
        image: PersistedImage,
    ) -> Result<(), RuntimeError> {
        self.store.replace_for_test(image)
    }

    pub fn attempt_audit_overwrite_for_test(
        &mut self,
        _sequence: u64,
        _replacement: AuditEvent,
    ) -> Result<(), RuntimeError> {
        Err(RuntimeError::AuditImmutable)
    }

    pub fn corrupt_audit_bytes_for_test(&mut self, sequence: u64) -> Result<(), RuntimeError> {
        let event = self
            .state
            .audit
            .iter_mut()
            .find(|event| event.sequence == sequence)
            .ok_or(RuntimeError::NotFound("audit_event"))?;
        event.event_type.push_str("-corrupt");
        Ok(())
    }
}
