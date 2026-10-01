use std::path::Path;

use crate::{
    AssertionSigner, DurableState, FileDurableState, PairwiseSubjectDeriver, RuntimeError,
    RuntimeTrust, audit, state::State, store,
};

pub struct IdentityRuntime {
    pub(crate) state: State,
    pub(crate) store: Box<dyn DurableState>,
    pub(crate) rollback_anchor: u64,
    pub(crate) pairwise_deriver: Box<dyn PairwiseSubjectDeriver>,
    pub(crate) assertion_signer: Option<Box<dyn AssertionSigner>>,
    pub(crate) status_signer: Option<Box<dyn AssertionSigner>>,
    pub(crate) trust: RuntimeTrust,
}

impl IdentityRuntime {
    pub fn open_file(
        path: impl AsRef<Path>,
        pairwise_deriver: Box<dyn PairwiseSubjectDeriver>,
        trust: RuntimeTrust,
    ) -> Result<Self, RuntimeError> {
        let store = FileDurableState::open(path)?;
        Self::open_store(Box::new(store), pairwise_deriver, trust)
    }

    #[doc(hidden)]
    pub fn open_store_for_test(
        store: Box<dyn DurableState>,
        pairwise_deriver: Box<dyn PairwiseSubjectDeriver>,
        trust: RuntimeTrust,
    ) -> Result<Self, RuntimeError> {
        Self::open_store(store, pairwise_deriver, trust)
    }

    fn open_store(
        mut store: Box<dyn DurableState>,
        pairwise_deriver: Box<dyn PairwiseSubjectDeriver>,
        trust: RuntimeTrust,
    ) -> Result<Self, RuntimeError> {
        let state = match store.read()? {
            Some(image) => store::decode_state(&image)?,
            None => {
                let state = State::new();
                store.compare_and_swap(None, store::encode_state(&state)?)?;
                state
            }
        };
        audit::verify(&state.audit)?;
        super::revocation_preparation_guard::validate_state(&state)?;
        let rollback_anchor = state.revision;
        Ok(Self {
            state,
            store,
            rollback_anchor,
            pairwise_deriver,
            assertion_signer: None,
            status_signer: None,
            trust,
        })
    }

    pub fn with_identity_signers(
        mut self,
        assertion_signer: Box<dyn AssertionSigner>,
        status_signer: Box<dyn AssertionSigner>,
    ) -> Self {
        self.assertion_signer = Some(assertion_signer);
        self.status_signer = Some(status_signer);
        self
    }

    pub(crate) fn before(&self) -> State {
        self.state.clone()
    }

    pub(crate) fn finish(
        &mut self,
        before: State,
        event: &str,
        command: &str,
    ) -> Result<(), RuntimeError> {
        if let Err(error) =
            super::revocation_preparation_transition::preserve(&before, &self.state, event, command)
        {
            self.state = before;
            return Err(error);
        }
        self.state.revision = before
            .revision
            .checked_add(1)
            .ok_or(RuntimeError::PersistenceFailure)?;
        audit::append(&mut self.state.audit, event, command);
        if let Err(error) = super::revocation_preparation_capacity::require(&self.state) {
            self.state = before;
            return Err(error);
        }
        let image = store::encode_state(&self.state)?;
        if let Err(error) = self.store.compare_and_swap(Some(before.revision), image) {
            self.state = before;
            return Err(error);
        }
        self.rollback_anchor = self.rollback_anchor.max(self.state.revision);
        Ok(())
    }

    pub(crate) fn unused(&self, values: &[&str]) -> Result<(), RuntimeError> {
        if values.iter().any(|value| {
            self.state.replay.contains(*value)
                || self.state.prepared_revocations.contains_key(*value)
        }) {
            return Err(RuntimeError::ReplayDetected);
        }
        Ok(())
    }

    pub(crate) fn consume(&mut self, values: &[&str]) {
        self.state
            .replay
            .extend(values.iter().map(|value| (*value).to_owned()));
    }
}
