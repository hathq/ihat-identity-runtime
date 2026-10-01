use crate::{InitialBootstrapReceipt, InitialBootstrapRequest, RuntimeError};

use super::{IdentityRuntime, bootstrap_validation};

impl IdentityRuntime {
    pub fn reconcile_initial_bootstrap(
        &self,
        request: InitialBootstrapRequest,
    ) -> Result<InitialBootstrapReceipt, RuntimeError> {
        bootstrap_validation::validate(&request)?;
        let digest = bootstrap_validation::digest(&request)?;
        let committed = self
            .state
            .initial_bootstrap
            .as_ref()
            .ok_or(RuntimeError::NotFound("initial_bootstrap_receipt"))?;
        if committed.request_digest != digest {
            return Err(RuntimeError::InvalidRequest("initial_bootstrap_reconcile"));
        }
        Ok(committed.receipt.clone())
    }
}
