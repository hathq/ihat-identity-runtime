use crate::RuntimeError;

pub trait PairwiseSubjectDeriver: Send + Sync {
    fn derive(&self, account_id: &str, service_id: &str) -> Result<String, RuntimeError>;
}
