#[derive(Default)]
struct TestMemoryDurableState {
    current: Option<PersistedImage>,
    revision: Option<u64>,
    history: Vec<(PersistedImage, u64)>,
}

impl DurableState for TestMemoryDurableState {
    fn read(&self) -> Result<Option<PersistedImage>, RuntimeError> {
        Ok(self.current.clone())
    }

    fn compare_and_swap(
        &mut self,
        expected: Option<u64>,
        replacement: PersistedImage,
    ) -> Result<(), RuntimeError> {
        if self.revision != expected {
            return Err(RuntimeError::DatabaseRollbackDetected);
        }
        let revision = expected.map_or(0, |value| value + 1);
        self.history.push((replacement.clone(), revision));
        self.current = Some(replacement);
        self.revision = Some(revision);
        Ok(())
    }

    fn replace_for_test(&mut self, replacement: PersistedImage) -> Result<(), RuntimeError> {
        let revision = self
            .history
            .iter()
            .find(|(image, _)| image == &replacement)
            .map(|(_, revision)| *revision)
            .ok_or(RuntimeError::PersistenceFailure)?;
        self.current = Some(replacement);
        self.revision = Some(revision);
        Ok(())
    }
}

pub struct TestPairwiseDeriver;

impl PairwiseSubjectDeriver for TestPairwiseDeriver {
    fn derive(&self, account_id: &str, service_id: &str) -> Result<String, RuntimeError> {
        let mut digest = Sha256::new();
        digest.update(b"ihat-test-pairwise-v1\0");
        digest.update(account_id.as_bytes());
        digest.update(b"\0");
        digest.update(service_id.as_bytes());
        Ok(format!("ps-{:x}", digest.finalize()))
    }
}

pub fn runtime_with_trust(trust: RuntimeTrust) -> IdentityRuntime {
    runtime_with_pairwise_deriver_and_trust(Box::new(TestPairwiseDeriver), trust)
}

pub fn runtime_with_pairwise_deriver(
    pairwise_deriver: Box<dyn PairwiseSubjectDeriver>,
) -> IdentityRuntime {
    runtime_with_pairwise_deriver_and_trust(pairwise_deriver, test_trust())
}

fn runtime_with_pairwise_deriver_and_trust(
    pairwise_deriver: Box<dyn PairwiseSubjectDeriver>,
    trust: RuntimeTrust,
) -> IdentityRuntime {
    IdentityRuntime::open_store_for_test(
        Box::<TestMemoryDurableState>::default(),
        pairwise_deriver,
        trust,
    )
    .unwrap()
}

pub fn runtime() -> IdentityRuntime {
    runtime_with_trust(test_trust())
}
