#[derive(Clone)]
struct StoreControl {
    image: Arc<Mutex<PersistedImage>>,
    fail: Arc<Mutex<bool>>,
}

struct SwitchStore(StoreControl);

impl StoreControl {
    fn new(image: PersistedImage) -> Self {
        Self {
            image: Arc::new(Mutex::new(image)),
            fail: Arc::new(Mutex::new(true)),
        }
    }
    fn store(&self) -> SwitchStore {
        SwitchStore(self.clone())
    }
    fn allow_commit(&self) {
        *self.fail.lock().unwrap() = false;
    }
}

impl DurableState for SwitchStore {
    fn read(&self) -> Result<Option<PersistedImage>, RuntimeError> {
        Ok(Some(self.0.image.lock().unwrap().clone()))
    }
    fn compare_and_swap(
        &mut self,
        _expected: Option<u64>,
        replacement: PersistedImage,
    ) -> Result<(), RuntimeError> {
        if *self.0.fail.lock().unwrap() {
            return Err(RuntimeError::PersistenceFailure);
        }
        *self.0.image.lock().unwrap() = replacement;
        Ok(())
    }
}

struct FailingPairwiseDeriver;

impl PairwiseSubjectDeriver for FailingPairwiseDeriver {
    fn derive(&self, _: &str, _: &str) -> Result<String, RuntimeError> {
        Err(RuntimeError::PersistenceFailure)
    }
}

struct TempDirectory {
    path: PathBuf,
}

impl TempDirectory {
    fn new() -> Self {
        let mut random = [0_u8; 8];
        getrandom::fill(&mut random).unwrap();
        let path = std::env::temp_dir().join(format!(
            "ihat-bootstrap-{}-{}",
            std::process::id(),
            u64::from_be_bytes(random)
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self { path }
    }
}

impl Drop for TempDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
