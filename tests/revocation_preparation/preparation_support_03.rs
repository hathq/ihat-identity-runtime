#[derive(Clone)]
struct ToggleRevocationAuthority(Arc<AtomicBool>);

impl RevocationAuthorityVerifier for ToggleRevocationAuthority {
    fn verify(&self, _request: &RevokeRequest) -> Option<VerifiedEvidenceWindow> {
        self.0.load(Ordering::SeqCst).then(test_window)
    }
}

#[derive(Clone)]
struct TogglePreparationAuthority(Arc<AtomicBool>);

impl RevocationPreparationVerifier for TogglePreparationAuthority {
    fn verify(
        &self,
        _action: RevocationPreparationAction,
        _handle: &RevocationPreparationHandle,
        _request: &RevokeRequest,
    ) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

fn controlled_preparation_trust(
    revocation: Arc<AtomicBool>,
    preparation: Arc<AtomicBool>,
) -> RuntimeTrust {
    RuntimeTrust::new(
        RuntimeVerifiers {
            authentication: Box::new(TestEvidenceVerifier),
            attestation: Box::new(TestEvidenceVerifier),
            possession: Box::new(TestEvidenceVerifier),
            session: Box::new(TestEvidenceVerifier),
            revocation: Box::new(ToggleRevocationAuthority(revocation)),
            revocation_preparation: Box::new(TogglePreparationAuthority(preparation)),
            recovery: Box::new(TestEvidenceVerifier),
            installer_bootstrap: Box::new(TestEvidenceVerifier),
        },
        Box::new(TestClock(TEST_NOW)),
    )
}

struct PreparationTempDirectory {
    path: PathBuf,
}

impl PreparationTempDirectory {
    fn new(label: &str) -> Self {
        let mut random = [0_u8; 8];
        getrandom::fill(&mut random).expect("random directory suffix");
        let path = std::env::temp_dir().join(format!(
            "ihat-preparation-{label}-{}-{}",
            std::process::id(),
            u64::from_be_bytes(random)
        ));
        fs::create_dir(&path).expect("temporary directory");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("directory mode");
        Self { path }
    }
}

impl Drop for PreparationTempDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn preparation_file_runtime(path: &Path) -> IdentityRuntime {
    IdentityRuntime::open_file(path, Box::new(TestPairwiseDeriver), test_trust())
        .expect("file runtime")
}
