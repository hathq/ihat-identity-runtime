#[test]
fn file_store_lock_makes_concurrent_compare_and_swap_single_winner() {
    let directory = TempDirectory::new("cas");
    let source = directory.path.join("source.state");
    let target = directory.path.join("target.state");
    let mut source_runtime = file_runtime(&source);
    source_runtime
        .create_account(account_request("account-a", "create-account-a"))
        .unwrap();
    let revision_one = source_runtime.snapshot_persistent_store_for_test().unwrap();
    drop(file_runtime(&target));
    let barrier = Arc::new(Barrier::new(3));
    let mut workers = Vec::new();
    for _ in 0..2 {
        let barrier = barrier.clone();
        let path = target.clone();
        let image = revision_one.clone();
        workers.push(thread::spawn(move || {
            let mut store = FileDurableState::open(path).unwrap();
            barrier.wait();
            store.compare_and_swap(Some(0), image)
        }));
    }
    barrier.wait();
    let results: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| **result == Err(RuntimeError::DatabaseRollbackDetected))
            .count(),
        1
    );
}

#[test]
fn file_store_rejects_symlink_and_permissive_parent() {
    let directory = TempDirectory::new("path-security");
    let real = directory.path.join("real.state");
    fs::write(&real, b"not-a-state").unwrap();
    fs::set_permissions(&real, fs::Permissions::from_mode(0o600)).unwrap();
    let link = directory.path.join("linked.state");
    symlink(&real, &link).unwrap();
    assert!(matches!(
        FileDurableState::open(&link),
        Err(RuntimeError::InvalidRequest("durable_symlink"))
    ));

    fs::set_permissions(&directory.path, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        FileDurableState::open(directory.path.join("permissive.state")),
        Err(RuntimeError::InvalidRequest("durable_parent_security"))
    ));
}

fn file_runtime(path: &Path) -> IdentityRuntime {
    IdentityRuntime::open_file(path, Box::new(TestPairwiseDeriver), test_trust()).unwrap()
}

fn assert_owner_only(directory: &Path, state: &Path) {
    assert_eq!(
        fs::metadata(directory).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(state).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let name = state.file_name().unwrap().to_str().unwrap();
    for path in [
        directory.join(format!(".{name}.anchor")),
        directory.join(format!(".{name}.lock")),
    ] {
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

struct TempDirectory {
    path: PathBuf,
}
impl TempDirectory {
    fn new(label: &str) -> Self {
        let mut random = [0_u8; 8];
        getrandom::fill(&mut random).unwrap();
        let path = std::env::temp_dir().join(format!(
            "ihat-identity-{label}-{}-{}",
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
