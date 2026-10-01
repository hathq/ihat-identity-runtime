fn seeded_image() -> (PersistedImage, DeviceRecord) {
    let mut runtime = runtime();
    let service = create_account_and_service(&mut runtime, "account-a", "service-a");
    let device = enroll(&mut runtime, "account-a", &service, "device-a", "key-a");
    issue(&mut runtime, "account-a", &service, &device, "session-a");
    (
        runtime.snapshot_persistent_store_for_test().unwrap(),
        device,
    )
}

fn request(device: &DeviceRecord) -> RevokeDeviceRequest {
    RevokeDeviceRequest {
        command_id: "revoke-device-a-atomically".into(),
        account_id: device.account_id.clone(),
        service_id: device.service_id.clone(),
        device_id: device.device_id.clone(),
        expected_device_epoch: device.device_epoch,
        authority_id: "identity-authority".into(),
    }
}

fn with_session_epoch(image: PersistedImage, epoch: u64) -> PersistedImage {
    let mut value: serde_json::Value = serde_json::from_slice(&image.0[16..]).expect("state JSON");
    let sessions = value["sessions"].as_object_mut().expect("sessions");
    sessions.values_mut().next().expect("session")["session_epoch"] = serde_json::json!(epoch);
    let mut bytes = image.0[..16].to_vec();
    bytes.extend(serde_json::to_vec(&value).expect("state JSON"));
    PersistedImage(bytes)
}

#[derive(Clone)]
struct StoreControl {
    state: Arc<Mutex<PersistedImage>>,
    fail: Arc<AtomicBool>,
}
struct SwitchStore {
    control: StoreControl,
}

impl StoreControl {
    fn new(image: PersistedImage, fail: bool) -> Self {
        Self {
            state: Arc::new(Mutex::new(image)),
            fail: Arc::new(AtomicBool::new(fail)),
        }
    }
    fn store(&self) -> SwitchStore {
        SwitchStore {
            control: self.clone(),
        }
    }
    fn image(&self) -> PersistedImage {
        self.state.lock().unwrap().clone()
    }
}

impl DurableState for SwitchStore {
    fn read(&self) -> Result<Option<PersistedImage>, RuntimeError> {
        Ok(Some(self.control.image()))
    }
    fn compare_and_swap(
        &mut self,
        _expected: Option<u64>,
        replacement: PersistedImage,
    ) -> Result<(), RuntimeError> {
        if self.control.fail.swap(false, Ordering::SeqCst) {
            return Err(RuntimeError::PersistenceFailure);
        }
        *self.control.state.lock().unwrap() = replacement;
        Ok(())
    }
}
