#[derive(Clone)]
struct PreparationImageControl {
    image: Arc<Mutex<PersistedImage>>,
}

struct PreparationImageStore {
    control: PreparationImageControl,
}

impl PreparationImageControl {
    fn new(image: PersistedImage) -> Self {
        Self {
            image: Arc::new(Mutex::new(image)),
        }
    }

    fn store(&self) -> PreparationImageStore {
        PreparationImageStore {
            control: self.clone(),
        }
    }

    fn image(&self) -> PersistedImage {
        self.image.lock().expect("image lock").clone()
    }
}

impl DurableState for PreparationImageStore {
    fn read(&self) -> Result<Option<PersistedImage>, RuntimeError> {
        Ok(Some(self.control.image()))
    }

    fn compare_and_swap(
        &mut self,
        expected: Option<u64>,
        replacement: PersistedImage,
    ) -> Result<(), RuntimeError> {
        let current = preparation_image_revision(&self.control.image())?;
        if expected != Some(current)
            || preparation_image_revision(&replacement)? != current.saturating_add(1)
        {
            return Err(RuntimeError::DatabaseRollbackDetected);
        }
        *self.control.image.lock().expect("image lock") = replacement;
        Ok(())
    }
}

fn preparation_image_revision(image: &PersistedImage) -> Result<u64, RuntimeError> {
    let bytes: [u8; 8] = image
        .0
        .get(8..16)
        .ok_or(RuntimeError::PersistenceFailure)?
        .try_into()
        .map_err(|_| RuntimeError::PersistenceFailure)?;
    Ok(u64::from_be_bytes(bytes))
}

fn preparation_runtime_from_control(
    control: &PreparationImageControl,
    trust: RuntimeTrust,
) -> Result<IdentityRuntime, RuntimeError> {
    IdentityRuntime::open_store_for_test(
        Box::new(control.store()),
        Box::new(TestPairwiseDeriver),
        trust,
    )
}

fn map_preparation_image(
    image: &PersistedImage,
    change: impl FnOnce(&mut Value),
) -> PersistedImage {
    let mut payload: Value = serde_json::from_slice(&image.0[16..]).expect("state payload");
    change(&mut payload);
    let mut bytes = image.0[..16].to_vec();
    bytes.extend(serde_json::to_vec(&payload).expect("state payload"));
    PersistedImage(bytes)
}

fn insert_synthetic_receipts(image: &PersistedImage, count: usize) -> PersistedImage {
    map_preparation_image(image, |payload| {
        let receipts = payload["revocation_receipts"]
            .as_object_mut()
            .expect("receipt map");
        let mut replay_commands = Vec::with_capacity(count);
        for index in 0..count {
            let command = format!("capacity-receipt-{index:04}");
            let target = json!({"Session": {
                "account_id": "account-a",
                "service_id": "service-a",
                "session_id": "session-b"
            }});
            let previous = index as u64 + 1;
            receipts.insert(
                command.clone(),
                json!({
                    "request": {
                        "command_id": command,
                        "target": target.clone(),
                        "expected_epoch": previous,
                        "authority_id": "capacity-authority"
                    },
                    "receipt": {
                        "target": target,
                        "previous_epoch": previous,
                        "current_epoch": previous + 1,
                        "audit_sequence": previous,
                        "revoked_session_count": 0
                    }
                }),
            );
            replay_commands.push(json!(format!("capacity-receipt-{index:04}")));
        }
        payload["replay"]
            .as_array_mut()
            .expect("replay set")
            .extend(replay_commands);
    })
}
