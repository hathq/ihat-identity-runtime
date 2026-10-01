use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{
    AccountRecord, AuditEvent, DeviceRecord, IdentityGraph, InitialBootstrapReceipt,
    RevocationReceipt, RevocationSnapshot, RevokeRequest, ServiceAccountRecord, SessionRecord,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct InitialBootstrapCommit {
    pub request_digest: String,
    pub receipt: InitialBootstrapReceipt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CommittedRevocation {
    pub request: RevokeRequest,
    pub receipt: RevocationReceipt,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preparation_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PreparedRevocation {
    pub preparation_id: String,
    pub begin_command_digest_sha256: String,
    pub request: RevokeRequest,
    pub future_bytes: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CancelledPreparedRevocation {
    pub preparation_id: String,
    pub request: RevokeRequest,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct State {
    pub revision: u64,
    pub initial_bootstrap: Option<InitialBootstrapCommit>,
    pub accounts: BTreeMap<String, AccountRecord>,
    pub services: BTreeMap<String, ServiceAccountRecord>,
    pub devices: BTreeMap<String, DeviceRecord>,
    pub sessions: BTreeMap<String, SessionRecord>,
    pub current_identity_sessions: BTreeMap<String, String>,
    pub revoked_subjects: BTreeSet<String>,
    pub retired_keys: BTreeSet<String>,
    pub replay: BTreeSet<String>,
    #[serde(default)]
    pub revocation_receipts: BTreeMap<String, CommittedRevocation>,
    #[serde(default)]
    pub prepared_revocations: BTreeMap<String, PreparedRevocation>,
    #[serde(default)]
    pub cancelled_revocation_preparations: BTreeMap<String, CancelledPreparedRevocation>,
    pub audit: Vec<AuditEvent>,
}

impl State {
    pub fn new() -> Self {
        Self {
            revision: 0,
            initial_bootstrap: None,
            accounts: BTreeMap::new(),
            services: BTreeMap::new(),
            devices: BTreeMap::new(),
            sessions: BTreeMap::new(),
            current_identity_sessions: BTreeMap::new(),
            revoked_subjects: BTreeSet::new(),
            retired_keys: BTreeSet::new(),
            replay: BTreeSet::new(),
            revocation_receipts: BTreeMap::new(),
            prepared_revocations: BTreeMap::new(),
            cancelled_revocation_preparations: BTreeMap::new(),
            audit: Vec::new(),
        }
    }

    pub fn graph(&self) -> IdentityGraph {
        IdentityGraph {
            accounts: self.accounts.values().cloned().collect(),
            service_accounts: self.services.values().cloned().collect(),
            devices: self.devices.values().cloned().collect(),
            sessions: self.sessions.values().cloned().collect(),
        }
    }

    pub fn revocations(&self) -> RevocationSnapshot {
        let mut out = RevocationSnapshot::default();
        for value in self.accounts.values() {
            out.subject_epochs
                .insert(value.account_id.clone(), value.subject_epoch);
        }
        for value in self.services.values() {
            out.service_epochs.insert(
                (value.account_id.clone(), value.service_id.clone()),
                value.service_epoch,
            );
        }
        for value in self.devices.values() {
            out.device_epochs.insert(
                (
                    value.account_id.clone(),
                    value.service_id.clone(),
                    value.device_id.clone(),
                ),
                value.device_epoch,
            );
        }
        for value in self.sessions.values() {
            out.session_epochs.insert(
                (
                    value.account_id.clone(),
                    value.service_id.clone(),
                    value.session_id.clone(),
                ),
                value.session_epoch,
            );
        }
        out
    }
}

pub(crate) fn service_key(account: &str, service: &str) -> String {
    format!("{account}\u{1f}{service}")
}
pub(crate) fn device_key(account: &str, service: &str, device: &str) -> String {
    format!("{account}\u{1f}{service}\u{1f}{device}")
}
pub(crate) fn session_key(account: &str, service: &str, session: &str) -> String {
    format!("{account}\u{1f}{service}\u{1f}{session}")
}
