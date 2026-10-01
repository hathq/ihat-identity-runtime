use crate::{RevocationTarget, state};

pub(super) fn unchanged(
    before: &state::State,
    after: &state::State,
    target: &RevocationTarget,
) -> bool {
    match target {
        RevocationTarget::Subject { account_id } => {
            before.accounts.get(account_id) == after.accounts.get(account_id)
                && before.revoked_subjects.contains(account_id)
                    == after.revoked_subjects.contains(account_id)
                && services(before, account_id, None) == services(after, account_id, None)
                && devices(before, account_id, None, None) == devices(after, account_id, None, None)
                && sessions(before, account_id, None, None, None)
                    == sessions(after, account_id, None, None, None)
        }
        RevocationTarget::ServiceAccount {
            account_id,
            service_id,
        } => {
            subject(before, after, account_id)
                && services(before, account_id, Some(service_id))
                    == services(after, account_id, Some(service_id))
                && devices(before, account_id, Some(service_id), None)
                    == devices(after, account_id, Some(service_id), None)
                && sessions(before, account_id, Some(service_id), None, None)
                    == sessions(after, account_id, Some(service_id), None, None)
        }
        RevocationTarget::Device {
            account_id,
            service_id,
            device_id,
        } => {
            subject(before, after, account_id)
                && services(before, account_id, Some(service_id))
                    == services(after, account_id, Some(service_id))
                && devices(before, account_id, Some(service_id), Some(device_id))
                    == devices(after, account_id, Some(service_id), Some(device_id))
                && sessions(before, account_id, Some(service_id), Some(device_id), None)
                    == sessions(after, account_id, Some(service_id), Some(device_id), None)
        }
        RevocationTarget::Session {
            account_id,
            service_id,
            session_id,
        } => {
            let device = session_device(before, account_id, service_id, session_id);
            subject(before, after, account_id)
                && services(before, account_id, Some(service_id))
                    == services(after, account_id, Some(service_id))
                && device.is_some_and(|device_id| {
                    devices(before, account_id, Some(service_id), Some(device_id))
                        == devices(after, account_id, Some(service_id), Some(device_id))
                })
                && sessions(before, account_id, Some(service_id), None, Some(session_id))
                    == sessions(after, account_id, Some(service_id), None, Some(session_id))
        }
    }
}

fn subject(before: &state::State, after: &state::State, account: &str) -> bool {
    before.accounts.get(account) == after.accounts.get(account)
        && before.revoked_subjects.contains(account) == after.revoked_subjects.contains(account)
}

fn session_device<'a>(
    state: &'a state::State,
    account: &str,
    service: &str,
    session: &str,
) -> Option<&'a str> {
    state
        .sessions
        .values()
        .find(|value| {
            value.account_id == account
                && value.service_id == service
                && value.session_id == session
        })
        .map(|value| value.device_id.as_str())
}

fn services(
    state: &state::State,
    account: &str,
    service: Option<&str>,
) -> Vec<(String, crate::ServiceAccountRecord)> {
    state
        .services
        .iter()
        .filter(|(_, value)| {
            value.account_id == account && service.is_none_or(|id| value.service_id == id)
        })
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

fn devices(
    state: &state::State,
    account: &str,
    service: Option<&str>,
    device: Option<&str>,
) -> Vec<(String, crate::DeviceRecord)> {
    state
        .devices
        .iter()
        .filter(|(_, value)| {
            value.account_id == account
                && service.is_none_or(|id| value.service_id == id)
                && device.is_none_or(|id| value.device_id == id)
        })
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

fn sessions(
    state: &state::State,
    account: &str,
    service: Option<&str>,
    device: Option<&str>,
    session: Option<&str>,
) -> Vec<(String, crate::SessionRecord)> {
    state
        .sessions
        .iter()
        .filter(|(_, value)| {
            value.account_id == account
                && service.is_none_or(|id| value.service_id == id)
                && device.is_none_or(|id| value.device_id == id)
                && session.is_none_or(|id| value.session_id == id)
        })
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}
