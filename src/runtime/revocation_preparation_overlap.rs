use crate::{RevocationTarget, state};

pub(super) fn overlaps(
    state: &state::State,
    left: &RevocationTarget,
    right: &RevocationTarget,
) -> bool {
    match (left, right) {
        (RevocationTarget::Subject { account_id: a }, target)
        | (target, RevocationTarget::Subject { account_id: a }) => account(target) == a,
        (
            RevocationTarget::ServiceAccount {
                account_id: a,
                service_id: s,
            },
            target,
        )
        | (
            target,
            RevocationTarget::ServiceAccount {
                account_id: a,
                service_id: s,
            },
        ) => account(target) == a && service(target) == Some(s),
        (
            RevocationTarget::Device {
                account_id: a,
                service_id: s,
                device_id: d,
            },
            target,
        )
        | (
            target,
            RevocationTarget::Device {
                account_id: a,
                service_id: s,
                device_id: d,
            },
        ) => {
            account(target) == a
                && service(target) == Some(s)
                && (device(target) == Some(d)
                    || session_device(state, target).is_some_and(|value| value == d))
        }
        (
            RevocationTarget::Session {
                account_id: a,
                service_id: s,
                session_id: x,
            },
            RevocationTarget::Session {
                account_id: b,
                service_id: t,
                session_id: y,
            },
        ) => a == b && s == t && x == y,
    }
}

fn session_device<'a>(state: &'a state::State, target: &RevocationTarget) -> Option<&'a str> {
    let RevocationTarget::Session {
        account_id,
        service_id,
        session_id,
    } = target
    else {
        return None;
    };
    state
        .sessions
        .values()
        .find(|value| {
            value.account_id == *account_id
                && value.service_id == *service_id
                && value.session_id == *session_id
        })
        .map(|value| value.device_id.as_str())
}

fn account(value: &RevocationTarget) -> &str {
    match value {
        RevocationTarget::Subject { account_id }
        | RevocationTarget::ServiceAccount { account_id, .. }
        | RevocationTarget::Device { account_id, .. }
        | RevocationTarget::Session { account_id, .. } => account_id,
    }
}

fn service(value: &RevocationTarget) -> Option<&String> {
    match value {
        RevocationTarget::Subject { .. } => None,
        RevocationTarget::ServiceAccount { service_id, .. }
        | RevocationTarget::Device { service_id, .. }
        | RevocationTarget::Session { service_id, .. } => Some(service_id),
    }
}

fn device(value: &RevocationTarget) -> Option<&String> {
    match value {
        RevocationTarget::Device { device_id, .. } => Some(device_id),
        _ => None,
    }
}
