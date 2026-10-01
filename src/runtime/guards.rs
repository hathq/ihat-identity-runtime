use crate::{
    AccountRecord, RevocationScope, RuntimeError, ServiceAccountRecord,
    state::{State, service_key},
};

pub(crate) fn account(state: &State, account_id: &str) -> Result<AccountRecord, RuntimeError> {
    state
        .accounts
        .get(account_id)
        .cloned()
        .ok_or(RuntimeError::NotFound("account"))
}

pub(crate) fn service(
    state: &State,
    account_id: &str,
    service_id: &str,
) -> Result<ServiceAccountRecord, RuntimeError> {
    state
        .services
        .get(&service_key(account_id, service_id))
        .cloned()
        .ok_or(RuntimeError::NotFound("service_account"))
}

pub(crate) fn bound_service(
    state: &State,
    account_id: &str,
    service_id: &str,
    pairwise_subject: &str,
) -> Result<ServiceAccountRecord, RuntimeError> {
    let record = service(state, account_id, service_id)?;
    if record.pairwise_subject == pairwise_subject {
        return Ok(record);
    }
    if state
        .services
        .values()
        .any(|value| value.pairwise_subject == pairwise_subject && value.account_id != account_id)
    {
        return Err(RuntimeError::WrongAccount);
    }
    Err(RuntimeError::WrongService)
}

pub(crate) fn epoch(
    scope: RevocationScope,
    presented: u64,
    current: u64,
) -> Result<(), RuntimeError> {
    if presented != current {
        return Err(RuntimeError::StaleEpoch {
            scope,
            presented,
            current,
        });
    }
    Ok(())
}
