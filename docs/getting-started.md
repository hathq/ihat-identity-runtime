# Using ihat-identity-runtime

Maintain account, service-account, device, session and revocation relationships in an owner-local authority.

## Before you start

Use the current 0.1.0 contract. Synced passkeys authenticate a user but are not treated as device identity.

## First steps

Run from the repository root:

```sh
cargo test --locked
```

## How to assess the result

- Derive service-specific opaque subject references.
- Bind sessions to the registered device proof key.

A passing source-level check establishes only what that check observes. Keep missing configuration, unavailable services and unverified deployment paths visible.

## Continue reading

[Repository overview](../README.md)
