# ihat-identity-runtime

Maintain account, service-account, device, session and revocation relationships in an owner-local authority.

## What you can do

- Derive service-specific opaque subject references.
- Bind sessions to the registered device proof key.

## Current scope

Use the current 0.1.0 contract. Synced passkeys authenticate a user but are not treated as device identity.

Package distribution is not activated by this documentation. Use the checked-in source and the declared dependency versions; published availability must be verified separately.

## Getting started

Install Rust 1.97 or newer and make the declared dependencies available. Use the configured private registry when a dependency is not distributed publicly. Run from this repository:

```sh
cargo test --locked
```

## Documentation and source

[Interface reference](docs/interface-reference.md)

[Usage guide](docs/getting-started.md)

[Schemas](schemas) · [Implementation and public interfaces](src) · [Verification cases](tests) · [Contributing](CONTRIBUTING.md) · [Security reporting](SECURITY.md) · [License](LICENSE) · [Attribution notices](NOTICE)
