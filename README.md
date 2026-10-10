# ihat-identity-runtime

Maintain account, service-account, device, session and revocation relationships in an owner-local authority.

## What you can do

- Derive service-specific opaque subject references.
- Bind sessions to the registered device proof key.

## Current scope

Use the current 0.1.0 contract. Synced passkeys authenticate a user but are not treated as device identity.

This is an independently packaged Rust library. Cargo dependencies are resolved from crates.io; runtime authority, network and storage configuration remain caller-owned.

## Getting started

Install Rust 1.97 or newer and make the declared dependencies available. No private dependency registry or sibling source checkout is required. Run from this repository:

```sh
cargo test --locked
```

## Documentation and source

[Interface reference](docs/interface-reference.md)

[Usage guide](docs/getting-started.md)

[Schemas](schemas) · [Implementation and public interfaces](src) · [Verification cases](tests) · [Contributing](CONTRIBUTING.md) · [Security reporting](SECURITY.md) · [License](LICENSE) · [Attribution notices](NOTICE)
