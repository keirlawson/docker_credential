# docker_credential

[![Latest version](https://img.shields.io/crates/v/docker_credential.svg)](https://crates.io/crates/docker_credential)
[![Documentation](https://docs.rs/docker_credential/badge.svg)](https://docs.rs/docker_credential)

A Rust library for reading a user's Docker or Podman credentials from config.

Parses a docker `config.json` either at the location specified by the
`$DOCKER_CONFIG` environment variable or in `$HOME/.docker`. If credential
helpers or a credential store is configured these will be contacted to retrieve
the requested credential.

## Usage

Add the following to your `cargo.toml`:

```toml
[dependencies]
docker_credential = "1.0.1"
```

Then invoke from within your along the lines of:

```rust
use docker_credential;
use docker_credential::DockerCredential;

let credential = docker_credential::get_credential("https://index.docker.io/v1/").expect("Unable to retrieve credential");

match credential {
  DockerCredential::IdentityToken(token) => println!("Identity token: {}", token),
  DockerCredential::UsernamePassword(user_name, password) => println!("Username: {}, Password: {}", user_name, password),
};

```
