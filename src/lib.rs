mod config;
mod helper;

use std::env;
use std::error::Error;
use std::fmt;
use std::path::{Path, PathBuf};
use std::str;

type Result<T> = std::result::Result<T, CredentialRetrievalError>;

/// An error that occurred whilst attempting to retrieve a credential.
#[derive(Debug, PartialEq)]
pub enum CredentialRetrievalError {
    HelperCommunicationError,
    MalformedHelperResponse,
    HelperFailure,
    CredentialDecodingError,
    NoCredentialConfigured,
    ConfigNotFound,
    ConfigReadError,
}

impl fmt::Display for CredentialRetrievalError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let message = match self {
            CredentialRetrievalError::HelperCommunicationError => {
                "Unable to communicate with credential helper"
            }
            CredentialRetrievalError::MalformedHelperResponse => {
                "Credential helper response malformed"
            }
            CredentialRetrievalError::HelperFailure => {
                "Credential helper returned non-zero response code"
            }
            CredentialRetrievalError::CredentialDecodingError => "Unable to decode credential",
            CredentialRetrievalError::NoCredentialConfigured => "User has no credential configured",
            CredentialRetrievalError::ConfigNotFound => "No config file found",
            CredentialRetrievalError::ConfigReadError => "Unable to read config",
        };
        write!(f, "{}", message)
    }
}

impl Error for CredentialRetrievalError {}

/// A docker credential, either a single identity token or a username/password pair.
#[derive(Debug, PartialEq)]
pub enum DockerCredential {
    IdentityToken(String),
    UsernamePassword(String, String),
}

fn config_dir() -> Option<PathBuf> {
    let home_config = || env::var_os("HOME").map(|home| Path::new(&home).join(".docker"));
    env::var_os("DOCKER_CONFIG")
        .map(|dir| Path::new(&dir).to_path_buf())
        .or_else(home_config)
}

fn decode_auth(encoded_auth: &str) -> Result<DockerCredential> {
    let decoded = base64::decode(encoded_auth)
        .map_err(|_| CredentialRetrievalError::CredentialDecodingError)?;
    let decoded =
        str::from_utf8(&decoded).map_err(|_| CredentialRetrievalError::CredentialDecodingError)?;
    let parts: Vec<&str> = decoded.splitn(2, ':').collect();
    let username = String::from(*parts.get(0).unwrap());
    let password = String::from(
        *parts
            .get(1)
            .ok_or(CredentialRetrievalError::CredentialDecodingError)?,
    );
    Ok(DockerCredential::UsernamePassword(username, password))
}

fn extract_credential<T>(
    conf: config::DockerConfig,
    server: &str,
    from_helper: T,
) -> Result<DockerCredential>
where
    T: Fn(&str, &str) -> Result<DockerCredential>,
{
    if let Some(helper_name) = conf.get_helper(server) {
        return from_helper(server, helper_name);
    }

    if let Some(auth) = conf.get_auth(server) {
        return decode_auth(auth);
    }

    if let Some(store_name) = conf.creds_store {
        return from_helper(server, &store_name);
    }

    Err(CredentialRetrievalError::NoCredentialConfigured)
}

/// Retrieve a user's docker credential via config.json.
///
/// If necessary, credential helpers/store will be invoked.
///
/// Example:
/// ```no_run
/// use docker_credential::DockerCredential;
///
/// let credential = docker_credential::get_credential("https://index.docker.io/v1/").expect("Unable to retrieve credential");
///
/// match credential {
///   DockerCredential::IdentityToken(token) => println!("Identity token: {}", token),
///   DockerCredential::UsernamePassword(user_name, password) => println!("Username: {}, Password: {}", user_name, password),
/// };
/// ```
pub fn get_credential(server: &str) -> Result<DockerCredential> {
    let dir = config_dir().ok_or(CredentialRetrievalError::ConfigNotFound)?;
    let conf = config::read_config(&dir)?;
    extract_credential(conf, server, helper::credential_from_helper)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn errors_when_no_relevant_config() {
        let empty_config = config::DockerConfig {
            auths: None,
            creds_store: None,
            cred_helpers: None,
        };
        let dummy_helper =
            |_: &str, _: &str| Err(CredentialRetrievalError::HelperCommunicationError);
        let result = extract_credential(empty_config, "some server", dummy_helper);

        assert_eq!(
            result,
            Err(CredentialRetrievalError::NoCredentialConfigured)
        );
    }

    #[test]
    fn decodes_auth_when_no_helpers() {
        let encoded_auth = base64::encode("some_user:some_password");
        let mut auths = HashMap::new();
        auths.insert(
            String::from("some server"),
            config::AuthConfig {
                auth: Some(String::from(encoded_auth)),
            },
        );
        let auth_config = config::DockerConfig {
            auths: Some(auths),
            creds_store: None,
            cred_helpers: None,
        };
        let dummy_helper =
            |_: &str, _: &str| Err(CredentialRetrievalError::HelperCommunicationError);
        let result = extract_credential(auth_config, "some server", dummy_helper);

        assert_eq!(
            result,
            Ok(DockerCredential::UsernamePassword(
                String::from("some_user"),
                String::from("some_password")
            ))
        );
    }

    #[test]
    fn gets_credential_from_helper() {
        let mut helpers = HashMap::new();
        helpers.insert(String::from("some server"), String::from("some_helper"));
        let helper_config = config::DockerConfig {
            auths: None,
            creds_store: None,
            cred_helpers: Some(helpers),
        };
        let dummy_helper = |address: &str, helper: &str| {
            if address == String::from("some server") && helper == String::from("some_helper") {
                Ok(DockerCredential::IdentityToken(String::from(
                    "expected_token",
                )))
            } else {
                Err(CredentialRetrievalError::HelperCommunicationError)
            }
        };
        let result = extract_credential(helper_config, "some server", dummy_helper);

        assert_eq!(
            result,
            Ok(DockerCredential::IdentityToken(String::from(
                "expected_token"
            )))
        );
    }

    #[test]
    fn gets_credential_from_store() {
        let store_config = config::DockerConfig {
            auths: None,
            creds_store: Some(String::from("cred_store")),
            cred_helpers: None,
        };
        let dummy_helper = |address: &str, helper: &str| {
            if address == String::from("some server") && helper == String::from("cred_store") {
                Ok(DockerCredential::IdentityToken(String::from(
                    "expected_token",
                )))
            } else {
                Err(CredentialRetrievalError::HelperCommunicationError)
            }
        };
        let result = extract_credential(store_config, "some server", dummy_helper);

        assert_eq!(
            result,
            Ok(DockerCredential::IdentityToken(String::from(
                "expected_token"
            )))
        );
    }
}
