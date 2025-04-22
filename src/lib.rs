mod config;
mod helper;

use base64::engine::general_purpose;
use base64::Engine;
use std::env;
use std::error::Error;
use std::fmt;
use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::str;

type Result<T> = std::result::Result<T, CredentialRetrievalError>;

/// An error that occurred whilst attempting to retrieve a credential.
#[derive(Debug, PartialEq)]
pub enum CredentialRetrievalError {
    HelperCommunicationError,
    MalformedHelperResponse,
    HelperFailure {
        helper: String,
        stdout: String,
        stderr: String,
    },
    CredentialDecodingError,
    NoCredentialConfigured,
    ConfigNotFound,
    ConfigReadError,
}

impl fmt::Display for CredentialRetrievalError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CredentialRetrievalError::HelperCommunicationError => {
                write!(f, "Unable to communicate with credential helper")
            }
            CredentialRetrievalError::MalformedHelperResponse => {
                write!(f, "Credential helper response malformed")
            }
            CredentialRetrievalError::HelperFailure {
                helper,
                stdout,
                stderr,
            } => {
                write!(
                    f,
                    "Credential helper `{helper}` returned non-zero response code:\n\
                    stdout:\n{stdout}\n\n\
                    stderr:\n{stderr}\n",
                )
            }
            CredentialRetrievalError::CredentialDecodingError => {
                write!(f, "Unable to decode credential")
            }
            CredentialRetrievalError::NoCredentialConfigured => {
                write!(f, "User has no credential configured")
            }
            CredentialRetrievalError::ConfigNotFound => write!(f, "No config file found"),
            CredentialRetrievalError::ConfigReadError => write!(f, "Unable to read config"),
        }
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
        .map(PathBuf::from)
        .or_else(home_config)
}

fn decode_auth(encoded_auth: &str) -> Result<DockerCredential> {
    let config = general_purpose::GeneralPurposeConfig::new()
        .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent);

    let engine = general_purpose::GeneralPurpose::new(&base64::alphabet::STANDARD, config);

    let decoded = engine
        .decode(encoded_auth)
        .map_err(|_| CredentialRetrievalError::CredentialDecodingError)?;
    let decoded =
        str::from_utf8(&decoded).map_err(|_| CredentialRetrievalError::CredentialDecodingError)?;
    let parts: Vec<&str> = decoded.splitn(2, ':').collect();
    let username = String::from(*parts.first().unwrap());
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

    if let Some(identity_token) = conf.get_identity_token(server) {
        return Ok(DockerCredential::IdentityToken(identity_token.to_string()));
    }

    if let Some(auth) = conf.get_auth(server) {
        return decode_auth(auth);
    }

    if let Some(store_name) = conf.creds_store {
        return from_helper(server, &store_name);
    }

    Err(CredentialRetrievalError::NoCredentialConfigured)
}

/// Retrieve a user's docker credential from a given reader.
///
/// Example:
/// ```no_run
/// use std::{fs::File, io::BufReader};
/// use docker_credential::DockerCredential;
///
/// let file = File::open("config.json").expect("Unable to open config file");
///
/// let reader = BufReader::new(file);
///
/// let credential = docker_credential::get_credential_from_reader(reader, "https://index.docker.io/v1/").expect("Unable to retrieve credential");
///
/// match credential {
///   DockerCredential::IdentityToken(token) => println!("Identity token: {}", token),
///   DockerCredential::UsernamePassword(user_name, password) => println!("Username: {}, Password: {}", user_name, password),
/// };
/// ```
pub fn get_credential_from_reader(
    reader: impl std::io::Read,
    server: &str,
) -> Result<DockerCredential> {
    let conf = config::read_config(reader)?;
    extract_credential(conf, server, helper::credential_from_helper)
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
    let config_path = config_dir()
        .ok_or(CredentialRetrievalError::ConfigNotFound)?
        .join("config.json");

    let f = File::open(config_path).map_err(|_| CredentialRetrievalError::ConfigReadError)?;

    get_credential_from_reader(BufReader::new(f), server)
}

/// Retrieve a user's docker credential from auth.json (as used by podman).
///
/// The lookup strategy adheres to the logic described
/// [in the podman docs](https://docs.podman.io/en/stable/markdown/podman-login.1.html#authfile-path).
///
/// For a usage example, refer to [`get_credential`].
pub fn get_podman_credential(server: &str) -> Result<DockerCredential> {
    let config_path = if let Some(auth_path) = env::var_os("REGISTRY_AUTH_FILE") {
        PathBuf::from(auth_path)
    } else {
        let primary_path = if cfg!(target_os = "linux") {
            env::var_os("XDG_RUNTIME_DIR")
                .map(PathBuf::from)
                .ok_or(CredentialRetrievalError::ConfigNotFound)?
                .join("containers/auth.json")
        } else {
            env::var_os("HOME")
                .map(PathBuf::from)
                .ok_or(CredentialRetrievalError::ConfigNotFound)?
                .join(".config/containers/auth.json")
        };

        if primary_path.is_file() {
            primary_path
        } else {
            config_dir()
                .ok_or(CredentialRetrievalError::ConfigNotFound)?
                .join("containers/auth.json")
        }
    };

    let f = File::open(config_path).map_err(|_| CredentialRetrievalError::ConfigReadError)?;

    get_credential_from_reader(BufReader::new(f), server)
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
        let encoded_auth = general_purpose::STANDARD_NO_PAD.encode("some_user:some_password");
        let mut auths = HashMap::new();
        auths.insert(
            String::from("some server"),
            config::AuthConfig {
                auth: Some(encoded_auth),
                identitytoken: None,
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
    fn decodes_regardless_of_padding() {
        let encoded_auths = [
            general_purpose::STANDARD.encode("some_user:some_password"),
            general_purpose::STANDARD_NO_PAD.encode("some_user:some_password"),
        ];

        let dummy_helper =
            |_: &str, _: &str| Err(CredentialRetrievalError::HelperCommunicationError);

        for encoded_auth in encoded_auths {
            let auths = HashMap::from([(
                String::from("some server"),
                config::AuthConfig {
                    auth: Some(encoded_auth),
                    identitytoken: None,
                },
            )]);

            let auth_config = config::DockerConfig {
                auths: Some(auths),
                creds_store: None,
                cred_helpers: None,
            };

            let result = extract_credential(auth_config, "some server", dummy_helper);

            assert_eq!(
                result,
                Ok(DockerCredential::UsernamePassword(
                    String::from("some_user"),
                    String::from("some_password")
                ))
            );
        }
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
            if address == "some server" && helper == "some_helper" {
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
            if address == "some server" && helper == "cred_store" {
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
