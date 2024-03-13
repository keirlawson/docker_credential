use super::{CredentialRetrievalError, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::io::Read;

#[derive(Deserialize)]
pub(crate) struct AuthConfig {
    pub(crate) auth: Option<String>,
    pub(crate) identitytoken: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DockerConfig {
    pub(crate) auths: Option<HashMap<String, AuthConfig>>,
    pub(crate) creds_store: Option<String>,
    pub(crate) cred_helpers: Option<HashMap<String, String>>,
}

impl DockerConfig {
    pub fn get_auth(&self, image_registry: &str) -> Option<&String> {
        if let Some(auths) = &self.auths {
            if let Some(credential) = auths.get(image_registry) {
                return credential.auth.as_ref();
            }

            let image_registry = normalize_registry(image_registry);
            if let Some((_, auth_str)) = auths
                .iter()
                .find(|(key, _)| normalize_key_to_registry(key) == image_registry)
            {
                return auth_str.auth.as_ref();
            }
        }

        None
    }

    pub fn get_identity_token(&self, image_registry: &str) -> Option<&String> {
        if let Some(auths) = &self.auths {
            if let Some(auth_config) = auths.get(image_registry) {
                return auth_config.identitytoken.as_ref();
            }

            let image_registry = normalize_registry(image_registry);
            if let Some((_, auth_config)) = auths
                .iter()
                .find(|(key, _)| normalize_key_to_registry(key) == image_registry)
            {
                return auth_config.identitytoken.as_ref();
            }
        }

        None
    }

    pub fn get_helper(&self, server: &str) -> Option<&String> {
        self.cred_helpers
            .as_ref()
            .and_then(|helpers| helpers.get(server).filter(|s| !s.is_empty()))
    }
}

pub(crate) fn read_config(reader: impl Read) -> Result<DockerConfig> {
    serde_json::from_reader(reader).map_err(|_| CredentialRetrievalError::ConfigReadError)
}

/// Normalizes a given key (image reference) into its resulting registry
fn normalize_key_to_registry(key: &str) -> &str {
    let stripped = key.strip_prefix("http://").unwrap_or(key);
    let mut stripped = key.strip_prefix("https://").unwrap_or(stripped);
    if stripped != key {
        stripped = stripped.split_once('/').unwrap_or((stripped, "")).0;
    }

    normalize_registry(stripped)
}

/// Converts the provided registry if a known `docker.io` host
/// is provided.
fn normalize_registry(registry: &str) -> &str {
    match registry {
        "registry-1.docker.io" | "docker.io" => "index.docker.io",
        _ => registry,
    }
}

#[cfg(test)]
mod tests {
    #[rstest::rstest]
    #[case("https://index.docker.io/v1/", "index.docker.io")]
    #[case("https://docker.io/v1/", "index.docker.io")]
    #[case("quay.io", "quay.io")]
    fn test_normalize_key_to_registry(#[case] key: &str, #[case] expected: &str) {
        let registry = super::normalize_key_to_registry(key);
        assert_eq!(registry, expected);
    }
}
