use super::{CredentialRetrievalError, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::fs::File;
use std::path::Path;

#[derive(Deserialize)]
pub(crate) struct AuthConfig {
    pub(crate) auth: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DockerConfig {
    pub(crate) auths: Option<HashMap<String, AuthConfig>>,
    pub(crate) creds_store: Option<String>,
    pub(crate) cred_helpers: Option<HashMap<String, String>>,
}

impl DockerConfig {
    pub fn get_auth(&self, server: &str) -> Option<&String> {
        self.auths
            .as_ref()
            .and_then(|auths| auths.get(server))
            .and_then(|auth_config| auth_config.auth.as_ref())
    }

    pub fn get_helper(&self, server: &str) -> Option<&String> {
        self.cred_helpers
            .as_ref()
            .and_then(|helpers| helpers.get(server))
    }
}

pub(crate) fn read_config(config_dir: &Path) -> Result<DockerConfig> {
    let config_path = config_dir.join("config.json");

    let f = File::open(config_path).map_err(|_| CredentialRetrievalError::ConfigReadError)?;

    serde_json::from_reader(f).map_err(|_| CredentialRetrievalError::ConfigReadError)
}
