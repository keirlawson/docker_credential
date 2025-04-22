use super::{CredentialRetrievalError, DockerCredential, Result};
use serde::Deserialize;
use std::io::Write;
use std::process::{Command, Stdio};

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct HelperResponse {
    username: String,
    secret: String,
}

fn response_from_helper(address: &str, helper: &str) -> Result<HelperResponse> {
    let full_helper_name = format!("docker-credential-{}", helper);
    let mut process = Command::new(&full_helper_name)
        .arg("get")
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|_| CredentialRetrievalError::HelperCommunicationError)?;

    process
        .stdin
        .as_mut()
        .ok_or(CredentialRetrievalError::HelperCommunicationError)?
        .write_all(address.as_bytes())
        .map_err(|_| CredentialRetrievalError::HelperCommunicationError)?;

    let output = process
        .wait_with_output()
        .map_err(|_| CredentialRetrievalError::HelperCommunicationError)?;

    if output.status.success() {
        let parsed = serde_json::from_slice(&output.stdout)
            .map_err(|_| CredentialRetrievalError::MalformedHelperResponse)?;
        Ok(parsed)
    } else {
        Err(CredentialRetrievalError::HelperFailure {
            helper: full_helper_name,
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

pub fn credential_from_helper(address: &str, helper: &str) -> Result<DockerCredential> {
    let response = response_from_helper(address, helper)?;

    if response.username == "<token>" {
        Ok(DockerCredential::IdentityToken(response.secret))
    } else {
        Ok(DockerCredential::UsernamePassword(
            response.username,
            response.secret,
        ))
    }
}
